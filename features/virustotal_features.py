"""
features/virustotal_features.py — VirusTotal Threat Intelligence.

Queries VirusTotal's API to check a URL against 70+ antivirus and
threat intelligence engines simultaneously. This is the industry-standard
threat lookup used by security teams worldwide.

Edit THIS file if VirusTotal queries fail or return wrong results.
For API key configuration → config.py / .env

Free API: https://www.virustotal.com/gui/sign-in (500 lookups/day)
"""

import base64
import logging
import time
from typing import Optional

import requests

from config import REQUEST_TIMEOUT, VIRUSTOTAL_API_KEY

log = logging.getLogger(__name__)


def _url_to_vt_id(url: str) -> str:
    """
    VirusTotal v3 API expects URLs encoded as URL-safe base64 without padding.
    This is the format VT uses internally to deduplicate URLs.
    """
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def virustotal_lookup(url: str, submit: bool = True) -> dict:
    """
    Query VirusTotal API v3 for a URL's threat analysis.

    Returns a dict with:
      vt_malicious:   number of engines flagging as malicious
      vt_suspicious:  number of engines flagging as suspicious
      vt_clean:       number of engines that say it's clean
      vt_undetected:  number of engines with no opinion
      vt_total:       total engines queried
      vt_score:       ratio of (malicious+suspicious) / total (0.0–1.0)
      vt_status:      'clean', 'suspicious', 'malicious', 'unknown', or 'error'

    Returns all zeros with status='error' if:
      - API key not configured
      - URL not yet in VT database (submits for analysis and returns unknown)
      - Network error
    """
    empty = {
        "vt_malicious": 0, "vt_suspicious": 0, "vt_clean": 0,
        "vt_undetected": 0, "vt_total": 0, "vt_score": -1.0,
        "vt_status": "error",
    }

    if VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        log.debug("VirusTotal API key not configured — skipping lookup.")
        empty["vt_status"] = "not_configured"
        return empty

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url_id  = _url_to_vt_id(url)

    try:
        # Try fetching existing analysis first
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if resp.status_code == 404 and not submit:
            empty["vt_status"] = "not_found"      # unknown to VT — NOT the same as clean
            return empty

        if resp.status_code == 404:
            # URL not in VT database — submit for analysis
            log.debug(f"VT: URL not found, submitting for analysis: {url[:60]}")
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=REQUEST_TIMEOUT,
            )
            if submit.status_code not in (200, 201):
                empty["vt_status"] = "submission_failed"
                return empty
            # Wait briefly then re-fetch
            time.sleep(3)
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )

        if resp.status_code != 200:
            log.warning(f"VT API returned {resp.status_code} for {url[:60]}")
            empty["vt_status"] = f"http_{resp.status_code}"
            return empty

        data  = resp.json()
        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        clean      = stats.get("harmless",   0) + stats.get("undetected", 0)
        undetected = stats.get("undetected", 0)
        total      = sum(stats.values())

        score = round((malicious + suspicious) / total, 4) if total else -1.0

        if malicious > 2:
            status = "malicious"
        elif suspicious > 2 or malicious > 0:
            status = "suspicious"
        elif total > 0:
            status = "clean"
        else:
            status = "unknown"

        return {
            "vt_malicious":  malicious,
            "vt_suspicious": suspicious,
            "vt_clean":      clean,
            "vt_undetected": undetected,
            "vt_total":      total,
            "vt_score":      score,
            "vt_status":     status,
        }

    except requests.RequestException as e:
        log.warning(f"VirusTotal API error for {url[:60]}: {e}")
        empty["vt_status"] = "network_error"
        return empty


def virustotal_score(url: str) -> float:
    """
    Single feature: ratio of VirusTotal engines that flag this URL as
    malicious or suspicious. Range 0.0–1.0. Returns -1.0 if unavailable.

    Threshold for suspicion: > 0.05 (more than 5% of engines flag it).
    Even 1–2 engines flagging a URL is meaningful — phishing URLs often
    appear on only a few specialised threat intel engines first.
    """
    result = virustotal_lookup(url)
    return result["vt_score"]


def virustotal_is_malicious(url: str) -> int:
    """
    Binary feature: returns 1 if VirusTotal considers URL malicious/suspicious,
    0 if clean, -1 if API not available.
    """
    result = virustotal_lookup(url)
    if result["vt_status"] in ("malicious", "suspicious"):
        return 1
    if result["vt_status"] in ("error", "not_configured", "network_error"):
        return -1
    return 0
