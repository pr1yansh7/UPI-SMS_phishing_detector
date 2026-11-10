"""
features/advanced_domain_features.py — Advanced Domain & Network features.

Contains the remaining Tier 2 and 3 features:
  - Phonetic brand similarity (Soundex/Metaphone)
  - IPFS/decentralised hosting detection
  - Full redirect chain analysis
  - WHOIS privacy shield detection
  - Tranco/Alexa popularity rank
  - Certificate Transparency log monitoring

Edit THIS file if any of these give wrong results.
For basic domain features (TLD, brand) → domain_features.py
"""

import logging
import re
import socket
from urllib.parse import urlparse

import requests

from config import (
    IPFS_GATEWAYS,
    REQUEST_TIMEOUT,
    TRANCO_API_URL,
    UPI_BRANDS,
    USER_AGENT,
    WHOIS_API_KEY,
)

log = logging.getLogger(__name__)

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# ── Phonetic Similarity ────────────────────────────────────────────────────────

_PHONETIC_RULES = (("ph", "f"), ("ck", "k"), ("ch", "x"), ("sh", "x"), ("x", "ks"),
                   ("q", "k"), ("z", "s"), ("w", "v"))


def phonetic_key(word: str) -> str:
    """
    Tiny deterministic 'sounds-like' key: normalise common spelling variants (ph→f, ck→k,
    c→k/s, z→s, q→k…), keep the first letter, drop later vowels/y/h, collapse repeats.

        phonepe, fhonepe, phonpe  → fnp        paytm, paytem → ptm        aadhaar, adhar → adr

    Pure Python on purpose (an earlier version used the `fuzzy` C extension, which returned
    garbage/raised intermittently). Heuristic — short keys (< 3 chars) are never compared.
    """
    w = re.sub(r"[^a-z]", "", word.lower())
    if not w:
        return ""
    for old, new in _PHONETIC_RULES:
        w = w.replace(old, new)
    w = re.sub(r"c(?=[eiy])", "s", w).replace("c", "k")
    key = w[0] + "".join(ch for ch in w[1:] if ch not in "aeiouyh")
    return re.sub(r"(.)\1+", r"\1", key)


def phonetic_brand_similarity(url: str) -> int:
    """
    Returns 1 if a label of the domain SOUNDS like a UPI/Aadhaar brand without being spelled
    like it — typosquats that edit distance can miss:  fhonepe.xyz ~ phonepe,  paytem.in ~ paytm.
    Labels are split on - and _ so  fhonepe-kyc.xyz  is caught too. Exact brand names return 0.
    Always returns 0 or 1 (no external dependency).
    """
    host = urlparse(url).netloc.lower().split(":")[0]
    labels = host.split(".")[:-1] or host.split(".")
    tokens = [t for label in labels for t in re.split(r"[-_]", label) if t]
    brand_keys = {}
    for brand in UPI_BRANDS:
        k = phonetic_key(brand)
        if len(k) >= 3:
            brand_keys.setdefault(k, set()).add(brand)
    for tok in tokens:
        k = phonetic_key(tok)
        if len(k) >= 3 and k in brand_keys and tok not in brand_keys[k]:
            return 1
    return 0


# ── IPFS / Decentralised Hosting ───────────────────────────────────────────────

def is_ipfs_hosted(url: str) -> int:
    """
    Returns 1 if the URL is served via an IPFS (InterPlanetary File System)
    gateway or any other decentralised hosting provider.

    Phishers use IPFS because:
      1. Content cannot be removed by any central authority (no takedown)
      2. Traditional domain blocklists are ineffective against content hashes
      3. The same phishing page can be accessed via thousands of gateways

    IPFS phishing is a growing threat — CERT-In issued advisories in 2023
    about IPFS-hosted phishing pages targeting Indian banking customers.

    To add new IPFS gateways: edit IPFS_GATEWAYS in config.py.
    """
    host = urlparse(url).netloc.lower().split(":")[0]
    # Direct gateway URL: ipfs.io/ipfs/Qm...
    if any(gw in host for gw in IPFS_GATEWAYS):
        return 1
    # Hash-based subdomain: Qm....ipfs.dweb.link
    if re.search(r'Qm[a-zA-Z0-9]{44}', url) or 'ipfs' in host:
        return 1
    return 0


# ── Full Redirect Chain Analysis ────────────────────────────────────────────────

def redirect_chain(url: str) -> dict:
    """
    Follow the full redirect chain and return details about each hop.
    Phishing campaigns chain redirects through:
      1. A legitimate-looking link shortener or tracker
      2. An intermediate landing page that checks the visitor's country/device
      3. The actual credential-harvesting page

    Returns:
      chain:          list of URLs visited in order
      chain_length:   total number of hops
      crosses_domain: 1 if the chain changes domain at any point
      final_url:      the last URL in the chain
      has_suspicious_hop: 1 if any URL in the chain looks suspicious
    """
    result = {
        "chain":               [],
        "chain_length":        0,
        "crosses_domain":      0,
        "final_url":           url,
        "has_suspicious_hop":  0,
    }
    from config import SUSPICIOUS_TLDS

    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
            verify=False,
        )
        chain   = [r.url for r in resp.history] + [resp.url]
        domains = [urlparse(u).netloc for u in chain]
        first_d = domains[0] if domains else ""

        crosses = int(len(set(domains)) > 1)
        susp    = int(any(
            any(urlparse(u).netloc.endswith(tld) for tld in SUSPICIOUS_TLDS)
            for u in chain
        ))

        result.update({
            "chain":              chain,
            "chain_length":       len(chain) - 1,
            "crosses_domain":     crosses,
            "final_url":          resp.url,
            "has_suspicious_hop": susp,
        })
    except Exception as e:
        log.debug(f"redirect_chain failed for {url}: {e}")

    return result


def redirect_crosses_domain(url: str) -> int:
    """
    Returns 1 if the URL's redirect chain crosses at least one domain boundary.
    Single feature version of redirect_chain() for the ML pipeline.
    """
    return redirect_chain(url).get("crosses_domain", 0)


def redirect_has_suspicious_hop(url: str) -> int:
    """
    Returns 1 if any URL in the redirect chain uses a suspicious TLD.
    Catches chains that start on a clean domain but route through evil.xyz.
    """
    return redirect_chain(url).get("has_suspicious_hop", 0)


# ── WHOIS Privacy Shield Detection ─────────────────────────────────────────────

def whois_privacy_protected(url: str) -> int:
    """
    Returns 1 if the domain uses a WHOIS privacy shield.
    Legitimate businesses (banks, NPCI, UIDAI) never hide their registration.
    Phishing domains almost always use privacy shields to hide registrant details.

    Returns:
      1  — WHOIS is privacy-protected (suspicious)
      0  — WHOIS shows real registrant details (clean signal)
     -1  — WHOIS API not configured or lookup failed

    Requires WHOIS_API_KEY in .env (https://www.whoisxmlapi.com)
    """
    if WHOIS_API_KEY == "YOUR_WHOIS_API_KEY":
        return -1

    host    = urlparse(url).netloc.split(":")[0]
    api_url = (
        f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
        f"?apiKey={WHOIS_API_KEY}&domainName={host}&outputFormat=JSON"
    )
    try:
        resp = requests.get(api_url, timeout=REQUEST_TIMEOUT)
        data = resp.json()
        registrant = (
            data.get("WhoisRecord", {})
            .get("registrant", {})
            .get("organization", "")
            .lower()
        )
        privacy_keywords = [
            "privacy", "redacted", "whoisguard", "domains by proxy",
            "perfect privacy", "contact privacy", "withheld",
        ]
        return int(any(kw in registrant for kw in privacy_keywords))
    except Exception as e:
        log.debug(f"WHOIS privacy check failed for {host}: {e}")
        return -1


# ── Tranco Popularity Rank ──────────────────────────────────────────────────────

def tranco_rank(url: str) -> int:
    """
    Query the Tranco list (research-grade replacement for Alexa) to get the
    global popularity rank of the domain.

    Real UPI/Aadhaar apps are globally popular (rank < 100,000).
    Phishing domains have no rank (not listed = 0) or are newly created.

    Returns:
      int > 0  — the domain's Tranco rank (lower = more popular)
      0        — domain not in Tranco top 1 million (suspicious)
     -1        — API unavailable or lookup failed

    Free API: https://tranco-list.eu/api/ranks/domain/{domain}
    """
    host = urlparse(url).netloc.split(":")[0]
    # Strip www prefix for lookup
    if host.startswith("www."):
        host = host[4:]

    try:
        resp = requests.get(
            f"https://tranco-list.eu/api/ranks/domain/{host}",
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            data  = resp.json()
            ranks = data.get("ranks", [])
            if ranks:
                return int(ranks[0].get("rank", 0))
            return 0   # not in top 1M = suspicious
        return -1
    except Exception as e:
        log.debug(f"Tranco lookup failed for {host}: {e}")
        return -1


def is_low_popularity_domain(url: str, threshold: int = 100_000) -> int:
    """
    Returns 1 if the domain has no Tranco rank or is ranked below threshold.
    Real UPI app domains (phonepe.com, uidai.gov.in) are in top 100K globally.
    Phishing domains are almost never ranked.

    Returns -1 if Tranco API unavailable.
    """
    rank = tranco_rank(url)
    if rank == -1:
        return -1
    return 1 if rank == 0 or rank > threshold else 0


# ── Certificate Transparency Log Monitoring ─────────────────────────────────────

def crt_sh_new_cert_count(url: str, days: int = 7) -> int:
    """
    Query crt.sh (Certificate Transparency log aggregator) for the number of
    SSL certificates issued for this domain in the last N days.

    Phishers register fresh certificates moments before launching attacks.
    A domain with certificates issued in the last 7 days is suspicious —
    legitimate businesses don't change their certs that frequently.

    Returns:
      int >= 0  — number of certs issued in last N days
      -1        — crt.sh lookup failed

    No API key required — crt.sh is a free public service.
    """
    host = urlparse(url).netloc.split(":")[0]
    if host.startswith("www."):
        host = host[4:]

    try:
        resp = requests.get(
            f"https://crt.sh/?q={host}&output=json",
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        if resp.status_code != 200:
            return -1

        from datetime import datetime, timedelta, timezone
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        certs  = resp.json()
        recent = sum(
            1 for c in certs
            if datetime.strptime(
                c.get("not_before", "2000-01-01T00:00:00"),
                "%Y-%m-%dT%H:%M:%S"
            ) >= cutoff
        )
        return recent
    except Exception as e:
        log.debug(f"crt.sh lookup failed for {host}: {e}")
        return -1


def has_recent_certificate(url: str, days: int = 7) -> int:
    """
    Binary feature: returns 1 if the domain got a new SSL cert in last N days.
    This is a strong phishing signal when combined with suspicious TLD/brand signals.
    Returns -1 if crt.sh unavailable.
    """
    count = crt_sh_new_cert_count(url, days=days)
    if count == -1:
        return -1
    return 1 if count > 0 else 0
