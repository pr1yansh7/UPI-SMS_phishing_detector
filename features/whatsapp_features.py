"""
features/whatsapp_features.py — WhatsApp message scam analyser.

Reuses the SMS analyser (OTP requests, threats, urgency, regional languages) and adds
WhatsApp-specific scams: lottery/KBC, chain-forwards, work-from-home tasks, fake .apk
downloads (RTO challan / PM-Kisan), utility threats, group-invite pushes, embedded
links and embedded upi:// links.

Edit THIS file if a WhatsApp message is scored wrongly. Patterns/weights are in
config.py (WA_PATTERNS, WA_PATTERN_WEIGHTS). Rule-based — NOT a trained model.
"""

import re
from urllib.parse import urlparse

from allowlist import is_official_domain
from config import WA_PATTERN_WEIGHTS, WA_PATTERNS, WA_PHISHING_THRESHOLD, WA_URL_PATTERN
from features.deeplink_features import ADVICE as UPI_ADVICE
from features.deeplink_features import analyse_upi_deeplink, extract_upi_links
from features.domain_features import brand_in_hostname, suspicious_tld
from features.osint_features import is_url_shortener
from features.sms_features import analyse_sms

ADVICE = ("Do not click links, install apps or share OTP/PIN. Real banks, UIDAI and UPI apps "
          "never ask for these on WhatsApp. " + UPI_ADVICE)

_URL_RE = re.compile(WA_URL_PATTERN, re.IGNORECASE)

_REASONS = {
    "lottery_prize": "Claims you won a prize/lottery — you can't win a contest you never entered",
    "forward_chain": "Asks you to forward it to contacts/groups (chain-message pattern)",
    "fake_job": "Work-from-home / easy daily-income offer (common task & investment scam)",
    "apk_download": "Asks you to install an app file (.apk) — a common way to steal UPI/SMS access",
    "govt_lure": "Uses a government-scheme or free-benefit lure (PM-Kisan, ration, free recharge…)",
    "utility_threat": "Threatens disconnection/blocking or a fine (electricity, SIM, challan, parcel)",
    "group_invite": "Pushes you into a WhatsApp/Telegram group",
    "otp_request": "Asks you to share/send an OTP — no real service ever does this",
    "account_threat": "Threatens to block/suspend your account, UPI or Aadhaar",
}


def extract_urls(text: str) -> list:
    urls = []
    for m in _URL_RE.findall(text or ""):
        u = m.rstrip(".,;:!?)")
        if not u.lower().startswith("http"):
            u = "https://" + u
        urls.append(u)
    return urls


def link_risk(url: str):
    """Offline risk of one link: returns (risk 0..1, [reasons])."""
    if is_official_domain(url):
        return 0.0, []
    risk, flags = 0.0, []
    if is_url_shortener(url):
        risk += 0.40; flags.append("Link uses a URL shortener (hides the real destination)")
    if suspicious_tld(url):
        risk += 0.40; flags.append("Link uses a domain extension common in scams (.xyz, .tk, .top …)")
    if brand_in_hostname(url):
        risk += 0.30; flags.append("Link imitates a UPI/Aadhaar brand but is not the official site")
    p = urlparse(url)
    if p.scheme.lower() == "http":
        risk += 0.15; flags.append("Link is not HTTPS")
    if p.path.lower().endswith(".apk"):
        risk += 0.35; flags.append("Link downloads an app file (.apk)")
    return min(risk, 1.0), flags


def _dedupe(items):
    seen, out = set(), []
    for i in items:
        if i not in seen:
            seen.add(i); out.append(i)
    return out


def analyse_whatsapp(text: str) -> dict:
    text = text or ""
    sms = analyse_sms(text, "")

    hits = {name: int(any(re.search(p, text, re.IGNORECASE) for p in pats))
            for name, pats in WA_PATTERNS.items()}
    pattern_points = sum(WA_PATTERN_WEIGHTS[n] for n, h in hits.items() if h)

    urls = extract_urls(text)
    link_info = [link_risk(u) for u in urls]
    max_link = max((r for r, _ in link_info), default=0.0)

    upi_links = extract_upi_links(text)
    upi_results = [analyse_upi_deeplink(u) for u in upi_links]
    max_upi = max((r["risk_score"] for r in upi_results), default=0.0)

    score = round(min(1.0, 0.5 * sms["sms_risk_score"] + pattern_points
                      + 0.5 * max_link + 0.5 * max_upi), 4)

    flags = [_REASONS[n] for n in WA_PATTERNS if hits[n]]
    for _, fl in link_info:
        flags.extend(fl)
    for r in upi_results:
        if r["risk_score"] >= 0.25:
            flags.extend(f"UPI link: {f}" for f in r["flags"])
    if sms["sms_urgency_score"] > 0.1:
        flags.append("Uses urgency/pressure wording")
    if sms["sms_phish_keyword_count"] >= 2:
        flags.append("Contains several known phishing phrases")
    if sms["sms_hinglish_phish_score"] > 0.05:
        flags.append("Contains phishing wording in Hindi/Tamil/Telugu/Bengali")

    result = {f"wa_{n}": h for n, h in hits.items()}
    result.update({
        "sms_risk_score": sms["sms_risk_score"],
        "max_link_risk": round(max_link, 4), "max_upi_risk": round(max_upi, 4),
        "urls_found": urls, "upi_links_found": upi_links,
        "whatsapp_risk_score": score, "risk_score": score,
        "is_phishing_whatsapp": score >= WA_PHISHING_THRESHOLD,
        "is_phishing": score >= WA_PHISHING_THRESHOLD,
        "flags": _dedupe(flags), "advice": ADVICE,
    })
    return result
