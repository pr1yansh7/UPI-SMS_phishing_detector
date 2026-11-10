"""
features/deeplink_features.py — UPI deep-link analyser (upi://pay?pa=…&pn=…&am=…).

Scam links sent on WhatsApp/SMS use the upi:// scheme, so URL checks never see
them. This module parses the link and scores the payee/amount/note.

Edit THIS file if a UPI link is scored wrongly. Word lists / handles live in
config.py (UPI_* lists). Rules are heuristics — NOT a guarantee either way.

Key fact for users: a UPI PIN is only ever needed to SEND money.
"""

import re
from urllib.parse import parse_qs

from config import (
    UPI_KNOWN_HANDLES, UPI_LINK_PATTERN, UPI_NOTE_BAIT_WORDS,
    UPI_PAYEE_TERMS, UPI_VPA_BAIT_WORDS,
)

ADVICE = ("A UPI PIN is only needed to SEND money — you never enter it to receive money. "
          "If you did not expect to pay, do not proceed; verify the payee directly.")

_VPA_RE = re.compile(r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$")
_AMOUNT_RE = re.compile(r"^\d+(?:\.\d{1,2})?$")
_LINK_RE = re.compile(UPI_LINK_PATTERN, re.IGNORECASE)
_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def _tokens(text: str) -> list:
    return [t for t in _SPLIT_RE.split(text.lower()) if t]


def contains_term(text: str, term: str) -> bool:
    """Whole-token match (long words also match as a prefix: 'refund' ~ 'refunds');
    multi-word terms match as substrings. Avoids 'care' matching 'healthcare'."""
    lower = text.lower()
    if " " in term:
        return term in lower
    return any(tok == term or (len(term) >= 5 and tok.startswith(term)) for tok in _tokens(lower))


def extract_upi_links(text: str) -> list:
    return [m.rstrip(".,;)") for m in _LINK_RE.findall(text or "")]


def parse_upi_link(uri: str):
    uri = (uri or "").strip()
    if not uri.lower().startswith("upi://"):
        return None
    rest = uri[6:].split("#", 1)[0]
    action, _, query = rest.partition("?")
    params = {k.lower(): v[0] for k, v in parse_qs(query, keep_blank_values=True).items()}
    return {"action": action.strip("/").lower(), "params": params}


def analyse_upi_deeplink(uri: str) -> dict:
    result = {
        "uri": uri, "valid_upi_link": 0, "action": "", "payee_vpa": "", "payee_name": "",
        "amount": None, "currency": "", "note": "", "flags": [], "risk_score": 0.0,
        "risk_level": "unknown", "is_suspicious_link": False, "is_phishing": False,
        "advice": ADVICE,
    }
    parsed = parse_upi_link(uri)
    if not parsed:
        result["flags"] = ["Not a upi:// link"]
        return result

    action, p = parsed["action"], parsed["params"]
    score, flags = 0.0, []

    pa = p.get("pa", "").strip()
    if not pa:
        score += 0.30; flags.append("No payee UPI ID in the link")
    elif not _VPA_RE.match(pa):
        score += 0.30; flags.append("Payee UPI ID is malformed")
    else:
        local, handle = pa.rsplit("@", 1)
        if handle.lower() not in UPI_KNOWN_HANDLES:
            score += 0.10; flags.append(f"Unrecognised UPI handle '@{handle}' (list is not exhaustive)")
        if any(contains_term(local, w) for w in UPI_VPA_BAIT_WORDS):
            score += 0.35; flags.append("Payee UPI ID contains scam-bait words (refund / support / kyc …)")

    pn = p.get("pn", "")
    if pn and any(contains_term(pn, t) for t in UPI_PAYEE_TERMS):
        score += 0.25; flags.append("Payee name imitates a brand or authority")

    tn = p.get("tn", "")
    if tn and any(contains_term(tn, w) for w in UPI_NOTE_BAIT_WORDS):
        score += 0.25; flags.append("Payment note uses refund / prize / KYC bait")

    am = p.get("am", "").strip()
    if am:
        if not _AMOUNT_RE.match(am):
            score += 0.15; flags.append("Amount is not a valid number")
        elif float(am) >= 10000:
            score += 0.20; flags.append("High pre-filled amount")
        elif float(am) > 0:
            score += 0.05; flags.append("Amount is pre-filled — check it is what you expect")

    cu = p.get("cu", "").upper()
    if cu and cu != "INR":
        score += 0.15; flags.append(f"Currency is {cu}, not INR")

    if action == "mandate":
        score += 0.15; flags.append("Recurring auto-debit (mandate) link")
    elif action != "pay":
        score += 0.15; flags.append(f"Unusual UPI action '{action}'")

    if "url" in p:
        score += 0.05; flags.append("Link carries an extra URL parameter")

    score = round(min(score, 1.0), 4)
    result.update({
        "valid_upi_link": 1, "action": action, "payee_vpa": pa, "payee_name": pn,
        "amount": am or None, "currency": cu, "note": tn, "flags": flags,
        "risk_score": score,
        "risk_level": "low" if score < 0.25 else ("medium" if score < 0.5 else "high"),
        "is_suspicious_link": score >= 0.40, "is_phishing": score >= 0.40,
    })
    return result
