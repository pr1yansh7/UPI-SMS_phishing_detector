"""
features/qr_features.py — QR Code Phishing Detection (QRishing).

UPI is QR-code-first. Phishers physically replace merchant QR codes
with malicious ones, or send fake QR images via WhatsApp/SMS.
This module decodes QR codes and runs the embedded URL through the
existing phishing pipeline.

Edit THIS file if QR decoding gives wrong results.
For phishing logic on the extracted URL → feature_extractor.py

Requires: pip install pyzbar Pillow
On Ubuntu/Debian also: sudo apt-get install libzbar0
"""

import logging
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

log = logging.getLogger(__name__)

# Optional — gracefully degrade if pyzbar/Pillow not installed
try:
    from pyzbar.pyzbar import decode as decode_qr
    from PIL import Image
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False
    log.debug("pyzbar/Pillow not installed — QR features unavailable. Run: pip install pyzbar Pillow")


def extract_url_from_qr(image_path: str) -> Optional[str]:
    """
    Decode a QR code image and return the embedded URL.

    Args:
        image_path: Path to a PNG, JPG, or any PIL-supported image file.

    Returns:
        The decoded URL string, or None if:
          - pyzbar/Pillow not installed
          - No QR code found in image
          - QR code does not contain a URL
    """
    if not QR_AVAILABLE:
        log.warning("pyzbar not installed — cannot decode QR code.")
        return None

    path = Path(image_path)
    if not path.exists():
        log.warning(f"QR image not found: {image_path}")
        return None

    try:
        img      = Image.open(str(path))
        decoded  = decode_qr(img)
        if not decoded:
            log.debug(f"No QR code found in: {image_path}")
            return None

        raw = decoded[0].data.decode("utf-8", errors="ignore").strip()
        log.debug(f"QR decoded: {raw[:80]}")
        return raw
    except Exception as e:
        log.warning(f"QR decode failed for {image_path}: {e}")
        return None


def is_upi_qr(image_path: str) -> int:
    """
    Returns 1 if the QR code contains a UPI deep link (upi://pay?...).
    Legitimate UPI QR codes use the upi:// scheme with a verified PA.
    Malicious QR codes use http/https URLs that redirect to phishing pages.
    """
    url = extract_url_from_qr(image_path)
    if not url:
        return 0
    return 1 if url.lower().startswith("upi://") else 0


def qr_url_is_http(image_path: str) -> int:
    """
    Returns 1 if the QR encodes a plain HTTP URL (not HTTPS, not upi://).
    Legitimate payment QR codes use upi:// scheme or HTTPS.
    HTTP-only QR codes in payment context are almost always malicious.
    """
    url = extract_url_from_qr(image_path)
    if not url:
        return 0
    return 1 if urlparse(url).scheme.lower() == "http" else 0


def qr_contains_suspicious_domain(image_path: str) -> int:
    """
    Decode the QR and check if the embedded URL uses a suspicious TLD.
    Mirrors the suspicious_tld feature from domain_features.py but
    applied to QR-encoded URLs specifically.
    """
    from config import SUSPICIOUS_TLDS
    url = extract_url_from_qr(image_path)
    if not url:
        return 0
    host = urlparse(url).netloc.lower()
    return int(any(host.endswith(tld) for tld in SUSPICIOUS_TLDS))


def analyse_qr(image_path: str, model=None) -> dict:
    """
    Full QR phishing analysis pipeline:
      1. Decode QR code from image
      2. Extract embedded URL
      3. Run URL through full 39-feature ML pipeline (if model provided)
      4. Return combined result

    Args:
        image_path: Path to QR code image file.
        model:      Trained sklearn Pipeline (optional). If provided,
                    runs full ML prediction on the decoded URL.

    Returns:
        dict with:
          decoded_url     — the URL found in the QR (or None)
          is_upi_qr       — 1 if uses upi:// scheme
          qr_url_is_http  — 1 if plain HTTP (suspicious)
          suspicious_domain — 1 if suspicious TLD
          ml_result       — full predict_url() result (if model provided)
    """
    result = {
        "image_path":         image_path,
        "decoded_url":        None,
        "is_upi_qr":          0,
        "qr_url_is_http":     0,
        "suspicious_domain":  0,
        "ml_result":          None,
        "error":              None,
    }

    if not QR_AVAILABLE:
        result["error"] = "pyzbar not installed. Run: pip install pyzbar Pillow"
        return result

    url = extract_url_from_qr(image_path)
    if not url:
        result["error"] = "No QR code found or could not decode"
        return result

    result["decoded_url"]       = url
    result["is_upi_qr"]         = 1 if url.lower().startswith("upi://") else 0
    result["qr_url_is_http"]    = 1 if urlparse(url).scheme.lower() == "http" else 0
    result["suspicious_domain"] = qr_contains_suspicious_domain(image_path)

    # If URL is a web URL and model is provided, run full ML prediction
    if model and urlparse(url).scheme in ("http", "https"):
        try:
            from predictor import predict_url
            result["ml_result"] = predict_url(url, model, fetch_html=False, verbose=False)
        except Exception as e:
            result["error"] = f"ML prediction failed: {e}"

    return result
