"""
features/visual_features.py — Visual Similarity Detection (Perceptual Hashing).

Takes a screenshot of the phishing page and compares it pixel-by-pixel
to reference screenshots of real UPI/Aadhaar apps. Catches pixel-perfect
clones that fool all text-based features.

Edit THIS file if visual similarity scores are wrong.

Requires: pip install selenium imagehash Pillow
          Chrome/Chromium must be installed on the system.
"""

import io
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# Optional — gracefully degrade if dependencies not installed
try:
    from PIL import Image
    import imagehash
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

# ── Reference hashes of real UPI/Aadhaar app homepages ─────────────────────
# These are pre-computed perceptual hashes. Generate fresh ones by running:
#   python -c "from features.visual_features import generate_reference_hashes; generate_reference_hashes()"
#
# Hashes below are placeholders — replace with real ones after running above.
REFERENCE_HASHES: dict[str, str] = {
    "phonepe":  "",   # generated from https://www.phonepe.com/
    "gpay":     "",   # generated from https://pay.google.com/
    "paytm":    "",   # generated from https://paytm.com/
    "bhim":     "",   # generated from https://www.bhimupi.org.in/
    "uidai":    "",   # generated from https://uidai.gov.in/
    "digilocker": "", # generated from https://digilocker.gov.in/
}

REFERENCE_URLS: dict[str, str] = {
    "phonepe":    "https://www.phonepe.com/",
    "gpay":       "https://pay.google.com/",
    "paytm":      "https://paytm.com/",
    "bhim":       "https://www.bhimupi.org.in/",
    "uidai":      "https://uidai.gov.in/",
    "digilocker": "https://digilocker.gov.in/",
}


def _chrome_driver() -> Optional[object]:
    """Create a headless Chrome driver. Returns None if Selenium not available."""
    if not SELENIUM_AVAILABLE:
        log.debug("Selenium not installed — visual features unavailable.")
        return None
    try:
        opts = Options()
        opts.add_argument("--headless")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--window-size=1280,800")
        opts.add_argument("--disable-gpu")
        return webdriver.Chrome(options=opts)
    except Exception as e:
        log.debug(f"Chrome driver failed: {e}")
        return None


def screenshot_url(url: str, timeout: int = 10) -> Optional[bytes]:
    """
    Take a headless screenshot of a URL and return raw PNG bytes.
    Returns None if Selenium/Chrome not available or navigation fails.
    """
    driver = _chrome_driver()
    if not driver:
        return None
    try:
        driver.set_page_load_timeout(timeout)
        driver.get(url)
        return driver.get_screenshot_as_png()
    except Exception as e:
        log.debug(f"Screenshot failed for {url}: {e}")
        return None
    finally:
        try:
            driver.quit()
        except Exception:
            pass


def compute_phash(png_bytes: bytes) -> Optional[str]:
    """
    Compute the perceptual hash of a PNG screenshot.
    Returns the hash as a hex string, or None if PIL not available.
    """
    if not PIL_AVAILABLE:
        return None
    try:
        img  = Image.open(io.BytesIO(png_bytes))
        return str(imagehash.phash(img))
    except Exception as e:
        log.debug(f"phash computation failed: {e}")
        return None


def generate_reference_hashes(
    output_path: str = "data/reference_hashes.json",
) -> dict[str, str]:
    """
    Screenshot each real UPI/Aadhaar app and compute its perceptual hash.
    Run this once to populate the REFERENCE_HASHES dict above.

    Usage:
        python -c "from features.visual_features import generate_reference_hashes; generate_reference_hashes()"
    """
    import json
    hashes = {}
    for name, url in REFERENCE_URLS.items():
        log.info(f"Screenshotting {name}: {url}")
        png = screenshot_url(url)
        if png:
            h = compute_phash(png)
            if h:
                hashes[name] = h
                log.info(f"  {name}: {h}")
            else:
                log.warning(f"  {name}: hash failed")
        else:
            log.warning(f"  {name}: screenshot failed")

    Path(output_path).parent.mkdir(exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(hashes, f, indent=2)
    log.info(f"Reference hashes saved → {output_path}")
    return hashes


def load_reference_hashes(path: str = "data/reference_hashes.json") -> dict[str, str]:
    """Load pre-computed reference hashes from JSON file."""
    import json
    p = Path(path)
    if p.exists():
        with open(p) as f:
            return json.load(f)
    return REFERENCE_HASHES  # fall back to module-level placeholders


def visual_similarity_score(url: str, timeout: int = 10) -> float:
    """
    Screenshot the URL and compare to all reference app pages using
    perceptual hashing. Returns the maximum similarity score (0.0–1.0).

    0.0 = completely different from all known UPI/Aadhaar pages
    1.0 = pixel-identical to a real UPI/Aadhaar app page

    A HIGH score on a NON-LEGITIMATE domain is a very strong phishing signal.

    Returns -1.0 if Selenium/PIL not available.
    """
    if not PIL_AVAILABLE or not SELENIUM_AVAILABLE:
        log.debug("visual_similarity_score: PIL or Selenium not available — returning -1.0")
        return -1.0

    png = screenshot_url(url, timeout=timeout)
    if not png:
        return -1.0

    page_hash_str = compute_phash(png)
    if not page_hash_str:
        return -1.0

    ref_hashes = load_reference_hashes()
    scores = []
    try:
        page_hash = imagehash.hex_to_hash(page_hash_str)
        for name, ref_str in ref_hashes.items():
            if not ref_str:
                continue
            ref_hash = imagehash.hex_to_hash(ref_str)
            diff     = page_hash - ref_hash     # 0 = identical, 64 = completely different
            score    = 1.0 - (diff / 64.0)
            scores.append(score)
    except Exception as e:
        log.debug(f"Hash comparison failed: {e}")

    return round(max(scores), 4) if scores else -1.0


def visual_clone_detected(url: str, threshold: float = 0.85) -> int:
    """
    Returns 1 if the page is visually similar enough to a real UPI/Aadhaar
    app to be considered a visual clone (threshold: 85% similarity).
    Returns 0 if not a clone, -1 if visual analysis unavailable.
    """
    score = visual_similarity_score(url)
    if score < 0:
        return -1
    return 1 if score >= threshold else 0
