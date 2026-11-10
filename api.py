"""
api.py — Lightweight Flask API that bridges the HTML frontend to the ML model.

The HTML dashboard (index.html) calls this on http://localhost:5050/predict
If this server isn't running, the HTML falls back to browser-side heuristics automatically.

Run:
    python api.py

Endpoints:
    POST /predict        { "url": "...", "fetch_html": false }
    GET  /health         → { "status": "ok", "model": "Random Forest" }
    GET  /history        → list of last 50 predictions
"""

import json
import logging
import pickle
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from flask import Flask, jsonify, request
from flask_cors import CORS

from config import FEATURE_COLUMNS, MODEL_DIR, PHISH_PROBABILITY_THRESHOLD
from model_io import load_model_bundle, vectorize
from feature_extractor import extract_features
from thresholds import is_feature_suspicious
from allowlist import apply_allowlist
from config import REPORTING_CHANNELS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)   # allow requests from the HTML file opened locally

# ─── Load model at startup ────────────────────────────────────────
MODEL_PATH = f"{MODEL_DIR}best_model.pkl"
model = None

def load_model():
    global model
    p = Path(MODEL_PATH)
    if p.exists():
        model = load_model_bundle(str(p))[0]   # also sets model.feature_columns_
        log.info(f"Model loaded: {MODEL_PATH}")
    else:
        log.warning(f"Model not found at {MODEL_PATH} — run python trainer.py first")

# ─── In-memory prediction history ─────────────────────────────────
_history: list[dict] = []
MAX_HISTORY = 50


# ─── Routes ───────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    clf = model.named_steps["clf"].__class__.__name__ if model else "not loaded"
    return jsonify({
        "status":     "ok",
        "model":      clf,
        "model_path": MODEL_PATH,
        "history_count": len(_history),
        "feature_set": getattr(model, "feature_set_", "full") if model else None,
        "n_features": len(getattr(model, "feature_columns_", FEATURE_COLUMNS)) if model else 0,
    })


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True)
    url = (data.get("url") or "").strip()
    fetch_html = data.get("fetch_html", False)

    if not url:
        return jsonify({"error": "url field is required"}), 400

    if not model:
        return jsonify({"error": "Model not loaded. Run python trainer.py first."}), 503

    # Extract features
    try:
        columns = getattr(model, "feature_columns_", FEATURE_COLUMNS)
        features = extract_features(url, fetch_html_content=fetch_html, only=columns)
    except Exception as e:
        log.warning(f"Feature extraction failed for {url}: {e}")
        features = {col: 0 for col in columns}

    # Build feature vector
    feature_vector = vectorize(features, columns)

    # Predict
    prob_phishing = float(model.predict_proba(feature_vector)[0][1])
    is_phishing   = prob_phishing >= PHISH_PROBABILITY_THRESHOLD
    confidence    = prob_phishing if is_phishing else (1 - prob_phishing)

    suspicious_flags = [
        name for name in columns
        if is_feature_suspicious(name, features.get(name, 0))
    ]

    result = {
        "url":              url,
        "label":            "PHISHING" if is_phishing else "LEGITIMATE",
        "is_phishing":      is_phishing,
        "probability":      round(prob_phishing, 4),
        "confidence":       round(confidence, 4),
        "features":         {k: (v if v is not None else -1) for k, v in features.items()},
        "suspicious_flags": suspicious_flags,
        "source":           "ml_model",
        "analysed_at":      datetime.now(timezone.utc).isoformat(),
    }

    result = apply_allowlist(result)   # official HTTPS domains are never flagged

    # Store in history
    _history.insert(0, result)
    if len(_history) > MAX_HISTORY:
        _history.pop()

    log.info(f"{'🚨 PHISHING' if is_phishing else '✅ LEGIT':14s} p={prob_phishing:.3f}  {url[:80]}")
    return jsonify(result)


@app.route("/history", methods=["GET"])
def history():
    return jsonify(_history)


@app.route("/history", methods=["DELETE"])
def clear_history():
    _history.clear()
    return jsonify({"cleared": True})


@app.route("/features", methods=["POST"])
def features_only():
    """Return only extracted features without ML prediction (useful for debugging)."""
    data = request.get_json(force=True)
    url = (data.get("url") or "").strip()
    fetch_html = data.get("fetch_html", False)
    if not url:
        return jsonify({"error": "url required"}), 400
    feats = extract_features(url, fetch_html_content=fetch_html)
    return jsonify({"url": url, "features": feats})


# ── WhatsApp message endpoint ─────────────────────────────────────────────────

@app.route("/analyse-whatsapp", methods=["POST"])
def analyse_whatsapp_endpoint():
    """POST /analyse-whatsapp  Body: {"text": "forwarded message…"}"""
    data = request.get_json(force=True)
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "text field is required"}), 400
    from features.whatsapp_features import analyse_whatsapp
    result = analyse_whatsapp(text)
    result["analysed_at"] = datetime.now(timezone.utc).isoformat()
    log.info(f"WhatsApp {'PHISH' if result['is_phishing'] else 'LEGIT':5s} score={result['risk_score']:.3f}  {text[:60]}")
    return jsonify(result)


# ── UPI deep-link endpoint ────────────────────────────────────────────────────

@app.route("/analyse-upi-link", methods=["POST"])
def analyse_upi_link_endpoint():
    """POST /analyse-upi-link  Body: {"uri": "upi://pay?pa=…"} or {"text": "message containing a upi:// link"}"""
    data = request.get_json(force=True)
    uri = (data.get("uri") or "").strip()
    if not uri and data.get("text"):
        from features.deeplink_features import extract_upi_links
        links = extract_upi_links(data["text"])
        uri = links[0] if links else ""
    if not uri:
        return jsonify({"error": "uri (or text containing a upi:// link) is required"}), 400
    from features.deeplink_features import analyse_upi_deeplink
    result = analyse_upi_deeplink(uri)
    result["analysed_at"] = datetime.now(timezone.utc).isoformat()
    return jsonify(result)


# ── Where to report ───────────────────────────────────────────────────────────

@app.route("/report-info", methods=["GET"])
def report_info():
    return jsonify(REPORTING_CHANNELS)


# ─── Entry point ──────────────────────────────────────────────────
if __name__ == "__main__":
    load_model()
    log.info("Starting UPI Phishing Detector API on http://localhost:5050")
    log.info("Open index.html in your browser to use the dashboard")
    app.run(host="0.0.0.0", port=5050, debug=False)


# ── SMS phishing endpoint ──────────────────────────────────────────────────────

@app.route("/analyse-sms", methods=["POST"])
def analyse_sms_endpoint():
    """
    POST /analyse-sms
    Body: { "text": "SMS content here", "sender": "VK-UIDAI" }
    Returns: full SMS feature analysis + risk_score + is_phishing_sms
    """
    data   = request.get_json(force=True)
    text   = (data.get("text") or "").strip()
    sender = (data.get("sender") or "").strip()

    if not text:
        return jsonify({"error": "text field is required"}), 400

    from features.sms_features import analyse_sms
    result = analyse_sms(text, sender)
    result["analysed_at"] = datetime.now(timezone.utc).isoformat()
    log.info(f"SMS {'PHISH' if result['is_phishing_sms'] else 'LEGIT':5s} score={result['sms_risk_score']:.3f}  {text[:60]}")
    return jsonify(result)


# ── QR code phishing endpoint ─────────────────────────────────────────────────

@app.route("/analyse-qr", methods=["POST"])
def analyse_qr_endpoint():
    """
    POST /analyse-qr
    Body: multipart/form-data with field 'image' (PNG/JPG file)
       or JSON: { "image_path": "/path/to/qr.png" }
    Returns: decoded URL + phishing analysis
    """
    import tempfile, os
    from features.qr_features import analyse_qr

    # Handle file upload
    if "image" in request.files:
        img_file = request.files["image"]
        suffix   = os.path.splitext(img_file.filename)[1] or ".png"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            img_file.save(tmp.name)
            tmp_path = tmp.name
        try:
            result = analyse_qr(tmp_path, model)
        finally:
            os.unlink(tmp_path)
    elif request.is_json:
        data      = request.get_json(force=True)
        img_path  = data.get("image_path", "")
        if not img_path:
            return jsonify({"error": "image_path required"}), 400
        result = analyse_qr(img_path, model)
    else:
        return jsonify({"error": "Send image as multipart/form-data or JSON image_path"}), 400

    result["analysed_at"] = datetime.now(timezone.utc).isoformat()
    return jsonify(result)
