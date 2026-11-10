"""
dashboard.py — Streamlit web dashboard for UPI Phishing URL Detector.

Features:
  - Real-time URL analysis with feature breakdown
  - Visual risk gauge
  - Feature importance chart
  - Batch upload (CSV/TXT)
  - Recent prediction history

Run:
    streamlit run dashboard.py
"""

import pickle
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px

from config import (
    DASHBOARD_TITLE,
    FEATURE_COLUMNS,
    MODEL_DIR,
    PHISH_PROBABILITY_THRESHOLD,
)
from feature_extractor import extract_features
from model_io import load_model_bundle
from predictor import predict_url
from thresholds import is_feature_suspicious

# ─── Page Config ─────────────────────────────────────────────────────────────

st.set_page_config(
    page_title=DASHBOARD_TITLE,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ───────────────────────────────────────────────────────────────

st.markdown("""
<style>
  .risk-card {
    padding: 1.5rem;
    border-radius: 12px;
    text-align: center;
    margin-bottom: 1rem;
  }
  .risk-phishing {
    background: linear-gradient(135deg, #ff4b4b22, #ff4b4b11);
    border: 2px solid #ff4b4b;
  }
  .risk-legit {
    background: linear-gradient(135deg, #00cc8822, #00cc8811);
    border: 2px solid #00cc88;
  }
  .feature-row-warn { background-color: #fff3cd44; }
</style>
""", unsafe_allow_html=True)


# ─── Model Loading ────────────────────────────────────────────────────────────

@st.cache_resource
def load_model(path: str):
    p = Path(path)
    if not p.exists():
        return None
    return load_model_bundle(str(p))[0]


# ─── Gauge Chart ─────────────────────────────────────────────────────────────

def make_gauge(probability: float) -> go.Figure:
    color = "#ff4b4b" if probability >= PHISH_PROBABILITY_THRESHOLD else "#00cc88"
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=round(probability * 100, 1),
        title={"text": "Phishing Probability (%)", "font": {"size": 16}},
        number={"suffix": "%", "font": {"size": 36}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1},
            "bar": {"color": color, "thickness": 0.3},
            "steps": [
                {"range": [0, 40],  "color": "#e8f5e922"},
                {"range": [40, 60], "color": "#fff9c422"},
                {"range": [60, 100],"color": "#ffebee22"},
            ],
            "threshold": {
                "line": {"color": "#e63946", "width": 3},
                "thickness": 0.8,
                "value": PHISH_PROBABILITY_THRESHOLD * 100,
            },
        },
    ))
    fig.update_layout(height=280, margin=dict(l=20, r=20, t=40, b=0))
    return fig


# ─── Feature Breakdown Chart ──────────────────────────────────────────────────

def make_feature_chart(features: dict) -> go.Figure:
    """Horizontal bar chart of feature values, coloured by suspiciousness."""
    names, values, colors = [], [], []
    for name in FEATURE_COLUMNS:
        val = features.get(name, 0)
        names.append(name)
        values.append(float(val) if val != -1 else 0)
        colors.append("#ff4b4b" if is_feature_suspicious(name, val) else "#2196F3")

    fig = go.Figure(go.Bar(
        x=values,
        y=names,
        orientation="h",
        marker_color=colors,
        hovertemplate="%{y}: %{x}<extra></extra>",
    ))
    fig.update_layout(
        title="Feature Values (red = suspicious)",
        height=600,
        margin=dict(l=200, r=20, t=40, b=20),
        xaxis_title="Value",
        yaxis={"autorange": "reversed"},
        plot_bgcolor="rgba(0,0,0,0)",
    )
    return fig


# ─── Sidebar ──────────────────────────────────────────────────────────────────

def sidebar():
    with st.sidebar:
        st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/e/e9/NPCI_logo.svg/320px-NPCI_logo.svg.png", width=120)
        st.title("🛡️ UPI Phishing Detector")
        st.markdown("Detect phishing URLs targeting Indian UPI payment apps using ML.")
        st.divider()

        # Model selector
        model_options = list(Path(MODEL_DIR).glob("*.pkl")) if Path(MODEL_DIR).exists() else []
        if model_options:
            selected_model = st.selectbox(
                "Model",
                options=[str(p) for p in model_options],
                format_func=lambda p: Path(p).stem.replace("_", " ").title(),
            )
        else:
            selected_model = f"{MODEL_DIR}best_model.pkl"
            st.warning("No models found. Run `python trainer.py` first.")

        fetch_html = st.toggle("Fetch HTML (slower, more accurate)", value=True)

        st.divider()
        st.markdown("**About**")
        st.markdown(
            "Built with OpenPhish + PhishTank feeds, "
            "WHOIS domain age, SSL cert analysis, and HTML similarity scoring."
        )
        st.markdown("[GitHub →](https://github.com/YOUR_USERNAME/upi-phish-detector)")

    return selected_model, fetch_html


# ─── Single URL Tab ───────────────────────────────────────────────────────────

def tab_single_url(model, fetch_html: bool):
    st.subheader("🔍 Analyse a URL")

    col_input, col_examples = st.columns([3, 1])
    with col_input:
        url = st.text_input(
            "Enter a URL to analyse:",
            placeholder="https://phonepe.com  or  http://phonepe-kyc.xyz/login",
        )
    with col_examples:
        st.markdown("**Try an example:**")
        if st.button("🚨 Phishing example"):
            url = "http://phonepe-upi-kyc-verify.xyz/login"
            st.session_state["example_url"] = url
        if st.button("✅ Legit example"):
            url = "https://www.phonepe.com/"
            st.session_state["example_url"] = url

    if "example_url" in st.session_state:
        url = st.session_state.pop("example_url")

    if not url:
        st.info("Enter a URL above and click Analyse.")
        return

    if st.button("Analyse URL", type="primary", use_container_width=True):
        with st.spinner("Extracting features and running ML model…"):
            result = predict_url(url, model, fetch_html=fetch_html, verbose=False)

        # Store in history
        if "history" not in st.session_state:
            st.session_state["history"] = []
        st.session_state["history"].insert(0, result)

        # ── Result Card ──
        col_gauge, col_verdict = st.columns([1, 1])

        with col_gauge:
            st.plotly_chart(make_gauge(result["probability"]), use_container_width=True)

        with col_verdict:
            if result["is_phishing"]:
                st.markdown(f"""
                <div class="risk-card risk-phishing">
                  <h1>🚨</h1>
                  <h2 style="color:#ff4b4b">PHISHING</h2>
                  <p>Confidence: <strong>{result['confidence']}%</strong></p>
                  <p>⚠ DO NOT enter any credentials</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="risk-card risk-legit">
                  <h1>✅</h1>
                  <h2 style="color:#00cc88">LEGITIMATE</h2>
                  <p>Confidence: <strong>{result['confidence']}%</strong></p>
                  <p>No major phishing signals detected</p>
                </div>
                """, unsafe_allow_html=True)

            flags = result["suspicious_flags"]
            if flags:
                st.markdown(f"**{len(flags)} suspicious signal(s):**")
                for f in flags[:8]:
                    st.markdown(f"  ⚠ `{f}`")

        # ── Feature Breakdown ──
        st.divider()
        st.subheader("Feature Breakdown")
        col_chart, col_table = st.columns([1, 1])

        with col_chart:
            st.plotly_chart(
                make_feature_chart(result["features"]),
                use_container_width=True,
            )

        with col_table:
            rows = []
            for name in FEATURE_COLUMNS:
                val = result["features"].get(name, 0)
                susp = is_feature_suspicious(name, val)
                rows.append({
                    "Feature": name,
                    "Value": val if val != -1 else "N/A",
                    "Status": "⚠ Suspicious" if susp else "✓ OK",
                })
            df_feat = pd.DataFrame(rows)
            st.dataframe(
                df_feat,
                use_container_width=True,
                height=540,
                hide_index=True,
            )


# ─── Batch Analysis Tab ───────────────────────────────────────────────────────

def tab_batch(model, fetch_html: bool):
    st.subheader("📋 Batch URL Analysis")
    st.markdown("Upload a `.txt` or `.csv` file with one URL per line / per row.")

    uploaded = st.file_uploader("Upload file", type=["txt", "csv"])
    if not uploaded:
        return

    content = uploaded.read().decode("utf-8")
    if uploaded.name.endswith(".csv"):
        lines = [row.split(",")[0].strip() for row in content.splitlines() if row.strip()]
    else:
        lines = [line.strip() for line in content.splitlines() if line.strip()]

    urls = [u for u in lines if u.startswith("http")]
    st.info(f"Found {len(urls)} URLs to analyse.")

    if st.button("Run Batch Analysis", type="primary"):
        results = []
        progress = st.progress(0, text="Analysing…")
        for i, url in enumerate(urls):
            result = predict_url(url, model, fetch_html=fetch_html, verbose=False)
            results.append(result)
            progress.progress((i + 1) / len(urls), text=f"[{i+1}/{len(urls)}] {url[:60]}…")

        progress.empty()

        phish_count = sum(1 for r in results if r["is_phishing"])

        # Summary metrics
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total URLs", len(results))
        c2.metric("🚨 Phishing", phish_count, delta=None)
        c3.metric("✅ Legitimate", len(results) - phish_count)
        c4.metric("Detection Rate", f"{phish_count/len(results)*100:.1f}%")

        # Results table
        df_results = pd.DataFrame([{
            "URL":         r["url"],
            "Label":       r["label"],
            "Probability": r["probability"],
            "Confidence":  f"{r['confidence']}%",
            "Flags":       len(r["suspicious_flags"]),
        } for r in results])

        st.dataframe(df_results, use_container_width=True, hide_index=True)

        # Download CSV
        csv = df_results.to_csv(index=False)
        st.download_button(
            "⬇ Download Results CSV",
            data=csv,
            file_name="upi_phishing_results.csv",
            mime="text/csv",
        )

        # Distribution pie
        fig = px.pie(
            values=[phish_count, len(results) - phish_count],
            names=["Phishing", "Legitimate"],
            color_discrete_sequence=["#ff4b4b", "#00cc88"],
            title="Detection Distribution",
        )
        st.plotly_chart(fig, use_container_width=True)


# ─── History Tab ──────────────────────────────────────────────────────────────

def tab_history():
    st.subheader("📜 Recent Predictions")
    history = st.session_state.get("history", [])
    if not history:
        st.info("No predictions yet. Analyse a URL first.")
        return

    rows = [{
        "URL":         r["url"][:80],
        "Label":       r["label"],
        "Probability": r["probability"],
        "Confidence":  f"{r['confidence']}%",
        "Flags":       len(r["suspicious_flags"]),
    } for r in history]

    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    if st.button("Clear History"):
        st.session_state["history"] = []
        st.rerun()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    selected_model_path, fetch_html = sidebar()
    model = load_model(selected_model_path)

    if model is None:
        st.error(
            "⚠ No trained model found. "
            "Please run `python trainer.py` to train a model first."
        )
        return

    tab1, tab2, tab3 = st.tabs(["🔍 Single URL", "📋 Batch Analysis", "📜 History"])
    with tab1:
        tab_single_url(model, fetch_html)
    with tab2:
        tab_batch(model, fetch_html)
    with tab3:
        tab_history()


if __name__ == "__main__":
    main()
