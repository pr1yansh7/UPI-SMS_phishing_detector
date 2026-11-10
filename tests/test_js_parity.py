"""
tests/test_js_parity.py — the browser rules must agree with the Python analysers.

If a test here fails, the two implementations have drifted:
  * 'generated config is out of date'  → run `make sync-js`
  * a parity mismatch                  → fix static/messages.js (or scoring.js) to match Python

Skipped automatically when Node.js is not installed.
Run:  python -m pytest tests/test_js_parity.py -v
"""

import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

import pytest

from allowlist import is_official_domain
from features.deeplink_features import analyse_upi_deeplink, extract_upi_links
from features.sms_features import analyse_sms
from features.whatsapp_features import analyse_whatsapp
from tools.sync_js_config import EXT_OUT, OUT, render, render_extension

FIXTURES = json.load(open(os.path.join(ROOT, "tests", "fixtures", "message_cases.json"), encoding="utf-8"))
needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed")


def test_generated_js_config_is_up_to_date():
    assert OUT.read_text(encoding="utf-8") == render(), (
        "static/upi-config.js is out of date with config.py — run `make sync-js`")


def test_generated_extension_config_is_up_to_date():
    assert EXT_OUT.read_text(encoding="utf-8") == render_extension(), (
        "extension/config.js is out of date with config.py — run `make sync-js`")


@pytest.fixture(scope="module")
def js():
    proc = subprocess.run(["node", os.path.join(ROOT, "tests", "js", "run_fixtures.js")],
                          capture_output=True, check=True, encoding="utf-8")
    return json.loads(proc.stdout)


def _py_upi(text):
    links = extract_upi_links(text)
    return analyse_upi_deeplink(links[0] if links else text)


@needs_node
@pytest.mark.parametrize("i", range(len(FIXTURES["sms"])))
def test_sms_parity(js, i):
    case = FIXTURES["sms"][i]
    py, br = analyse_sms(case["text"], case["sender"]), js["sms"][i]
    assert br["is_phishing"] == py["is_phishing"], case
    assert abs(br["risk_score"] - py["risk_score"]) < 0.002, case
    assert br["flags"] == py["flags"], case


@needs_node
@pytest.mark.parametrize("i", range(len(FIXTURES["whatsapp"])))
def test_whatsapp_parity(js, i):
    text = FIXTURES["whatsapp"][i]
    py, br = analyse_whatsapp(text), js["whatsapp"][i]
    assert br["is_phishing"] == py["is_phishing"], text
    assert abs(br["risk_score"] - py["risk_score"]) < 0.002, text
    assert br["flags"] == py["flags"], text
    assert br["urls_found"] == py["urls_found"], text
    assert br["upi_links_found"] == py["upi_links_found"], text


@needs_node
@pytest.mark.parametrize("i", range(len(FIXTURES["upi"])))
def test_upi_parity(js, i):
    text = FIXTURES["upi"][i]
    py, br = _py_upi(text), js["upi"][i]
    assert br["is_suspicious_link"] == py["is_suspicious_link"], text
    assert br["risk_level"] == py["risk_level"], text
    assert abs(br["risk_score"] - py["risk_score"]) < 0.002, text
    assert br["flags"] == py["flags"], text


@needs_node
def test_official_domain_parity(js):
    expected = [is_official_domain(u) for u in FIXTURES["official"]]
    assert js["official"] == expected
