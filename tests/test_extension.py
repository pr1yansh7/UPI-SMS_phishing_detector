"""
tests/test_extension.py — extension/ (Chrome MV3): manifest safety + pure-logic unit tests.
The browser wiring (background.js/warning.js/popup.js) is NOT exercised here — only loaded
in real Chrome. If a test fails: manifest/permissions → extension/manifest.json;
decision logic → extension/logic.js.
"""
import json
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
EXT = os.path.join(ROOT, "extension")
MANIFEST = json.load(open(os.path.join(EXT, "manifest.json"), encoding="utf-8"))


def test_manifest_v3_and_least_privilege():
    assert MANIFEST["manifest_version"] == 3
    assert set(MANIFEST["permissions"]) <= {"webNavigation", "storage", "activeTab"}
    assert MANIFEST["host_permissions"] == ["http://localhost:5050/*"], "must only talk to the local backend"
    assert "content_scripts" not in MANIFEST and "<all_urls>" not in json.dumps(MANIFEST)


def test_every_file_the_manifest_references_exists():
    refs = [MANIFEST["background"]["service_worker"], MANIFEST["action"]["default_popup"]]
    for r in refs:
        assert os.path.exists(os.path.join(EXT, r)), r


@pytest.mark.parametrize("page", ["popup.html", "warning.html"])
def test_html_pages_are_csp_safe(page):
    """MV3 forbids inline scripts and inline event handlers."""
    html = open(os.path.join(EXT, page), encoding="utf-8").read()
    for body in re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.DOTALL):
        assert not body.strip(), f"inline <script> in {page}"
    assert not re.search(r"\son[a-z]+\s*=", html), f"inline event handler in {page}"
    for src in re.findall(r'<script[^>]*\bsrc="([^"]+)"', html):
        assert os.path.exists(os.path.join(EXT, src)), src


def test_user_controlled_text_never_goes_through_innerhtml():
    for js in ("warning.js", "popup.js"):
        assert "innerHTML" not in open(os.path.join(EXT, js), encoding="utf-8").read(), js


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed")
def test_decision_logic_unit_tests():
    proc = subprocess.run(["node", os.path.join(ROOT, "tests", "js", "test_extension_logic.js")],
                          capture_output=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stdout + proc.stderr
