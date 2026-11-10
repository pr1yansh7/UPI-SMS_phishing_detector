"""
tests/test_ui.py — runs tests/js/ui_test.js (simulated clicks on START.html in jsdom).

Skipped unless Node.js AND jsdom are available:   npm install   (once, in the project folder)
If it fails, the bug is in index.html / static/app.js / static/messages.js — then `make build`.
"""
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))


def _has_jsdom():
    if not shutil.which("node"):
        return False
    return subprocess.run(["node", "-e", "require('jsdom')"], cwd=ROOT, capture_output=True).returncode == 0


@pytest.mark.skipif(not _has_jsdom(), reason="needs Node.js + `npm install` (jsdom)")
def test_start_html_end_to_end():
    proc = subprocess.run(["node", "tests/js/ui_test.js"], cwd=ROOT, capture_output=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stdout + proc.stderr
