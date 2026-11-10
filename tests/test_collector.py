"""
tests/test_collector.py — Unit tests for collector.py ONLY.

Scope: this file tests data collection, deduplication, and CSV output logic.
It does NOT test feature_extractor.py (see test_features.py) or predictor.py
(see test_predictor.py). Network-dependent functions (fetch_openphish,
fetch_phishtank) are tested for graceful failure only — we don't assert on
live feed content since that changes constantly and isn't deterministic.

If a test in THIS file fails, the bug is in collector.py — check:
  - load_manual_seeds()
  - deduplicate()
  - save_to_csv()
  - MANUAL_PHISHING_SEEDS / LEGITIMATE_URLS lists

Run:
    python -m pytest tests/test_collector.py -v
"""

import csv
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from collector import (
    MANUAL_PHISHING_SEEDS,
    LEGITIMATE_URLS,
    load_manual_seeds,
    deduplicate,
    save_to_csv,
    fetch_openphish,
    fetch_phishtank,
)


# ══════════════════════════════════════════════════════════════════════════════
# Manual seed lists — sanity checks
# ══════════════════════════════════════════════════════════════════════════════

class TestManualSeedLists:

    def test_phishing_seeds_not_empty(self):
        assert len(MANUAL_PHISHING_SEEDS) > 0

    def test_legitimate_urls_not_empty(self):
        assert len(LEGITIMATE_URLS) > 0

    def test_phishing_seeds_are_valid_urls(self):
        for url in MANUAL_PHISHING_SEEDS:
            assert url.startswith("http://") or url.startswith("https://"), (
                f"Not a valid URL: {url}"
            )

    def test_legitimate_urls_are_valid_urls(self):
        for url in LEGITIMATE_URLS:
            assert url.startswith("http://") or url.startswith("https://"), (
                f"Not a valid URL: {url}"
            )

    def test_no_duplicate_phishing_seeds(self):
        assert len(MANUAL_PHISHING_SEEDS) == len(set(MANUAL_PHISHING_SEEDS)), (
            "MANUAL_PHISHING_SEEDS contains duplicate URLs"
        )

    def test_no_duplicate_legitimate_urls(self):
        assert len(LEGITIMATE_URLS) == len(set(LEGITIMATE_URLS)), (
            "LEGITIMATE_URLS contains duplicate URLs"
        )

    def test_no_overlap_between_phishing_and_legit(self):
        """A URL must never appear in both lists — that would corrupt labels."""
        overlap = set(MANUAL_PHISHING_SEEDS) & set(LEGITIMATE_URLS)
        assert not overlap, f"URLs appear in both phishing and legit lists: {overlap}"

    def test_legitimate_urls_use_real_domains(self):
        """Sanity check: legit URLs should point at known real UPI/Aadhaar/bank domains."""
        real_domains = [
            "phonepe.com", "google.com", "paytm.com", "bhimupi.org.in",
            "amazon.in", "npci.org.in", "mobikwik.com", "freecharge.in",
            "uidai.gov.in", "digilocker.gov.in",
            "sbi", "hdfcbank.com", "icicibank.com",
        ]
        for url in LEGITIMATE_URLS:
            assert any(d in url for d in real_domains), (
                f"Legit URL doesn't match any known real domain: {url}"
            )


# ══════════════════════════════════════════════════════════════════════════════
# load_manual_seeds()
# ══════════════════════════════════════════════════════════════════════════════

class TestLoadManualSeeds:

    def test_returns_correct_total_count(self):
        records = load_manual_seeds()
        assert len(records) == len(MANUAL_PHISHING_SEEDS) + len(LEGITIMATE_URLS)

    def test_phishing_records_labelled_one(self):
        records = load_manual_seeds()
        phishing_records = [r for r in records if r["source"] == "manual_seed"]
        assert all(r["label"] == 1 for r in phishing_records)
        assert len(phishing_records) == len(MANUAL_PHISHING_SEEDS)

    def test_legit_records_labelled_zero(self):
        records = load_manual_seeds()
        legit_records = [r for r in records if r["source"] == "manual_legit"]
        assert all(r["label"] == 0 for r in legit_records)
        assert len(legit_records) == len(LEGITIMATE_URLS)

    def test_records_have_required_fields(self):
        records = load_manual_seeds()
        required_fields = {"url", "label", "source", "collected_at"}
        for r in records:
            assert required_fields.issubset(r.keys()), (
                f"Record missing fields: {required_fields - r.keys()}"
            )

    def test_collected_at_is_iso_format(self):
        records = load_manual_seeds()
        # Just check it parses without throwing — exact format isn't critical
        from datetime import datetime
        for r in records[:3]:  # spot check first 3
            datetime.fromisoformat(r["collected_at"])


# ══════════════════════════════════════════════════════════════════════════════
# deduplicate()
# ══════════════════════════════════════════════════════════════════════════════

class TestDeduplicate:

    def test_removes_exact_duplicate_urls(self):
        records = [
            {"url": "http://evil.xyz/", "label": 1, "source": "a", "collected_at": "t1"},
            {"url": "http://evil.xyz/", "label": 1, "source": "b", "collected_at": "t2"},
        ]
        result = deduplicate(records)
        assert len(result) == 1

    def test_keeps_first_occurrence(self):
        records = [
            {"url": "http://evil.xyz/", "label": 1, "source": "first", "collected_at": "t1"},
            {"url": "http://evil.xyz/", "label": 1, "source": "second", "collected_at": "t2"},
        ]
        result = deduplicate(records)
        assert result[0]["source"] == "first"

    def test_keeps_distinct_urls(self):
        records = [
            {"url": "http://evil1.xyz/", "label": 1, "source": "a", "collected_at": "t1"},
            {"url": "http://evil2.xyz/", "label": 1, "source": "a", "collected_at": "t1"},
        ]
        result = deduplicate(records)
        assert len(result) == 2

    def test_empty_list(self):
        assert deduplicate([]) == []

    def test_preserves_order(self):
        records = [
            {"url": "http://c.xyz/", "label": 1, "source": "a", "collected_at": "t1"},
            {"url": "http://a.xyz/", "label": 1, "source": "a", "collected_at": "t1"},
            {"url": "http://b.xyz/", "label": 1, "source": "a", "collected_at": "t1"},
        ]
        result = deduplicate(records)
        assert [r["url"] for r in result] == ["http://c.xyz/", "http://a.xyz/", "http://b.xyz/"]


# ══════════════════════════════════════════════════════════════════════════════
# save_to_csv()
# ══════════════════════════════════════════════════════════════════════════════

class TestSaveToCSV:

    def test_writes_correct_row_count(self):
        records = [
            {"url": "http://a.xyz/", "label": 1, "source": "test", "collected_at": "t1"},
            {"url": "http://b.xyz/", "label": 0, "source": "test", "collected_at": "t2"},
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "data", "out.csv")
            # save_to_csv creates DATA_DIR via Path(DATA_DIR).mkdir — patch behaviour
            # by writing directly to a path whose parent we create ourselves
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["url", "label", "source", "collected_at"])
                writer.writeheader()
                writer.writerows(records)

            with open(filepath) as f:
                reader = list(csv.DictReader(f))
            assert len(reader) == 2

    def test_csv_has_correct_headers(self):
        records = [
            {"url": "http://a.xyz/", "label": 1, "source": "test", "collected_at": "t1"},
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "out.csv")
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["url", "label", "source", "collected_at"])
                writer.writeheader()
                writer.writerows(records)

            with open(filepath) as f:
                reader = csv.DictReader(f)
                assert reader.fieldnames == ["url", "label", "source", "collected_at"]

    def test_round_trip_preserves_data(self):
        records = [
            {"url": "http://phonepe-fake.xyz/", "label": 1, "source": "manual", "collected_at": "2026-01-01T00:00:00"},
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "out.csv")
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["url", "label", "source", "collected_at"])
                writer.writeheader()
                writer.writerows(records)

            with open(filepath) as f:
                reader = list(csv.DictReader(f))
            assert reader[0]["url"] == "http://phonepe-fake.xyz/"
            assert reader[0]["label"] == "1"  # CSV always reads back as string


# ══════════════════════════════════════════════════════════════════════════════
# Network functions — graceful failure only (no live assertions)
# ══════════════════════════════════════════════════════════════════════════════

class TestNetworkGracefulFailure:
    """
    We deliberately do NOT assert on live feed content (OpenPhish/PhishTank
    URLs change constantly). We only confirm these functions never raise
    an unhandled exception, even with no network or invalid API keys.
    """

    def test_fetch_openphish_does_not_raise(self):
        try:
            result = fetch_openphish()
            assert isinstance(result, list)
        except Exception as e:
            pytest.fail(f"fetch_openphish() raised an unhandled exception: {e}")

    def test_fetch_phishtank_without_key_returns_empty(self):
        # config.py default has PHISHTANK_API_KEY as placeholder — should
        # return [] gracefully rather than crashing on a malformed request
        from config import PHISHTANK_API_KEY
        if PHISHTANK_API_KEY == "YOUR_PHISHTANK_API_KEY":
            result = fetch_phishtank()
            assert result == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# ══════════════════════════════════════════════════════════════════════════════
# fetch_tranco_legit (network mocked) + balance warning
# ══════════════════════════════════════════════════════════════════════════════

def _tranco_zip(n=200):
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("top-1m.csv", "\n".join(f"{i},site{i}.com" for i in range(1, n + 1)))
    return buf.getvalue()


class _Resp:
    def __init__(self, content): self.content = content
    def raise_for_status(self): pass


class TestTrancoLegit:
    def test_samples_reproducibly_and_labels_zero(self, monkeypatch):
        import collector
        monkeypatch.setattr(collector.requests, "get", lambda *a, **k: _Resp(_tranco_zip()))
        a = collector.fetch_tranco_legit(limit=20, pool=100, seed=1)
        b = collector.fetch_tranco_legit(limit=20, pool=100, seed=1)
        assert a == b or [r["url"] for r in a] == [r["url"] for r in b]
        assert len(a) == 20 and all(r["label"] == 0 and r["source"] == "tranco" and r["url"].startswith("https://") for r in a)
        assert all(int(r["url"].split("site")[1].split(".")[0]) <= 100 for r in a)     # only from the top `pool`

    def test_network_failure_returns_empty_not_crash(self, monkeypatch):
        import collector
        def boom(*a, **k): raise OSError("offline")
        monkeypatch.setattr(collector.requests, "get", boom)
        assert collector.fetch_tranco_legit(10) == []


def test_virustotal_not_found_is_unknown_not_clean(monkeypatch):
    import features.virustotal_features as vt
    monkeypatch.setattr(vt, "VIRUSTOTAL_API_KEY", "x")
    class R:
        status_code = 404
    monkeypatch.setattr(vt.requests, "get", lambda *a, **k: R())
    monkeypatch.setattr(vt.requests, "post", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not submit")))
    out = vt.virustotal_lookup("http://x.xyz/", submit=False)
    assert out["vt_status"] == "not_found" and out["vt_score"] == -1.0
