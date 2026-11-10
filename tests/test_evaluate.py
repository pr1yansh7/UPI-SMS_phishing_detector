"""tests/test_evaluate.py — evaluate.py ONLY (metrics, overlap, report, our_detector wiring)."""
import os, pickle, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

import evaluate as ev
from config import LEXICAL_FEATURES
from model_io import save_meta

Y = [1, 1, 1, 0, 0, 0, 0]
P = [1, 1, 0, 1, 0, 0, 0]          # tp=2 fn=1 fp=1 tn=3


def test_confusion_metrics_hand_computed():
    m = ev.confusion_metrics(Y, P)
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (2, 1, 1, 3)
    assert m["precision"] == pytest.approx(2 / 3) and m["recall"] == pytest.approx(2 / 3)
    assert m["false_alarm_rate"] == pytest.approx(1 / 4) and m["accuracy"] == pytest.approx(5 / 7)
    assert m["f1"] == pytest.approx(2 / 3)


def test_unanswered_items_are_excluded_but_counted_in_total():
    m = ev.confusion_metrics([1, 1, 0, 0], [1, None, None, 0])
    assert m["answered"] == 2 and m["total"] == 4 and (m["tp"], m["tn"]) == (1, 1)


def test_no_division_by_zero():
    m = ev.confusion_metrics([0, 0], [0, 0])
    assert m["precision"] is None and m["recall"] is None and m["f1"] is None and m["false_alarm_rate"] == 0


def test_wilson_interval():
    lo, hi = ev.wilson_interval(5, 10)
    assert lo == pytest.approx(0.2366, abs=1e-3) and hi == pytest.approx(0.7634, abs=1e-3)
    assert ev.wilson_interval(0, 0) == (None, None)
    assert ev.wilson_interval(10, 10)[1] == 1.0 and ev.wilson_interval(0, 10)[0] == 0.0


def test_overlap_counts():
    y = [1, 1, 1, 1, 0, 0, 0]
    ours = [1, 1, 0, 0, 1, 0, None]
    other = [1, 0, 1, 0, 0, 1, 1]
    o = ev.overlap(y, ours, other)
    assert o == dict(common=6, both_caught=1, ours_only_caught=1, other_only_caught=1, both_missed=1,
                     ours_only_false_alarms=1, other_only_false_alarms=1)


def test_report_and_markdown_render():
    rep = ev.build_report(["a"] * 7, Y, {ev.OURS: P, "Google Safe Browsing": [1, 1, 1, 0, 0, 0, 0]})
    md = ev.render_markdown(rep, ev.caveats(7, True, 0))
    assert "Google Safe Browsing" in md and "NOT statistically meaningful" in md and "Read before quoting" in md
    assert rep["detectors"]["Google Safe Browsing"]["recall"] == 1.0


def test_caveat_warns_on_train_test_overlap():
    assert any("WARNING" in n for n in ev.caveats(500, False, 3))
    assert not any("WARNING" in n for n in ev.caveats(500, False, 0))


def test_our_detector_uses_the_models_own_columns_and_the_allowlist(tmp_path):
    rng = np.random.default_rng(0)
    m = RandomForestClassifier(n_estimators=5, random_state=0).fit(rng.random((30, len(LEXICAL_FEATURES))), [0, 1] * 15)
    p = str(tmp_path / "m.pkl")
    pickle.dump(m, open(p, "wb"))
    save_meta(p, {"feature_set": "lexical", "columns": LEXICAL_FEATURES})
    detect = ev.our_detector(p)
    assert detect("http://uidai-update-kyc.xyz/verify") in (0, 1)
    assert detect("https://uidai.gov.in/") == 0          # official domain can never be flagged
    assert detect.meta["feature_set"] == "lexical"


def test_external_detectors_are_skipped_without_keys():
    assert ev.gsb_detector() is None and ev.vt_detector() is None
