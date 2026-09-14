"""A labelled corpus must arrive labelled.

The Accuracy tab reported "not computable" on a corpus where every record
carries a label. Two things were wrong: the pipeline dropped the field on the
way in, and the scorecard only ever looked for a filename convention
("...-red" / "...-benign"), so a per-row label was invisible to it.

Absent and zero have to stay distinct. A corpus of benign records is scoreable
and scores perfectly on recall; an unlabelled corpus cannot be scored at all.
Collapsing the two lets the dashboard quote a number it has no basis for.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from live_scorecard import _label_of  # noqa: E402
from pipeline import STANDARD_COLUMNS, _label_value  # noqa: E402


def test_the_label_column_survives_ingestion():
    assert "label" in STANDARD_COLUMNS


def test_attack_and_benign_and_unlabelled_are_three_answers():
    assert _label_value({"label": 1}) == 1
    assert _label_value({"label": "1"}) == 1
    assert _label_value({"label": "true"}) == 1
    assert _label_value({"label": 0}) == 0
    assert _label_value({"label": "benign"}) == 0
    assert _label_value({}) is None
    assert _label_value({"label": ""}) is None


def test_zero_is_not_mistaken_for_missing():
    """The bug this guards: `if row.get("label")` treats 0 and absent alike."""
    assert _label_value({"label": 0}) == 0
    assert _label_value({"label": 0}) is not None


def test_the_scorecard_reads_a_per_row_label():
    assert _label_of({"label": 1}) == 1
    assert _label_of({"_raw": {"label": 0}}) == 0
    assert _label_of({"malicious": "yes"}) == 1


def test_the_filename_convention_still_works_when_there_is_no_row_label():
    assert _label_of({"_raw": {"source_file": "golden-red"}}) == 1
    assert _label_of({"_raw": {"source_file": "golden-benign"}}) == 0
    assert _label_of({"_raw": {"source_file": "some-customer-export"}}) is None


def test_a_row_label_beats_a_contradicting_filename():
    """The row is the more specific claim."""
    assert _label_of({"label": 1, "_raw": {"source_file": "golden-benign"}}) == 1
