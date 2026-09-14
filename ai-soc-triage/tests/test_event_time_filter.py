"""The log view has to be able to answer "between these two times".

Asking for a window did three wrong things at once: no time parameter existed
on /events, so the filter never left the browser; the client filtered only the
500 rows it happened to be holding; and the header went on reporting the
server's unfiltered total, so a handful of matching rows appeared above the
words "20,200 logs".

`source` had the same shape of bug for a different reason — it was accepted as
a parameter but left out of the list that decides whether to filter at all.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from api_server import _parse_when  # noqa: E402


def test_reads_every_timestamp_shape_the_corpus_contains():
    # As the funnel writes it, and as it comes back through the browser.
    assert _parse_when("2015-01-01 01:29:27") == datetime(2015, 1, 1, 1, 29, 27)
    assert _parse_when("2015-01-01T01:29:27.000Z") == datetime(2015, 1, 1, 1, 29, 27)
    assert _parse_when("2015-01-01T01:29") == datetime(2015, 1, 1, 1, 29)
    assert _parse_when("2015-01-01") == datetime(2015, 1, 1, 0, 0)


def test_reads_a_numeric_epoch():
    # LANL ships seconds-since-epoch; a corpus can arrive either way.
    assert _parse_when("1420070400") == datetime(2015, 1, 1, 0, 0)


def test_unreadable_timestamps_are_not_guessed():
    for junk in (None, "", "not a time", "13:99", []):
        assert _parse_when(junk) is None


def test_source_is_part_of_the_filter_decision():
    """`source` was accepted and then ignored unless another filter was set."""
    import inspect

    import api_server

    src = inspect.getsource(api_server.get_events)
    assert "any_filter" in src, "the filter gate was rewritten without the fix"
    gate = src[src.index("any_filter"):src.index("any_filter") + 200]
    for field in ("source", "time_from", "time_to"):
        assert field in gate, f"{field} can be set but would filter nothing"
