"""Unit tests for first-divergence extraction in analyzer/compare.py — AC-2."""
from __future__ import annotations

from analyzer.compare import compare_canonical, _build_first_divergence


def _make_event(index, name, ret="0x0", errno=0):
    return {
        "index": index,
        "syscall_name": name,
        "args": [],
        "return_value": ret,
        "errno": errno,
        "outputs": [],
    }


def _make_trace(events):
    ref_ev = events.get("ref", [])
    cand_ev = events.get("cand", [])
    return {
        "event_count": len(ref_ev),
        "events": ref_ev,
        "final_state": {},
        "process_exit": 0,
    }, {
        "event_count": len(cand_ev),
        "events": cand_ev,
        "final_state": {},
        "process_exit": 0,
    }


def test_equivalent_traces():
    ref, cand = _make_trace({
        "ref": [_make_event(0, "openat"), _make_event(1, "write"), _make_event(2, "close")],
        "cand": [_make_event(0, "openat"), _make_event(1, "write"), _make_event(2, "close")],
    })
    result = compare_canonical(ref, cand)
    assert result["equivalent"]
    assert result["first_divergence_index"] is None


def test_event_count_mismatch():
    ref, cand = _make_trace({
        "ref": [_make_event(0, "openat"), _make_event(1, "write")],
        "cand": [_make_event(0, "openat"), _make_event(1, "write"), _make_event(2, "close")],
    })
    result = compare_canonical(ref, cand)
    assert not result["equivalent"]
    assert result["first_divergence_index"] == 2


def test_syscall_name_divergence():
    ref, cand = _make_trace({
        "ref": [_make_event(0, "openat"), _make_event(1, "read"), _make_event(2, "close")],
        "cand": [_make_event(0, "openat"), _make_event(1, "mmap"), _make_event(2, "close")],
    })
    result = compare_canonical(ref, cand)
    assert not result["equivalent"]
    assert result["first_divergence_index"] == 1
    assert result.get("first_divergence", {}).get("syscall") == "read"


def test_return_value_divergence():
    ref, cand = _make_trace({
        "ref": [_make_event(0, "openat", ret="0x3"), _make_event(1, "close")],
        "cand": [_make_event(0, "openat", ret="-1"), _make_event(1, "close")],
    })
    result = compare_canonical(ref, cand)
    assert not result["equivalent"]
    assert result["first_divergence_index"] == 0
    assert result["first_divergence"]["reference_ret"] == "0x3"
    assert result["first_divergence"]["candidate_ret"] == "-1"


def test_enosys_first_divergence_details():
    ref, cand = _make_trace({
        "ref": [_make_event(0, "openat", ret="0x3"), _make_event(1, "mmap", ret="0x7f")],
        "cand": [_make_event(0, "openat", ret="0x3"), _make_event(1, "mmap", ret="-1", errno=38)],
    })
    result = compare_canonical(ref, cand)
    fd = result["first_divergence"]
    assert fd["index"] == 1
    assert fd["syscall"] == "mmap"
    assert fd["reference_ret"] == "0x7f"
    assert fd["candidate_ret"] == "-1"
    assert fd["candidate_errno"] == "38"
