"""Unit tests for core/enosys_triage.py — AC-1."""
from __future__ import annotations

from core.enosys_triage import (
    candidate_returns_enosys,
    lookup_syscall_capability,
    resolve_capability_status,
    classify_enosys_divergence,
)


SAMPLE_MANIFEST = {
    "target": "test_target",
    "syscalls": {
        "openat": {"status": "implemented", "handler": "sys_openat"},
        "mmap": {"status": "implemented", "handler": "sys_mmap"},
        "write": {"status": "implemented", "handler": "sys_write"},
        "renameat2": {"status": "unsupported", "handler": None},
        "clone": {"status": "partial", "handler": "sys_clone"},
        "unknown_sys": {"status": "unknown"},
    },
}


def test_enosys_by_errno_string():
    assert candidate_returns_enosys({"candidate_errno": "ENOSYS"})


def test_enosys_by_errno_number():
    assert candidate_returns_enosys({"candidate_errno": "38"})


def test_enosys_by_return_value():
    assert candidate_returns_enosys({"candidate_ret": -38})


def test_no_enosys():
    assert not candidate_returns_enosys({"candidate_errno": "EINVAL", "candidate_ret": -22})


def test_implemented_enosys_classified_bug_likely():
    cls_name, reason, cap = classify_enosys_divergence(
        {"base": "mmap", "candidate_errno": "ENOSYS"}, SAMPLE_MANIFEST
    )
    assert cls_name == "bug_likely"
    assert reason == "implemented_syscall_returned_enosys"
    assert cap["status"] == "implemented"


def test_unsupported_enosys_classified_unsupported_feature():
    cls_name, reason, cap = classify_enosys_divergence(
        {"base": "renameat2", "candidate_errno": "ENOSYS"}, SAMPLE_MANIFEST
    )
    assert cls_name == "unsupported_feature"
    assert reason == "enosys_matches_manifest_unsupported"


def test_partial_enosys_classified_partial_semantic_gap():
    cls_name, reason, cap = classify_enosys_divergence(
        {"base": "clone", "candidate_errno": "ENOSYS"}, SAMPLE_MANIFEST
    )
    assert cls_name == "partial_semantic_gap"
    assert reason == "partial_syscall_returned_enosys"


def test_unknown_enosys_classified_unknown_capability_gap():
    cls_name, reason, cap = classify_enosys_divergence(
        {"base": "unknown_sys", "candidate_errno": "ENOSYS"}, SAMPLE_MANIFEST
    )
    assert cls_name == "unknown_capability_gap"


def test_missing_from_manifest_enosys():
    cls_name, reason, cap = classify_enosys_divergence(
        {"base": "nonexistent_syscall", "candidate_errno": "ENOSYS"}, SAMPLE_MANIFEST
    )
    assert cls_name == "unknown_capability_gap"


def test_no_manifest_returns_empty():
    cls_name, reason, cap = classify_enosys_divergence(
        {"base": "mmap", "candidate_errno": "ENOSYS"}, None
    )
    assert cls_name == ""


def test_non_enosys_divergence_returns_empty():
    cls_name, reason, cap = classify_enosys_divergence(
        {"base": "mmap", "candidate_errno": "EINVAL"}, SAMPLE_MANIFEST
    )
    assert cls_name == ""


def test_resolve_capability_status():
    assert resolve_capability_status(SAMPLE_MANIFEST, "mmap") == "implemented"
    assert resolve_capability_status(SAMPLE_MANIFEST, "renameat2") == "unsupported"
    assert resolve_capability_status(SAMPLE_MANIFEST, "clone") == "partial"
    assert resolve_capability_status(SAMPLE_MANIFEST, "missing") == "unknown"
