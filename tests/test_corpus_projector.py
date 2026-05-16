"""Unit tests for core/corpus_projector.py — AC-5."""
from __future__ import annotations

from core.corpus_projector import project_program


SAMPLE_MANIFEST = {
    "syscalls": {
        "openat": {"status": "implemented", "handler": "sys_openat"},
        "write": {"status": "implemented", "handler": "sys_write"},
        "close": {"status": "implemented", "handler": "sys_close"},
        "renameat2": {"status": "unsupported"},
        "clone": {"status": "partial", "notes": ["partial clone"]},
        "mmap": {"status": "implemented"},
    },
}

STRICT_POLICY = {"replay": {"supported": True, "partial": False, "unknown": False, "unsupported": False}}
BALANCED_POLICY = {"replay": {"supported": True, "partial": True, "unknown": False, "unsupported": False}}


def test_all_implemented_is_supported():
    meta = {"program_id": "abc", "required_syscalls": ["openat", "write", "close"]}
    result = project_program(meta, SAMPLE_MANIFEST, BALANCED_POLICY)
    assert result["projection"] == "supported"
    assert result["default_replay"] is True


def test_contains_unsupported_is_unsupported():
    meta = {"program_id": "def", "required_syscalls": ["openat", "renameat2", "close"]}
    result = project_program(meta, SAMPLE_MANIFEST, BALANCED_POLICY)
    assert result["projection"] == "unsupported"
    assert result["default_replay"] is False
    assert len(result["blocked_by"]) == 1
    assert result["blocked_by"][0]["syscall"] == "renameat2"


def test_contains_partial_is_partial():
    meta = {"program_id": "ghi", "required_syscalls": ["clone", "close"]}
    result = project_program(meta, SAMPLE_MANIFEST, BALANCED_POLICY)
    assert result["projection"] == "partial"
    assert result["default_replay"] is True  # balanced policy replays partial


def test_partial_not_replayed_in_strict():
    meta = {"program_id": "jkl", "required_syscalls": ["clone", "close"]}
    result = project_program(meta, SAMPLE_MANIFEST, STRICT_POLICY)
    assert result["projection"] == "partial"
    assert result["default_replay"] is False


def test_missing_from_manifest_is_unknown():
    meta = {"program_id": "mno", "required_syscalls": ["openat", "nonexistent", "close"]}
    result = project_program(meta, SAMPLE_MANIFEST, BALANCED_POLICY)
    assert result["projection"] == "unknown"
    assert result["default_replay"] is False


def test_stub_treated_as_unsupported():
    manifest = {
        "syscalls": {
            "openat": {"status": "implemented"},
            "iopl": {"status": "stub", "stub_evidence": ["todo!"]},
        }
    }
    meta = {"program_id": "pqr", "required_syscalls": ["openat", "iopl"]}
    result = project_program(meta, manifest, BALANCED_POLICY)
    assert result["projection"] == "unsupported"


def test_empty_syscall_list_is_supported():
    meta = {"program_id": "stu", "required_syscalls": []}
    result = project_program(meta, SAMPLE_MANIFEST, BALANCED_POLICY)
    assert result["projection"] == "supported"
