"""Unit tests for core/corpus_store.py — AC-4."""
from __future__ import annotations

import tempfile
from pathlib import Path

from core.corpus_store import CorpusStore, normalize_syz_text, compute_program_id


def test_program_id_deterministic():
    text = "openat(0x0, &(0x7f0000000000), 0x0, 0x0)\n"
    assert compute_program_id(normalize_syz_text(text)) == compute_program_id(normalize_syz_text(text))


def test_different_content_produces_different_id():
    t1 = "openat(0x0, 'file', 0x0, 0x0)\n"
    t2 = "openat(0x0, 'other', 0x0, 0x0)\n"
    assert compute_program_id(normalize_syz_text(t1)) != compute_program_id(normalize_syz_text(t2))


def test_normalize_strips_whitespace_unifies_newlines():
    text = "  openat(0x0)\r\n  write(r0)\r\n"
    normalized = normalize_syz_text(text)
    assert "\r\n" not in normalized
    assert normalized.startswith("openat")
    assert normalized.endswith("\n")


def test_corpus_store_dedup(tmp_path):
    store = CorpusStore(tmp_path)
    text = "openat(0x0, &(0x7f), 0x0, 0x0)\nwrite(r0, &(0x7f), 0x100)\nclose(r0)\n"
    pid = compute_program_id(normalize_syz_text(text))
    store.write(pid, normalize_syz_text(text))
    store.add_object(pid, {"campaign": "test", "source": "corpus.db"})
    assert store.exists(pid)

    store.add_origin(pid, {"campaign": "test2", "source": "corpus.db"})
    obj = store.get(pid)
    assert len(obj["origins"]) == 2
    assert obj["origins"][0]["campaign"] == "test"
    assert obj["origins"][1]["campaign"] == "test2"


def test_corpus_store_new_program_not_inspected(tmp_path):
    store = CorpusStore(tmp_path)
    text = "openat(0x0)\n"
    pid = compute_program_id(normalize_syz_text(text))
    store.write(pid, normalize_syz_text(text))
    store.add_object(pid, {"campaign": "test"})
    assert not store.get(pid)["lifecycle"]["inspected"]


def test_corpus_store_mark_inspected(tmp_path):
    store = CorpusStore(tmp_path)
    text = "openat(0x0)\n"
    pid = compute_program_id(normalize_syz_text(text))
    store.write(pid, normalize_syz_text(text))
    store.add_object(pid, {"campaign": "test"})
    store.mark_inspected(pid)
    assert store.get(pid)["lifecycle"]["inspected"]


def test_corpus_store_pending_program_ids(tmp_path):
    store = CorpusStore(tmp_path)
    for i in range(5):
        text = f"openat(0x0)\nwrite(r0, &(0x7f), {i})\nclose(r0)\n"
        pid = compute_program_id(normalize_syz_text(text))
        store.write(pid, normalize_syz_text(text))
        store.add_object(pid, {"campaign": "test"})
    store.mark_inspected(compute_program_id(normalize_syz_text("openat(0x0)\nwrite(r0, &(0x7f), 2)\nclose(r0)\n")))
    assert len(store.pending_program_ids()) == 4


def test_corpus_store_count(tmp_path):
    store = CorpusStore(tmp_path)
    for i in range(10):
        text = f"openat(0x0)\nwrite(r0, &(0x7f), {i})\nclose(r0)\n"
        pid = compute_program_id(normalize_syz_text(text))
        store.write(pid, normalize_syz_text(text))
        store.add_object(pid, {"campaign": "test"})
    assert store.count() == 10
