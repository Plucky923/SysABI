"""Unit tests for core/cache.py — AC-10."""
from __future__ import annotations

from core.cache import (
    build_cache_key,
    reference_trace_cache_key,
    manifest_cache_key,
    BuildCache,
    ReferenceTraceCache,
)


def test_build_cache_key_deterministic():
    k1 = build_cache_key("syz content", "commit1", "options", "riscv64", "gcc-12")
    k2 = build_cache_key("syz content", "commit1", "options", "riscv64", "gcc-12")
    assert k1 == k2


def test_build_cache_key_changes_with_content():
    k1 = build_cache_key("content A", "commit1", "", "riscv64", "gcc-12")
    k2 = build_cache_key("content B", "commit1", "", "riscv64", "gcc-12")
    assert k1 != k2


def test_reference_trace_cache_key_deterministic():
    k1 = reference_trace_cache_key("syz", "kernel1", "rootfs1", "runner1", "norm1")
    k2 = reference_trace_cache_key("syz", "kernel1", "rootfs1", "runner1", "norm1")
    assert k1 == k2


def test_reference_trace_cache_key_changes_with_kernel():
    k1 = reference_trace_cache_key("syz", "kernel1", "rootfs1", "runner1", "norm1")
    k2 = reference_trace_cache_key("syz", "kernel2", "rootfs1", "runner1", "norm1")
    assert k1 != k2


def test_manifest_cache_key_deterministic():
    k1 = manifest_cache_key("rev1", "rules_hash", "riscv64")
    k2 = manifest_cache_key("rev1", "rules_hash", "riscv64")
    assert k1 == k2


def test_build_cache_store_and_read(tmp_path):
    from pathlib import Path
    import json
    cache = BuildCache(tmp_path)
    key = build_cache_key("test", "commit", "", "riscv64", "gcc")
    assert not cache.exists(key)
    info = {"compiler": "gcc", "arch": "riscv64"}
    info_path = cache.get(key) / "build-info.json"
    info_path.parent.mkdir(parents=True, exist_ok=True)
    info_path.write_text(json.dumps(info))
    assert cache.exists(key)
    assert cache.read(key) == info


def test_reference_trace_cache_store_and_load(tmp_path):
    cache = ReferenceTraceCache(tmp_path)
    key = reference_trace_cache_key("test", "k1", "r1", "v1", "n1")
    assert not cache.exists(key)
    cache.store(key, {"raw": True}, {"canonical": True}, {"exit": 0})
    assert cache.exists(key)
    loaded = cache.load_canonical(key)
    assert loaded == {"canonical": True}
