from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path


def build_cache_key(
    syz_content: str,
    syzkaller_commit: str,
    syz_prog2c_options: str,
    arch: str,
    compiler_version: str,
) -> str:
    payload = json.dumps(
        {
            "syz_sha256": hashlib.sha256(syz_content.encode()).hexdigest(),
            "syzkaller_commit": syzkaller_commit,
            "syz_prog2c_options": syz_prog2c_options,
            "arch": arch,
            "compiler_version": compiler_version,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def reference_trace_cache_key(
    syz_content: str,
    linux_kernel_build_id: str,
    rootfs_hash: str,
    runner_version: str,
    normalizer_version: str,
) -> str:
    payload = json.dumps(
        {
            "syz_sha256": hashlib.sha256(syz_content.encode()).hexdigest(),
            "linux_kernel_build_id": linux_kernel_build_id,
            "rootfs_hash": rootfs_hash,
            "runner_version": runner_version,
            "normalizer_version": normalizer_version,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def manifest_cache_key(
    target_source_rev: str,
    rules_file_hash: str,
    arch: str,
) -> str:
    payload = json.dumps(
        {
            "target_source_rev": target_source_rev,
            "rules_file_hash": rules_file_hash,
            "arch": arch,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


class BuildCache:
    def __init__(self, root: Path):
        self.root = Path(root)

    def get(self, cache_key: str) -> Path:
        return self.root / "build" / cache_key

    def exists(self, cache_key: str) -> bool:
        return (self.get(cache_key) / "build-info.json").exists()

    def read(self, cache_key: str) -> dict | None:
        info_path = self.get(cache_key) / "build-info.json"
        if info_path.exists():
            return json.loads(info_path.read_text())
        return None

    def store(self, cache_key: str, binary_path: Path | None, source_path: Path | None, info: dict):
        target = self.get(cache_key)
        target.mkdir(parents=True, exist_ok=True)
        if binary_path is not None and binary_path.exists():
            shutil.copy2(binary_path, target / "testcase.bin")
        if source_path is not None and source_path.exists():
            shutil.copy2(source_path, target / "testcase.c")
        (target / "build-info.json").write_text(json.dumps(info, indent=2))


class ReferenceTraceCache:
    def __init__(self, root: Path):
        self.root = Path(root)

    def get(self, cache_key: str) -> Path:
        return self.root / "reference-trace" / cache_key

    def exists(self, cache_key: str) -> bool:
        return (self.get(cache_key) / "canonical-trace.json").exists()

    def store(self, cache_key: str, raw_trace: dict, canonical_trace: dict, execution_result: dict):
        target = self.get(cache_key)
        target.mkdir(parents=True, exist_ok=True)
        (target / "raw-trace.json").write_text(json.dumps(raw_trace))
        (target / "canonical-trace.json").write_text(json.dumps(canonical_trace))
        (target / "execution-result.json").write_text(json.dumps(execution_result))

    def load_canonical(self, cache_key: str) -> dict | None:
        path = self.get(cache_key) / "canonical-trace.json"
        if path.exists():
            return json.loads(path.read_text())
        return None
