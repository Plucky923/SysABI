#!/usr/bin/env python3
"""Collect coverage snapshot from a syzkaller campaign."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path


def collect_coverage_snapshot(workdir: Path, snapshot_dir: Path):
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    rawcover = workdir / "rawcover"
    if rawcover.exists():
        shutil.copy2(rawcover, snapshot_dir / "rawcover")
    coverage_csv = workdir / "coverage.csv"
    if coverage_csv.exists():
        shutil.copy2(coverage_csv, snapshot_dir / "function_coverage.csv")
    return snapshot_dir


def compute_rawcover_hash(rawcover: Path) -> str:
    if not rawcover.exists():
        return ""
    hasher = hashlib.sha256()
    with open(rawcover, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Collect syzkaller coverage snapshot")
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--workdir-root", default="artifacts/linux-harvest/workdirs")
    parser.add_argument("--coverage-root", default="artifacts/linux-corpus/coverage")
    parser.add_argument("--snapshot", action="store_true", default=True)
    args = parser.parse_args()

    workdir = Path(args.workdir_root) / args.campaign
    coverage_root = Path(args.coverage_root)
    ts = datetime.now(timezone.utc).strftime("snapshot-%Y%m%d-%H%M%S")
    snapshot_dir = coverage_root / "snapshots" / ts

    collect_coverage_snapshot(workdir, snapshot_dir)
    rawcover = snapshot_dir / "rawcover"
    rawcover_hash = compute_rawcover_hash(rawcover) if rawcover.exists() else ""

    corpus_db = workdir / "corpus.db"
    corpus_db_hash = ""
    if corpus_db.exists():
        hasher = hashlib.sha256()
        with open(corpus_db, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        corpus_db_hash = hasher.hexdigest()

    snapshot_meta = {
        "snapshot_id": ts,
        "campaign": args.campaign,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "corpus_db_hash": corpus_db_hash,
        "rawcover_hash": rawcover_hash,
    }
    (snapshot_dir / "snapshot-meta.json").write_text(json.dumps(snapshot_meta, indent=2))

    coverage_summary = {
        "snapshot_id": ts,
        "campaign": args.campaign,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "rawcover_hash": rawcover_hash,
    }
    (snapshot_dir / "coverage-summary.json").write_text(json.dumps(coverage_summary, indent=2))

    latest_link = coverage_root / "latest"
    if latest_link.is_symlink() or latest_link.exists():
        latest_link.unlink()
    latest_link.symlink_to(snapshot_dir.relative_to(coverage_root))

    with open(coverage_root / "coverage-history.jsonl", "a") as f:
        f.write(json.dumps({
            "snapshot_id": ts,
            "campaign": args.campaign,
            "rawcover_hash": rawcover_hash,
        }) + "\n")

    print(f"Coverage snapshot saved: {snapshot_dir}")


if __name__ == "__main__":
    main()
