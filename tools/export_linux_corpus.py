#!/usr/bin/env python3
"""Export programs from syzkaller corpus.db and detect changes."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from core.harvest_state import CampaignState, CampaignStatus


def compute_corpus_db_hash(corpus_db_path: Path) -> str:
    if not corpus_db_path.exists():
        return ""
    hasher = hashlib.sha256()
    with open(corpus_db_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def export_from_db(workdir: Path, export_dir: Path):
    corpus_db = workdir / "corpus.db"
    if not corpus_db.exists():
        raise FileNotFoundError(f"corpus.db not found: {corpus_db}")
    export_dir.mkdir(parents=True, exist_ok=True)
    bin_dir = workdir / "corpus"
    if bin_dir.exists():
        for f in bin_dir.iterdir():
            if f.is_file():
                shutil.copy2(f, export_dir / f.name)
    shutil.copy2(corpus_db, export_dir / "corpus.db")


def main():
    parser = argparse.ArgumentParser(description="Export syzkaller corpus")
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--workdir-root", default="artifacts/linux-harvest/workdirs")
    parser.add_argument("--export-root", default="artifacts/linux-harvest/exports")
    parser.add_argument("--campaign-root", default="artifacts/linux-harvest/campaigns")
    args = parser.parse_args()

    workdir = Path(args.workdir_root) / args.campaign
    campaign_dir = Path(args.campaign_root) / args.campaign
    campaign_state = CampaignState(campaign_dir)
    export_dir = Path(args.export_root) / args.campaign / datetime.now(timezone.utc).strftime("export-%Y%m%d-%H%M%S")

    current_hash = compute_corpus_db_hash(workdir / "corpus.db")
    prev_export = campaign_dir / "export-history.jsonl"

    if prev_export.exists():
        last_line = prev_export.read_text().strip().splitlines()[-1]
        last = json.loads(last_line)
        if last.get("corpus_db_hash") == current_hash:
            print(f"corpus.db unchanged (hash: {current_hash[:12]}), skipping export")
            return

    export_from_db(workdir, export_dir)
    program_count = len(list(export_dir.glob("*"))) - 1
    export_id = export_dir.name

    with open(prev_export, "a") as f:
        f.write(json.dumps({
            "export_id": export_id,
            "campaign": args.campaign,
            "corpus_db_hash": current_hash,
            "exported_program_count": program_count,
            "export_completed": True,
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }) + "\n")

    campaign_state.transition_to(CampaignStatus.EXPORTED)
    print(f"Exported {program_count} programs to {export_dir}")


if __name__ == "__main__":
    main()
