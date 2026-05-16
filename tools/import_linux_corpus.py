#!/usr/bin/env python3
"""Incrementally import exported .syz programs into the content-addressed corpus store."""
from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from core.corpus_store import CorpusStore, normalize_syz_text, compute_program_id
from core.harvest_state import CampaignState, CampaignStatus


def run_syzabi_inspect(syz_path: Path, target_os: str = "linux", arch: str = "riscv64") -> dict:
    result = subprocess.run(
        [
            "syzabi_inspect",
            "-prog", str(syz_path),
            "-os", target_os,
            "-arch", arch,
        ],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"syzabi_inspect failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def import_export_batch(export_dir: Path, store: CorpusStore, origin: dict) -> dict:
    new_count = 0
    existing_count = 0
    for syz_path in sorted(export_dir.glob("*.syz")):
        text = syz_path.read_text()
        normalized = normalize_syz_text(text)
        program_id = compute_program_id(normalized)
        if store.exists(program_id):
            store.add_origin(program_id, origin)
            existing_count += 1
        else:
            store.write(program_id, normalized)
            store.add_object(program_id, origin, inspected=False)
            new_count += 1
    return {"new": new_count, "existing": existing_count}


def main():
    parser = argparse.ArgumentParser(description="Import syz programs into corpus store")
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--export-dir", required=True)
    parser.add_argument("--store-root", default="artifacts/linux-corpus/store")
    parser.add_argument("--campaign-root", default="artifacts/linux-harvest/campaigns")
    parser.add_argument("--arch", default="riscv64")
    args = parser.parse_args()

    store = CorpusStore(Path(args.store_root))
    campaign_dir = Path(args.campaign_root) / args.campaign
    campaign_state = CampaignState(campaign_dir)

    export_dir = Path(args.export_dir)
    if not export_dir.exists():
        print(f"Export directory not found: {export_dir}")
        return 1

    origin = {
        "campaign": args.campaign,
        "source": "corpus.db",
        "export_batch": export_dir.name,
        "imported_at": datetime.now(timezone.utc).isoformat(),
    }

    result = import_export_batch(export_dir, store, origin)

    with open(campaign_dir / "import-history.jsonl", "a") as f:
        f.write(json.dumps({
            "imported_at": datetime.now(timezone.utc).isoformat(),
            "export_dir": str(export_dir),
            "new": result["new"],
            "existing": result["existing"],
        }) + "\n")

    campaign_state.transition_to(CampaignStatus.IMPORTED)
    current = campaign_state.load()
    current.setdefault("corpus", {})["programs_new_last_import"] = result["new"]
    campaign_state.save(current)

    print(f"Imported: {result['new']} new, {result['existing']} existing. Store total: {store.count()}")


if __name__ == "__main__":
    main()
