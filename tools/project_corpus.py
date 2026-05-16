#!/usr/bin/env python3
"""Project the broad Linux corpus onto a specific target using its capability manifest."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from core.corpus_projector import (
    project_program, load_policy, load_program_index,
    load_projection_state, save_projection_state,
)


def main():
    parser = argparse.ArgumentParser(description="Project corpus onto target")
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--policy", default="default-balanced")
    parser.add_argument("--manifest", required=True, help="Path to manifest JSON")
    parser.add_argument("--index-dir", default="corpus/index")
    parser.add_argument("--meta-dir", default="corpus/meta")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--policy-dir", default="configs/projection_policy")
    parser.add_argument("--eligible-output", required=True, help="Path to eligible_programs default.jsonl")
    args = parser.parse_args()

    manifest = json.loads(Path(args.manifest).read_text())
    policy_path = Path(args.policy_dir) / f"{args.policy}.json"
    policy = load_policy(policy_path) if policy_path.exists() else {
        "name": args.policy,
        "replay": {"supported": True, "partial": True, "unknown": False, "unsupported": False},
    }

    index_dir = Path(args.index_dir)
    all_ids = load_program_index(index_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    state_path = output_dir / "projection-state.json"
    proj_state = load_projection_state(state_path)
    projected_ids = set(proj_state.get("projected_ids", []))

    pending = all_ids - projected_ids

    supported_f = open(output_dir / "supported.jsonl", "a")
    partial_f = open(output_dir / "partial.jsonl", "a")
    unsupported_f = open(output_dir / "unsupported.jsonl", "a")
    unknown_f = open(output_dir / "unknown.jsonl", "a")

    eligible_path = Path(args.eligible_output)
    eligible_path.parent.mkdir(parents=True, exist_ok=True)
    defaults_f = open(eligible_path, "a")

    try:
        for program_id in sorted(pending):
            meta_path = Path(args.meta_dir) / program_id[:2] / f"{program_id}.json"
            if not meta_path.exists():
                continue
            meta = json.loads(meta_path.read_text())
            record = project_program(meta, manifest, policy)
            record["target"] = manifest.get("target", "")
            record["policy"] = args.policy
            record["workflow"] = args.workflow

            line = json.dumps(record) + "\n"
            projection = record["projection"]
            if projection == "supported":
                supported_f.write(line)
            elif projection == "partial":
                partial_f.write(line)
            elif projection == "unsupported":
                unsupported_f.write(line)
            else:
                unknown_f.write(line)

            if record["default_replay"]:
                defaults_f.write(json.dumps({
                    "program_id": program_id,
                    "workflow": args.workflow,
                    "reason": [record.get("reason", "")],
                    "normalized_path": meta.get("source", {}).get("path", ""),
                    "meta_path": str(meta_path),
                }) + "\n")

            projected_ids.add(program_id)

    finally:
        for f in (supported_f, partial_f, unsupported_f, unknown_f, defaults_f):
            f.close()

    proj_state.update({
        "target": manifest.get("target", ""),
        "policy": args.policy,
        "programs_total": len(all_ids),
        "programs_projected": len(projected_ids),
        "programs_pending": len(pending),
        "projected_ids": list(projected_ids),
        "last_updated_at": datetime.now(timezone.utc).isoformat(),
    })
    save_projection_state(state_path, proj_state)

    summary = {
        "target": manifest.get("target", ""),
        "policy": args.policy,
        "total_programs": len(all_ids),
        "projected": len(projected_ids),
        "pending": len(pending),
    }
    (output_dir / "projection-summary.json").write_text(json.dumps(summary, indent=2))
    print(f"Projection complete: {summary}")


if __name__ == "__main__":
    main()
