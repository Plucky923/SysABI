#!/usr/bin/env python3
"""Probe target OS to identify and remove ENOSYS (unimplemented) syscalls.

Runs a campaign, collects candidate traces, identifies syscalls that return
errno=38 (ENOSYS) in all observed calls, and removes them from the workflow
allowlist.  Iterates until no new ENOSYS syscalls are found.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from orchestrator.common import config, configure_runtime, resolve_repo_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Probe ENOSYS syscalls in target OS")
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--max-rounds", type=int, default=3)
    parser.add_argument("--min-confirm", type=int, default=2,
                        help="Minimum samples before marking a syscall as ENOSYS")
    return parser.parse_args()


def load_workflow_config(workflow: str) -> dict:
    configure_runtime(workflow=workflow)
    return config()


def launch_path() -> Path:
    return ROOT / "tools" / "tgoskits_launch.py"


def run_campaign(workflow: str, limit: int, jobs: int) -> None:
    env = os.environ.copy()
    env["SYZABI_WORKFLOW"] = workflow
    cmd = [
        sys.executable, str(launch_path()),
        "--workflow", workflow,
        "campaign",
        "--limit", str(limit),
        "--jobs", str(jobs),
    ]
    result = subprocess.run(cmd, cwd=str(ROOT), env=env, check=False)
    if result.returncode != 0:
        raise SystemExit(f"campaign failed with exit code {result.returncode}")


def collect_candidate_enosys(cfg: dict, min_confirm: int) -> set[str]:
    """Scan candidate traces and return syscalls that ALWAYS return ENOSYS."""
    runs_dir = resolve_repo_path(cfg["paths"]["artifacts_dir"])
    if not runs_dir.exists():
        return set()

    syscall_errnos: dict[str, set[int]] = defaultdict(set)
    syscall_counts: dict[str, int] = defaultdict(int)

    for program_dir in runs_dir.iterdir():
        if not program_dir.is_dir():
            continue
        for run_dir in program_dir.iterdir():
            if not run_dir.name.endswith("-candidate0"):
                continue
            trace_path = run_dir / "candidate" / "raw-trace.json"
            if not trace_path.exists():
                continue
            try:
                trace = json.loads(trace_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            for ev in trace.get("events", []):
                name = ev.get("syscall_name", "")
                if not name:
                    continue
                errno = ev.get("errno", 0)
                syscall_errnos[name].add(errno)
                syscall_counts[name] += 1

    enosys = set()
    for name, errnos in sorted(syscall_errnos.items()):
        if errnos == {38} and syscall_counts[name] >= min_confirm:
            enosys.add(name)
    return enosys


def update_allowlist(workflow: str, remove_syscalls: set[str]) -> int:
    config_path = ROOT / "configs" / "workflows" / f"{workflow}.json"
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    current = set(cfg["allowlist"]["syscalls"])
    cfg["allowlist"]["syscalls"] = sorted(current - remove_syscalls)
    config_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return len(cfg["allowlist"]["syscalls"])


def main() -> None:
    args = parse_args()
    cfg = load_workflow_config(args.workflow)
    all_removed: set[str] = set()

    for round_num in range(1, args.max_rounds + 1):
        current_allowlist = set(cfg["allowlist"]["syscalls"])
        print(f"\n=== Round {round_num} ({len(current_allowlist)} syscalls in allowlist) ===")

        run_campaign(args.workflow, args.limit, args.jobs)

        cfg = load_workflow_config(args.workflow)
        enosys = collect_candidate_enosys(cfg, args.min_confirm)

        already_removed = enosys & all_removed
        new_enosys = enosys - all_removed
        all_removed |= enosys

        if already_removed:
            print(f"Already removed: {sorted(already_removed)}")

        if not new_enosys:
            print("No new ENOSYS syscalls found. Allowlist is clean!")
            break

        print(f"Removing {len(new_enosys)} ENOSYS syscalls: {sorted(new_enosys)}")
        remaining = update_allowlist(args.workflow, new_enosys)
        print(f"Remaining in allowlist: {remaining}")

        # Regenerate corpus with filtered allowlist
        print("Regenerating corpus...")
        env = os.environ.copy()
        env["SYZABI_WORKFLOW"] = args.workflow
        subprocess.run(
            [sys.executable, str(ROOT / "tools" / "generate_corpus.py"),
             "--count", "3000", "--output-dir", "corpus/input/generated"],
            cwd=str(ROOT), env=env, check=True,
        )
        subprocess.run(
            [sys.executable, str(ROOT / "tools" / "import_syz.py"),
             "--input-dir", "corpus/input/generated", "--source-type", "generated"],
            cwd=str(ROOT), env=env, check=True,
        )
        subprocess.run(
            [sys.executable, str(ROOT / "tools" / "filter_corpus.py")],
            cwd=str(ROOT), env=env, check=True,
        )

        cfg = load_workflow_config(args.workflow)

    print(f"\n=== Done: removed {len(all_removed)} ENOSYS syscalls total ===")
    if all_removed:
        print(f"Removed: {sorted(all_removed)}")
    print(f"Final allowlist size: {len(set(cfg['allowlist']['syscalls']))}")


if __name__ == "__main__":
    main()
