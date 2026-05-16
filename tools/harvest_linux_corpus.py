#!/usr/bin/env python3
"""Run a syzkaller campaign to harvest Linux broad syscall corpus."""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from core.harvest_state import CampaignState, CampaignStatus, WorkdirState


def run_syzkaller_manager(workdir: Path, hours: int):
    manager_cfg = workdir / "manager.cfg"
    if not manager_cfg.exists():
        raise FileNotFoundError(f"syzkaller config not found: {manager_cfg}")
    deadline = time.time() + hours * 3600
    cmd = [
        "syz-manager",
        "-config", str(manager_cfg),
    ]
    proc = subprocess.Popen(cmd, cwd=workdir)
    try:
        while time.time() < deadline:
            ret = proc.poll()
            if ret is not None:
                break
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    return proc.returncode


def main():
    parser = argparse.ArgumentParser(description="Harvest Linux syscall corpus via syzkaller")
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--hours", type=int, default=6)
    parser.add_argument("--resume", action="store_true", default=False)
    parser.add_argument("--clean", action="store_true", default=False)
    parser.add_argument("--workdir-root", default="artifacts/linux-harvest/workdirs")
    parser.add_argument("--campaign-root", default="artifacts/linux-harvest/campaigns")
    args = parser.parse_args()

    workdir = Path(args.workdir_root) / args.campaign
    campaign_dir = Path(args.campaign_root) / args.campaign
    campaign_state = CampaignState(campaign_dir)
    wd_state = WorkdirState(workdir, args.campaign)

    if args.clean and workdir.exists():
        import shutil
        shutil.rmtree(workdir)
        print(f"Cleaned workdir: {workdir}")

    if campaign_state.exists():
        current_status = campaign_state.status()
        if current_status == CampaignStatus.FAILED:
            print(f"Campaign {args.campaign} is in FAILED state. Manual recovery required.")
            return 1
        if current_status == CampaignStatus.STALE:
            print(f"Campaign {args.campaign} is STALE. Resuming with existing data.")
        campaign_state.transition_to(CampaignStatus.RUNNING)
    else:
        campaign_state.save({
            "schema_version": 1,
            "campaign": args.campaign,
            "status": CampaignStatus.NEW.value,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        campaign_state.transition_to(CampaignStatus.CONFIGURED)
        campaign_state.transition_to(CampaignStatus.RUNNING)

    if wd_state.exists() and args.resume:
        print(f"Resuming existing workdir: {workdir}")
        wd_state.mark_running()
    else:
        wd_state.init_state()
        wd_state.mark_running()

    ret = run_syzkaller_manager(workdir, args.hours)
    wd_state.mark_paused()
    campaign_state.transition_to(CampaignStatus.PAUSED)
    print(f"Campaign {args.campaign} paused (exit code: {ret})")


if __name__ == "__main__":
    main()
