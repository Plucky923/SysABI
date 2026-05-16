from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Optional


class CampaignStatus(StrEnum):
    NEW = "NEW"
    CONFIGURED = "CONFIGURED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    EXPORTED = "EXPORTED"
    IMPORTED = "IMPORTED"
    INSPECTED = "INSPECTED"
    COVERAGE_COLLECTED = "COVERAGE_COLLECTED"
    READY_FOR_PROJECTION = "READY_FOR_PROJECTION"
    STALE = "STALE"
    FAILED = "FAILED"


VALID_TRANSITIONS: dict[CampaignStatus, set[CampaignStatus]] = {
    CampaignStatus.NEW: {
        CampaignStatus.CONFIGURED,
        CampaignStatus.RUNNING,
    },
    CampaignStatus.CONFIGURED: {
        CampaignStatus.RUNNING,
        CampaignStatus.STALE,
        CampaignStatus.FAILED,
    },
    CampaignStatus.RUNNING: {
        CampaignStatus.PAUSED,
        CampaignStatus.EXPORTED,
        CampaignStatus.FAILED,
    },
    CampaignStatus.PAUSED: {
        CampaignStatus.RUNNING,
        CampaignStatus.EXPORTED,
        CampaignStatus.STALE,
        CampaignStatus.FAILED,
    },
    CampaignStatus.EXPORTED: {
        CampaignStatus.IMPORTED,
        CampaignStatus.FAILED,
    },
    CampaignStatus.IMPORTED: {
        CampaignStatus.INSPECTED,
        CampaignStatus.FAILED,
    },
    CampaignStatus.INSPECTED: {
        CampaignStatus.COVERAGE_COLLECTED,
        CampaignStatus.FAILED,
    },
    CampaignStatus.COVERAGE_COLLECTED: {
        CampaignStatus.READY_FOR_PROJECTION,
        CampaignStatus.FAILED,
    },
    CampaignStatus.READY_FOR_PROJECTION: {
        CampaignStatus.STALE,
        CampaignStatus.FAILED,
    },
    CampaignStatus.STALE: {
        CampaignStatus.CONFIGURED,
    },
}


STALE_TRIGGERS = [
    "syzkaller_commit_changed",
    "linux_kernel_build_changed",
    "rootfs_changed",
    "harvest_profile_changed",
    "inspector_version_changed",
    "corpus_store_manually_modified",
]


def compute_input_fingerprint(components: dict[str, str]) -> str:
    payload = json.dumps(components, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


class CampaignState:
    def __init__(self, campaign_dir: Path):
        self.campaign_dir = Path(campaign_dir)
        self.state_path = self.campaign_dir / "campaign-state.json"
        self.fingerprint_path = self.campaign_dir / "input-fingerprint.json"
        self._data: dict = {}
        self._fingerprint: dict = {}

    def exists(self) -> bool:
        return self.state_path.exists()

    def load(self) -> dict:
        if self.state_path.exists():
            self._data = json.loads(self.state_path.read_text())
        if self.fingerprint_path.exists():
            self._fingerprint = json.loads(self.fingerprint_path.read_text())
        return self._data

    def save(self, data: dict):
        self.campaign_dir.mkdir(parents=True, exist_ok=True)
        self._data = data
        self.state_path.write_text(json.dumps(data, indent=2))

    def save_fingerprint(self, components: dict[str, str]):
        fp = compute_input_fingerprint(components)
        doc = {
            "schema_version": 1,
            "fingerprint": fp,
            "components": components,
        }
        self.campaign_dir.mkdir(parents=True, exist_ok=True)
        self.fingerprint_path.write_text(json.dumps(doc, indent=2))
        self._fingerprint = doc

    def fingerprint(self) -> Optional[str]:
        return self._fingerprint.get("fingerprint") if self._fingerprint else None

    def fingerprint_changed(self, current_components: dict[str, str]) -> bool:
        current_fp = compute_input_fingerprint(current_components)
        return self.fingerprint() != current_fp

    def status(self) -> Optional[CampaignStatus]:
        if not self._data:
            self.load()
        status_str = self._data.get("status")
        if status_str:
            return CampaignStatus(status_str)
        return None

    def transition_to(self, target: CampaignStatus):
        current = self.status()
        if current is not None:
            allowed = VALID_TRANSITIONS.get(current, set())
            if target not in allowed:
                raise ValueError(
                    f"Invalid transition: {current.value} -> {target.value}"
                )
        self._data["status"] = target.value
        self.save(self._data)

    def mark_stale(self, reasons: list[str]):
        known = [r for r in reasons if r in STALE_TRIGGERS]
        self._data["stale_reasons"] = known
        self.transition_to(CampaignStatus.STALE)


class WorkdirState:
    def __init__(self, workdir: Path, campaign: str):
        self.workdir = Path(workdir)
        self.campaign = campaign
        self.state_path = self.workdir / "workdir-state.json"

    def init_state(self):
        self.workdir.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).isoformat()
        doc = {
            "schema_version": 1,
            "campaign": self.campaign,
            "workdir": str(self.workdir),
            "corpus_db": str(self.workdir / "corpus.db"),
            "status": "created",
            "created_at": now,
            "resume_supported": False,
        }
        self.state_path.write_text(json.dumps(doc, indent=2))
        return doc

    def load(self) -> dict:
        if self.state_path.exists():
            return json.loads(self.state_path.read_text())
        return {}

    def mark_running(self):
        doc = self.load()
        doc["status"] = "running"
        doc["last_started_at"] = datetime.now(timezone.utc).isoformat()
        self.state_path.write_text(json.dumps(doc, indent=2))
        return doc

    def mark_paused(self, total_runtime_seconds: int = 0):
        doc = self.load()
        doc["status"] = "paused"
        doc["last_stopped_at"] = datetime.now(timezone.utc).isoformat()
        doc["resume_supported"] = True
        if "total_runtime_seconds" in doc:
            doc["total_runtime_seconds"] += total_runtime_seconds
        else:
            doc["total_runtime_seconds"] = total_runtime_seconds
        self.state_path.write_text(json.dumps(doc, indent=2))
        return doc

    def exists(self) -> bool:
        return self.state_path.exists()

    def is_resumable(self) -> bool:
        doc = self.load()
        return doc.get("resume_supported", False)
