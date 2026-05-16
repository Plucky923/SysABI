from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def compute_program_id(normalized_syz_text: str) -> str:
    return hashlib.sha256(normalized_syz_text.encode()).hexdigest()


def normalize_syz_text(text: str) -> str:
    return text.strip().replace("\r\n", "\n") + "\n"


class CorpusStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.programs_dir = self.root / "programs"
        self.objects_path = self.root / "objects.jsonl"
        self.state_path = self.root / "corpus-store-state.json"
        self._objects: dict[str, dict] = {}
        self._loaded = False

    def _ensure_loaded(self):
        if self._loaded:
            return
        self.programs_dir.mkdir(parents=True, exist_ok=True)
        if self.objects_path.exists():
            with open(self.objects_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    self._objects[obj["program_id"]] = obj
        self._loaded = True

    def _persist_objects(self):
        self.objects_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.objects_path, "w") as f:
            for obj in self._objects.values():
                f.write(json.dumps(obj, sort_keys=True) + "\n")

    def _program_path(self, program_id: str) -> Path:
        return self.programs_dir / program_id[:2] / (program_id + ".syz")

    def exists(self, program_id: str) -> bool:
        self._ensure_loaded()
        return program_id in self._objects

    def add_origin(self, program_id: str, origin: dict):
        self._ensure_loaded()
        if program_id not in self._objects:
            raise KeyError(f"program_id not in store: {program_id}")
        obj = self._objects[program_id]
        obj["origins"].append(origin)
        obj["last_seen_at"] = datetime.now(timezone.utc).isoformat()
        self._persist_objects()

    def write(self, program_id: str, normalized_text: str):
        file_path = self._program_path(program_id)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "w") as f:
            f.write(normalized_text)

    def add_object(self, program_id: str, origin: dict, inspected: bool = False):
        self._ensure_loaded()
        now = datetime.now(timezone.utc).isoformat()
        self._objects[program_id] = {
            "program_id": program_id,
            "path": str(self._program_path(program_id)),
            "sha256": program_id,
            "size_bytes": self._program_path(program_id).stat().st_size
            if self._program_path(program_id).exists()
            else 0,
            "first_seen_at": now,
            "last_seen_at": now,
            "origins": [origin],
            "lifecycle": {
                "imported": True,
                "inspected": inspected,
                "projected": {},
                "replayed": {},
            },
        }
        self._persist_objects()

    def get(self, program_id: str) -> Optional[dict]:
        self._ensure_loaded()
        return self._objects.get(program_id)

    def program_ids(self) -> set[str]:
        self._ensure_loaded()
        return set(self._objects.keys())

    def read_program_text(self, program_id: str) -> str:
        file_path = self._program_path(program_id)
        if not file_path.exists():
            raise FileNotFoundError(f"Program file not found: {file_path}")
        return file_path.read_text()

    def mark_inspected(self, program_id: str):
        self._ensure_loaded()
        if program_id in self._objects:
            self._objects[program_id]["lifecycle"]["inspected"] = True
            self._persist_objects()

    def mark_projected(self, program_id: str, target: str):
        self._ensure_loaded()
        if program_id in self._objects:
            self._objects[program_id]["lifecycle"]["projected"][target] = True
            self._persist_objects()

    def mark_replayed(self, program_id: str, target: str):
        self._ensure_loaded()
        if program_id in self._objects:
            self._objects[program_id]["lifecycle"]["replayed"][target] = True
            self._persist_objects()

    def count(self) -> int:
        self._ensure_loaded()
        return len(self._objects)

    def count_inspected(self) -> int:
        self._ensure_loaded()
        return sum(
            1 for obj in self._objects.values() if obj["lifecycle"].get("inspected", False)
        )

    def pending_program_ids(self) -> set[str]:
        self._ensure_loaded()
        return {
            pid
            for pid, obj in self._objects.items()
            if not obj["lifecycle"].get("inspected", False)
        }
