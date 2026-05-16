from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

VALID_STATUSES = {"implemented", "partial", "stub", "unsupported", "unknown"}


def validate_manifest(manifest: dict) -> list[str]:
    errors = []
    if "target" not in manifest:
        errors.append("missing 'target' field")
    if "arch" not in manifest:
        errors.append("missing 'arch' field")
    source = manifest.get("source", {})
    if "rev" not in source:
        errors.append("missing 'source.rev'")
    if "rules_hash" not in source:
        errors.append("missing 'source.rules_hash'")
    syscalls = manifest.get("syscalls", {})
    for name, entry in syscalls.items():
        status = entry.get("status")
        if status not in VALID_STATUSES:
            errors.append(f"syscall '{name}': invalid status '{status}'")
        if status == "implemented":
            if not entry.get("handler_sites") and not entry.get("evidence"):
                errors.append(f"syscall '{name}': implemented but no handler or evidence")
        if status == "unsupported":
            if entry.get("handler_sites"):
                errors.append(f"syscall '{name}': unsupported but has handler sites")
        if status == "stub":
            if not entry.get("stub_evidence"):
                errors.append(f"syscall '{name}': stub but no stub_evidence")
        if status == "partial":
            if not entry.get("notes") and not entry.get("subfeatures"):
                errors.append(f"syscall '{name}': partial but no notes or subfeatures")
    return errors


def load_manifest(path: Path) -> dict:
    return json.loads(path.read_text())


def save_manifest(manifest: dict, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2))


def lookup_syscall(manifest: dict, syscall_name: str) -> Optional[dict]:
    return manifest.get("syscalls", {}).get(syscall_name)


def apply_manual_overrides(manifest: dict, overrides: dict[str, dict]):
    for name, override in overrides.items():
        status = override.get("status")
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid override status '{status}' for syscall '{name}'")
        if name in manifest.get("syscalls", {}):
            entry = manifest["syscalls"][name]
            entry["status"] = status
            entry.setdefault("notes", [])
            for note in override.get("notes", []):
                if note not in entry["notes"]:
                    entry["notes"].append(f"manual override: {note}")
        else:
            manifest.setdefault("syscalls", {})[name] = {
                "nr": None,
                "status": status,
                "handler": None,
                "dispatch_sites": [],
                "handler_sites": [],
                "stub_evidence": [],
                "features": [],
                "confidence": "manual",
                "notes": [f"manual override: {n}" for n in override.get("notes", [])],
            }
