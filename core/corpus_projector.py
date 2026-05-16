from __future__ import annotations

import json
from pathlib import Path


PROJECTION_CATEGORIES = ("supported", "partial", "unsupported", "unknown", "hazardous")


def project_program(program_meta: dict, manifest: dict, policy: dict) -> dict:
    required = program_meta.get("required_syscalls", []) or program_meta.get("syscall_list", [])
    statuses = []
    for sc in required:
        cap = manifest.get("syscalls", {}).get(sc)
        if cap is None:
            statuses.append((sc, "unknown", None))
        else:
            statuses.append((sc, cap.get("status", "unknown"), cap))

    if any(s in ("unsupported", "stub") for _, s, _ in statuses):
        projection = "unsupported"
    elif any(s == "unknown" for _, s, _ in statuses):
        projection = "unknown"
    elif any(s == "partial" for _, s, _ in statuses):
        projection = "partial"
    else:
        projection = "supported"

    default_replay = policy.get("replay", {}).get(projection, False)
    blocked = [(sc, s, c.get("evidence", []) if c else []) for sc, s, c in statuses if s in ("unsupported", "stub")]
    partial = [(sc, s, c.get("notes", []) if c else []) for sc, s, c in statuses if s == "partial"]
    unknown = [(sc, s) for sc, s, _ in statuses if s == "unknown"]

    return {
        "program_id": program_meta.get("program_id", ""),
        "projection": projection,
        "default_replay": default_replay,
        "required_syscalls": required,
        "syscall_capabilities": {sc: s for sc, s, _ in statuses},
        "blocked_by": [{"syscall": sc, "status": s, "evidence": e} for sc, s, e in blocked],
        "partial_by": [{"syscall": sc, "status": s, "notes": n} for sc, s, n in partial],
        "unknown_by": [{"syscall": sc, "status": s} for sc, s in unknown],
        "reason": projection_reason(projection, blocked, partial, unknown),
    }


def projection_reason(projection, blocked, partial, unknown):
    if projection == "supported":
        return "all_required_syscalls_implemented"
    if projection == "unsupported":
        return "contains_unsupported_syscall"
    if projection == "partial":
        return "contains_partial_syscall"
    if projection == "unknown":
        return "contains_unknown_capability_syscall"
    return projection


def load_policy(policy_path: Path) -> dict:
    return json.loads(policy_path.read_text())


def load_program_index(index_dir: Path) -> set[str]:
    ids = set()
    all_path = index_dir / "all-programs.jsonl"
    if all_path.exists():
        for line in all_path.read_text().strip().splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            ids.add(entry.get("program_id", ""))
    return ids - {""}


def load_projection_state(state_path: Path) -> dict:
    if state_path.exists():
        return json.loads(state_path.read_text())
    return {"programs_projected": 0}


def save_projection_state(state_path: Path, state: dict):
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2))
