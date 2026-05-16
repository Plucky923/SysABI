#!/usr/bin/env python3
"""Extract syscall capability manifest for a target RustOS from source code."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from core.syscall_manifest import apply_manual_overrides, validate_manifest, save_manifest


def collect_source_files(source_roots: list[str], project_root: Path) -> list[Path]:
    files = []
    extensions = {".rs", ".S", ".s", ".c", ".h"}
    for root in source_roots:
        expanded = list(project_root.glob(root))
        for p in expanded:
            if p.is_file() and p.suffix in extensions:
                files.append(p)
            elif p.is_dir():
                for ext in extensions:
                    files.extend(p.rglob(f"*{ext}"))
    return sorted(set(files))


def extract_syscall_numbers(files: list[Path], patterns: list[str]) -> dict[str, int]:
    numbers = {}
    for file_path in files:
        try:
            text = file_path.read_text(errors="replace")
        except Exception:
            continue
        for pat in patterns:
            for m in re.finditer(pat, text):
                name = m.group(1).lower()
                num = int(m.group(2))
                if name not in numbers:
                    numbers[name] = num
    return numbers


def extract_dispatch_entries(files: list[Path], patterns: list[str]) -> dict[str, list[dict]]:
    entries: dict[str, list[dict]] = {}
    for file_path in files:
        try:
            text = file_path.read_text(errors="replace")
        except Exception:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for pat in patterns:
                m = re.search(pat, line)
                if m:
                    name = m.group(1).lower()
                    handler = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
                    if "sys_" in handler.lower():
                        handler_name = re.search(r"(sys_\w+)", handler)
                        handler = handler_name.group(1) if handler_name else handler
                    entries.setdefault(name, []).append({
                        "file": str(file_path),
                        "line": i,
                        "kind": "match_arm" if "=>" in line else "table_entry",
                        "text": line.strip()[:200],
                    })
    return entries


def extract_handler_defs(files: list[Path], patterns: list[str]) -> dict[str, list[dict]]:
    defs: dict[str, list[dict]] = {}
    for file_path in files:
        try:
            text = file_path.read_text(errors="replace")
        except Exception:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for pat in patterns:
                m = re.search(pat, line)
                if m:
                    name = m.group(1).lower()
                    defs.setdefault(name, []).append({
                        "file": str(file_path),
                        "line": i,
                        "kind": "function",
                    })
    return defs


def is_stub_handler(handler_def: dict, files_lookup: dict[str, str], stub_patterns: list[str]) -> tuple[bool, list[str]]:
    file_path = handler_def.get("file", "")
    if file_path not in files_lookup:
        return False, []
    line = handler_def.get("line", 0)
    lines = files_lookup[file_path].splitlines()
    start = max(0, line - 1)
    end = min(len(lines), line + 80)
    body = "\n".join(lines[start:end])
    evidence = []
    for pat in stub_patterns:
        if re.search(re.escape(pat), body, re.IGNORECASE):
            evidence.append(f"stub_pattern_matched: {pat}")
    return bool(evidence), evidence


def resolve_handler(dispatch_entry: dict, handler_defs: dict[str, list[dict]]) -> list[dict]:
    text = dispatch_entry.get("text", "")
    for name, sites in handler_defs.items():
        if name in text.lower():
            return sites
    return []


def get_git_rev(project_root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root, capture_output=True, text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "unknown"


def main():
    parser = argparse.ArgumentParser(description="Extract syscall capability manifest")
    parser.add_argument("--target", required=True, help="Target name (e.g., tgoskits_starryos)")
    parser.add_argument("--source-root", required=True, help="Path to target source root")
    parser.add_argument("--arch", default="riscv64", help="Target architecture")
    parser.add_argument("--rules", required=True, help="Path to rules JSON file")
    parser.add_argument("--output", required=True, help="Output manifest JSON path")
    parser.add_argument("--linux-syscall-list", help="Path to Linux syscall list (one per line)")
    args = parser.parse_args()

    rules = json.loads(Path(args.rules).read_text())
    source_root = Path(args.source_root)
    project_root = source_root
    output_path = Path(args.output)

    syscall_universe = set()
    if args.linux_syscall_list:
        sc_list_path = Path(args.linux_syscall_list)
        if sc_list_path.exists():
            syscall_universe = set(
                line.strip().lower()
                for line in sc_list_path.read_text().splitlines()
                if line.strip()
            )

    files = collect_source_files(rules.get("source_roots", []), source_root)
    numbers = extract_syscall_numbers(files, rules.get("number_patterns", []))
    dispatch = extract_dispatch_entries(files, rules.get("dispatch_patterns", []))
    handlers = extract_handler_defs(files, rules.get("handler_patterns", []))

    files_lookup = {}
    for f in files:
        try:
            files_lookup[str(f)] = f.read_text(errors="replace")
        except Exception:
            pass

    manifest: dict = {
        "schema_version": 1,
        "target": args.target,
        "arch": args.arch,
        "source": {
            "root": str(source_root),
            "rev": get_git_rev(source_root),
            "rules_hash": hashlib.sha256(
                Path(args.rules).read_bytes()
            ).hexdigest(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "syscalls": {},
    }

    for sc in sorted(syscall_universe):
        nr = numbers.get(sc)
        d_entries = dispatch.get(sc, [])
        h_sites = []
        for de in d_entries:
            resolved = resolve_handler(de, handlers)
            if resolved:
                h_sites.extend(resolved)

        if not d_entries:
            status = "unsupported"
            evidence = ["missing_dispatch"]
        elif not h_sites:
            status = "unknown"
            evidence = ["dispatch_found", "handler_unresolved"]
        else:
            stub_flag = False
            stub_ev = []
            for hs in h_sites:
                is_stub, ev = is_stub_handler(hs, files_lookup, rules.get("stub_patterns", []))
                if is_stub:
                    stub_flag = True
                    stub_ev.extend(ev)
            if stub_flag:
                status = "stub"
                evidence = ["dispatch_found", "handler_found", "stub_body"]
            else:
                status = "implemented"
                evidence = ["dispatch_found", "handler_found"]

        manifest["syscalls"][sc] = {
            "nr": nr,
            "status": status,
            "handler": h_sites[0].get("file", "").split("/")[-1] if h_sites else None,
            "dispatch_sites": d_entries,
            "handler_sites": h_sites,
            "stub_evidence": stub_ev if status == "stub" else [],
            "features": [],
            "confidence": "high" if status in ("unsupported", "implemented") and d_entries or not d_entries else "medium",
            "notes": [],
        }

    manual_overrides = rules.get("manual_overrides", {})
    if manual_overrides:
        apply_manual_overrides(manifest, manual_overrides)

    errors = validate_manifest(manifest)
    if errors:
        print("WARNING: Manifest validation warnings:")
        for e in errors:
            print(f"  - {e}")

    save_manifest(manifest, output_path)
    total = len(manifest["syscalls"])
    by_status = {}
    for sc in manifest["syscalls"].values():
        s = sc["status"]
        by_status[s] = by_status.get(s, 0) + 1
    print(f"Manifest written to {output_path} ({total} syscalls: {by_status})")


if __name__ == "__main__":
    main()
