from __future__ import annotations

from typing import Optional


def candidate_returns_enosys(first_divergence: dict) -> bool:
    errno = first_divergence.get("candidate_errno")
    if errno is not None:
        if str(errno) == "ENOSYS" or str(errno) == "38":
            return True
    ret = first_divergence.get("candidate_ret")
    if ret is not None:
        try:
            if int(ret) == -38:
                return True
        except (ValueError, TypeError):
            pass
    return False


def lookup_syscall_capability(manifest: dict, syscall_name: str) -> Optional[dict]:
    syscalls = manifest.get("syscalls", {})
    if syscall_name in syscalls:
        return syscalls[syscall_name]
    return None


def resolve_capability_status(manifest: dict, syscall_name: str) -> str:
    cap = lookup_syscall_capability(manifest, syscall_name)
    if cap is None:
        return "unknown"
    return cap.get("status", "unknown")


def classify_enosys_divergence(
    first_divergence: dict,
    manifest: Optional[dict],
) -> tuple[str, str, Optional[dict]]:
    if not candidate_returns_enosys(first_divergence):
        return "", "", None
    syscall_name = first_divergence.get("base") or first_divergence.get("syscall") or ""
    if not syscall_name:
        return "", "", None
    if manifest is None:
        return "", "", None
    cap_status = resolve_capability_status(manifest, syscall_name)
    cap = lookup_syscall_capability(manifest, syscall_name)
    if cap_status in ("unsupported", "stub"):
        return "unsupported_feature", "enosys_matches_manifest_unsupported", cap
    if cap_status == "implemented":
        return "bug_likely", "implemented_syscall_returned_enosys", cap
    if cap_status == "partial":
        return "partial_semantic_gap", "partial_syscall_returned_enosys", cap
    return "unknown_capability_gap", "enosys_on_unknown_capability", cap
