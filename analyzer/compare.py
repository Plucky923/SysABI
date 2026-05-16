from __future__ import annotations

from orchestrator.common import config


def _is_noise_event(left: dict[str, object], right: dict[str, object], noise_syscalls: set[str]) -> bool:
    if left["syscall_name"] != right["syscall_name"]:
        return False
    if left["syscall_name"] not in noise_syscalls:
        return False
    # For noise syscalls, differences in return_value and errno are ignored,
    # but args and outputs must still match.
    for field in ("args", "outputs"):
        if left[field] != right[field]:
            return False
    return True


def _build_first_divergence(index, reference_events, candidate_events):
    ref_count = len(reference_events)
    cand_count = len(candidate_events)
    if index >= ref_count or index >= cand_count:
        return {
            "index": index,
            "syscall": None,
            "base": None,
            "variant": None,
            "reference_ret": None,
            "reference_errno": None,
            "candidate_ret": None,
            "candidate_errno": None,
        }
    ref_ev = reference_events[index]
    cand_ev = candidate_events[index]
    return {
        "index": index,
        "syscall": ref_ev["syscall_name"],
        "base": ref_ev.get("base_syscall", ref_ev["syscall_name"]),
        "variant": ref_ev.get("variant"),
        "reference_ret": ref_ev.get("return_value"),
        "reference_errno": str(ref_ev.get("errno", "")) if ref_ev.get("errno") is not None else None,
        "candidate_ret": cand_ev.get("return_value"),
        "candidate_errno": str(cand_ev.get("errno", "")) if cand_ev.get("errno") is not None else None,
    }


def compare_canonical(reference: dict[str, object], candidate: dict[str, object]) -> dict[str, object]:
    ref_events = reference.get("events", [])
    cand_events = candidate.get("events", [])

    if reference["event_count"] != candidate["event_count"]:
        fd_idx = min(reference["event_count"], candidate["event_count"])
        return {
            "equivalent": False,
            "noise_only": False,
            "first_divergence_index": fd_idx,
            "first_divergence": _build_first_divergence(fd_idx, ref_events, cand_events)
            if fd_idx > 0 or (ref_events and not cand_events) or (cand_events and not ref_events)
            else {},
            "reason": "event_count_mismatch",
        }

    noise_syscalls = set(config().get("normalization", {}).get("noise_syscalls", []))

    first_divergence_index = None
    noise_only = True
    for left, right in zip(ref_events, cand_events, strict=True):
        if left["syscall_name"] != right["syscall_name"]:
            first_divergence_index = left["index"]
            noise_only = False
            break
        is_noise = _is_noise_event(left, right, noise_syscalls)
        for field in ("args", "return_value", "errno", "outputs"):
            if left[field] != right[field]:
                if is_noise and field in ("return_value", "errno"):
                    continue
                first_divergence_index = left["index"]
                noise_only = False
                break
        if first_divergence_index is not None:
            break

    final_state_equal = reference["final_state"] == candidate["final_state"]
    process_exit_equal = reference["process_exit"] == candidate["process_exit"]
    if not process_exit_equal:
        noise_only = False
        if first_divergence_index is None:
            first_divergence_index = reference["event_count"]
    equivalent = first_divergence_index is None and final_state_equal and process_exit_equal
    if equivalent:
        noise_only = False

    result = {
        "equivalent": equivalent,
        "noise_only": noise_only and final_state_equal,
        "first_divergence_index": first_divergence_index,
        "reason": "no_diff" if equivalent else "content_mismatch",
        "final_state_equal": final_state_equal,
        "process_exit_equal": process_exit_equal,
    }
    if first_divergence_index is not None:
        result["first_divergence"] = _build_first_divergence(
            first_divergence_index, ref_events, cand_events
        )
    return result
