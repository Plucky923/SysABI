from __future__ import annotations

from typing import Optional

from core.constants import Classification, ExecutionStatus
from core.enosys_triage import classify_enosys_divergence
from orchestrator.common import config


def classify_result(
    *,
    reference_stable: bool,
    reference_status: str,
    candidate_status: str,
    comparison: dict[str, object] | None,
    manifest: Optional[dict] = None,
) -> str:
    classes = config()["classification"]
    if not reference_stable or reference_status != ExecutionStatus.OK:
        return classes[Classification.BASELINE_INVALID]
    if candidate_status == ExecutionStatus.UNSUPPORTED:
        return classes[Classification.UNSUPPORTED_FEATURE]
    if candidate_status in {ExecutionStatus.CRASH, ExecutionStatus.TIMEOUT, ExecutionStatus.CANDIDATE_BUG}:
        return classes[Classification.BUG_LIKELY]
    if comparison is None:
        if candidate_status == ExecutionStatus.INFRA_ERROR:
            return classes[Classification.WEAK_SPEC_OR_ENV_NOISE]
        return classes[Classification.UNSUPPORTED_FEATURE]
    if comparison["equivalent"]:
        return classes[Classification.NO_DIFF]

    first_div = comparison.get("first_divergence")
    if manifest is not None and isinstance(first_div, dict):
        cls_name, reason, cap = classify_enosys_divergence(first_div, manifest)
        if cls_name:
            cls_enum = Classification(cls_name)
            if cls_enum in classes:
                return classes[cls_enum]

    if candidate_status in {ExecutionStatus.CRASH, ExecutionStatus.TIMEOUT, ExecutionStatus.CANDIDATE_BUG}:
        return classes[Classification.BUG_LIKELY]
    if candidate_status == ExecutionStatus.INFRA_ERROR:
        return classes[Classification.WEAK_SPEC_OR_ENV_NOISE]
    if comparison["noise_only"]:
        return classes[Classification.WEAK_SPEC_OR_ENV_NOISE]
    return classes[Classification.BUG_LIKELY]


def classify_with_context(
    *,
    reference_stable: bool,
    reference_status: str,
    candidate_status: str,
    comparison: dict[str, object] | None,
    manifest: Optional[dict] = None,
    program_id: str = "",
) -> dict:
    classification = classify_result(
        reference_stable=reference_stable,
        reference_status=reference_status,
        candidate_status=candidate_status,
        comparison=comparison,
        manifest=manifest,
    )
    result: dict = {
        "program_id": program_id,
        "classification": classification,
    }
    first_div = comparison.get("first_divergence") if comparison else None

    if first_div and isinstance(first_div, dict):
        result["first_divergence_details"] = first_div

    if manifest is not None and first_div and isinstance(first_div, dict):
        syscall_name = first_div.get("base") or first_div.get("syscall") or ""
        _, reason, cap = classify_enosys_divergence(first_div, manifest)
        if reason:
            result["reason"] = reason
        if cap is not None:
            result["capability_context"] = {
                "status": cap.get("status", "unknown"),
                "handler": cap.get("handler"),
                "evidence": cap.get("stub_evidence", []) or [
                    "dispatch_found" if cap.get("dispatch_sites") else "",
                    "handler_found" if cap.get("handler_sites") else "",
                ],
                "confidence": cap.get("confidence", "medium"),
            }
            result["capability_context"]["evidence"] = [
                e for e in result["capability_context"]["evidence"] if e
            ]
    return result
