"""Unit tests for core/harvest_state.py — AC-9."""
from __future__ import annotations

import tempfile
from pathlib import Path

from core.harvest_state import (
    CampaignState, CampaignStatus, WorkdirState,
    compute_input_fingerprint, STALE_TRIGGERS,
)


def test_compute_fingerprint_deterministic():
    components = {"syzkaller_commit": "abc123", "linux_kernel_build_id": "sha256:def456"}
    assert compute_input_fingerprint(components) == compute_input_fingerprint(components)


def test_compute_fingerprint_changes_with_different_components():
    c1 = {"syzkaller_commit": "abc123"}
    c2 = {"syzkaller_commit": "xyz789"}
    assert compute_input_fingerprint(c1) != compute_input_fingerprint(c2)


def test_campaign_state_new(tmp_path):
    state = CampaignState(tmp_path)
    assert not state.exists()
    assert state.status() is None


def test_campaign_state_transitions(tmp_path):
    state = CampaignState(tmp_path)
    state.save({"schema_version": 1, "campaign": "test", "status": "NEW"})
    state.transition_to(CampaignStatus.CONFIGURED)
    assert state.status() == CampaignStatus.CONFIGURED
    state.transition_to(CampaignStatus.RUNNING)
    assert state.status() == CampaignStatus.RUNNING


def test_campaign_state_invalid_transition(tmp_path):
    state = CampaignState(tmp_path)
    state.save({"schema_version": 1, "campaign": "test", "status": "NEW"})
    try:
        state.transition_to(CampaignStatus.READY_FOR_PROJECTION)
        assert False, "should have raised ValueError"
    except ValueError:
        pass


def test_campaign_state_fingerprint(tmp_path):
    state = CampaignState(tmp_path)
    components = {"syzkaller_commit": "abc123"}
    state.save_fingerprint(components)
    assert state.fingerprint() is not None
    assert not state.fingerprint_changed(components)
    assert state.fingerprint_changed({"syzkaller_commit": "different"})


def test_campaign_mark_stale(tmp_path):
    state = CampaignState(tmp_path)
    state.save({"schema_version": 1, "campaign": "test", "status": "CONFIGURED"})
    state.mark_stale(["syzkaller_commit_changed", "unknown_trigger"])
    assert state.status() == CampaignStatus.STALE


def test_workdir_state_init(tmp_path):
    wd = WorkdirState(tmp_path, "test-campaign")
    doc = wd.init_state()
    assert doc["campaign"] == "test-campaign"
    assert doc["status"] == "created"
    assert wd.exists()


def test_workdir_state_lifecycle(tmp_path):
    wd = WorkdirState(tmp_path, "test-campaign")
    wd.init_state()
    assert not wd.is_resumable()
    wd.mark_running()
    wd.mark_paused(total_runtime_seconds=3600)
    assert wd.is_resumable()
