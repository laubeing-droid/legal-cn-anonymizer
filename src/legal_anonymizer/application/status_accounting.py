"""Shared matter-status accounting used by all document pipelines."""

from __future__ import annotations

from .state import MatterState


def update_matter_review_flag(state: MatterState, review_required: bool) -> None:
    """Matter-level review requirement is monotonic during a run: any document
    that requires review keeps the whole matter in REVIEW_REQUIRED until a
    signed human review receipt resolves it (S9)."""
    private = state.read_private()
    previous = bool(private.get("matter_review_required", False))
    private["matter_review_required"] = previous or review_required
    state.write_private(private)
    public = state.read_public()
    public["status"] = (
        "REVIEW_REQUIRED" if private["matter_review_required"] else "AUTO_READY"
    )
    state.write_public(public)
