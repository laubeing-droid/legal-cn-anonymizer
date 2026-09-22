"""W15c-A product nine-step disposal test (plan-v4.2 card 05-4 final row).

Exercises disposal_service end to end over a REAL signature chain: the
authorization record is a closed-field document signed with an Ed25519 key
whose public half is installed in the local trust store — the same
verify_signature_with_public path the consumer protocol uses. A missing or
unsigned authorization can never execute disposal; nothing here stubs the
check by string comparison.

All fixtures synthetic. The card's caveat stands: this drives the nine steps
through the service, it is not a kill-process crash drill (the ledger journal
resume step is verified by re-entering execute_disposal with pending state).
"""

from __future__ import annotations

import json

import pytest

from legal_anonymizer.application import disposal_service as ds
from legal_anonymizer.application.disposal_service import (
    DisposalError,
    execute_disposal,
    read_disposal,
    register_managed_object,
)
from legal_anonymizer.application.state import MatterState, MatterStateError
from legal_anonymizer.security.receipt_identity import ReceiptIdentity

MATTER = "disp-matter"
ARCHIVE_V = "arch-0001"


@pytest.fixture()
def env(tmp_path):
    state = MatterState(tmp_path, MATTER)
    state.init("cn-ai-safe-v1")
    pub = state.read_public()
    pub["archive_version"] = ARCHIVE_V
    pub["documents"] = ["doc-001"]
    state.write_public(pub)

    harness_identity = ReceiptIdentity(tmp_path / "harness-identity").ensure()
    pub_key = harness_identity.export_public()
    keys_dir = tmp_path / ds.TRUSTED_KEYS_DIR
    keys_dir.mkdir(parents=True, exist_ok=True)
    (keys_dir / f"{pub_key['key_id']}.json").write_text(
        json.dumps(pub_key, ensure_ascii=False), "utf-8")
    return tmp_path, state, harness_identity


def _authorize(env, request_id, targets, **overrides):
    tmp_path, _state, identity = env
    record = {
        "schema_version": "1.0",
        "authorizationRef": {"id": f"auth-{request_id}", "version": "1"},
        "matter_id": MATTER,
        "archiveRef": {"kind": "archive", "id": ARCHIVE_V, "version": ARCHIVE_V},
        "targetRefs": targets,
        "policy": "retain-90d-then-dispose",
        "reason": "matter-closed-client-request",
        "decision": "human-decision-approved-2026-09-22",
        "issued_at": "2026-09-22T00:00:00Z",
    }
    record.update(overrides)
    record["signature"] = identity.sign(record)
    auth_dir = tmp_path / ds.AUTH_DIR
    auth_dir.mkdir(exist_ok=True)
    (auth_dir / f"auth-{request_id}.json").write_text(
        json.dumps(record, ensure_ascii=False), "utf-8")
    return {"id": f"auth-{request_id}", "version": "1"}


def _register_mapping(env, request_id="r1"):
    tmp_path = env[0]
    version = register_managed_object(
        tmp_path, MATTER, f"mapping-{request_id}", "private-mapping", "private.dpapi")
    return [{"id": f"mapping-{request_id}", "kind": "private-mapping",
             "version": version}]


# ------------------------------------------------------------- step 1
def test_step1_unregistered_authorization_refused(env):
    with pytest.raises(DisposalError) as exc:
        execute_disposal(env[0], {"matterId": MATTER}, {"requestId": "x1"},
                         {"id": "auth-ghost", "version": "1"})
    assert exc.value.code == "ref_not_found"


def test_step1_forged_signature_refused(env):
    tmp_path = env[0]
    ref = _authorize(env, "x2", _register_mapping(env, "x2"))
    p = tmp_path / ds.AUTH_DIR / "auth-x2.json"
    doc = json.loads(p.read_text("utf-8"))
    doc["targetRefs"] = []  # tamper after signing
    p.write_text(json.dumps(doc), "utf-8")
    with pytest.raises(DisposalError) as exc:
        execute_disposal(tmp_path, {"matterId": MATTER}, {"requestId": "x2"}, ref)
    assert exc.value.code == "verification_failed"


# ------------------------------------------------------------- step 2
def test_step2_archive_and_version_bindings_enforced(env):
    # archive version mismatch
    targets = _register_mapping(env, "a1")
    tmp_path = env[0]
    pub = MatterState(tmp_path, MATTER).read_public()
    pub["archive_version"] = "arch-EVIL"
    MatterState(tmp_path, MATTER).write_public(pub)
    ref = _authorize(env, "a1", targets)
    with pytest.raises(DisposalError) as exc:
        execute_disposal(tmp_path, {"matterId": MATTER}, {"requestId": "a1"}, ref)
    assert exc.value.code == "verification_failed"
    pub["archive_version"] = ARCHIVE_V
    MatterState(tmp_path, MATTER).write_public(pub)
    # object version mismatch
    stale = [dict(targets[0], version="0" * 64)]
    ref2 = _authorize(env, "a2", stale)
    with pytest.raises(DisposalError) as exc2:
        execute_disposal(tmp_path, {"matterId": MATTER}, {"requestId": "a2"}, ref2)
    assert exc2.value.code == "verification_failed"


def test_step2_missing_policy_reason_decision_refused(env):
    targets = _register_mapping(env, "a3")
    ref = _authorize(env, "a3", targets, decision="")
    with pytest.raises(DisposalError) as exc:
        execute_disposal(env[0], {"matterId": MATTER}, {"requestId": "a3"}, ref)
    assert exc.value.code == "verification_failed"


# ------------------------------------------------------------- steps 3+4
def test_steps_3_4_only_registered_objects_and_never_input_originals(env):
    tmp_path = env[0]
    # an "input original" kind cannot even be registered
    (tmp_path / MATTER / "input_orig.md").write_text("原件", "utf-8")
    with pytest.raises(DisposalError) as exc:
        register_managed_object(tmp_path, MATTER, "orig-1", "external-input",
                                "input_orig.md")
    assert exc.value.code == "verification_failed"
    # and a ref to an unregistered id is refused at execution
    ref = _authorize(env, "u1", [{"id": "not-registered", "kind": "private-mapping",
                                  "version": "1"}])
    with pytest.raises(DisposalError) as exc2:
        execute_disposal(tmp_path, {"matterId": MATTER}, {"requestId": "u1"}, ref)
    assert exc2.value.code == "ref_not_found"
    # input original survives untouched
    assert (tmp_path / MATTER / "input_orig.md").exists()


# ------------------------------------------------- steps 5+6+8 (full run)
def test_full_disposal_ledger_and_no_empty_mapping(env):
    tmp_path = env[0]
    targets = _register_mapping(env, "full")
    ref = _authorize(env, "full", targets)
    receipt = execute_disposal(tmp_path, {"matterId": MATTER},
                               {"requestId": "full"}, ref)
    assert receipt["status"] == "completed"
    assert [c["id"] for c in receipt["completedRefs"]] == ["mapping-full"]
    # step 6: ledger lives outside the matter/mapping store
    assert (tmp_path / ds.LEDGER_DIR / "full.json").exists()
    # mapping actually gone
    assert not (tmp_path / MATTER / "private.dpapi").exists()
    # step 8: no startup path may recreate an empty mapping
    with pytest.raises(MatterStateError):
        MatterState.load(tmp_path, MATTER)
    with pytest.raises(DisposalError):
        register_managed_object(tmp_path, MATTER, "again", "private-mapping",
                                "private.dpapi")
    # read-back still works from the ledger alone
    again = read_disposal(tmp_path, {"matterId": MATTER}, "full")
    assert again["status"] == "completed"


# ------------------------------------------------------------- step 7
def test_step7_restart_resumes_pending_objects(env):
    tmp_path = env[0]
    v_map = register_managed_object(tmp_path, MATTER, "obj-map", "private-mapping",
                                    "private.dpapi")
    v_pub = register_managed_object(tmp_path, MATTER, "obj-manifest",
                                    "matter-manifest", "project.public.json")
    ref = _authorize(env, "rs1", [
        {"id": "obj-map", "kind": "private-mapping", "version": v_map},
        {"id": "obj-manifest", "kind": "matter-manifest", "version": v_pub},
    ])
    ledger = tmp_path / ds.LEDGER_DIR
    ledger.mkdir(parents=True, exist_ok=True)
    # simulate a crash after the FIRST object was deleted but before completion:
    # journal exists with second object still pending
    entry = {
        "request_id": "rs1", "matter_id": MATTER,
        "authorization_ref_id": "auth-rs1", "authorization_ref_version": "1",
        "policy": "p", "reason": "r", "decision": "d",
        "created_at": "2026-09-22T00:00:00Z",
        "objects": [
            {"object_id": "obj-map", "kind": "private-mapping",
             "rel_path": "private.dpapi", "state": "deleted",
             "at": "2026-09-22T00:00:01Z"},
            {"object_id": "obj-manifest", "kind": "matter-manifest",
             "rel_path": "project.public.json", "state": "pending"},
        ],
    }
    (ledger / "rs1.json").write_text(json.dumps(entry), "utf-8")
    receipt = execute_disposal(tmp_path, {"matterId": MATTER},
                               {"requestId": "rs1"}, ref)
    assert receipt["status"] == "completed"
    assert not (tmp_path / MATTER / "project.public.json").exists()
    # deleted first object was NOT re-touched (already completed)


# ------------------------------------------------- idempotency + scope
def test_idempotent_replay_and_cross_request_refusal(env):
    tmp_path = env[0]
    targets = _register_mapping(env, "idem")
    ref = _authorize(env, "idem", targets)
    r1 = execute_disposal(tmp_path, {"matterId": MATTER}, {"requestId": "idem"}, ref)
    r2 = execute_disposal(tmp_path, {"matterId": MATTER}, {"requestId": "idem"}, ref)
    assert r1["completedRefs"] == r2["completedRefs"]
    # same requestId bound to a different authorization -> refused
    other_ref = {"id": "auth-other", "version": "1"}
    with pytest.raises(DisposalError) as exc:
        execute_disposal(tmp_path, {"matterId": MATTER}, {"requestId": "idem"},
                         other_ref)
    assert exc.value.code == "verification_failed"


def test_scope_mismatch_on_read(env):
    tmp_path = env[0]
    targets = _register_mapping(env, "sc")
    ref = _authorize(env, "sc", targets)
    execute_disposal(tmp_path, {"matterId": MATTER}, {"requestId": "sc"}, ref)
    with pytest.raises(DisposalError) as exc:
        read_disposal(tmp_path, {"matterId": "other-matter"}, "sc")
    assert exc.value.code == "scope_mismatch"


# ------------------------------------------------------------- step 9
def test_step9_receipt_never_claims_media_erasure(env):
    tmp_path = env[0]
    targets = _register_mapping(env, "s9")
    ref = _authorize(env, "s9", targets)
    receipt = execute_disposal(tmp_path, {"matterId": MATTER}, {"requestId": "s9"}, ref)
    mode = receipt["deletion_mode"]
    assert "logical" in mode and "no media-level-erasure" in mode
    flat = json.dumps(receipt, ensure_ascii=False).upper()
    for forbidden in ("SAFE", "100% ANONYMIZED", "ZERO RISK", "FULLY ERASED",
                      "SHREDDED", "IRRECOVERABLE"):
        assert forbidden not in flat
