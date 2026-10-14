"""W2a-U05 / F09 overlay revisions: 原件字节不变＋user_overrides_json 覆盖层
形成新 revision 并可回读旧件（义务 06:10/17:10）。

All fixtures synthetic Chinese legal material. The original file is a
read-only snapshot: every revision re-verifies its sha256 (a mutated original
fails closed). The overlay lands on the SANITIZED view only — originals and
the identity mapping (Vault) never enter this surface, per the anonymizer
hard rules. The deterministic final-byte rescan refuses overlays that carry
regex-catchable PII back in (never a fake success).
"""

from __future__ import annotations

import pytest

from legal_anonymizer.application import overlay_service as os_
from legal_anonymizer.application.overlay_service import (
    OverlayError,
    apply_overlay,
    list_revisions,
    read_revision,
    register_document,
)
from legal_anonymizer.config import Config
from legal_anonymizer.pipeline import deidentify

SYN_ORIGINAL = (
    "委托代理合同（合成材料）。\n"
    "委托人：周测敏（测试用合成身份，身份证11010119900307867X，"
    "电话13700009999，邮箱zhoubin@example.com）。\n"
    "代理费123,456.78元，2026年10月15日签订于北京市海淀区。\n"
)


@pytest.fixture()
def env(tmp_path):
    """Synthetic original file + revision-1 registration from a real P10 run."""
    matter = tmp_path / "m-f09"
    originals = matter / "originals"
    originals.mkdir(parents=True)
    original = originals / "contract.txt"
    original.write_text(SYN_ORIGINAL, encoding="utf-8")
    result = deidentify(SYN_ORIGINAL, Config(use_llm=False, critic=False,
                                             policy="balanced", locale="zh"))
    record = register_document(tmp_path, "m-f09", "doc-contract",
                               original, result.text)
    return tmp_path, matter, original, result.text, record


class TestRegister:
    def test_revision1_binds_read_only_original(self, env):
        tmp_path, matter, original, sanitized, record = env
        assert record["revision"] == 1
        assert record["origin"] == "pipeline"
        assert record["originalSha256"] == os_._sha256_bytes(
            original.read_bytes())
        # PII caught by the rules layer is tokenized in the stored revision 1.
        assert "13700009999" not in sanitized
        assert "PHONE_1" in sanitized

    def test_non_sanitized_base_refused(self, env):
        tmp_path, matter, original, _sanitized, _record = env
        with pytest.raises(OverlayError, match="overlay_base_not_sanitized"):
            register_document(tmp_path, "m-f09", "doc-raw", original,
                              SYN_ORIGINAL)

    def test_double_registration_refused(self, env):
        tmp_path, _matter, original, sanitized, _record = env
        with pytest.raises(OverlayError,
                           match="overlay_document_already_registered"):
            register_document(tmp_path, "m-f09", "doc-contract", original,
                              sanitized)


class TestOverlayRevisions:
    def test_overlay_forms_new_revision_old_readable(self, env):
        tmp_path, _matter, _original, sanitized, record = env
        # The person name survives the rules layer — a human proofread redacts
        # it via the overlay (start/end on the sanitized base).
        start = sanitized.index("周测敏")
        end = start + len("周测敏")
        second = apply_overlay(tmp_path, "m-f09", "doc-contract", [
            {"op": "redact_span", "start": start, "end": end,
             "replacement": "PERSON_1"},
        ])
        assert second["revision"] == 2
        assert second["origin"] == "user_overrides"
        assert second["baseRevision"] == 1
        assert second["appliedOps"] == 1
        assert second["overridesDigest"]
        old = read_revision(tmp_path, "m-f09", "doc-contract", 1)
        new = read_revision(tmp_path, "m-f09", "doc-contract", 2)
        assert old["text"] == sanitized
        assert "周测敏" not in new["text"]
        assert "PERSON_1" in new["text"]
        assert old["record"]["originalSha256"] == new["record"]["originalSha256"]
        # Chain readable: list shows both revisions, current is 2.
        listing = list_revisions(tmp_path, "m-f09", "doc-contract")
        assert listing["currentRevision"] == 2
        assert [r["revision"] for r in listing["revisions"]] == [1, 2]

    def test_replace_text_proofread_chain(self, env):
        tmp_path, _matter, _original, _sanitized, _record = env
        second = apply_overlay(tmp_path, "m-f09", "doc-contract", [
            {"op": "replace_text", "find": "委托代理合同",
             "replace": "委托代理合同（修订稿）"},
        ])
        third = apply_overlay(tmp_path, "m-f09", "doc-contract", [
            {"op": "replace_text", "find": "修订稿", "replace": "二审稿"},
        ])
        assert (second["revision"], third["revision"]) == (2, 3)
        assert "二审稿" in read_revision(
            tmp_path, "m-f09", "doc-contract", 3)["text"]

    def test_original_bytes_never_change_across_revisions(self, env):
        tmp_path, _matter, original, _sanitized, record = env
        digest_before = os_._sha256_bytes(original.read_bytes())
        start = 0
        apply_overlay(tmp_path, "m-f09", "doc-contract", [
            {"op": "redact_span", "start": start, "end": start + 2,
             "replacement": "XX"},
        ])
        apply_overlay(tmp_path, "m-f09", "doc-contract", [
            {"op": "replace_text", "find": "XX", "replace": "YY"},
        ])
        assert os_._sha256_bytes(original.read_bytes()) == digest_before
        assert record["originalSha256"] == digest_before


class TestFailClosed:
    def test_overlay_carrying_catchable_pii_refused(self, env):
        tmp_path, _matter, _original, _sanitized, _record = env
        with pytest.raises(OverlayError,
                           match="overlay_introduces_catchable_pii"):
            apply_overlay(tmp_path, "m-f09", "doc-contract", [
                {"op": "replace_text", "find": "委托人",
                 "replace": "委托人13900001111"},
            ])

    def test_span_out_of_bounds_refused(self, env):
        tmp_path, _matter, _original, sanitized, _record = env
        with pytest.raises(OverlayError, match="overlay_span_out_of_bounds"):
            apply_overlay(tmp_path, "m-f09", "doc-contract", [
                {"op": "redact_span", "start": 0,
                 "end": len(sanitized) + 10, "replacement": "X"},
            ])

    def test_missing_target_refused_not_silently_skipped(self, env):
        tmp_path, _matter, _original, _sanitized, _record = env
        with pytest.raises(OverlayError, match="overlay_target_missing"):
            apply_overlay(tmp_path, "m-f09", "doc-contract", [
                {"op": "replace_text", "find": "不存在的文本",
                 "replace": "x"},
            ])

    def test_no_effect_overlay_refused(self, env):
        tmp_path, _matter, _original, sanitized, _record = env
        with pytest.raises(OverlayError, match="overlay_no_effect"):
            apply_overlay(tmp_path, "m-f09", "doc-contract", [
                {"op": "redact_span", "start": 0, "end": 2,
                 "replacement": sanitized[:2]},
            ])

    def test_unknown_op_and_open_fields_refused(self, env):
        tmp_path, _matter, _original, _sanitized, _record = env
        for bad in (
            [{"op": "delete_file", "path": "x"}],
            [{"op": "redact_span", "start": 0, "end": 2,
              "replacement": "X", "extra": 1}],
            [],
            "not-a-list",
        ):
            with pytest.raises(OverlayError):
                apply_overlay(tmp_path, "m-f09", "doc-contract", bad)

    def test_mutated_original_fails_closed(self, env):
        tmp_path, _matter, original, _sanitized, _record = env
        original.write_text(SYN_ORIGINAL + "\n（被外部改动）", encoding="utf-8")
        with pytest.raises(OverlayError, match="overlay_original_mutated"):
            apply_overlay(tmp_path, "m-f09", "doc-contract", [
                {"op": "replace_text", "find": "委托人", "replace": "委托方"},
            ])

    def test_missing_original_fails_closed(self, env):
        tmp_path, _matter, original, _sanitized, _record = env
        original.unlink()
        with pytest.raises(OverlayError, match="overlay_original_missing"):
            apply_overlay(tmp_path, "m-f09", "doc-contract", [
                {"op": "replace_text", "find": "委托人", "replace": "委托方"},
            ])

    def test_unregistered_document_and_revision_fail_closed(self, tmp_path):
        with pytest.raises(OverlayError,
                           match="overlay_document_not_registered"):
            apply_overlay(tmp_path, "m-x", "doc-none", [
                {"op": "replace_text", "find": "a", "replace": "b"}])
        with pytest.raises(OverlayError,
                           match="overlay_document_not_registered"):
            read_revision(tmp_path, "m-x", "doc-none", 1)

    def test_error_strings_never_carry_surfaces(self, env):
        tmp_path, _matter, _original, _sanitized, _record = env
        with pytest.raises(OverlayError) as caught:
            apply_overlay(tmp_path, "m-f09", "doc-contract", [
                {"op": "replace_text", "find": "委托人",
                 "replace": "委托人13700009999"},
            ])
        # Category/count only — the phone surface itself must not be echoed.
        assert "13700009999" not in str(caught.value)
