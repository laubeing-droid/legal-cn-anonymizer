"""Matter state. On Windows the private envelope is sealed with DPAPI bound to
the current user (private.dpapi); the plaintext seam survives only as a
migration path from S4 matters and on non-Windows dev hosts (marked INSECURE).
Public manifests are plain JSON."""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

from ..security.dpapi_vault import MatterVault, VaultError

SEAM_MARKER = "INSECURE-TEST-SEAM.md"
SEAM_FILE = "private.seam.json"


class MatterStateError(RuntimeError):
    pass


class MatterState:
    """Per-matter state directory layout (S8 hardened):

    <state>/<matter-id>/
      project.public.json        public manifest
      private.dpapi              DPAPI-sealed private envelope (current user)
      cache.dpapi                optional sealed OCR cache
    """

    def __init__(self, state_root: Path, matter_id: str):
        self.state_root = Path(state_root)
        self.matter_id = matter_id
        self.dir = self.state_root / matter_id
        self.public_path = self.dir / "project.public.json"
        self._vault = MatterVault(self.dir, matter_id)

    # -- lifecycle -------------------------------------------------------------

    def exists(self) -> bool:
        return self.public_path.exists() and self._vault.private_path.exists()

    def init(self, profile_id: str) -> None:
        if self.exists():
            raise MatterStateError(f"matter {self.matter_id} already initialized")
        if self.public_path.exists() or self._vault.private_path.exists():
            raise MatterStateError(
                f"matter {self.matter_id} is half-initialized; refusing to recreate (fail closed)"
            )
        from ..security.safe_storage import atomic_write_bytes, safe_root

        safe_root(self.state_root, matter_id=self.matter_id)
        self._write_json(
            self.public_path,
            {
                "schema_version": "1.0",
                "matter_id": self.matter_id,
                "profile_id": profile_id,
                "documents": [],
                "status": "REVIEW_REQUIRED",
            },
        )
        self._vault.create(
            {
                "schema_version": "1.0",
                "matter_id": self.matter_id,
                "matter_secret_b64": secrets.token_bytes(32).hex(),
                "entities": [],
                "identifier_aliases": [],
                "original_filename_map": {},
                "decisions": [],
            }
        )

    @classmethod
    def load(cls, state_root: Path, matter_id: str) -> "MatterState":
        state = cls(state_root, matter_id)
        if not state.exists():
            raise MatterStateError(
                f"matter {matter_id} not initialized (fail closed: no empty mapping will be created)"
            )
        return state

    # -- accessors ---------------------------------------------------------------

    def _write_json(self, path: Path, payload: dict) -> None:
        from ..security.safe_storage import atomic_write_bytes

        atomic_write_bytes(
            path,
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8"),
        )

    def read_public(self) -> dict:
        return json.loads(self.public_path.read_text(encoding="utf-8"))

    def write_public(self, payload: dict) -> None:
        self._write_json(self.public_path, payload)

    def read_private(self) -> dict:
        if self._vault.private_path.exists():
            try:
                return self._vault.unseal_private()
            except VaultError as exc:
                raise MatterStateError(str(exc)) from exc
        if (self.dir / SEAM_FILE).exists():
            # legacy S4 seam: migrate to DPAPI on first touch
            payload = json.loads((self.dir / SEAM_FILE).read_text(encoding="utf-8"))
            self.write_private(payload)
            (self.dir / SEAM_FILE).unlink()
            return payload
        raise MatterStateError("private state missing; refusing to recreate (fail closed)")

    def write_private(self, payload: dict) -> None:
        if not self._vault.private_path.exists() and not (self.dir / SEAM_FILE).exists():
            raise MatterStateError("private state missing; refusing to recreate (fail closed)")
        try:
            self._vault.seal_private(payload)
        except VaultError as exc:
            raise MatterStateError(str(exc)) from exc
        seam = self.dir / SEAM_FILE
        if seam.exists():
            seam.unlink()

    @property
    def matter_secret(self) -> bytes:
        return bytes.fromhex(self.read_private()["matter_secret_b64"])
