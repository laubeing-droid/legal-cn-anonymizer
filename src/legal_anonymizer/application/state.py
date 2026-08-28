"""Matter private state. S4 uses an explicit INSECURE test seam (plaintext under
the state directory, clearly marked); S8 replaces it with DPAPI-sealed storage
and this module's persistence calls move behind the vault interface. Public
manifests are written as plain JSON here already."""

from __future__ import annotations

import json
import secrets
from pathlib import Path

SEAM_MARKER = "INSECURE-TEST-SEAM.md"


class MatterStateError(RuntimeError):
    pass


class MatterState:
    """Per-matter state directory layout (S4 seam):

    <state>/<matter-id>/
      project.public.json        public manifest
      private.seam.json          INSECURE plaintext private state (S8 -> DPAPI)
      INSECURE-TEST-SEAM.md      marker explaining the seam
    """

    def __init__(self, state_root: Path, matter_id: str):
        self.state_root = Path(state_root)
        self.matter_id = matter_id
        self.dir = self.state_root / matter_id
        self.public_path = self.dir / "project.public.json"
        self.private_path = self.dir / "private.seam.json"

    # -- lifecycle -------------------------------------------------------------

    def exists(self) -> bool:
        return self.public_path.exists()

    def init(self, profile_id: str) -> None:
        if self.exists():
            raise MatterStateError(f"matter {self.matter_id} already initialized")
        self.dir.mkdir(parents=True, exist_ok=True)
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
        self._write_json(
            self.private_path,
            {
                "schema_version": "1.0",
                "matter_id": self.matter_id,
                "matter_secret_b64": secrets.token_bytes(32).hex(),
                "entities": [],
                "identifier_aliases": [],
                "original_filename_map": {},
                "decisions": [],
            },
        )
        (self.dir / SEAM_MARKER).write_text(
            "# INSECURE TEST SEAM\n\n"
            "This matter state is plaintext until S8 installs the DPAPI vault.\n"
            "Do not claim durable secrecy for anything under this directory.\n",
            encoding="utf-8",
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
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def read_public(self) -> dict:
        return json.loads(self.public_path.read_text(encoding="utf-8"))

    def write_public(self, payload: dict) -> None:
        self._write_json(self.public_path, payload)

    def read_private(self) -> dict:
        return json.loads(self.private_path.read_text(encoding="utf-8"))

    def write_private(self, payload: dict) -> None:
        if not self.private_path.exists():
            raise MatterStateError("private state missing; refusing to recreate (fail closed)")
        self._write_json(self.private_path, payload)

    @property
    def matter_secret(self) -> bytes:
        return bytes.fromhex(self.read_private()["matter_secret_b64"])
