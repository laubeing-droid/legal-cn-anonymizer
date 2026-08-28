"""Security adapters: DPAPI vault, receipt signing identity, network guard."""

from __future__ import annotations

from .dpapi import VaultUnavailableError, protect, unprotect  # noqa: F401
from .receipt_identity import ReceiptIdentity, ReceiptIdentityError  # noqa: F401
