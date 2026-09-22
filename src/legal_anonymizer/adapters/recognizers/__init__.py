"""Recognizer adapters (all offline)."""

from __future__ import annotations

from .cn_rules import (  # noqa: F401
    RULES,
    CnRuleRecognizer,
    StructureFieldRecognizer,
    resolve_overlaps,
)
from .project_dictionary import ProjectDictionaryProvider  # noqa: F401
