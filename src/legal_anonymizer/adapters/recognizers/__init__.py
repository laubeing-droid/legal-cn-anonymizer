"""Recognizer adapters (all offline)."""

from __future__ import annotations

from .cn_rules import CnRuleRecognizer, RULES, StructureFieldRecognizer, resolve_overlaps  # noqa: F401
from .project_dictionary import ProjectDictionaryProvider  # noqa: F401
