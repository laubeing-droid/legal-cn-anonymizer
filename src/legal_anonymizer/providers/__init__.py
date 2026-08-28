"""Provider registry. Importing this package registers the built-in backends.

Network providers were removed at S0 by construction decision: this tool is
local-only. Detection runs through offline ports (deterministic rules, project
dictionaries, optional local ONNX NER). A cloud model is a *consumer* of
sanitized output, never a detector.
"""

from __future__ import annotations

from .base import (Provider, ProviderError, available, get_provider,  # noqa: F401
                   parse_json_array, register)

# Import side effects register each provider under its name.
from . import null      # noqa: F401,E402  -> 'null'

__all__ = ["Provider", "ProviderError", "available", "get_provider",
           "parse_json_array", "register"]
