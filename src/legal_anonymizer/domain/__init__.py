"""Domain core: matter-scoped entity resolution, typed transforms, utility
snapshots and profiles. No dependency on document formats, OCR, Windows APIs
or the network."""

from __future__ import annotations

from .entities import Entity  # noqa: F401
from .entity_vault import EntityVault  # noqa: F401
from .equivalence import CannotLinkConflict, ConstraintUnionFind  # noqa: F401
from .mentions import Locator, Mention, Span, apply_spans  # noqa: F401
from .profiles import AI_SAFE_V1, PUBLISH_V1, Profile, get_profile  # noqa: F401
from .transforms import TransformExecutor  # noqa: F401
from .utility_snapshot import (  # noqa: F401
    legal_date_multiset,
    money_multiset,
    multiset_difference,
    percent_multiset,
)
