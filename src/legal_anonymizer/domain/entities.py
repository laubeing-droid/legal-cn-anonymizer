"""Case-level typed entity."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Entity:
    entity_id: str  # ent:<type-slug>:<0001>
    entity_type: str
    canonical_surface: str = ""  # RAW - private
    aliases: tuple[str, ...] = ()  # RAW - private
    display_alias: str = ""
    roles: tuple[str, ...] = field(default_factory=tuple)
    transform: str = "PSEUDONYMIZE"

    def with_role(self, role: str) -> "Entity":
        if role and role not in self.roles:
            self.roles = self.roles + (role,)
        return self
