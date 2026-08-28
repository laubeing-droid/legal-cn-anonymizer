"""Constrained union-find for MSSP entity resolution.

Merging rules (frozen by the construction plan):

- must-link (strong): same strong identifier (id card / phone / email / credit
  code), explicit "以下简称" declaration, user confirmation, Harness Party
  confirmation;
- cannot-link: different strong identifiers of the same type, co-occurrence in a
  conflicting procedural context, user split decision, same-name persons with
  different orgs/contacts;
- weak candidates (fuzzy similarity, OCR approximation, same role/address) never
  merge automatically: they raise REVIEW_REQUIRED/entity_resolution_ambiguous.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class CannotLinkConflict(ValueError):
    error_code = "entity_cannot_link_conflict"


@dataclass
class ResolutionResult:
    groups: list[list[int]] = field(default_factory=list)  # mention index groups
    review_pairs: list[tuple[int, int]] = field(default_factory=list)
    review_reason: str = "ENTITY_RESOLUTION_AMBIGUOUS"


class ConstraintUnionFind:
    """Union-find over mention indices with cannot-link constraints."""

    def __init__(self, n: int):
        self._parent = list(range(n))
        self._rank = [0] * n
        self._cannot: set[tuple[int, int]] = set()
        self._must_evidence: dict[int, set[str]] = {}

    def find(self, x: int) -> int:
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]
            x = self._parent[x]
        return x

    def _same_root_pair(self, a: int, b: int) -> tuple[int, int]:
        return min(a, b), max(a, b)

    def has_cannot_link(self, a: int, b: int) -> bool:
        return self._same_root_pair(a, b) in self._cannot

    def cannot_link(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            raise CannotLinkConflict(f"mentions {a},{b} already merged but marked cannot-link")
        self._cannot.add(self._same_root_pair(ra, rb))

    def union(self, a: int, b: int, *, evidence: str = "") -> None:
        """Merge the roots of a and b unless a cannot-link exists anywhere in
        their groups. Evidence records the strongest justification."""
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            if evidence:
                self._must_evidence.setdefault(ra, set()).add(evidence)
            return
        for x in (ra, rb):
            for y in (ra, rb):
                if x != y and self._same_root_pair(x, y) in self._cannot:
                    raise CannotLinkConflict(f"cannot-link constraint blocks union of {a},{b}")
        if self._rank[ra] < self._rank[rb]:
            ra, rb = rb, ra
        self._parent[rb] = ra
        if self._rank[ra] == self._rank[rb]:
            self._rank[ra] += 1
        merged_cannot = {
            pair
            for pair in self._cannot
            if pair[0] == rb or pair[1] == rb
        }
        for pair in merged_cannot:
            self._cannot.discard(pair)
            other = pair[0] if pair[1] == rb else pair[1]
            self._cannot.add(self._same_root_pair(ra, other))
        if evidence:
            self._must_evidence.setdefault(ra, set()).add(evidence)

    def groups(self) -> list[list[int]]:
        by_root: dict[int, list[int]] = {}
        for i in range(len(self._parent)):
            by_root.setdefault(self.find(i), []).append(i)
        return [sorted(g) for _, g in sorted(by_root.items())]

    def evidence_for(self, group: list[int]) -> set[str]:
        out: set[str] = set()
        for member in group:
            out |= self._must_evidence.get(self.find(member), set())
        return out
