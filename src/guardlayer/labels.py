"""Information-flow labels: where content came from, and how bad it would be if it leaked.

Every piece of content an agent reads carries a label on two independent axes:

| axis              | levels (low → high)                      | meaning                                          |
|-------------------|------------------------------------------|--------------------------------------------------|
| `integrity`       | `trusted` → `untrusted` → `hostile`      | who could have written it; `hostile` = an injection was detected in it |
| `confidentiality` | `public` → `private` → `restricted`      | how bad a leak would be; `restricted` = credentials, secrets, personal data |

Labels combine **most-restrictive-wins** on each axis, so a session that has read one untrusted page and one private record
carries `untrusted` + `private`. Policies then ask whether *this* tool may run in *that* context: may untrusted content
drive it, and may data this confidential reach it? That question has a deterministic answer, whatever the model was told.

The algebra matches information-flow-control designs for agents in the research literature (integrity and confidentiality
labels, most-restrictive-wins), plus `hostile`, which keeps GuardLayer's rule that a *detected* injection holds back
side-effecting actions.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any


class _Ordered(str, Enum):
    """A string enum whose members compare by declaration order (low → high)."""

    @property
    def rank(self) -> int:
        return list(type(self)).index(self)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank >= other.rank


class Integrity(_Ordered):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    HOSTILE = "hostile"


class Confidentiality(_Ordered):
    PUBLIC = "public"
    PRIVATE = "private"
    RESTRICTED = "restricted"


@dataclass(frozen=True)
class Label:
    integrity: Integrity = Integrity.TRUSTED
    confidentiality: Confidentiality = Confidentiality.PUBLIC

    def __post_init__(self) -> None:
        object.__setattr__(self, "integrity", Integrity(self.integrity))
        object.__setattr__(self, "confidentiality", Confidentiality(self.confidentiality))

    def combine(self, *others: Label) -> Label:
        """Most restrictive of each axis across this label and `others`."""
        return combine(self, *others)

    def to_dict(self) -> dict[str, str]:
        return {"integrity": self.integrity.value, "confidentiality": self.confidentiality.value}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Label:
        return cls(Integrity(data.get("integrity", "trusted")), Confidentiality(data.get("confidentiality", "public")))

    def __str__(self) -> str:
        return f"{self.integrity.value}/{self.confidentiality.value}"


BOTTOM = Label()  # trusted + public: developer-controlled, safe to show anywhere


def combine(*labels: Label) -> Label:
    """Most-restrictive-wins on each axis. `combine()` with no labels is trusted + public."""
    items: tuple[Label, ...] = tuple(labels) or (BOTTOM,)
    return Label(max(label.integrity for label in items), max(label.confidentiality for label in items))
