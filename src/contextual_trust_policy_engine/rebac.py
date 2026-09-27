"""Zanzibar-style relationship checks with memoisation and cycle safety."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Literal

RewriteKind = Literal[
    "this", "computed_userset", "tuple_to_userset", "union", "intersection", "exclusion"
]


@dataclass(frozen=True, slots=True)
class Rewrite:
    kind: RewriteKind
    relation: str | None = None
    tupleset: str | None = None
    computed: str | None = None
    children: tuple[Rewrite, ...] = ()


@dataclass(frozen=True, slots=True)
class NamespaceConfig:
    relations: Mapping[str, Rewrite]

    @classmethod
    def simple(cls, relations: Iterable[str]) -> NamespaceConfig:
        return cls({rel: Rewrite("this") for rel in relations})


def parse_tuple(value: str) -> tuple[str, str, str]:
    left, subject = value.split("@", 1)
    obj, relation = left.split("#", 1)
    return obj, relation, subject


class TupleStore:
    def __init__(self, tuples: Iterable[str] = ()) -> None:
        self._tuples: set[tuple[str, str, str]] = set()
        self._by_obj_rel: dict[tuple[str, str], set[str]] = defaultdict(set)
        for item in tuples:
            self.add(item)

    def add(self, value: str) -> None:
        obj, rel, subj = parse_tuple(value)
        self._tuples.add((obj, rel, subj))
        self._by_obj_rel[(obj, rel)].add(subj)

    def subjects(self, obj: str, relation: str) -> set[str]:
        return set(self._by_obj_rel.get((obj, relation), set()))

    def __len__(self) -> int:
        return len(self._tuples)


class RebacEngine:
    def __init__(
        self,
        store: TupleStore | None = None,
        namespaces: Mapping[str, NamespaceConfig] | None = None,
        *,
        max_depth: int = 20,
    ) -> None:
        self.store = store or TupleStore()
        self.namespaces = dict(
            namespaces
            or {"default": NamespaceConfig.simple(["read", "write", "send", "egress", "member"])}
        )
        self.max_depth = max_depth
        self._memo: dict[tuple[str, str, str], bool] = {}

    def check(self, subject: str, obj: str, relation: str) -> bool:
        key = (subject, obj, relation)
        if key not in self._memo:
            self._memo[key] = self._check(subject, obj, relation, self.max_depth, set())
        return self._memo[key]

    def _check(
        self, subject: str, obj: str, relation: str, depth: int, seen: set[tuple[str, str, str]]
    ) -> bool:
        if depth < 0 or (subject, obj, relation) in seen:
            return False
        seen.add((subject, obj, relation))
        return self._eval_rewrite(subject, obj, self._rewrite(obj, relation), depth, seen)

    def _rewrite(self, obj: str, relation: str) -> Rewrite:
        namespace = obj.split(":", 1)[0] if ":" in obj else "default"
        rewrite = self.namespaces.get(namespace, self.namespaces["default"]).relations.get(
            relation, Rewrite("this")
        )
        if rewrite.kind == "this" and rewrite.relation is None:
            return Rewrite("this", relation=relation)
        return rewrite

    def _eval_rewrite(
        self, subject: str, obj: str, rewrite: Rewrite, depth: int, seen: set[tuple[str, str, str]]
    ) -> bool:
        if rewrite.kind == "this":
            return self._direct(subject, obj, rewrite.relation or "")
        if rewrite.kind == "computed_userset":
            return self._check(subject, obj, rewrite.relation or "", depth - 1, seen)
        if rewrite.kind == "tuple_to_userset":
            return any(
                self._check(subject, mid, rewrite.computed or "", depth - 1, seen)
                for mid in self.store.subjects(obj, rewrite.tupleset or "")
            )
        if rewrite.kind == "union":
            return any(
                self._eval_rewrite(subject, obj, c, depth - 1, seen) for c in rewrite.children
            )
        if rewrite.kind == "intersection":
            return all(
                self._eval_rewrite(subject, obj, c, depth - 1, seen) for c in rewrite.children
            )
        if rewrite.kind == "exclusion":
            first, *rest = rewrite.children
            return self._eval_rewrite(subject, obj, first, depth - 1, seen) and not any(
                self._eval_rewrite(subject, obj, c, depth - 1, seen) for c in rest
            )
        return False

    def _direct(self, subject: str, obj: str, relation: str) -> bool:
        subjects = self.store.subjects(obj, relation)
        if subject in subjects:
            return True
        queue = deque(subjects)
        seen_usersets: set[str] = set()
        while queue:
            userset = queue.popleft()
            if userset in seen_usersets:
                continue
            seen_usersets.add(userset)
            if "#" not in userset:
                continue
            u_obj, u_rel = userset.split("#", 1)
            nested = self.store.subjects(u_obj, u_rel)
            if subject in nested:
                return True
            queue.extend(nested)
        return False

    def expand(self, obj: str, relation: str) -> set[str]:
        result: set[str] = set()
        queue = deque(self.store.subjects(obj, relation))
        while queue:
            value = queue.popleft()
            if value in result:
                continue
            result.add(value)
            if "#" in value:
                u_obj, u_rel = value.split("#", 1)
                queue.extend(self.store.subjects(u_obj, u_rel))
        return result

    def bulk_load(self, tuples: Iterable[str]) -> None:
        for item in tuples:
            self.store.add(item)
        self._memo.clear()
