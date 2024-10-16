from collections.abc import Generator

from _typeshed import Incomplete

class TagExpression:
    ands: Incomplete
    limits: Incomplete
    def __init__(self, tag_expressions) -> None: ...
    @staticmethod
    def normalize_tag(tag): ...
    @classmethod
    def normalized_tags_from_or(cls, expr) -> Generator[Incomplete, None, None]: ...
    def store_and_extract_limits(self, tags) -> None: ...
    def check(self, tags): ...
    def __len__(self) -> int: ...
