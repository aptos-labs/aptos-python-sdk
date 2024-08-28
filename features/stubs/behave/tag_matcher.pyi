from collections.abc import Generator

from _typeshed import Incomplete

class TagMatcher:
    def should_run_with(self, tags): ...
    def should_exclude_with(self, tags) -> None: ...

class ActiveTagMatcher(TagMatcher):
    value_separator: str
    tag_prefixes: Incomplete
    tag_schema: str
    ignore_unknown_categories: bool
    use_exclude_reason: bool
    value_provider: Incomplete
    tag_pattern: Incomplete
    exclude_reason: Incomplete
    def __init__(
        self,
        value_provider,
        tag_prefixes: Incomplete | None = None,
        value_separator: Incomplete | None = None,
        ignore_unknown_categories: Incomplete | None = None,
    ) -> None: ...
    @classmethod
    def make_tag_pattern(
        cls, tag_prefixes, value_separator: Incomplete | None = None
    ): ...
    @classmethod
    def make_category_tag(
        cls,
        category,
        value: Incomplete | None = None,
        tag_prefix: Incomplete | None = None,
        value_sep: Incomplete | None = None,
    ): ...
    def is_tag_negated(self, tag): ...
    def is_tag_group_enabled(self, group_category, group_tag_pairs): ...
    def should_exclude_with(self, tags): ...
    def select_active_tags(self, tags) -> Generator[Incomplete, None, None]: ...
    def group_active_tags_by_category(
        self, tags
    ) -> Generator[Incomplete, None, None]: ...

class PredicateTagMatcher(TagMatcher):
    predicate: Incomplete
    def __init__(self, exclude_function) -> None: ...
    def should_exclude_with(self, tags): ...

class CompositeTagMatcher(TagMatcher):
    tag_matchers: Incomplete
    def __init__(self, tag_matchers: Incomplete | None = None) -> None: ...
    def should_exclude_with(self, tags): ...

def setup_active_tag_values(active_tag_values, data) -> None: ...

class OnlyWithCategoryTagMatcher(TagMatcher):
    tag_prefix: str
    value_separator: str
    active_tag: Incomplete
    category_tag_prefix: Incomplete
    def __init__(
        self,
        category,
        value,
        tag_prefix: Incomplete | None = None,
        value_sep: Incomplete | None = None,
    ) -> None: ...
    def should_exclude_with(self, tags): ...
    def select_category_tags(self, tags): ...
    @classmethod
    def make_category_tag(
        cls,
        category,
        value: Incomplete | None = None,
        tag_prefix: Incomplete | None = None,
        value_sep: Incomplete | None = None,
    ): ...

class OnlyWithAnyCategoryTagMatcher(TagMatcher):
    value_provider: Incomplete
    tag_prefix: Incomplete
    value_separator: Incomplete
    def __init__(
        self,
        value_provider,
        tag_prefix: Incomplete | None = None,
        value_sep: Incomplete | None = None,
    ) -> None: ...
    def should_exclude_with(self, tags): ...
    def select_category_tags(self, tags): ...
    def parse_category_tag(self, tag): ...
