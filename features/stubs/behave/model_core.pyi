from enum import Enum

from _typeshed import Incomplete
from behave.capture import Captured as Captured

PLATFORM_WIN: Incomplete

def posixpath_normalize(path): ...

class Status(Enum):
    untested: int
    skipped: int
    passed: int
    failed: int
    undefined: int
    executing: int
    IGNORE_LINT = 99  # Used to ignore linting error
    def __eq__(self, other): ...
    @classmethod
    def from_name(cls, name): ...

class Argument:
    start: Incomplete
    end: Incomplete
    original: Incomplete
    value: Incomplete
    name: Incomplete
    def __init__(
        self, start, end, original, value, name: Incomplete | None = None
    ) -> None: ...

class FileLocation:
    __pychecker__: str
    filename: Incomplete
    line: Incomplete
    def __init__(self, filename, line: Incomplete | None = None) -> None: ...
    def get(self): ...
    def abspath(self): ...
    def basename(self): ...
    def dirname(self): ...
    def relpath(self, start=...): ...
    def exists(self): ...
    def __eq__(self, other): ...
    def __ne__(self, other): ...
    def __lt__(self, other): ...
    def __le__(self, other): ...
    def __gt__(self, other): ...
    def __ge__(self, other): ...
    @classmethod
    def for_function(cls, func, curdir: Incomplete | None = None): ...

class BasicStatement:
    location: Incomplete
    keyword: Incomplete
    name: Incomplete
    captured: Incomplete
    exception: Incomplete
    exc_traceback: Incomplete
    error_message: Incomplete
    def __init__(self, filename, line, keyword, name) -> None: ...
    @property
    def filename(self): ...
    @property
    def line(self): ...
    def reset(self) -> None: ...
    def store_exception_context(self, exception) -> None: ...
    def __hash__(self): ...
    def __eq__(self, other): ...
    def __lt__(self, other): ...
    def __ne__(self, other): ...
    def __le__(self, other): ...
    def __gt__(self, other): ...
    def __ge__(self, other): ...

class TagStatement(BasicStatement):
    tags: Incomplete
    def __init__(self, filename, line, keyword, name, tags) -> None: ...
    def should_run_with_tags(self, tag_expression): ...

class TagAndStatusStatement(BasicStatement):
    final_status: Incomplete
    tags: Incomplete
    should_skip: bool
    skip_reason: Incomplete
    def __init__(self, filename, line, keyword, name, tags) -> None: ...
    def should_run_with_tags(self, tag_expression): ...
    @property
    def status(self): ...
    def set_status(self, value) -> None: ...
    def clear_status(self) -> None: ...
    def reset(self) -> None: ...
    def compute_status(self) -> None: ...

class Replayable:
    type: Incomplete
    def replay(self, formatter) -> None: ...

def unwrap_function(func, max_depth: int = 10): ...
