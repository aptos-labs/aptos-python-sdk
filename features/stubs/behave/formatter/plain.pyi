from _typeshed import Incomplete
from behave.formatter.base import Formatter as Formatter
from behave.model_describe import ModelPrinter as ModelPrinter
from behave.textutil import make_indentation as make_indentation

class PlainFormatter(Formatter):
    name: str
    description: str
    SHOW_MULTI_LINE: bool
    SHOW_TAGS: bool
    SHOW_ALIGNED_KEYWORDS: bool
    DEFAULT_INDENT_SIZE: int
    RAISE_OUTPUT_ERRORS: bool
    steps: Incomplete
    show_timings: Incomplete
    show_multiline: Incomplete
    show_aligned_keywords: Incomplete
    show_tags: Incomplete
    indent_size: Incomplete
    stream: Incomplete
    printer: Incomplete
    def __init__(self, stream_opener, config, **kwargs) -> None: ...
    @property
    def multiline_indentation(self): ...
    def reset_steps(self) -> None: ...
    def write_tags(self, tags, indent: Incomplete | None = None) -> None: ...
    def feature(self, feature) -> None: ...
    def background(self, background) -> None: ...
    def scenario(self, scenario) -> None: ...
    def step(self, step) -> None: ...
    def result(self, step) -> None: ...
    def eof(self) -> None: ...
    def doc_string(self, doc_string) -> None: ...
    def table(self, table) -> None: ...

class Plain0Formatter(PlainFormatter):
    name: str
    description: str
    SHOW_MULTI_LINE: bool
    SHOW_TAGS: bool
    SHOW_ALIGNED_KEYWORDS: bool
