from _typeshed import Incomplete
from behave.textutil import compute_words_maxsize as compute_words_maxsize

class DocumentWriter:
    heading_styles: Incomplete
    default_encoding: str
    default_toctree_title: str
    stream: Incomplete
    filename: Incomplete
    should_close: Incomplete
    def __init__(
        self, stream, filename: Incomplete | None = None, should_close: bool = True
    ) -> None: ...
    @classmethod
    def open(cls, filename, encoding: Incomplete | None = None): ...
    def write(self, *args): ...
    def close(self) -> None: ...
    def write_heading(
        self,
        heading,
        level: int = 0,
        index_id: Incomplete | None = None,
        label: Incomplete | None = None,
    ) -> None: ...
    def write_toctree(
        self, entries, title: Incomplete | None = None, maxdepth: int = 2
    ) -> None: ...
    def write_table(self, table) -> None: ...
