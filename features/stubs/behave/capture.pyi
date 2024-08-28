from collections.abc import Generator

from _typeshed import Incomplete
from behave.log_capture import LoggingCapture as LoggingCapture

def add_text_to(value, more_text, separator: str = "\n"): ...

class Captured:
    empty: str
    linesep: str
    stdout: Incomplete
    stderr: Incomplete
    log_output: Incomplete
    def __init__(
        self,
        stdout: Incomplete | None = None,
        stderr: Incomplete | None = None,
        log_output: Incomplete | None = None,
    ) -> None: ...
    def reset(self) -> None: ...
    def __bool__(self) -> bool: ...
    @property
    def output(self): ...
    def add(self, captured): ...
    def make_report(self): ...
    def __add__(self, other): ...
    def __iadd__(self, other): ...

class CaptureController:
    config: Incomplete
    stdout_capture: Incomplete
    stderr_capture: Incomplete
    log_capture: Incomplete
    old_stdout: Incomplete
    old_stderr: Incomplete
    def __init__(self, config) -> None: ...
    @property
    def captured(self): ...
    def setup_capture(self, context) -> None: ...
    def start_capture(self) -> None: ...
    def stop_capture(self) -> None: ...
    def teardown_capture(self) -> None: ...
    def make_capture_report(self): ...

def capture_output(controller, enabled: bool = True) -> Generator[None, None, None]: ...
