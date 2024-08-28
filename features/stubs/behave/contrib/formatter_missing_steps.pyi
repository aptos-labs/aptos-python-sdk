from _typeshed import Incomplete
from behave.runner_util import (
    make_undefined_step_snippets as make_undefined_step_snippets,
)

from .steps import StepsUsageFormatter as StepsUsageFormatter

STEP_MODULE_TEMPLATE: str

class MissingStepsFormatter(StepsUsageFormatter):
    name: str
    description: str
    template = STEP_MODULE_TEMPLATE
    scope: str
    def __init__(self, stream_opener, config) -> None: ...
    def init_from_userdata(self, userdata) -> None: ...
    stream: Incomplete
    def close(self) -> None: ...
    def report(self) -> None: ...
