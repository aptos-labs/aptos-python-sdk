from _typeshed import Incomplete
from behave.formatter.base import StreamOpener as StreamOpener
from behave.model import ScenarioOutline as ScenarioOutline
from behave.model_core import Status as Status
from behave.reporter.base import Reporter as Reporter

optional_steps: Incomplete
status_order: Incomplete

def format_summary(statement_type, summary): ...

class SummaryReporter(Reporter):
    show_failed_scenarios: bool
    output_stream_name: str
    stream: Incomplete
    feature_summary: Incomplete
    scenario_summary: Incomplete
    step_summary: Incomplete
    duration: float
    failed_scenarios: Incomplete
    def __init__(self, config) -> None: ...
    def feature(self, feature) -> None: ...
    def end(self) -> None: ...
    def process_scenario(self, scenario) -> None: ...
    def process_scenario_outline(self, scenario_outline) -> None: ...
