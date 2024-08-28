from xml.etree import ElementTree

from _typeshed import Incomplete
from behave.formatter import ansi_escapes as ansi_escapes
from behave.model import Scenario as Scenario
from behave.model import ScenarioOutline as ScenarioOutline
from behave.model import Step as Step
from behave.model_core import Status as Status
from behave.model_describe import ModelDescriptor as ModelDescriptor
from behave.reporter.base import Reporter as Reporter
from behave.textutil import indent as indent
from behave.textutil import make_indentation as make_indentation
from behave.userdata import UserDataNamespace as UserDataNamespace

def CDATA(text: Incomplete | None = None): ...

class ElementTreeWithCDATA(ElementTree.ElementTree): ...

class FeatureReportData:
    feature: Incomplete
    filename: Incomplete
    classname: Incomplete
    testcases: Incomplete
    counts_tests: int
    counts_errors: int
    counts_failed: int
    counts_skipped: int
    def __init__(
        self, feature, filename, classname: Incomplete | None = None
    ) -> None: ...
    def reset(self) -> None: ...

class JUnitReporter(Reporter):
    userdata_scope: str
    show_timings: bool
    show_skipped_always: bool
    show_timestamp: bool
    show_hostname: bool
    show_scenarios: bool
    show_tags: bool
    show_multiline: bool
    def __init__(self, config) -> None: ...
    def setup_with_userdata(self, userdata) -> None: ...
    def make_feature_filename(self, feature): ...
    @property
    def show_skipped(self): ...
    def feature(self, feature) -> None: ...
    @staticmethod
    def select_step_with_status(status, steps): ...
    def describe_step(self, step): ...
    @classmethod
    def describe_tags(cls, tags): ...
    def describe_scenario(self, scenario): ...

def gethostname(): ...
