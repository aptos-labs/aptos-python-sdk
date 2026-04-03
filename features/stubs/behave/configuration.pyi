from collections.abc import Generator

from _typeshed import Incomplete
from behave._types import Unknown as Unknown
from behave.formatter.base import StreamOpener as StreamOpener
from behave.model import ScenarioOutline as ScenarioOutline
from behave.model_core import FileLocation as FileLocation
from behave.reporter.junit import JUnitReporter as JUnitReporter
from behave.reporter.summary import SummaryReporter as SummaryReporter
from behave.tag_expression import TagExpression as TagExpression
from behave.textutil import select_best_encoding as select_best_encoding
from behave.textutil import to_texts as to_texts
from behave.userdata import UserData as UserData
from behave.userdata import parse_user_define as parse_user_define

ConfigParser: Incomplete

class LogLevel:
    names: Incomplete
    @staticmethod
    def parse(levelname, unknown_level: Incomplete | None = None): ...
    @classmethod
    def parse_type(cls, levelname): ...
    @staticmethod
    def to_string(level): ...

class ConfigError(Exception): ...

options: Incomplete
raw_value_options: Incomplete

def read_configuration(path): ...
def config_filenames() -> Generator[Incomplete, None, None]: ...
def load_configuration(defaults, verbose: bool = False) -> None: ...
def setup_parser(): ...

class Configuration:
    defaults: Incomplete
    cmdline_only_options: Incomplete
    version: Incomplete
    tags_help: Incomplete
    lang_list: Incomplete
    lang_help: Incomplete
    default_tags: Incomplete
    junit: Incomplete
    logging_format: Incomplete
    logging_datefmt: Incomplete
    name: Incomplete
    scope: Incomplete
    steps_catalog: Incomplete
    userdata: Incomplete
    wip: Incomplete
    formatters: Incomplete
    reporters: Incomplete
    name_re: Incomplete
    outputs: Incomplete
    include_re: Incomplete
    exclude_re: Incomplete
    scenario_outline_annotation_schema: Incomplete
    steps_dir: str
    environment_file: str
    userdata_defines: Incomplete
    more_formatters: Incomplete
    paths: Incomplete
    default_format: str
    format: Incomplete
    dry_run: bool
    summary: bool
    show_skipped: bool
    quiet: bool
    tags: Incomplete
    color: bool
    stop: bool
    log_capture: bool
    stdout_capture: bool
    show_source: bool
    show_snippets: bool
    stage: Incomplete
    stderr_capture: bool
    def __init__(
        self,
        command_args: Incomplete | None = None,
        load_config: bool = True,
        verbose: Incomplete | None = None,
        **kwargs,
    ) -> None: ...
    def setup_outputs(self, args_outfiles: Incomplete | None = None) -> None: ...
    def setup_formats(self) -> None: ...
    def collect_unknown_formats(self): ...
    @staticmethod
    def build_name_re(names): ...
    def exclude(self, filename): ...
    def setup_logging(
        self,
        level: Incomplete | None = None,
        configfile: Incomplete | None = None,
        **kwargs,
    ) -> None: ...
    def setup_model(self) -> None: ...
    def setup_stage(self, stage: Incomplete | None = None) -> None: ...
    def setup_userdata(self) -> None: ...
    def update_userdata(self, data) -> None: ...
