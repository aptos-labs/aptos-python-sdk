from _typeshed import Incomplete
from behave import model as model
from behave.model_core import Status as Status

def parse(json_filename, encoding: str = "UTF-8"): ...

class JsonParser:
    current_scenario_outline: Incomplete
    def __init__(self) -> None: ...
    def parse_features(self, json_data): ...
    def parse_feature(self, json_feature): ...
    def add_feature_element(self, feature, json_element) -> None: ...
    def parse_background(self, json_element): ...
    def parse_scenario(self, json_element): ...
    def parse_scenario_outline(self, json_element): ...
    def parse_steps(self, json_steps): ...
    def parse_step(self, json_element): ...
    @staticmethod
    def add_step_result(step, json_result) -> None: ...
    @staticmethod
    def parse_table(json_table): ...
    def parse_examples(self, json_element): ...