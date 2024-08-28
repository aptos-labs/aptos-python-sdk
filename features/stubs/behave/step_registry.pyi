import typing

from _typeshed import Incomplete

__all__ = ["given", "when", "then", "step", "Given", "When", "Then", "Step"]

from typing import Callable, List

class AmbiguousStep(ValueError): ...

class StepRegistry:
    steps: Incomplete
    def __init__(self) -> None: ...
    @staticmethod
    def same_step_definition(step, other_pattern, other_location): ...
    def add_step_definition(self, keyword, step_text, func) -> None: ...
    def find_step_definition(self, step): ...
    def find_match(self, step): ...
    def make_decorator(self, step_type): ...

# Names in __all__ with no definition:
#   Given
#   Step
#   Then
#   When
#   given
#   step
#   then
#   when
def given(any: typing.Any) -> Callable[[typing.Any], List[str]]: ...
def then(any: typing.Any) -> Callable[[typing.Any], List[str]]: ...
def when(any: typing.Any) -> Callable[[typing.Any], List[str]]: ...

registry = StepRegistry()
