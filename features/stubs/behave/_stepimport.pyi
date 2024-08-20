from collections.abc import Generator
from types import ModuleType

from _typeshed import Incomplete

def setup_api_with_step_decorators(module, step_registry) -> None: ...
def setup_api_with_matcher_functions(module, matcher_factory) -> None: ...

class FakeModule(ModuleType):
    ensure_fake: bool
    def __setitem__(self, name, value) -> None: ...

class StepRegistryModule(FakeModule):
    registry: Incomplete
    def __init__(self, step_registry) -> None: ...

class StepMatchersModule(FakeModule):
    matcher_factory: Incomplete
    use_default_step_matcher: Incomplete
    get_matcher: Incomplete
    def __init__(self, matcher_factory) -> None: ...

class BehaveModule(FakeModule):
    use_default_step_matcher: Incomplete
    def __init__(
        self, step_registry, matcher_factory: Incomplete | None = None
    ) -> None: ...

class StepImportModuleContext:
    step_registry: Incomplete
    matcher_factory: Incomplete
    modules: Incomplete
    def __init__(self, step_container) -> None: ...
    def reset_current_matcher(self) -> None: ...

unknown: Incomplete

def use_step_import_modules(step_container) -> Generator[Incomplete, None, None]: ...
