from _typeshed import Incomplete

has_asyncio: bool

def async_run_until_complete(
    astep_func: Incomplete | None = None,
    loop: Incomplete | None = None,
    timeout: Incomplete | None = None,
    async_context: Incomplete | None = None,
    should_close: bool = False,
): ...

run_until_complete = async_run_until_complete

class AsyncContext:
    default_name: str
    loop: Incomplete
    tasks: Incomplete
    name: Incomplete
    should_close: Incomplete
    def __init__(
        self,
        loop: Incomplete | None = None,
        name: Incomplete | None = None,
        should_close: bool = False,
        tasks: Incomplete | None = None,
    ) -> None: ...
    def __del__(self) -> None: ...
    def close(self) -> None: ...

def use_or_create_async_context(
    context, name: Incomplete | None = None, loop: Incomplete | None = None, **kwargs
): ...
