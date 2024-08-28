class Unknown: ...

class ExceptionUtil:
    @staticmethod
    def get_traceback(exception): ...
    @staticmethod
    def set_traceback(exception, exc_traceback=...) -> None: ...
    @classmethod
    def has_traceback(cls, exception): ...
    @classmethod
    def describe(cls, exception, use_traceback: bool = False, prefix: str = ""): ...

class ChainedExceptionUtil(ExceptionUtil):
    @staticmethod
    def get_cause(exception): ...
    @staticmethod
    def set_cause(exception, exc_cause) -> None: ...
    @classmethod
    def describe(
        cls,
        exception,
        use_traceback: bool = False,
        prefix: str = "",
        style: str = "reversed",
    ): ...
