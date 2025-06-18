from typing import Optional

from ..account_address import AccountAddress


class SupraApiError(Exception):
    """Base exception for Supra API errors."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code
        self.message = message

    def __str__(self) -> str:
        if self.status_code:
            return f"SupraApiError ({self.status_code}): {self.message}"
        return f"SupraApiError: {self.message}"


class SupraAccountNotFound(SupraApiError):
    """Exception raised when an account is not found."""

    def __init__(self, account_address: AccountAddress):
        self.account_address = account_address
        super().__init__(f"Account not found: {account_address}", 404)


class SupraResourceNotFound(SupraApiError):
    """Exception raised when a resource is not found."""

    def __init__(self, account_address: AccountAddress, resource_type: str):
        self.account_address = account_address
        self.resource_type = resource_type
        super().__init__(
            f"Resource '{resource_type}' not found for account {account_address}", 404
        )


class SupraModuleNotFound(SupraApiError):
    """Exception raised when a module is not found."""

    def __init__(self, account_address: AccountAddress, module_name: str):
        self.account_address = account_address
        self.module_name = module_name
        super().__init__(
            f"Module '{module_name}' not found for account {account_address}", 404
        )


class SupraCursorDecodeError(SupraApiError):
    """Exception raised when cursor decoding fails."""

    def __init__(self, cursor: str):
        self.cursor = cursor
        super().__init__(f"Failed to decode cursor: {cursor}", 400)


class SupraAcceptTypeNotSupported(SupraApiError):
    """Exception raised when an Accept type is not supported."""

    def __init__(self, accept_type: str, supported_types: list[str]):
        self.accept_type = accept_type
        self.supported_types = supported_types
        super().__init__(
            f"Accept type '{accept_type}' not supported. Supported types: {
                ', '.join(supported_types)
            }",
            415,
        )
