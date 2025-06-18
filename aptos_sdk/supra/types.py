from dataclasses import dataclass
from typing import Any, Dict, Optional

MAX_NUM_OF_TRANSACTIONS_TO_RETURN: int = 100
DEFAULT_SIZE_OF_PAGE: int = 20


@dataclass
class SupraAccountData:
    """Account Data from Supra v3 api"""

    auth_key: str
    sequece_number: int

    def from_dict(cls, data: Dict[str, Any]) -> "SupraAccountData":
        return cls(
            auth_key=data["auth_key"], sequece_number=int(data["sequece_number"])
        )

    def to_dict(self) -> Dict[str, Any]:
        return {"auth_key": self.auth_key, "sequece_number": self.sequece_number}


# @dataclass
# class SupraTransaction:
#     """Transaction data for Supra v3 api"""


@dataclass
class AccountAutomatedTxPagination:
    # Maximum number of items to return. Default is 20.
    count: Optional[int] = None

    # Starting block height (inclusive). Optional.
    # The block height at which to start lookup for transactions.
    # If provided, returns `:count` of transactions starting from it in the specified order.
    # For order see `:ascending` flag.
    # Note: If a `:cursor` is specified then this field will be ignored.
    block_height: Optional[int] = None

    # The cursor (exclusive) to start the query from. Optional.
    # If provided, returns `:count` of transactions starting from this cursor in the specified order.
    # For order see `:ascending` flag.
    # If not specified, the lookup will be done based on the `:block_height` parameter value.
    # Note: If both `:cursor` and `:block_height` are specified then `:cursor` has precedence.
    cursor: Optional[str] = None

    # Flag indicating order of lookup
    # Defaults to `false`; i.e. transactions are returned in descending order of their execution.
    # If `true`, transactions are returned in ascending order of their execution.
    ascending: bool = False

    def to_params(self) -> Dict[str, Any]:
        params = {}
        if self.count is not None:
            params["count"] = self.count
        if self.block_height is not None:
            params["block_height"] = self.block_height
        if self.cursor is not None:
            params["cursor"] = self.cursor
        params["ascending"] = str(self.ascending).lower()
        return params


@dataclass
class AccountTxPaginationWithOrder:
    """
    Pagination parameters for account transactions.

    Attributes:
        count: Maximum number of items to return. Default is 20.
        start: Starting sequence number. If provided, return :count of transactions
               starting from this sequence number (inclusive) in the specified order.
        ascending: Flag indicating order of lookup. Defaults to false; i.e. the
                  transactions are returned in descending order by sequence number.
    """

    count: Optional[int] = None
    start: Optional[int] = None
    ascending: bool = False

    def to_params(self) -> Dict[str, Any]:
        params = {}
        if self.count is not None:
            params["count"] = self.count
        if self.start is not None:
            params["start"] = self.start
        params["ascending"] = str(self.ascending).lower()
        return params
