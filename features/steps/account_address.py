from behave import *

from aptos_sdk.account_address import AccountAddress
from aptos_sdk.bcs import Serializer

# Use regular expressions
use_step_matcher("re")


@when("I parse the account address")
def when_parse_account_address(context):
    try:
        context.output = AccountAddress.from_str_relaxed(context.input)
    except Exception as e:
        context.output = e


@when("I convert the address to a string")
def when_account_address_to_string(context):
    context.output = str(context.input)


@when("I convert the address to a string long")
def when_account_address_to_string_long(context):
    # TODO make more straightforward, needed for indexer
    ser = Serializer()
    ser.struct(context.input)
    bytes = ser.output()
    context.output = "0x" + bytes.hex()


@then("I should fail to parse the account address")
def then_fail_account_address(context):
    assert isinstance(context.output, Exception)
