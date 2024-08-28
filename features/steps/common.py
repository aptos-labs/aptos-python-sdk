import typing

from behave import given, then, use_step_matcher

from aptos_sdk.account_address import AccountAddress

# Use regular expressions
use_step_matcher("re")


@given(r"(?P<input_type>[a-zA-Z0-9]+) (?P<input_value>\S+)")
def given_input(context: typing.Any, input_type: str, input_value: str):
    if input_type == "bool":
        context.input = parse_bool(input_value)
    elif (
        input_type == "u8"
        or input_type == "u16"
        or input_type == "u32"
        or input_type == "u64"
        or input_type == "u128"
        or input_type == "u256"
    ):
        context.input = int(input_value)
    elif input_type == "address":
        context.input = AccountAddress.from_str_relaxed(input_value)
    elif input_type == "bytes":
        context.input = parse_hex(input_value)
    elif input_type == "string":
        context.input = parse_string(input_value)
    else:
        raise Exception("Unrecognized input type")


@given(r"sequence of (?P<input_type>[a-zA-Z0-9]+) \[(?P<input_value>.*)]")
def given_sequence_input(context: typing.Any, input_type: str, input_value: str):
    context.input = parse_sequence(input_type, input_value)


@then(r"the result should be (?P<expected_type>[a-zA-Z0-9]+) (?P<expected_value>\S+)")
def then_result(context: typing.Any, expected_type: str, expected_value: str):
    expected_val: bool | str | AccountAddress | bytes | int = expected_value
    if expected_type == "bool":
        expected_val = parse_bool(expected_value)
    elif expected_type == "address":
        expected_val = AccountAddress.from_str_relaxed(expected_value)
    elif expected_type == "bytes":
        expected_val = parse_hex(expected_value)
    elif expected_type == "string":
        expected_val = parse_string(expected_value)
    elif (
        expected_type == "u8"
        or expected_type == "u16"
        or expected_type == "u32"
        or expected_type == "u64"
        or expected_type == "u128"
        or expected_type == "u256"
        or expected_type == "uleb128"
    ):
        expected_val = int(expected_value)
    assert context.output == expected_val, (
        "Expected " + str(expected_value) + " but got " + str(context.output)
    )


@then(
    r"the result should be sequence of (?P<expected_type>[a-zA-Z0-9]+) \[(?P<expected_value>\S*)]"
)
def then_result_sequence(context: typing.Any, expected_type: str, expected_value: str):
    expected_val = parse_sequence(expected_type, expected_value)
    assert context.output == expected_val, (
        "Expected " + str(expected_val) + " but got " + str(context.output)
    )


def parse_sequence(input_type: str, input_value: str) -> typing.List[typing.Any]:
    vals: typing.List[typing.Any] = []

    # Skip early if there are no values
    if len(input_value) == 0:
        return vals

    for val in input_value.split(","):
        if input_type == "bool":
            vals.append(parse_bool(val))
        elif (
            input_type == "u8"
            or input_type == "u16"
            or input_type == "u32"
            or input_type == "u64"
            or input_type == "u128"
            or input_type == "u256"
            or input_type == "uleb128"
        ):
            vals.append(int(val))
        elif input_type == "address":
            vals.append(AccountAddress.from_str_relaxed(val))
        elif input_type == "bytes":
            vals.append(parse_hex(val))
        elif input_type == "string":
            vals.append(parse_string(val))
        else:
            raise Exception("Unrecognized input type")

    return vals


def parse_hex(input_value: str):
    return bytes.fromhex(input_value.removeprefix("0x"))


def parse_bool(input_value: str):
    return input_value == "true"


def parse_string(input_value: str):
    return input_value.removeprefix('"').removesuffix('"')
