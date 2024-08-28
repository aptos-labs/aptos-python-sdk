import typing

from behave import then, use_step_matcher, when

from aptos_sdk.account_address import AccountAddress
from aptos_sdk.bcs import Deserializer, Serializer

# Use regular expressions
use_step_matcher("re")


@when(r"I serialize as (?P<input_type>[a-zA-Z0-9]+)")
def when_serialize(context: typing.Any, input_type: str):
    ser = Serializer()

    if input_type == "bool":
        ser.bool(context.input)
    elif input_type == "u8":
        ser.u8(context.input)
    elif input_type == "u16":
        ser.u16(context.input)
    elif input_type == "u32":
        ser.u32(context.input)
    elif input_type == "u64":
        ser.u64(context.input)
    elif input_type == "u128":
        ser.u128(context.input)
    elif input_type == "u256":
        ser.u256(context.input)
    elif input_type == "uleb128":
        ser.uleb128(context.input)
    elif input_type == "address":
        ser.struct(context.input)
    elif input_type == "bytes":
        # TODO: This should be more straightforward...
        ser.uleb128(len(context.input))
        ser.fixed_bytes(context.input)
    elif input_type == "string":
        ser.str(context.input)
    else:
        raise Exception("Unrecognized input type")

    context.output = ser.output()


@when(r"I deserialize as (?P<input_type>[a-zA-Z0-9]+)")
def when_deserialize(context: typing.Any, input_type: str):
    des = Deserializer(context.input)

    try:
        if input_type == "bool":
            context.output = des.bool()
        elif input_type == "u8":
            context.output = des.u8()
        elif input_type == "u16":
            context.output = des.u16()
        elif input_type == "u32":
            context.output = des.u32()
        elif input_type == "u64":
            context.output = des.u64()
        elif input_type == "u128":
            context.output = des.u128()
        elif input_type == "u256":
            context.output = des.u256()
        elif input_type == "uleb128":
            context.output = des.uleb128()
        elif input_type == "address":
            context.output = des.struct(AccountAddress)
        elif input_type == "bytes":
            # TODO: This should be more straightforward...
            length = des.uleb128()
            context.output = des.fixed_bytes(length)
        elif input_type == "string":
            context.output = des.str()

    except Exception as e:
        context.output = e

    # Catch all if it fails to be parsed
    if context.output is None:
        raise Exception("Unrecognized input type")


@when(r"I serialize as sequence of (?P<input_type>[a-zA-Z0-9]+)")
def when_serialize_sequence(context: typing.Any, input_type: str):
    ser = Serializer()

    if input_type == "bool":
        seq_ser = Serializer.sequence_serializer(Serializer.bool)
        seq_ser(ser, context.input)
    elif input_type == "u8":
        seq_ser = Serializer.sequence_serializer(Serializer.u8)
        seq_ser(ser, context.input)
    elif input_type == "u16":
        seq_ser = Serializer.sequence_serializer(Serializer.u16)
        seq_ser(ser, context.input)
    elif input_type == "u32":
        seq_ser = Serializer.sequence_serializer(Serializer.u32)
        seq_ser(ser, context.input)
    elif input_type == "u64":
        seq_ser = Serializer.sequence_serializer(Serializer.u64)
        seq_ser(ser, context.input)
    elif input_type == "u128":
        seq_ser = Serializer.sequence_serializer(Serializer.u128)
        seq_ser(ser, context.input)
    elif input_type == "u256":
        seq_ser = Serializer.sequence_serializer(Serializer.u256)
        seq_ser(ser, context.input)
    elif input_type == "uleb128":
        seq_ser = Serializer.sequence_serializer(Serializer.uleb128)
        seq_ser(ser, context.input)
    elif input_type == "address":
        seq_ser = Serializer.sequence_serializer(Serializer.struct)
        seq_ser(ser, context.input)
    elif input_type == "string":
        seq_ser = Serializer.sequence_serializer(Serializer.str)
        seq_ser(ser, context.input)
    else:
        raise Exception("Unrecognized input type")

    context.output = ser.output()


@when(r"I deserialize as sequence of (?P<input_type>[a-zA-Z0-9]+)")
def when_deserialize_sequence(context: typing.Any, input_type: str):
    des = Deserializer(context.input)

    if input_type == "bool":
        context.output = des.sequence(Deserializer.bool)
    elif input_type == "u8":
        context.output = des.sequence(Deserializer.u8)
    elif input_type == "u16":
        context.output = des.sequence(Deserializer.u16)
    elif input_type == "u32":
        context.output = des.sequence(Deserializer.u32)
    elif input_type == "u64":
        context.output = des.sequence(Deserializer.u64)
    elif input_type == "u128":
        context.output = des.sequence(Deserializer.u128)
    elif input_type == "u256":
        context.output = des.sequence(Deserializer.u256)
    elif input_type == "uleb128":
        context.output = des.sequence(Deserializer.uleb128)
    elif input_type == "address":
        context.output = des.sequence(AccountAddress.deserialize)
    elif input_type == "string":
        context.output = des.sequence(Deserializer.str)
    else:
        raise Exception("Unrecognized input type")


@when(r"I serialize as fixed bytes with length (?P<length>[0-9]+)")
def when_serialize_fixed_bytes(context: typing.Any, length: str):
    ser = Serializer()

    # TODO: Do we check the length?
    ser.fixed_bytes(context.input)
    context.output = ser.output()


@when(r"I deserialize as fixed bytes with length (?P<length>[0-9]+)")
def when_deserialize_fixed_bytes(context: typing.Any, length: str):
    try:
        des = Deserializer(context.input)
        context.output = des.fixed_bytes(int(length))
    except Exception as e:
        context.output = e


@then(r"the deserialization should fail")
def then_fail_deserialization(context: typing.Any):
    assert isinstance(context.output, Exception)
