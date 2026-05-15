"""Transaction payloads — EntryFunction, Script, and related types."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..bcs import Deserializer, Serializer
from ..errors import BcsDeserializationError, BcsSerializationError
from ..types.account_address import AccountAddress
from ..types.type_tag import TypeTag


class ModuleId:
    """A Move module identifier: address::name."""

    __slots__ = ("address", "name")

    def __init__(self, address: AccountAddress, name: str) -> None:
        self.address = address
        self.name = name

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ModuleId):
            return NotImplemented
        return self.address == other.address and self.name == other.name

    def __str__(self) -> str:
        return f"{self.address}::{self.name}"

    @staticmethod
    def from_str(module_id: str) -> ModuleId:
        parts = module_id.split("::")
        if len(parts) != 2:
            raise ValueError(
                f"Invalid module ID '{module_id}': expected format 'address::module_name'"
            )
        return ModuleId(AccountAddress.from_str(parts[0]), parts[1])

    @staticmethod
    def deserialize(deserializer: Deserializer) -> ModuleId:
        addr = AccountAddress.deserialize(deserializer)
        name = deserializer.str()
        return ModuleId(addr, name)

    def serialize(self, serializer: Serializer) -> None:
        self.address.serialize(serializer)
        serializer.str(self.name)


class TransactionArgument:
    """A typed transaction argument with a custom encoder."""

    __slots__ = ("value", "encoder")

    def __init__(self, value: Any, encoder: Callable[[Serializer, Any], None]) -> None:
        self.value = value
        self.encoder = encoder

    def encode(self) -> bytes:
        ser = Serializer()
        self.encoder(ser, self.value)
        return ser.output()


class EntryFunction:
    """An entry function call payload."""

    __slots__ = ("module", "function", "ty_args", "args")

    def __init__(
        self,
        module: ModuleId,
        function: str,
        ty_args: list[TypeTag],
        args: list[bytes],
    ) -> None:
        self.module = module
        self.function = function
        self.ty_args = ty_args
        self.args = args

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EntryFunction):
            return NotImplemented
        return (
            self.module == other.module
            and self.function == other.function
            and self.ty_args == other.ty_args
            and self.args == other.args
        )

    def __str__(self) -> str:
        return f"{self.module}::{self.function}::<{self.ty_args}>({self.args})"

    @staticmethod
    def natural(
        module: str,
        function: str,
        ty_args: list[TypeTag],
        args: list[TransactionArgument],
    ) -> EntryFunction:
        module_id = ModuleId.from_str(module)
        byte_args = [arg.encode() for arg in args]
        return EntryFunction(module_id, function, ty_args, byte_args)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> EntryFunction:
        module = ModuleId.deserialize(deserializer)
        function = deserializer.str()
        ty_args = deserializer.sequence(TypeTag.deserialize)
        args = deserializer.sequence(Deserializer.to_bytes)
        return EntryFunction(module, function, ty_args, args)

    def serialize(self, serializer: Serializer) -> None:
        self.module.serialize(serializer)
        serializer.str(self.function)
        serializer.sequence(self.ty_args, Serializer.struct)
        serializer.sequence(self.args, Serializer.to_bytes)


class Script:
    """A Move script payload with bytecode, type args, and script args."""

    __slots__ = ("code", "ty_args", "args")

    def __init__(self, code: bytes, ty_args: list[TypeTag], args: list[ScriptArgument]) -> None:
        self.code = code
        self.ty_args = ty_args
        self.args = args

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Script):
            return NotImplemented
        return self.code == other.code and self.ty_args == other.ty_args and self.args == other.args

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Script:
        code = deserializer.to_bytes()
        ty_args = deserializer.sequence(TypeTag.deserialize)
        args = deserializer.sequence(ScriptArgument.deserialize)
        return Script(code, ty_args, args)

    def serialize(self, serializer: Serializer) -> None:
        serializer.to_bytes(self.code)
        serializer.sequence(self.ty_args, Serializer.struct)
        serializer.sequence(self.args, Serializer.struct)


class ScriptArgument:
    """A typed script argument with variant tag."""

    U8 = 0
    U64 = 1
    U128 = 2
    ADDRESS = 3
    U8_VECTOR = 4
    BOOL = 5
    U16 = 6
    U32 = 7
    U256 = 8

    __slots__ = ("variant", "value")

    def __init__(self, variant: int, value: Any) -> None:
        self.variant = variant
        self.value = value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ScriptArgument):
            return NotImplemented
        return self.variant == other.variant and self.value == other.value

    @staticmethod
    def deserialize(deserializer: Deserializer) -> ScriptArgument:
        variant = deserializer.u8()
        value: Any
        match variant:
            case ScriptArgument.U8:
                value = deserializer.u8()
            case ScriptArgument.U16:
                value = deserializer.u16()
            case ScriptArgument.U32:
                value = deserializer.u32()
            case ScriptArgument.U64:
                value = deserializer.u64()
            case ScriptArgument.U128:
                value = deserializer.u128()
            case ScriptArgument.U256:
                value = deserializer.u256()
            case ScriptArgument.ADDRESS:
                value = AccountAddress.deserialize(deserializer)
            case ScriptArgument.U8_VECTOR:
                value = deserializer.to_bytes()
            case ScriptArgument.BOOL:
                value = deserializer.bool()
            case _:
                raise BcsDeserializationError(f"Invalid ScriptArgument variant: {variant}")
        return ScriptArgument(variant, value)

    def serialize(self, serializer: Serializer) -> None:
        serializer.u8(self.variant)
        match self.variant:
            case ScriptArgument.U8:
                serializer.u8(self.value)
            case ScriptArgument.U16:
                serializer.u16(self.value)
            case ScriptArgument.U32:
                serializer.u32(self.value)
            case ScriptArgument.U64:
                serializer.u64(self.value)
            case ScriptArgument.U128:
                serializer.u128(self.value)
            case ScriptArgument.U256:
                serializer.u256(self.value)
            case ScriptArgument.ADDRESS:
                serializer.struct(self.value)
            case ScriptArgument.U8_VECTOR:
                serializer.to_bytes(self.value)
            case ScriptArgument.BOOL:
                serializer.bool(self.value)
            case _:
                raise BcsSerializationError(f"Invalid ScriptArgument variant: {self.variant}")


class TransactionExecutable:
    """Wraps an EntryFunction or Script with a variant tag for orderless transactions."""

    SCRIPT = 0
    ENTRY_FUNCTION = 1
    EMPTY = 2

    __slots__ = ("variant", "value")

    def __init__(self, payload: Script | EntryFunction) -> None:
        if isinstance(payload, Script):
            self.variant = TransactionExecutable.SCRIPT
        elif isinstance(payload, EntryFunction):
            self.variant = TransactionExecutable.ENTRY_FUNCTION
        else:
            raise TypeError(f"Invalid executable type: {type(payload).__name__}")
        self.value = payload

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TransactionExecutable):
            return NotImplemented
        return self.variant == other.variant and self.value == other.value

    @staticmethod
    def deserialize(deserializer: Deserializer) -> TransactionExecutable:
        variant = deserializer.uleb128()
        match variant:
            case TransactionExecutable.SCRIPT:
                return TransactionExecutable(Script.deserialize(deserializer))
            case TransactionExecutable.ENTRY_FUNCTION:
                return TransactionExecutable(EntryFunction.deserialize(deserializer))
            case _:
                raise BcsDeserializationError(f"Invalid TransactionExecutable variant: {variant}")

    def serialize(self, serializer: Serializer) -> None:
        serializer.uleb128(self.variant)
        self.value.serialize(serializer)


class TransactionExtraConfig:
    """Holds optional multisig_address and replay_protection_nonce (V1 only)."""

    __slots__ = ("multisig_address", "replay_protection_nonce")

    def __init__(
        self,
        *,
        multisig_address: AccountAddress | None = None,
        replay_protection_nonce: int | None = None,
    ) -> None:
        self.multisig_address = multisig_address
        self.replay_protection_nonce = replay_protection_nonce

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TransactionExtraConfig):
            return NotImplemented
        return (
            self.multisig_address == other.multisig_address
            and self.replay_protection_nonce == other.replay_protection_nonce
        )

    @staticmethod
    def deserialize(deserializer: Deserializer) -> TransactionExtraConfig:
        variant = deserializer.uleb128()
        if variant != 0:
            raise BcsDeserializationError(f"Invalid TransactionExtraConfig variant: {variant}")
        multisig = deserializer.option(AccountAddress.deserialize)
        nonce = deserializer.option(Deserializer.u64)
        return TransactionExtraConfig(multisig_address=multisig, replay_protection_nonce=nonce)

    def serialize(self, serializer: Serializer) -> None:
        serializer.uleb128(0)  # V1
        serializer.option(self.multisig_address, Serializer.struct)
        serializer.option(self.replay_protection_nonce, Serializer.u64)


class TransactionInnerPayload:
    """Combines executable + extra_config for orderless transactions (V1 only)."""

    __slots__ = ("executable", "extra_config")

    def __init__(
        self,
        executable: TransactionExecutable,
        extra_config: TransactionExtraConfig,
    ) -> None:
        self.executable = executable
        self.extra_config = extra_config

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TransactionInnerPayload):
            return NotImplemented
        return self.executable == other.executable and self.extra_config == other.extra_config

    @staticmethod
    def deserialize(deserializer: Deserializer) -> TransactionInnerPayload:
        variant = deserializer.uleb128()
        if variant != 0:
            raise BcsDeserializationError(f"Invalid TransactionInnerPayload variant: {variant}")
        executable = TransactionExecutable.deserialize(deserializer)
        extra_config = TransactionExtraConfig.deserialize(deserializer)
        return TransactionInnerPayload(executable, extra_config)

    def serialize(self, serializer: Serializer) -> None:
        serializer.uleb128(0)  # V1
        self.executable.serialize(serializer)
        self.extra_config.serialize(serializer)


class TransactionPayload:
    """Wrapper around payload variants (Script, EntryFunction, or TransactionInnerPayload)."""

    SCRIPT = 0
    ENTRY_FUNCTION = 2
    PAYLOAD = 4

    __slots__ = ("variant", "value")

    def __init__(self, payload: Script | EntryFunction | TransactionInnerPayload) -> None:
        if isinstance(payload, Script):
            self.variant = TransactionPayload.SCRIPT
        elif isinstance(payload, EntryFunction):
            self.variant = TransactionPayload.ENTRY_FUNCTION
        elif isinstance(payload, TransactionInnerPayload):
            self.variant = TransactionPayload.PAYLOAD
        else:
            raise TypeError(f"Invalid payload type: {type(payload).__name__}")
        self.value = payload

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TransactionPayload):
            return NotImplemented
        return self.variant == other.variant and self.value == other.value

    def __str__(self) -> str:
        return str(self.value)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> TransactionPayload:
        variant = deserializer.uleb128()
        match variant:
            case TransactionPayload.SCRIPT:
                return TransactionPayload(Script.deserialize(deserializer))
            case TransactionPayload.ENTRY_FUNCTION:
                return TransactionPayload(EntryFunction.deserialize(deserializer))
            case TransactionPayload.PAYLOAD:
                return TransactionPayload(TransactionInnerPayload.deserialize(deserializer))
            case _:
                raise BcsDeserializationError(f"Invalid TransactionPayload variant: {variant}")

    def serialize(self, serializer: Serializer) -> None:
        serializer.uleb128(self.variant)
        self.value.serialize(serializer)
