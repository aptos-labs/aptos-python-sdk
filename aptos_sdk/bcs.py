# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
BCS serializer/deserializer — v1 compatibility wrapper around v2 implementation.

This module re-exports the v2 ``Serializer``, ``Deserializer``, ``Serializable``,
and ``Deserializable`` classes so that existing v1 code continues to work without
modification.  The v1 ``encoder`` helper is also provided (it wraps the v2
``_encode`` function).
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types
import unittest

from .errors import DeserializationError, SerializationError

# ---------------------------------------------------------------------------
# Bootstrap v2 sub-packages without triggering the heavy v2/__init__.py.
#
# The v2 BCS modules use relative imports like ``from ..errors import ...``
# which require ``aptos_sdk.v2`` and ``aptos_sdk.v2.errors`` to exist in
# ``sys.modules``.  We register lightweight stand-ins so that the normal
# import machinery can resolve those references.
# ---------------------------------------------------------------------------

_v2_dir = os.path.join(os.path.dirname(__file__), "v2")


def _load_module(fqn: str, filepath: str) -> types.ModuleType:
    """Load a single .py file as *fqn* without running any package __init__."""
    if fqn in sys.modules:
        return sys.modules[fqn]
    spec = importlib.util.spec_from_file_location(fqn, filepath)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules[fqn] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


# Ensure the v2 *package* entry exists (as a namespace package) so relative
# imports inside v2 sub-modules resolve correctly.
if "aptos_sdk.v2" not in sys.modules:
    _v2_pkg = types.ModuleType("aptos_sdk.v2")
    _v2_pkg.__path__ = [_v2_dir]  # type: ignore[attr-defined]
    _v2_pkg.__package__ = "aptos_sdk.v2"
    sys.modules["aptos_sdk.v2"] = _v2_pkg

# Load v2.errors so ``from ..errors import ...`` works inside v2.bcs.*
_load_module("aptos_sdk.v2.errors", os.path.join(_v2_dir, "errors.py"))

# Load v2.bcs package
_bcs_dir = os.path.join(_v2_dir, "bcs")
if "aptos_sdk.v2.bcs" not in sys.modules:
    _bcs_pkg = types.ModuleType("aptos_sdk.v2.bcs")
    _bcs_pkg.__path__ = [_bcs_dir]  # type: ignore[attr-defined]
    _bcs_pkg.__package__ = "aptos_sdk.v2.bcs"
    sys.modules["aptos_sdk.v2.bcs"] = _bcs_pkg

_serializer_mod = _load_module(
    "aptos_sdk.v2.bcs.serializer", os.path.join(_bcs_dir, "serializer.py")
)
_deserializer_mod = _load_module(
    "aptos_sdk.v2.bcs.deserializer", os.path.join(_bcs_dir, "deserializer.py")
)
_protocols_mod = _load_module(
    "aptos_sdk.v2.bcs.protocols", os.path.join(_bcs_dir, "protocols.py")
)

# Populate the v2.bcs package stub so that ``from ..bcs import Serializer``
# etc. works inside v2 sub-modules that are loaded via _load_module.
_bcs_stub = sys.modules["aptos_sdk.v2.bcs"]
_bcs_stub.Serializer = _serializer_mod.Serializer  # type: ignore[attr-defined]
_bcs_stub.Deserializer = _deserializer_mod.Deserializer  # type: ignore[attr-defined]
_bcs_stub.Serializable = _protocols_mod.Serializable  # type: ignore[attr-defined]
_bcs_stub.Deserializable = _protocols_mod.Deserializable  # type: ignore[attr-defined]

# ---------------------------------------------------------------------------
# Public re-exports
# ---------------------------------------------------------------------------

Serializer = _serializer_mod.Serializer
Deserializer = _deserializer_mod.Deserializer
Serializable = _protocols_mod.Serializable
Deserializable = _protocols_mod.Deserializable

encoder = _serializer_mod._encode

MAX_U8 = _serializer_mod.MAX_U8
MAX_U16 = _serializer_mod.MAX_U16
MAX_U32 = _serializer_mod.MAX_U32
MAX_U64 = _serializer_mod.MAX_U64
MAX_U128 = _serializer_mod.MAX_U128
MAX_U256 = _serializer_mod.MAX_U256


# ---------------------------------------------------------------------------
# Test suite (preserved from v1)
# ---------------------------------------------------------------------------


class Test(unittest.TestCase):
    def test_bool_true(self):
        in_value = True

        ser = Serializer()
        ser.bool(in_value)
        der = Deserializer(ser.output())
        out_value = der.bool()

        self.assertEqual(in_value, out_value)

    def test_bool_false(self):
        in_value = False

        ser = Serializer()
        ser.bool(in_value)
        der = Deserializer(ser.output())
        out_value = der.bool()

        self.assertEqual(in_value, out_value)

    def test_bool_error(self):
        ser = Serializer()
        ser.u8(32)
        der = Deserializer(ser.output())
        with self.assertRaises(Exception):
            der.bool()

    def test_bytes(self):
        in_value = b"1234567890"

        ser = Serializer()
        ser.to_bytes(in_value)
        der = Deserializer(ser.output())
        out_value = der.to_bytes()

        self.assertEqual(in_value, out_value)

    def test_map(self):
        in_value = {"a": 12345, "b": 99234, "c": 23829}

        ser = Serializer()
        ser.map(in_value, Serializer.str, Serializer.u32)
        der = Deserializer(ser.output())
        out_value = der.map(Deserializer.str, Deserializer.u32)

        self.assertEqual(in_value, out_value)

    def test_sequence(self):
        in_value = ["a", "abc", "def", "ghi"]

        ser = Serializer()
        ser.sequence(in_value, Serializer.str)
        der = Deserializer(ser.output())
        out_value = der.sequence(Deserializer.str)

        self.assertEqual(in_value, out_value)

    def test_sequence_serializer(self):
        in_value = ["a", "abc", "def", "ghi"]

        ser = Serializer()
        seq_ser = Serializer.sequence_serializer(Serializer.str)
        seq_ser(ser, in_value)
        der = Deserializer(ser.output())
        out_value = der.sequence(Deserializer.str)

        self.assertEqual(in_value, out_value)

    def test_str(self):
        in_value = "1234567890"

        ser = Serializer()
        ser.str(in_value)
        der = Deserializer(ser.output())
        out_value = der.str()

        self.assertEqual(in_value, out_value)

    def test_u8(self):
        in_value = 15

        ser = Serializer()
        ser.u8(in_value)
        der = Deserializer(ser.output())
        out_value = der.u8()

        self.assertEqual(in_value, out_value)

    def test_u16(self):
        in_value = 11115

        ser = Serializer()
        ser.u16(in_value)
        der = Deserializer(ser.output())
        out_value = der.u16()

        self.assertEqual(in_value, out_value)

    def test_u32(self):
        in_value = 1111111115

        ser = Serializer()
        ser.u32(in_value)
        der = Deserializer(ser.output())
        out_value = der.u32()

        self.assertEqual(in_value, out_value)

    def test_u64(self):
        in_value = 1111111111111111115

        ser = Serializer()
        ser.u64(in_value)
        der = Deserializer(ser.output())
        out_value = der.u64()

        self.assertEqual(in_value, out_value)

    def test_u128(self):
        in_value = 1111111111111111111111111111111111115

        ser = Serializer()
        ser.u128(in_value)
        der = Deserializer(ser.output())
        out_value = der.u128()

        self.assertEqual(in_value, out_value)

    def test_u256(self):
        in_value = 111111111111111111111111111111111111111111111111111111111111111111111111111115

        ser = Serializer()
        ser.u256(in_value)
        der = Deserializer(ser.output())
        out_value = der.u256()

        self.assertEqual(in_value, out_value)

    def test_uleb128(self):
        in_value = 1111111115

        ser = Serializer()
        ser.uleb128(in_value)
        der = Deserializer(ser.output())
        out_value = der.uleb128()

        self.assertEqual(in_value, out_value)


if __name__ == "__main__":
    unittest.main()
