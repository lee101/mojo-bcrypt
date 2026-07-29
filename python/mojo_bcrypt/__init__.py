"""The bcrypt password-based KDF, implemented in Mojo."""

from __future__ import annotations

import ctypes
import operator
import warnings

from ._lib import lib

__all__ = ["kdf"]
__version__ = "0.1.0"

_bytes_address = ctypes.pythonapi.PyBytes_AsString
_bytes_address.argtypes = [ctypes.py_object]
_bytes_address.restype = ctypes.c_void_p


def kdf(
    password,
    salt,
    desired_key_bytes,
    rounds,
    ignore_few_rounds=False,
):
    """Derive a key with OpenBSD bcrypt_pbkdf.

    The parameters and validation behavior match ``bcrypt.kdf``.
    """
    if not isinstance(password, bytes):
        raise TypeError(
            f"argument 'password': '{type(password).__name__}' object "
            "cannot be converted to 'PyBytes'"
        )
    if not isinstance(salt, bytes):
        raise TypeError(
            f"argument 'salt': '{type(salt).__name__}' object "
            "cannot be converted to 'PyBytes'"
        )
    desired_key_bytes = operator.index(desired_key_bytes)
    rounds = operator.index(rounds)
    if not isinstance(ignore_few_rounds, bool):
        raise TypeError(
            f"argument 'ignore_few_rounds': "
            f"'{type(ignore_few_rounds).__name__}' object cannot be converted to 'PyBool'"
        )
    if not password or not salt:
        raise ValueError("password and salt must not be empty")
    if desired_key_bytes < 0:
        raise OverflowError("can't convert negative int to unsigned")
    if desired_key_bytes <= 0 or desired_key_bytes > 512:
        raise ValueError("desired_key_bytes must be 1-512")
    if rounds < 0 or rounds > 0xFFFFFFFF:
        raise OverflowError("out of range integral type conversion attempted")
    if rounds < 1:
        raise ValueError("rounds must be 1 or more")
    if rounds < 50 and not ignore_few_rounds:
        warnings.warn(
            (
                f"Warning: bcrypt.kdf() called with only {rounds} round(s). "
                "This few is not secure: the parameter is linear, like PBKDF2."
            ),
            UserWarning,
            stacklevel=2,
        )

    key_buffer = ctypes.create_string_buffer(desired_key_bytes)
    result = lib().mbc_kdf(
        _bytes_address(password),
        len(password),
        _bytes_address(salt),
        len(salt),
        ctypes.addressof(key_buffer),
        desired_key_bytes,
        rounds,
    )
    if result:
        raise SystemError("bcrypt assertion failed")
    return key_buffer.raw
