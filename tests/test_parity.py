import inspect
import os
import warnings

import bcrypt
import pytest

import mojo_bcrypt
from mojo_bcrypt._lib import lib


def derive(module, password, salt, size, rounds):
    return module.kdf(
        password=password,
        salt=salt,
        desired_key_bytes=size,
        rounds=rounds,
        ignore_few_rounds=True,
    )


def test_signature_matches_upstream():
    assert inspect.signature(mojo_bcrypt.kdf) == inspect.signature(bcrypt.kdf)


def test_known_vector_password_salt():
    expected = bytes.fromhex(
        "5bbf0cc293587f1c3635555c27796598"
        "d47e579071bf427e9d8fbe842aba34d9"
    )
    assert derive(mojo_bcrypt, b"password", b"salt", 32, 4) == expected
    assert derive(bcrypt, b"password", b"salt", 32, 4) == expected


def test_openssh_bcrypt_pbkdf_vector():
    expected = bytes(
        [
            65, 207, 68, 58, 55, 252, 114, 141, 255, 65, 216, 175, 5, 92,
            235, 68, 220, 92, 118, 161, 40, 13, 241, 190, 56, 152, 69, 136,
            41, 214, 51, 205, 37, 221, 101, 59, 105, 73, 133, 36, 14, 59,
            94, 212, 111, 107, 109, 237, 213, 235, 246, 119, 59, 76, 45,
            130, 142, 81, 178, 231, 161, 158, 138, 108, 18, 162, 26, 50,
            218, 251, 23, 66, 2, 232, 20, 202, 216, 46, 12, 250, 247, 246,
            252, 23, 155, 74, 77, 195, 120, 113, 57, 88, 126, 81, 9, 249,
            72, 18, 208, 160,
        ]
    )
    assert derive(mojo_bcrypt, b"password", b"salt", 100, 5) == expected


@pytest.mark.parametrize("size", [1, 16, 31, 32, 33, 64, 100, 512])
def test_output_lengths_match_upstream(size):
    got = derive(mojo_bcrypt, b"correct horse", b"battery staple", size, 1)
    assert got == derive(bcrypt, b"correct horse", b"battery staple", size, 1)
    assert len(got) == size


def test_binary_password_and_salt_match_upstream():
    password = bytes(range(256))
    salt = bytes(reversed(range(256)))
    assert derive(mojo_bcrypt, password, salt, 73, 3) == derive(
        bcrypt, password, salt, 73, 3
    )


def test_simd_key_xor_scalar_tail_matches_upstream():
    password = bytes(range(64))
    salt = bytes(reversed(range(64)))
    assert derive(mojo_bcrypt, password, salt, 32, 3) == derive(
        bcrypt, password, salt, 32, 3
    )


@pytest.mark.parametrize("size", [31, 32, 33, 34])
def test_parallel_output_threshold_matches_upstream(size):
    assert derive(mojo_bcrypt, b"parallel threshold", b"tail", size, 2) == derive(
        bcrypt, b"parallel threshold", b"tail", size, 2
    )


def test_long_inputs_cross_sha512_block_boundaries():
    password = os.urandom(259)
    salt = os.urandom(391)
    assert derive(mojo_bcrypt, password, salt, 65, 2) == derive(
        bcrypt, password, salt, 65, 2
    )


def test_password_is_not_truncated_at_72_bytes():
    password = b"a" * 72
    longer = password + b"b"
    first = derive(mojo_bcrypt, password, b"salt", 32, 2)
    second = derive(mojo_bcrypt, longer, b"salt", 32, 2)
    assert first != second
    assert second == derive(bcrypt, longer, b"salt", 32, 2)


def test_low_round_warning_matches_upstream():
    with warnings.catch_warnings(record=True) as ours:
        warnings.simplefilter("always")
        mojo_bcrypt.kdf(b"p", b"s", 1, 1)
    with warnings.catch_warnings(record=True) as theirs:
        warnings.simplefilter("always")
        bcrypt.kdf(b"p", b"s", 1, 1)
    assert len(ours) == len(theirs) == 1
    assert type(ours[0].message) is type(theirs[0].message)
    assert str(ours[0].message) == str(theirs[0].message)


def test_ignore_few_rounds_suppresses_warning():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        mojo_bcrypt.kdf(b"p", b"s", 1, 1, ignore_few_rounds=True)


@pytest.mark.parametrize(
    ("kwargs", "error", "message"),
    [
        ({"password": "", "salt": b"s", "desired_key_bytes": 1, "rounds": 1},
         TypeError, "cannot be converted to 'PyBytes'"),
        ({"password": b"", "salt": b"s", "desired_key_bytes": 1, "rounds": 1},
         ValueError, "password and salt must not be empty"),
        ({"password": b"p", "salt": b"", "desired_key_bytes": 1, "rounds": 1},
         ValueError, "password and salt must not be empty"),
        ({"password": b"p", "salt": b"s", "desired_key_bytes": 0, "rounds": 1},
         ValueError, "desired_key_bytes must be 1-512"),
        ({"password": b"p", "salt": b"s", "desired_key_bytes": 513, "rounds": 1},
         ValueError, "desired_key_bytes must be 1-512"),
        ({"password": b"p", "salt": b"s", "desired_key_bytes": 1, "rounds": 0},
         ValueError, "rounds must be 1 or more"),
    ],
)
def test_validation_matches_upstream(kwargs, error, message):
    for module in (mojo_bcrypt, bcrypt):
        with pytest.raises(error, match=message):
            module.kdf(**kwargs, ignore_few_rounds=True)


@pytest.mark.parametrize(
    ("position", "value", "error"),
    [
        (0, bytearray(b"p"), TypeError),
        (1, memoryview(b"s"), TypeError),
        (2, 1.5, TypeError),
        (3, 1.5, TypeError),
        (2, -1, OverflowError),
        (3, -1, OverflowError),
        (3, 0x1_0000_0000, OverflowError),
    ],
)
def test_type_and_integer_range_validation_matches_upstream(position, value, error):
    arguments = [b"p", b"s", 1, 1]
    arguments[position] = value
    for module in (mojo_bcrypt, bcrypt):
        with pytest.raises(error):
            module.kdf(*arguments, ignore_few_rounds=True)


def test_non_boolean_ignore_flag_matches_upstream():
    for module in (mojo_bcrypt, bcrypt):
        with pytest.raises(TypeError, match="cannot be converted to 'PyBool'"):
            module.kdf(b"p", b"s", 1, 1, ignore_few_rounds=1)


@pytest.mark.parametrize(
    "arguments",
    [
        (0, 1, 1, 1, 1, 1, 1),
        (1, 1, 0, 1, 1, 1, 1),
        (1, 1, 1, 1, 0, 1, 1),
        (1, 0, 1, 1, 1, 1, 1),
        (1, 1, 1, 0, 1, 1, 1),
        (1, 1, 1, 1, 1, 0, 1),
        (1, 1, 1, 1, 1, 513, 1),
        (1, 1, 1, 1, 1, 1, 0),
        (1, 1, 1, 1, 1, 1, 0x1_0000_0000),
    ],
)
def test_native_boundary_rejects_invalid_arguments(arguments):
    assert lib().mbc_kdf(*arguments) == -1


def test_input_buffers_remain_alive_for_native_call():
    password = bytes(range(256)) * 2
    salt = bytes(reversed(range(256))) * 2
    expected = derive(bcrypt, password, salt, 64, 2)
    assert derive(mojo_bcrypt, password, salt, 64, 2) == expected
    assert password[:4] == b"\x00\x01\x02\x03"
    assert salt[:4] == b"\xff\xfe\xfd\xfc"
