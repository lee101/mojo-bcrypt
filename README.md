# mojo-bcrypt

`mojo-bcrypt` is a standalone Mojo implementation of the bcrypt password-based
key derivation function used by OpenBSD and OpenSSH. Its Python `kdf` function
has the same name, signature, validation, warning behavior, and byte output as
`bcrypt.kdf`.

The SHA-512 and EksBlowfish work runs in compiled Mojo. The Python layer only
validates arguments, owns the input/output buffers, and makes one ctypes call.

This project has not received an independent cryptographic audit. Use the
established upstream `bcrypt` package when that assurance matters more than
experimenting with a Mojo implementation.

## Coverage

Covered:

- `kdf(password, salt, desired_key_bytes, rounds, ignore_few_rounds=False)`
- binary passwords and salts, including embedded NUL bytes
- output lengths from 1 through 512 bytes
- the linear rounds parameter and the low-round security warning
- passwords longer than bcrypt password hashing's traditional 72-byte limit

Not covered:

- `hashpw`, `checkpw`, and `gensalt`
- modular crypt string parsing or bcrypt password hashing
- asynchronous or batched KDF calls

The omitted functions are outside this repository's bcrypt KDF scope.

## Install

Install the pinned Mojo toolchain and Python dependencies, then build the shared
library from a source checkout:

```bash
pixi install
pixi run build
```

Run the parity suite with:

```bash
pixi run test
```

## Usage

With the Pixi environment active, or through `pixi run python`:

```python
from mojo_bcrypt import kdf

key = kdf(
    password=b"password",
    salt=b"salt",
    desired_key_bytes=32,
    rounds=4,
    ignore_few_rounds=True,
)
print(key.hex())
```

Output:

```text
5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9
```

Production callers should select a rounds count for their threat model and
latency budget. The parameter is linear, not a base-2 cost as it is in bcrypt
password hashing.

## Benchmarks

Measured by running `pixi run bench` on this machine on July 29, 2026. The
script takes the best of three runs after loading and warming the shared
library. Both columns include the same Python-call overhead. `upstream / Mojo`
above 1 means Mojo is faster.

Machine: Intel(R) Xeon(R) CPU E5-2697 v4 @ 2.30GHz, Linux x86_64, Python
3.13.14, bcrypt 5.0.0.

| case | mojo-bcrypt | bcrypt | upstream / Mojo | result |
|---|---:|---:|---:|---|
| 32-byte key, 50 rounds | 235.83 ms | 259.67 ms | 1.10x | faster |
| 64-byte key, 50 rounds | 239.97 ms | 531.47 ms | 2.21x | faster |
| 32-byte key, 100 rounds | 467.16 ms | 515.72 ms | 1.10x | faster |

These are measurements from one shared factory host, not universal performance
claims. Run `pixi run bench` on the deployment machine for relevant numbers.

There is no GPU path.

## How it works

`src/bcrypt.mojo` contains SHA-512, Blowfish key expansion, Blowfish block
encryption, bcrypt's 64 expansion/encryption passes, round XOR folding, and the
OpenBSD strided output layout. The standard Blowfish P-array and S-box initial
state lives in `src/constants.mojo`. The build produces one shared object,
`dist/libmojo-bcrypt.so`.

The fixed-width key mixing and round folding use native-width SIMD with
unaligned-safe loads and stores plus scalar tails. Independent output blocks
are derived concurrently when more than one block is needed.

The C ABI transports buffers as integer addresses. The CPython wrapper keeps
the password and salt `bytes` objects alive for the whole native call, allocates
the output buffer, and passes non-null addresses with explicit lengths. Mojo
validates the boundary values before reconstructing byte pointers, writes into
the caller-owned output buffer, and returns a checked status code. There is one
FFI call per KDF operation.

The Blowfish state and SHA-512 work buffers use contiguous `InlineArray`
storage. Password-derived and per-block working buffers are overwritten before
returning.
