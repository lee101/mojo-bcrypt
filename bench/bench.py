"""Benchmark mojo-bcrypt against the upstream bcrypt package."""

from __future__ import annotations

import os
import platform
import sys
import time

sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "python"),
)

import bcrypt  # noqa: E402
import mojo_bcrypt  # noqa: E402


def timeit(function, repeat=3):
    best = float("inf")
    for _ in range(repeat):
        start = time.perf_counter()
        function()
        best = min(best, time.perf_counter() - start)
    return best


def cpu_name():
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or platform.machine()


def main():
    cases = [
        ("32-byte key, 50 rounds", b"password", b"benchmark salt", 32, 50),
        ("64-byte key, 50 rounds", b"password", b"benchmark salt", 64, 50),
        ("32-byte key, 100 rounds", b"a longer password phrase", b"salt", 32, 100),
    ]
    mojo_bcrypt.kdf(b"warmup", b"salt", 1, 1, ignore_few_rounds=True)
    print(f"Machine: {cpu_name()}; {platform.system()} {platform.machine()}")
    print(f"Python {platform.python_version()}; bcrypt {bcrypt.__version__}")
    print()
    print("| case | mojo-bcrypt | bcrypt | upstream / Mojo | result |")
    print("|---|---:|---:|---:|---|")
    for name, password, salt, size, rounds in cases:
        ours = lambda: mojo_bcrypt.kdf(
            password, salt, size, rounds, ignore_few_rounds=True
        )
        theirs = lambda: bcrypt.kdf(
            password, salt, size, rounds, ignore_few_rounds=True
        )
        assert ours() == theirs()
        mojo_time = timeit(ours)
        upstream_time = timeit(theirs)
        ratio = upstream_time / mojo_time
        result = "faster" if ratio > 1 else "slower"
        print(
            f"| {name} | {mojo_time * 1000:.2f} ms | "
            f"{upstream_time * 1000:.2f} ms | {ratio:.2f}x | {result} |"
        )


if __name__ == "__main__":
    main()
