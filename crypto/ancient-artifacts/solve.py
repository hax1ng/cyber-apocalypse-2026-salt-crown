#!/usr/bin/env python3
import functools
import random
import re
import shutil
import sys
import tempfile
import zlib
from pathlib import Path

from pwn import context, process, remote


MOD = 65521
POLY = 0xEDB88320
K = 96


def adler_parts(data):
    value = zlib.adler32(data)
    return value & 0xFFFF, value >> 16


def capacity_bounds(weights, caps, amount):
    if amount < 0 or amount > sum(caps):
        return None

    left = amount
    minimum = 0
    for weight, cap in reversed(list(zip(weights, caps))):
        take = min(cap, left)
        minimum += weight * take
        left -= take

    left = amount
    maximum = 0
    for weight, cap in zip(weights, caps):
        take = min(cap, left)
        maximum += weight * take
        left -= take
    return minimum, maximum


def recover_hash(my_salt, your_salt, salted):
    prefix = str(my_salt).encode()
    suffix = str(your_salt).encode()
    ap, bp = adler_parts(prefix)
    az, bz = adler_parts(suffix)
    at, bt = salted & 0xFFFF, salted >> 16

    # A(x || y) = A(x) + A(y) - 1
    an = (at - ap - az + 2) % MOD
    candidates = []
    for length in range(1, 40):
        # B(x || y) = B(x) + B(y) + len(y) * (A(x) - 1)
        bn = (
            bt
            - bp
            - length * (ap - 1)
            - bz
            - len(suffix) * (ap + an - 2)
        ) % MOD

        digit_sum = an - 1 - 48 * length
        weighted_digits = (
            bn - length - 48 * length * (length + 1) // 2
        ) % MOD
        if not 1 <= digit_sum <= 9 * length:
            continue

        # Reserve one unit for the nonzero first digit.
        weights = list(range(length, 0, -1))
        caps = [8] + [9] * (length - 1)
        bounds = capacity_bounds(weights, caps, digit_sum - 1)
        if bounds is None:
            continue
        low, high = length + bounds[0], length + bounds[1]
        if low <= weighted_digits <= high:
            candidates.append((length, (bn << 16) | an,
                               digit_sum, weighted_digits))

    if len(candidates) != 1:
        raise RuntimeError(f"ambiguous Adler recovery: {candidates!r}")
    return candidates[0]


def make_adler_collision(length, digit_sum, weighted_digits):
    # Start the first digit at one, then distribute the remaining digit units.
    weights = list(range(length, 0, -1))
    caps = [8] + [9] * (length - 1)
    remaining_sum = digit_sum - 1
    remaining_weight = weighted_digits - length
    allocation = []

    for i, (weight, cap) in enumerate(zip(weights, caps)):
        possible = []
        for value in range(cap + 1):
            bounds = capacity_bounds(
                weights[i + 1:], caps[i + 1:], remaining_sum - value
            )
            if bounds is None:
                continue
            target = remaining_weight - weight * value
            if bounds[0] <= target <= bounds[1]:
                possible.append(value)
        if not possible:
            raise RuntimeError("failed to construct an Adler collision")
        value = random.choice(possible)
        allocation.append(value)
        remaining_sum -= value
        remaining_weight -= weight * value

    if remaining_sum or remaining_weight:
        raise RuntimeError("bad Adler construction")
    allocation[0] += 1
    return "".join(map(str, allocation))


def gf2_matrix_times(matrix, vector):
    result = 0
    index = 0
    while vector:
        if vector & 1:
            result ^= matrix[index]
        vector >>= 1
        index += 1
    return result


def gf2_matrix_square(matrix):
    return [gf2_matrix_times(matrix, row) for row in matrix]


def crc32_combine(crc1, crc2, length2):
    """Equivalent to zlib's crc32_combine()."""
    if length2 <= 0:
        return crc1

    odd = [0] * 32
    odd[0] = POLY
    row = 1
    for i in range(1, 32):
        odd[i] = row
        row <<= 1
    even = gf2_matrix_square(odd)
    odd = gf2_matrix_square(even)

    while True:
        even = gf2_matrix_square(odd)
        if length2 & 1:
            crc1 = gf2_matrix_times(even, crc1)
        length2 >>= 1
        if not length2:
            break

        odd = gf2_matrix_square(even)
        if length2 & 1:
            crc1 = gf2_matrix_times(odd, crc1)
        length2 >>= 1
        if not length2:
            break
    return crc1 ^ crc2


def solve_gf2(columns, target):
    basis = [None] * 64
    for index, column in enumerate(columns):
        vector = column
        choice = 1 << index
        while vector:
            pivot = vector.bit_length() - 1
            if basis[pivot] is None:
                basis[pivot] = (vector, choice)
                break
            vector ^= basis[pivot][0]
            choice ^= basis[pivot][1]

    vector = target
    choice = 0
    while vector:
        pivot = vector.bit_length() - 1
        if basis[pivot] is None:
            return None
        vector ^= basis[pivot][0]
        choice ^= basis[pivot][1]
    return choice


def make_numbers(length, target, digit_sum, weighted_digits):
    candidates = []
    seen = set()
    while len(candidates) < 2 * K:
        value = make_adler_collision(length, digit_sum, weighted_digits)
        if value in seen:
            continue
        seen.add(value)
        assert zlib.adler32(value.encode()) == target
        candidates.append((value, zlib.crc32(value.encode())))

    pairs = [(candidates[2 * i], candidates[2 * i + 1])
             for i in range(K)]
    base_xor = 0
    base_concat = 0
    columns = []

    for i, (left, right) in enumerate(pairs):
        left_crc = left[1]
        delta = left_crc ^ right[1]
        base_xor ^= left_crc
        base_concat = crc32_combine(base_concat, left_crc, length)

        shifted = crc32_combine(delta, 0, length * (K - 1 - i))
        columns.append(delta | (shifted << 32))

    wanted = (base_xor ^ target) | ((base_concat ^ target) << 32)
    choices = solve_gf2(columns, wanted)
    if choices is None:
        raise RuntimeError("random CRC system did not have full rank; rerun")

    result = [pairs[i][(choices >> i) & 1][0] for i in range(K)]
    assert len(set(result)) == K
    crcs = [zlib.crc32(value.encode()) for value in result]
    assert functools.reduce(int.__xor__, crcs) == target
    assert zlib.crc32("".join(result).encode()) == target
    return result


def open_target():
    if len(sys.argv) == 3:
        return remote(sys.argv[1], int(sys.argv[2])), None
    if len(sys.argv) != 1:
        raise SystemExit(f"usage: {sys.argv[0]} [host port]")

    temporary = tempfile.TemporaryDirectory()
    source = Path(__file__).parent / "crypto_ancient_artifacts" / "server.py"
    shutil.copy(source, Path(temporary.name) / "server.py")
    (Path(temporary.name) / "flag.txt").write_text("HTB{local_test_success}\n")
    tube = process(
        [sys.executable, "-u", "server.py"], cwd=temporary.name
    )
    return tube, temporary


def main():
    context.log_level = "error"
    tube, temporary = open_target()
    your_salt = 1 << 127
    tube.sendlineafter(b"your salt: ", str(your_salt).encode())

    my_salt = int(tube.recvline().split(b"=")[1])
    salted = int(tube.recvline().split(b"=")[1])
    length, target, digit_sum, weighted_digits = recover_hash(
        my_salt, your_salt, salted
    )
    numbers = make_numbers(length, target, digit_sum, weighted_digits)

    # The whole transcript is small enough to pipeline, which avoids 96 RTTs.
    payload = b"".join(
        b"1\n" + value.encode() + b"\n" for value in numbers
    ) + b"2\n"
    tube.send(payload)
    output = tube.recvall(timeout=10)
    flags = re.findall(rb"(?:HTB|FLAG)\{[^}\r\n]+\}", output)
    if flags:
        print(flags[-1].decode())
    else:
        print(output.decode(errors="replace"))
    if temporary is not None:
        temporary.cleanup()


if __name__ == "__main__":
    main()
