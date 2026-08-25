# Ancient Artifacts Writeup

**Category:** Crypto  
**Flag:** `HTB{zl1b_func710n5_r34lly_5houldn7_b3_us3d_1n_cryp70!}`

## The short version

The challenge uses `zlib.adler32` and `zlib.crc32` as if they were
cryptographic hashes. They are not: both are small, predictable checksums.

The attack has three parts:

1. Recover the secret number's Adler-32 checksum from the salted checksum.
2. Generate lots of different decimal numbers with that same Adler-32 value.
3. Use CRC-32's linear algebra to select 96 of those numbers so both final
   CRC checks pass.

The completed exploit is in [`solve.py`](solve.py).

## Looking at the server

The important setup is:

```python
num = secrets.randbits(128)
h = apply_rune(zlib.adler32, num)

my_salt = secrets.randbits(128)
your_salt = int(input("your salt: "))
assert your_salt.bit_length() >= 128
salted = apply_rune(zlib.adler32, my_salt, num, your_salt)
print(f"{my_salt = }")
print(f"{salted = }")
```

`apply_rune()` converts every argument to decimal text, joins the texts
together, and checksums the resulting bytes.

We then have to submit distinct numbers satisfying:

```python
adler32(str(your_num)) == h
```

Finally, our complete list must satisfy:

```python
crc32(str(nums[0]) + str(nums[1]) + ...) == h

crc32(str(nums[0])) ^ crc32(str(nums[1])) ^ ... == h
```

Trying to guess the original random 128-bit number is hopeless. Fortunately,
we do not need the original number. We only need its 32-bit Adler checksum and
some checksum collisions.

## Part 1: Unsalting Adler-32

An Adler-32 value contains two 16-bit-ish values, normally called `A` and
`B`, calculated modulo:

```text
M = 65521
```

The final checksum is:

```text
(B << 16) | A
```

For byte strings `x` and `y`, Adler-32 can be combined as:

```text
A(x || y) = A(x) + A(y) - 1                    mod M

B(x || y) = B(x) + B(y) + len(y) * (A(x) - 1) mod M
```

This means adding known text before and after a secret does not hide its
checksum. Once the server prints `my_salt` and `salted`, nearly every part of
the equations is known.

I used this valid 128-bit salt:

```text
your_salt = 2^127
          = 170141183460469231731687303715884105728
```

Let:

```text
P = str(my_salt)
N = str(num)
Y = str(your_salt)
T = P || N || Y
```

From `A(T)`, `A(P)`, and `A(Y)`, the secret's first component is:

```text
A(N) = A(T) - A(P) - A(Y) + 2 mod M
```

Recovering `B(N)` also requires `len(N)`. A 128-bit nonnegative integer has at
most 39 decimal digits, so the solver simply tries lengths 1 through 39:

```text
B(N) = B(T)
     - B(P)
     - len(N) * (A(P) - 1)
     - B(Y)
     - len(Y) * (A(P) + A(N) - 2)
       mod M
```

Only one candidate length produces possible decimal digits. In practice this
is usually 38 or 39 digits.

So, without learning `num`, we now know:

```text
h = (B(N) << 16) | A(N)
```

## Part 2: Making Adler-32 collisions

Adler-32 is especially weak for this challenge because the input is decimal
text.

Suppose a number has `L` digits, and digit `i` has numeric value `d_i` from
0 through 9. Its ASCII value is `48 + d_i`. The Adler components become:

```text
A = 1 + 48L + sum(d_i)

B = L + 48 * L(L + 1)/2 + sum((L - i) * d_i)
```

The first digit is kept between 1 and 9 so that Python does not remove a
leading zero when it converts the submitted integer back to text.

For a recovered `A`, `B`, and `L`, the required digit equations are therefore:

```text
sum(d_i) = A - 1 - 48L

sum((L - i) * d_i) = B - L - 48 * L(L + 1)/2
```

These are only two small linear equations with about 39 digit variables.
There are a huge number of solutions.

The solver constructs a solution one digit at a time. Before accepting a
digit, it checks whether the remaining digit positions can still reach the
required minimum and maximum weighted sums. Randomly choosing among valid
digits gives plenty of distinct numbers, all with the secret number's
Adler-32 value.

At this point we can pass every per-number Adler assertion, but we still need
to deal with the two CRC assertions.

## Part 3: Treating CRC-32 as linear algebra

CRC-32 is intended to detect accidental corruption. It is not designed to
resist someone deliberately arranging the input.

For fixed-length byte strings, CRC concatenation can be written as:

```text
CRC(x || y) = shift_len(y)(CRC(x)) XOR CRC(y)
```

The `shift` operation is multiplication by a known polynomial over
`GF(2)`. That scary name mostly means:

- every value is a bit vector;
- addition is XOR;
- ordinary Gaussian elimination still works.

### Turning the choices into equations

I generate 192 Adler collisions and divide them into 96 pairs:

```text
(a_0, b_0), (a_1, b_1), ..., (a_95, b_95)
```

Exactly one number is selected from every pair. Let choice bit `x_i` mean:

```text
x_i = 0: select a_i
x_i = 1: select b_i
```

Changing the selection for pair `i` toggles its CRC by:

```text
delta_i = CRC(a_i) XOR CRC(b_i)
```

For the XOR-of-individual-CRCs assertion, its contribution is simply
`delta_i`.

For the concatenated CRC assertion, that same difference is shifted according
to how many fixed-length numbers appear after position `i`:

```text
shift_(L * (95 - i))(delta_i)
```

Join those two 32-bit effects into one 64-bit column:

```text
column_i =
    delta_i
    || shift_(L * (95 - i))(delta_i)
```

The all-`a_i` selection gives a known baseline. We XOR that baseline with the
two desired values of `h`, producing one 64-bit target. The remaining problem
is:

```text
x_0 * column_0 XOR ... XOR x_95 * column_95 = target
```

This is a 64-equation system with 96 unknown choice bits. The columns have
full rank with overwhelming probability, so a tiny GF(2) Gaussian elimination
finds a valid selection immediately.

The exploit verifies locally that:

```python
assert all(zlib.adler32(n.encode()) == h for n in selected)

assert functools.reduce(
    int.__xor__, [zlib.crc32(n.encode()) for n in selected]
) == h

assert zlib.crc32("".join(selected).encode()) == h
```

## Running it

For the bundled local server:

```bash
./solve.py
```

For the actual challenge:

```bash
./solve.py HOST PORT
```

The challenge has a 30-second alarm, so the exploit pipelines all 96 menu
choices and numbers in one write instead of waiting for every prompt.

One important gotcha is that a generated payload belongs to only one
connection. Both `num` and `my_salt` are freshly randomized for every new
connection, so reconnecting and pasting an old payload will fail immediately.

## Takeaway

The funny part is that neither checksum needed to be "cracked":

- Adler-32's composition formula let us remove the salt algebraically.
- Adler-32's tiny linear state made collisions easy to construct.
- CRC-32's linear structure let us satisfy both final conditions with a
  solvable system of XOR equations.

Checksums are great for catching random transmission errors. They are very bad
substitutes for cryptographic hashes.
