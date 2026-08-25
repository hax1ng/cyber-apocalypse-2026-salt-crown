# Hidden Secret

**Category:** Crypto | **Difficulty:** Unspecified | **Flag:** `HTB{too_few_samples_too_much_lattice_42874424b5e32fabd174491e1ba6cc85}`

## TL;DR

We are given only seven evaluations of secret degree-39 ternary polynomials, all multiplied by the same random value. By lifting those seven values to every degree-four monomial, we get 210 values that must lie in a space of dimension at most 157. This creates 53 unusually short modular relations, which we recover with lattice reduction and use to rebuild the polynomials coefficient by coefficient. A polynomial GCD then reveals the secret `x`, allowing us to derive the AES key and decrypt the flag.

## What We're Given

The challenge provides:

- `chall.py`, the generator and encryption source;
- `output.txt`, containing an 8192-bit prime, seven public samples, and an AES ciphertext.

The flavor text talks about old symbols concealing the **shape** of a secret. That is a good description of the actual attack: instead of recovering the secret directly, we first recover the algebraic curve, or “shape,” on which the samples were generated.

The important part of `chall.py` is:

```python
bits = 8192
samp = 7
deg = 40

for _ in range(samp):
    tot = 0
    for j in range(deg):
        tot += a * pow(x, j, p) * (1 - secrets.randbelow(3))
    arr.append(tot % p)
```

Since `1 - secrets.randbelow(3)` is one of `1`, `0`, or `-1`, each sample can be written as

\[
y_i=a f_i(x)\pmod p,
\]

where

\[
f_i(X)=\sum_{j=0}^{39}e_{i,j}X^j,\qquad e_{i,j}\in\{-1,0,1\}.
\]

The same unknown `a` and `x` are used for all seven samples. Finally, the flag is encrypted as:

```python
key = hashlib.sha256(str(x).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
encflag = cipher.encrypt(pad(flag, 16))
```

So recovering `x` is enough to derive the AES-256 key.

## Initial Recon

A small parser confirms the size of the instance:

```text
p bits: 8192
samples: 7
ciphertext bytes: 80
ciphertext blocks: 5
```

The obvious equation for eliminating `a` is

\[
y_i f_k(x)-y_k f_i(x)=0\pmod p.
\]

Unfortunately, this still contains `x` and all 280 unknown ternary coefficients. Brute-forcing the coefficients would require searching roughly \(3^{280}\) possibilities, so that is not useful.

The key observation is that the seven polynomials are not unrelated points. Define the polynomial map

\[
F(T)=(f_0(T),f_1(T),\ldots,f_6(T)).
\]

Although its seven coordinates are unknown, every public sample is a scaled point on this same curve:

\[
(y_0,\ldots,y_6)=aF(x).
\]

This suggests looking for polynomial identities that hold on the entire curve rather than trying to guess `x` immediately.

## The Vulnerability / Trick

### The fourth Veronese lift

Take every degree-four monomial in the seven coordinates of \(F(T)\), such as

\[
f_0(T)^4,\quad f_0(T)^3f_1(T),\quad
f_0(T)f_2(T)f_4(T)f_6(T).
\]

The number of degree-four monomials in seven variables is

\[
\binom{7+4-1}{4}=\binom{10}{4}=210.
\]

However, each product is an ordinary univariate polynomial of degree at most

\[
4\cdot39=156.
\]

The space of polynomials of degree at most 156 has only 157 coefficients. Therefore, 210 such products cannot be linearly independent: there must be at least

\[
210-157=53
\]

independent quartic identities

\[
Q(F(T))=0.
\]

Degree four is the first lift that forces this to happen. For comparison, a cubic lift gives only \(\binom{9}{3}=84\) products in a space of dimension 118.

This is a **Veronese lift**: we replace a point by all monomials of a fixed degree. It turns hidden nonlinear structure into linear relations in a larger coordinate space.

### Why the identities also hold for the public values

Each \(Q\) is homogeneous of degree four. Since \(y=aF(x)\),

\[
Q(y_0,\ldots,y_6)
=Q(aF(x))
=a^4Q(F(x))
=0\pmod p.
\]

Thus, if \(v\) is the vector of all 210 quartic monomials in the public `y` values, every genuine identity gives a vector \(c\) satisfying

\[
\langle c,v\rangle=0\pmod p.
\]

The coefficients of the original polynomials are only `-1`, `0`, and `1`, so the genuine relation vectors are much shorter than random modular relations. That size gap is what makes lattice reduction effective.

### Constructing the relation lattice

`dump_lattice.sage` enumerates the 210 monomials and builds

\[
L=\{c\in\mathbb Z^{210}:\langle c,v\rangle=0\pmod p\}.
\]

The core code is:

```python
mons = list(combinations_with_replacement(range(7), 4))
vals = [prod(ZZ(ys[i]) for i in m) % p for m in mons]

n = len(vals)
inv = inverse_mod(vals[0], p)
B = identity_matrix(ZZ, n)
B[0, 0] = p
for i in range(1, n):
    B[i, 0] = ZZ((-vals[i] * inv) % p)
```

Every row of this basis has dot product zero with `vals` modulo `p`. Reducing the basis should bring the unusually short, genuine quartic identities to the front.

Sage's proved fpLLL reduction was still running after ten minutes, so the practical pivot was to use [`flatter`](https://github.com/keeganryan/flatter) on the `kracken` compute host. It reduced the 210-dimensional basis with 8192-bit entries in about 25 seconds.

The result had a very clear norm gap:

```text
true-relation sqrt norm: 2^24.63 .. 2^25.12
next/generic sqrt norm:  2^48.87 ...
[+] short (53, 210) rank 53
```

That gives exactly the 53 identities predicted by the dimension count.

## Building the Exploit

The full solve is split across several Sage scripts and orchestrated by `solve.sh`.

### 1. Recover the quartic identities

`dump_lattice.sage` writes the lattice in fplll format. We reduce it with:

```bash
flatter -delta 0.99 lattice.fplll lattice_reduced.fplll
```

`parse_flatter.sage` parses the result and keeps the 53 vectors below the large norm gap:

```python
info = sorted((sum(z*z for z in r), i) for i, r in enumerate(B))
S = matrix(ZZ, [B[i] for N, i in info if N < 2^70])
```

These rows are saved as `quartic_relations.txt`.

### 2. Recover the hidden ternary polynomials

Write the seven coefficients at degree \(k\) as one vector:

\[
E_k=(e_{0,k},e_{1,k},\ldots,e_{6,k})\in\{-1,0,1\}^7.
\]

Then

\[
F(T)=E_0+E_1T+\cdots+E_{39}T^{39}.
\]

First, `recover_coeffs.sage` tests all \(3^7-1=2186\) nonzero ternary vectors as possible \(E_0\) values. It keeps only vectors satisfying all 53 quartic equations, with sign-equivalent vectors normalized to one representative:

```python
for e in tern:
    if e == (0,) * 7:
        continue
    if R * mon_values(e) == 0:
        # Normalize the projective sign.
        ...
```

Exactly two projective ternary points survive. They correspond to the constant and leading coefficient vectors; reversal of the parameter swaps those roles.

Now suppose \(E_0,\ldots,E_{k-1}\) are known. In the coefficient of \(T^k\) in a quartic identity, any term involving \(E_k\) must take its other three factors from \(E_0\). Therefore,

\[
[T^k]Q(F(T))
=J_Q(E_0)E_k+b_k(E_0,\ldots,E_{k-1}),
\]

where \(J_Q(E_0)\) is the Jacobian of \(Q\) evaluated at \(E_0\), and \(b_k\) is already known.

The condition \(Q(F(T))=0\) becomes a small linear test:

\[
J_Q(E_0)E_k=-b_k.
\]

There are only \(3^7=2187\) possible ternary vectors for each \(E_k\), so the script simply enumerates them and keeps those satisfying every relation:

```python
for k in range(1, 40):
    nxt = []
    for seq in branches:
        b = R * known_monomial_coeffs(seq, k)
        for e in lookup.get(tuple(-b), []):
            nxt.append(seq + (e,))
    branches = list(dict.fromkeys(nxt))
```

The branch count stays small, reaching at most 24 candidates in this instance. After degree 39, every survivor is validated against every coefficient of every quartic identity, not just the incremental conditions.

Four parametrizations remain. These are expected symmetries of the same curve: changing \(T\) to \(-T\), reversing the coefficients with \(T^{39}F(1/T)\), or combining the two does not change the implicit quartic relation space.

### 3. Eliminate the common multiplier and recover `x`

For any correct candidate polynomial tuple, the public equations give

\[
y_0f_i(x)-y_if_0(x)=0
\]

for every \(i=1,\ldots,6\). Thus `x` is a common root of all six polynomials

\[
h_i(X)=y_0f_i(X)-y_if_0(X)
\]

over \(\mathbb F_p\).

`extract_secret.sage` computes their GCD:

```python
g = PR(0)
for i in range(1, 7):
    h = Fp(ys[0]) * fs[i] - Fp(ys[i]) * fs[0]
    g = h if g == 0 else gcd(g, h)
```

For the first valid parametrization, the GCD has degree one, so its root immediately gives a candidate parameter.

Because of the sign and reversal symmetries, that root may represent any of

\[
x,\quad -x,\quad x^{-1},\quad -x^{-1}\pmod p.
\]

The script tries each candidate, derives

```python
key = hashlib.sha256(str(int(x)).encode()).digest()
```

and decrypts the ciphertext with AES-ECB. Valid PKCS#7 padding and the `HTB{` prefix provide a reliable correctness check.

## Running It

The expensive lattice work is intentionally offloaded to `kracken`. The wrapper copies the inputs there, runs Sage through `sage-run`, invokes `flatter`, and copies the recovered flag back:

```bash
$ ./solve.sh
[*] parsed (210, 210)
...
[+] short (53, 210) rank 53
[*] loaded relation matrix (53, 210) rank 53
[+] projectively distinct ternary seeds: 2
...
[+] total coefficient solutions: 4
[*] solution 0 common-root polynomial degree 1
[+] flag = HTB{too_few_samples_too_much_lattice_42874424b5e32fabd174491e1ba6cc85}
HTB{too_few_samples_too_much_lattice_42874424b5e32fabd174491e1ba6cc85}
```

## Key Takeaways

- When several hidden low-degree polynomials share one input, look for identities of the whole polynomial map rather than attacking each evaluation separately.
- A Veronese lift is useful when the number of lifted monomials exceeds the dimension of the polynomial space containing them.
- Small source coefficients can turn algebraic identities into exceptionally short lattice vectors.
- Homogeneous relations conveniently remove a common unknown scale factor.
- Once implicit equations are known, a small-alphabet parametrization can be rebuilt coefficient by coefficient using the Jacobian.
- The direct Sage/fpLLL reduction was far too slow here; exporting the basis to `flatter` was the key implementation improvement.
- Always account for natural parametrization symmetries such as \(T\mapsto -T\) and \(T\mapsto 1/T\) before rejecting a recovered root.
