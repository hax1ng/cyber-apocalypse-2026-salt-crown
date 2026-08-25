# The Far Orchard Writeup

## Challenge summary

The Far Orchard is a blockchain challenge built around:

- an ERC-721 contract containing eight **Far-Seals**;
- a Halo2 zero-knowledge circuit;
- a Merkle tree containing eight approved public keys; and
- a validator API that signs an EIP-712 receipt when it accepts a proof.

To solve the challenge, we need to obtain eight valid validator signatures and call `honorSeal()` once for every seal ID from `0` through `7`.

The short version of the bug is:

> The circuit lets the prover choose the elliptic-curve generator used to create their public key.

That is a little like an ID checker asking, “Does this signature match the rules?” but letting us rewrite the rules immediately before the check.

## The on-chain target

The important function in `FarOrchard.sol` is:

```solidity
function honorSeal(
    uint256 sealId,
    bytes32 nullifier,
    bytes calldata signature
) external {
    require(sealId < TOTAL_SEALS, "Invalid Far-Seal ID");

    uint256 sealBit = uint256(1) << sealId;
    require((honoredBitmap & sealBit) == 0, "Far-Seal already honored");
    require(!nullifierUsed[nullifier], "Nullifier already used");

    bytes32 structHash = keccak256(
        abi.encode(
            keccak256(
                "Honor(address claimant,uint256 sealId,bytes32 nullifier)"
            ),
            msg.sender,
            sealId,
            nullifier
        )
    );

    address signer = _hashTypedDataV4(structHash).recover(signature);
    require(signer == validatorSigner, "Invalid validator signature");

    nullifierUsed[nullifier] = true;
    honoredBitmap |= sealBit;
    honoredCount += 1;
    _safeMint(msg.sender, sealId);
}
```

The Solidity itself is not doing anything obviously unsafe. A seal can only be honored if:

1. its ID is valid;
2. it has not already been honored;
3. the nullifier has not already been used; and
4. the trusted validator signed the claimant, seal ID, and nullifier.

So, instead of attacking the contract's ECDSA logic, we need to convince the off-chain validator to sign eight receipts.

## What the proof is meant to show

The validator has a Merkle tree containing eight approved public keys. A normal proof should demonstrate:

1. I know a secret key `sk`.
2. My public key is derived from that secret key.
3. My public key is one of the leaves in the approved Merkle tree.
4. My public nullifier was derived from the same secret key.

The public key calculation should normally look like this:

```text
PK = [sk]G
```

Here, `G` is a fixed, globally agreed elliptic-curve generator. The square brackets mean scalar multiplication: add the curve point `G` to itself `sk` times.

The important word is **fixed**. If everyone can choose a different `G`, the public key no longer proves what it is supposed to prove.

## Finding the bug

The vulnerable section of `src/circuit.rs` is:

```rust
let g_d = NonIdentityPoint::new(
    ecc_chip.clone(),
    layouter.namespace(|| "witness g_d"),
    self.g_d,
)?;

let sk_cell = layouter.assign_region(
    || "witness sk",
    |mut region| region.assign_advice(|| "sk", config.advices[0], 0, || self.sk),
)?;

let sk_scalar = ScalarVar::from_base(
    ecc_chip.clone(),
    layouter.namespace(|| "sk as ScalarVar"),
    &sk_cell,
)?;

let (pk, _) = g_d.mul(
    layouter.namespace(|| "pk = [sk] * g_d"),
    sk_scalar,
)?;
```

Both `sk` **and `g_d`** are private witness values provided by us.

The circuit does check that `g_d` is a real, non-identity curve point, but it never checks that `g_d` equals the official Pallas generator.

The nullifier calculation, however, uses a fixed base:

```rust
let nullifier_base =
    FixedPointBaseField::from_inner(ecc_chip, FarOrchardBaseField);

let nullifier = nullifier_base.mul(
    layouter.namespace(|| "nullifier = [sk] * NullifierK"),
    sk_cell.clone(),
)?;
```

This difference gives us everything we need:

- the membership public key uses our chosen `g_d`;
- the nullifier uses the real fixed generator.

## Turning the bug into an exploit

Suppose an approved Merkle leaf represents the curve point `P`.

We choose any convenient nonzero secret key, for example:

```text
sk = 1
```

We then choose:

```text
g_d = [sk^-1]P
```

`sk^-1` is the multiplicative inverse of `sk` in the curve's scalar field.

Now the circuit calculates:

```text
[sk]g_d
= [sk]([sk^-1]P)
= P
```

So the circuit derives the approved point `P`, even though our chosen `sk` has nothing to do with the real secret key belonging to that leaf.

For the eight seals, I used small distinct secret keys:

```text
1, 2, 3, 4, 5, 6, 7, 8
```

Because the nullifier is calculated with the real fixed base, each secret key produces a different nullifier:

```text
NF_i = [sk_i]G
```

This bypasses the contract's `nullifierUsed` protection.

## Recovering a point from a published leaf

The API publishes only each public key's x-coordinate, `pk_x`.

Pallas uses a curve equation equivalent to:

```text
y² = x³ + 5
```

Given a published `x`, we calculate:

```text
y = sqrt(x³ + 5)
```

Either square root is acceptable because the Merkle tree commits only to the x-coordinate. The exploit performs this recovery with:

```rust
fn point_from_x(x: pallas::Base) -> Result<pallas::Affine, String> {
    let rhs = x.square() * x + pallas::Base::from(5);
    let y: Option<pallas::Base> = rhs.sqrt().into();
    let y = y.ok_or("registered leaf is not a valid Pallas x-coordinate")?;

    Option::from(pallas::Affine::from_xy(x, y))
        .ok_or_else(|| "failed to recover registered Pallas point".into())
}
```

For every seal, the solver:

1. recovers the registered curve point;
2. chooses a new `sk`;
3. calculates `g_d = [sk^-1]P`;
4. constructs the correct Merkle path; and
5. generates a Halo2 proof.

The complete proof generator is in:

```text
src/bin/exploit.rs
```

## Launching an instance

The challenge exposes an HTTP API:

```bash
BASE="http://154.57.164.69:32481"

curl -s -c session.cookie -b session.cookie \
  -X POST "$BASE/api/launch" |
  tee launch.json

curl -s -c session.cookie -b session.cookie \
  "$BASE/api/info" |
  tee info.json
```

Keeping the cookie is important. Without it, `/api/info` may return the global Merkle data but omit the contract addresses associated with our private instance.

The launch response contains:

- the RPC URL;
- the funded player's private key;
- the wallet address; and
- the Setup contract address.

`/api/info` supplies the Merkle root, all eight leaves, and the Orchard contract address.

## Preparing the tree input

The Rust solver accepts a simple text representation:

```text
MERKLE_ROOT=<root without 0x>
LEAF=0,<pk_x without 0x>
LEAF=1,<pk_x without 0x>
...
LEAF=7,<pk_x without 0x>
```

It can be generated from `info.json` with:

```bash
python3 - <<'PY' > live_tree.txt
import json

info = json.load(open("info.json"))
print("MERKLE_ROOT=" + info["merkle_root"].removeprefix("0x"))

for leaf in info["merkle_leaves"]:
    print(
        f"LEAF={leaf['index']},"
        f"{leaf['pk_x'].removeprefix('0x')}"
    )
PY
```

## Generating the forged proofs

Build and run the proof generator:

```bash
cargo run --release --bin exploit -- live_tree.txt > proofs.txt
```

Halo2 parameter and proving-key generation is the slow part. The resulting output contains one block per seal:

```text
SEAL_ID=0
NULLIFIER=...
LEAF=...
PROOF=...
```

### Deployed validator format

The deployed HTTP validator uses this binary envelope:

```text
merkle_root   32 bytes
nullifier     32 bytes
claimed_leaf  32 bytes
proof_length   4 bytes, little-endian
halo2_proof    proof_length bytes
```

This is slightly different from the two-public-input format in the released standalone serializer. The deployed verifier also exposes the selected leaf as public instance row `2`.

That is why the working solver includes the claimed leaf in both:

- the Halo2 public instance list; and
- the serialized HTTP proof envelope.

## Asking the validator for signatures

Each generated proof is submitted with its seal ID:

```bash
curl -s -b session.cookie \
  -X POST "$BASE/api/verify" \
  -H "Content-Type: application/json" \
  -d '{"proof":"<serialized proof hex>","seal_id":0}'
```

A successful response looks like:

```json
{
  "claimant": "0x...",
  "nullifier": "0x...",
  "orchard": "0x...",
  "seal_id": 0,
  "signature": "...",
  "status": "ok"
}
```

The validator signs an EIP-712 `Honor` receipt containing:

```text
claimant
sealId
nullifier
```

The process is repeated for all eight proofs.

## Honoring all eight seals

With the signatures saved in `receipts.json`, I used Web3.py to submit the transactions:

```python
import json
from web3 import Web3

launch = json.load(open("launch.json"))
receipts = json.load(open("receipts.json"))

w3 = Web3(Web3.HTTPProvider(launch["0"]["RPC_URL"]))
private_key = launch["1"]["PRIVKEY"]
wallet = Web3.to_checksum_address(launch["3"]["WALLET_ADDR"])

abi = [{
    "type": "function",
    "name": "honorSeal",
    "stateMutability": "nonpayable",
    "inputs": [
        {"name": "sealId", "type": "uint256"},
        {"name": "nullifier", "type": "bytes32"},
        {"name": "signature", "type": "bytes"}
    ],
    "outputs": []
}]

orchard = w3.eth.contract(
    address=Web3.to_checksum_address(receipts[0]["orchard"]),
    abi=abi,
)

nonce = w3.eth.get_transaction_count(wallet)

for receipt in receipts:
    tx = orchard.functions.honorSeal(
        receipt["seal_id"],
        bytes.fromhex(receipt["nullifier"].removeprefix("0x")),
        bytes.fromhex(receipt["signature"].removeprefix("0x")),
    ).build_transaction({
        "from": wallet,
        "nonce": nonce,
        "chainId": w3.eth.chain_id,
        "gas": 300000,
        "gasPrice": w3.eth.gas_price,
    })

    signed = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    result = w3.eth.wait_for_transaction_receipt(tx_hash)

    assert result.status == 1
    nonce += 1
```

After the eighth transaction:

```text
honoredCount  = 8
honoredBitmap = 0xff
```

`0xff` is binary `11111111`, meaning all eight seal bits are set.

## Getting the flag

Finally:

```bash
curl -s -b session.cookie "$BASE/api/flag"
```

Flag:

```text
HTB{d4m4s_f4r_s34ls_br0k3_b3n34th_g0ld_l34v3s_2662911efb20f0867cf54be8359b9f74}
```

## How the circuit should be fixed

The public-key generator must not be supplied as an unconstrained witness.

Instead of:

```text
PK = [sk]g_d
```

where `g_d` comes from the prover, the circuit should calculate:

```text
PK = [sk]G
```

where `G` is a fixed curve point built into the circuit.

If a variable generator is genuinely required by the protocol, the circuit must constrain it to an authenticated value or approved domain. Merely checking that it is a valid nonzero curve point is not enough.

## Takeaway

Zero-knowledge proofs can prove that a computation followed its constraints perfectly. They cannot tell us whether those constraints describe the right security rule.

Here, the proof system worked correctly. The circuit faithfully proved:

> “There exists a secret key and a prover-chosen generator that produce an approved x-coordinate.”

Unfortunately, the application needed it to prove:

> “There exists a secret key that produces an approved key under the one fixed generator everyone trusts.”

That tiny difference was enough to forge all eight approved identities and empty the Orchard.
