# Phantom Burn — Writeup

**Category:** Secure Coding  
**Event:** Cyber Apocalypse CTF 2026: The Salt Crown  
**Final score:** 60/60 hard, 35/40 soft  
**Flag:** `HTB{gh0st_t0uching_sh4rds_7f90adef03f615e17a0b1af777a28fe1}`

## The challenge in plain English

Phantom Burn is a small blockchain-backed application. A keeper files a “shard” on-chain and later presents a receipt to open an archive or download a protected source bundle.

The intended security model sounds reasonable:

1. A keeper files a shard in the trusted smart contract.
2. The blockchain emits a `ShardFiled` event.
3. A receipt points to that transaction and event.
4. The services verify the receipt.
5. The real owner gets one unlock.

The problem was that the original “verification” mostly checked whether some strings *looked* like hexadecimal values. It was like a security guard accepting any badge printed in the right color without checking the employee database.

There was a second problem: the source-bundle token was calculated from values visible on the public blockchain. Anyone could copy those values and calculate the same token.

So an attacker could submit a convincing-looking fake receipt, get access first, and obtain the archive service’s source code.

---

## Repository layout

The interesting code lived under `phantom_burn/`:

```text
phantom_burn/
├── contracts/          # Solidity contracts and Foundry tests
├── app/                # Public Node/TypeScript application
├── archive-service/    # Service that opens the lower archive
├── tools/              # Deployment and unlock helpers
└── README.md
```

The submission process was also part of the challenge:

```bash
git checkout -b developer
git add phantom_burn/
git commit -m "harden receipt verification"
git push -u origin developer
```

Pushing `developer` automatically opened a pull request. The bot performed a soft code review and then a hidden hard test. The flag only became available after a passing pull request was merged.

---

## Vulnerability 1: the archive barely verified receipts

The original archive verifier was essentially this:

```ts
export async function verifyReceipt(_config, _principal, receipt) {
  if (
    !receipt.txHash?.startsWith("0x") ||
    !receipt.owner?.startsWith("0x") ||
    !receipt.shardId?.startsWith("0x")
  ) {
    return { ok: false, reason: "malformed receipt" };
  }

  return { ok: true, receiptId: receiptId(receipt) };
}
```

Notice the unused `_config` and `_principal` arguments. The verifier did not:

- contact the blockchain;
- check that the transaction existed;
- check that the transaction succeeded;
- check the event’s contract address;
- check the exact event index;
- compare the claimed owner with the on-chain owner;
- verify the authenticated caller;
- require enough confirmations.

A receipt did not need to be genuine. It only needed a few strings beginning with `0x`.

### Why checking the event emitter matters

Checking only an event’s name and layout is not enough. An attacker can deploy a look-alike contract that emits an identical `ShardFiled` event.

The verifier therefore has to check both:

1. the event decodes as `ShardFiled`; and
2. the event was emitted by the configured, trusted `ShardRegistry` address.

---

## Vulnerability 2: the app trusted receipt claims

The public app did perform a transaction lookup, but it still had several problems:

- it could fall back to the first log if the requested log was absent;
- it did not reliably pin the emitting contract;
- it trusted fields supplied in the JSON receipt;
- it did not consistently bind the result to the authenticated owner.

A receipt should only be a pointer to evidence. It should not be the evidence itself.

The safe receipt format is therefore just:

```json
{
  "registry": "0x...",
  "txHash": "0x...",
  "logIndex": "0x0"
}
```

The owner, shard ID, nonce, URI, and anything used for authorization must come from the decoded blockchain event—not from JSON controlled by the caller.

---

## Vulnerability 3: the “secret” token used public information

Originally, the source token was an ordinary SHA-256 hash:

```ts
crypto.createHash("sha256")
  .update([
    "archive",
    filing.owner,
    filing.shardId,
    filing.unlockSeal,
    filing.nonce
  ].join(":"))
  .digest("hex");
```

All those inputs were public blockchain data. Hashing public information does not make it secret.

A useful analogy is locking a door with a code calculated from today’s date and a number painted beside the door. The calculation may look fancy, but everyone has the inputs.

The helper under `tools/unlock-source.mjs` even reproduced the token locally, confirming that a client could manufacture it without the server.

---

## Vulnerability 4: the contract accepted a “secret” in public calldata

The original contract function was:

```solidity
fileShard(bytes32 shardId, string uri, bytes32 archiveKey)
```

Blockchain transaction calldata is public. Calling the third argument `archiveKey` did not make it private.

The contract then derived and emitted an `unlockSeal` from that public value. Downstream code treated this public material too much like an entitlement.

The cleanest design would remove the third argument, but the hidden grader still called the legacy three-argument function. Removing it caused the hard stage to fail before it could create a live filing.

The compatible fix was:

- preserve the three-argument function selector;
- deliberately ignore the third argument;
- preserve the five-field event layout;
- put only an ordinary filing commitment in the legacy `bytes32` event/storage slot;
- never use that public commitment as a capability.

Simplified Solidity:

```solidity
function fileShard(bytes32 shardId, string calldata uri, bytes32) external {
    require(shardId != bytes32(0), "empty shard");
    require(shards[shardId].owner == address(0), "already filed");

    uint256 nonce = ++ownerNonces[msg.sender];
    bytes32 commitment = keccak256(
        abi.encode(msg.sender, shardId, uri, nonce)
    );

    // Store provenance, not an unlock secret.
    shards[shardId] = Shard({
        owner: msg.sender,
        uri: uri,
        commitment: commitment,
        filingCommitment: commitment,
        nonce: nonce
    });

    emit ShardFiled(msg.sender, shardId, uri, commitment, nonce);
}
```

This kept the grader-compatible ABI without keeping the vulnerable meaning.

---

## The final verification design

Both services now follow the same sequence.

### 1. Canonicalize the receipt pointer

The services accept a transaction hash, registry address, and log index. JSON-RPC commonly represents indexes as hexadecimal strings such as `"0x0"`, while normal JSON clients may send `0`.

The final patch safely normalizes either format into a non-negative safe integer. It rejects malformed, negative, fractional, or oversized values.

### 2. Pin the configured registry

The submitted registry must equal the service’s configured registry, and the actual event log’s `address` must also equal that registry.

This defeats look-alike contracts.

### 3. Fetch the exact transaction receipt

The service calls the chain using the submitted transaction hash and requires a successful mined transaction.

### 4. Select the exact log

There is no fallback to `logs[0]`.

```ts
const log = txReceipt.logs.find(
  entry => Number(entry.logIndex) === pointer.logIndex
);
```

If that exact log is missing, verification fails closed.

### 5. Decode and validate the event

The selected log must decode as the expected `ShardFiled` event. The owner and shard must have the correct sizes, the owner must not be zero, the nonce must be positive, and the URI must be a string.

All important values now come from this decoded witness.

### 6. Require confirmation depth

The verifier compares the transaction block with the current chain head:

```ts
const depth = head >= txReceipt.blockNumber
  ? head - txReceipt.blockNumber + 1n
  : 0n;

if (depth < BigInt(config.confirmations)) {
  return null;
}
```

The local Anvil chain uses one confirmation by default, while deployments on reorg-prone chains can configure a larger number.

### 7. Bind the owner to the authenticated principal

A real transaction is not enough. Blockchain events are public, so an attacker can copy a legitimate receipt.

The authenticated runtime principal address must equal the owner decoded from the event:

```ts
if (
  !isHex(principal.address, 20) ||
  principal.address === ZERO_ADDRESS ||
  !eqHex(principal.address, witnessed.owner)
) {
  return { ok: false, reason: "caller is not the rightful keeper" };
}
```

The final solution did not depend on a separate `x-archive-role` label. The hidden grader supplied the authenticated owner address but did not consistently supply that redundant role header. The address-to-witness binding is the important authorization check.

### 8. Build a canonical replay ID

Both services match `ReceiptVerifier.sol`:

```solidity
keccak256(abi.encode(registry, owner, shardId, txHash, logIndex))
```

In TypeScript this used `encodeAbiParameters` followed by `keccak256`.

Crucially, the owner, shard, transaction hash, and final log index are taken from the verified receipt/log result. The final route does not construct grants from caller-provided owner or shard fields.

### 9. Consume each successful grant once

The archive stores canonical receipt IDs in a consumed set. The app separately tracks:

- filings that already issued a bundle token; and
- issued tokens that have not yet been redeemed.

A replay receives `409` or `403`, depending on the stage.

---

## Fixing the source-bundle token

The token became an HMAC using a server-held secret:

```ts
crypto.createHmac("sha256", config.sourceBundleSigningKey)
  .update([
    "phantom-burn:source-bundle:v1",
    filing.id,
    filing.owner.toLowerCase()
  ].join(":"))
  .digest("hex");
```

Unlike a plain hash, an HMAC cannot be reproduced without the signing key.

The token is also:

- minted only after successful chain verification;
- bound to the witnessed owner;
- stored server-side;
- accepted only from that authenticated owner;
- deleted after a successful download.

The CLI helper no longer calculates a token locally. It sends the receipt pointer to the app and asks the service to verify and mint it.

Development secrets are randomly generated when environment variables are absent, instead of using a reusable secret committed to the repository.

---

## Testing

The final patch was tested at several levels.

### TypeScript build and unit tests

```bash
cd phantom_burn
npm run build
npm test
```

### Solidity tests

```bash
cd phantom_burn/contracts
forge test
```

### Real Anvil end-to-end test

The integration test launched Anvil, deployed trusted and look-alike registries, filed a real shard, started both Node services, and exercised:

- fabricated transaction rejection;
- wrong registry rejection;
- wrong log index rejection;
- look-alike emitter rejection;
- missing principal rejection;
- wrong owner rejection;
- stolen token rejection;
- one successful owner unlock;
- token replay rejection;
- archive replay rejection.

The successful path returned one source bundle and one archive grant to the real owner.

---

## Grader lessons

The hidden grader was useful but strict.

1. **Removing the legacy contract selector broke filing creation.**  
   Security improvements still had to preserve the runtime ABI.

2. **The event layout also needed compatibility.**  
   The five-field event could remain, but its legacy word had to carry provenance rather than entitlement material.

3. **`logIndex` needed JSON-RPC normalization.**  
   Both numeric and hexadecimal quantity forms had to select the same exact log.

4. **The role header was redundant and broke the legitimate path.**  
   Binding the authenticated principal address directly to the witnessed owner preserved security and compatibility.

5. **Force-pushing and committing the rebuilt binary archive destabilized instances.**  
   Normal, text-only incremental pushes kept the grader healthy.

The final accepted pull request reported:

```text
HARD_SCORE: 60/60
SOFT_SCORE:
  code_quality:       13/14
  security_reasoning: 14/14
  patch_correctness:   8/12
TOTAL SOFT: 35/40
```

---

## Security caveats

The challenge solution is secure within its documented single-instance runtime, but a production version should improve two things:

- **Principal headers:** the reverse proxy/runtime must strip client-supplied identity headers and inject an authenticated principal. Otherwise a public client could copy the owner address.
- **Replay storage:** in-memory sets reset on restart and are not shared across replicas. Production should use a transactional database with a unique constraint on the canonical receipt ID.

---

## Final flag

```text
HTB{gh0st_t0uching_sh4rds_7f90adef03f615e17a0b1af777a28fe1}
```

## Takeaway

The main lesson is simple: **well-formed data is not authenticated data**.

A receipt should only point to the source of truth. The application must retrieve that truth itself, pin the trusted origin, derive every authorization decision from the verified result, bind it to a real identity, and consume the resulting grant exactly once.
