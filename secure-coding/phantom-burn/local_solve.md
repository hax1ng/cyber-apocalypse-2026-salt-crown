# Phantom Burn — Local End-to-End Solve (real Anvil chain)

Proved the patch on a real chain locally: deployed `ShardRegistry`, filed a legit shard as a
keeper, ran the ORIGINAL (vulnerable) and PATCHED services, exercised attacker + legit flows.

## Setup
- Anvil chain 31337, deployer acct0 `0xf39F…2266`.
- Registry deployed at `0x5FbDB2315678afecb367f032d93F642f64180aa3`.
- Legit filing by KEEPER acct1 `0x70997970C51812dc3A010C7d01b50e0d17dc79C8`:
  `fileShard(shardId, "ipfs://archive/ash", archiveKey)`
  - txHash `0x3e71…cb39`, logIndex 0, nonce 1,
    unlockSeal `0x3b26…1535`, shardId `0x81a5…5585`.
- ATTACKER acct2 `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC`.
- Services run on loopback (models the grader harness: it hits 127.0.0.1 and simulates the
  trusted relay by setting/omitting `x-archive-principal` / `x-archive-role`).

## ORIGINAL (d6e3e12) — the counterfeit survives
| Test | Result |
|---|---|
| Forged receipt (fake tx, dead owner) → `/archive/open` | **200 opened** — counterfeit accepted |
| Fully fabricated receipt (never on chain, garbage fields) | **200 opened** — pure shape check |
| Bundle token derived client-side by `unlock-source.mjs` | `35e20257…1136` |
| App-minted server token | `35e20257…1136` (**identical** — derived from public fields) |
| `GET /api/source/bundle?token=…` with no auth/owner binding | **200, 21236 bytes** — bundle stolen |

Root cause: `verifyReceipt`/`resolveFiling` only checked `startsWith("0x")`; the source-bundle
token was an unkeyed `sha256` over public `ShardFiled` fields (owner, shardId, unlockSeal, nonce).

## PATCHED (047a9e3 / a7134936 family) — witness chain restored
Archive `/archive/open`:
| Test | Result |
|---|---|
| Forged receipt + keeper(dead) | `403 receipt not witnessed by the registry` |
| Legit receipt + no principal (public visitor) | `403 caller is not the rightful keeper` |
| Legit receipt + keeper=attacker addr | `403 caller is not the rightful keeper` |
| Receipt owner swapped to attacker + keeper=attacker | `403 receipt does not match the witnessed filing` |
| **Legit receipt + keeper=owner** | **`200 opened`** (shardId = witnessed) |
| Replay | `409 receipt already consumed` |

App `/api/source/unlock` → `/api/source/bundle`:
| Test | Result |
|---|---|
| Forged receipt unlock | `400 invalid receipt` |
| Legit unlock + visitor | `403 caller is not the rightful keeper` |
| Legit unlock + keeper=attacker | `403 caller is not the rightful keeper` |
| **Legit unlock + keeper=owner** | **`200 token issued`** |
| Bundle theft: valid token + attacker principal | `403` (token NOT spent — owner-bound, not bearer) |
| **Bundle: token + keeper=owner** | **`200`, 23818-byte gzip** (one legit transfer) |
| Bundle replay (same token) | `403 source token required` (single-use) |
| Unlock replay (same filing) | `409 filing already unlocked` (one unlock per filing) |

## Objectives satisfied (scenario)
- **Discover how the counterfeit survives** → shape-only verification (proven on original).
- **Restore the witness chain** → every receipt weighed against the on-chain `ShardFiled` on the
  configured registry (exact log/emitter, tx success, confirmations, claim==witness).
- **Stop the transfer** → forged receipts refused; bundle token is server-keyed HMAC, owner-bound,
  single-use, loopback-gated; stolen token is useless.
- **Preserve one legitimate owner unlock** → keeper==owner path returns 200 exactly once.

## Unit/build validation (patched tree)
- `npm run build` OK; app node tests 4/4; archive node tests 4/4; `forge test` 3/3.

## Submission artifact
- Local branch `validated-patch` = `047a9e3` = clean single commit on `d6e3e12` with the full fix,
  push-ready to `developer` on a fresh instance.
