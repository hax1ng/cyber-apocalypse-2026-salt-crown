# Second Stamp Writeup

## The short version

The Sharehouse had been upgraded three times, but its old v1 code was still
callable. Even worse, the shared `Versioned` object still said version `1`.

That let us:

1. Ask **v1** to calculate the Sharehouse value.
2. Let v1 forget about the enormous new travel-counter pool.
3. Buy very cheap claim-mark/LP tokens using that incorrect valuation.
4. Give those old tokens to **v3**, which happily redeemed them against both
   the old and travel pools.
5. Reinvest the stolen coins and repeat three times.

In everyday terms, an old cashier sold us ownership tickets using an outdated
inventory sheet, then the new cashier accepted those tickets against the full
warehouse.

---

## Understanding the challenge without knowing blockchain

The challenge is basically a vault with several piles of money:

- A small Sharehouse buffer
- An old-counter liquidity pool
- A much larger travel-counter liquidity pool
- Some fees and rewards

Users deposit two currencies:

- `PALE_WAX`, with 18 decimal places
- `GOLD_FLECK`, with 6 decimal places

In return, users receive `CLAIM_MARK` tokens. These behave like shares in the
whole vault. If someone owns 10% of the claim marks, they can withdraw roughly
10% of the assets.

The challenge is solved when nearly everything has been drained:

```move
const RESIDUAL_LIMIT_A: u64 = 25_000_000_000_000_000;
const RESIDUAL_LIMIT_B: u64 = 100_000_000;
```

Every checked WAX balance must be at most `0.025 WAX`, and every GOLD balance
must be at most `100 GOLD`.

---

## Why the three Sharehouse versions matter

The source contains three versions of the same package:

```text
v1/
v2/
v3/
```

v3 adds the travel counter and improves the accounting. Normally, that sounds
safe: the latest code knows about all the assets, so it should price claim
marks correctly.

However, Sui package upgrades do not delete the older package objects. A
transaction can still call a historical package by using that version's
package storage ID.

At the same time, upgraded types preserve their original identity. Therefore,
a `CLAIM_MARK` created through v1 is still the same kind of token that v3
expects.

This is useful for compatibility, but dangerous if old entry points are not
properly disabled.

---

## Bug 1: the version object never left v1

The protocol version starts at `1`:

```move
public fun new(ctx: &mut TxContext): Versioned {
    Versioned {
        id: object::new(ctx),
        version: 1,
    }
}
```

The old v1 guard checks:

```move
const SUPPORTED_VERSION: u64 = 1;

public fun assert_supported(versioned: &Versioned) {
    assert!(
        versioned.version <= SUPPORTED_VERSION,
        EUnsupportedVersion,
    );
}
```

There are functions capable of changing the version internally, but the
deployment never moves the shared object to version 2 or 3.

As a result:

```text
versioned.version = 1
SUPPORTED_VERSION = 1
1 <= 1 = true
```

So v1 remains fully usable after both upgrades.

The `<=` design is also risky. A safer design would require an exact version:

```move
assert!(versioned.version == SUPPORTED_VERSION, EUnsupportedVersion);
```

The deployment would then update the shared version during every upgrade.

---

## Bug 2: v1 values only the old design

The v1 AUM function calculates the Sharehouse's total value:

```move
public fun calculate_aum(
    house: &mut Sharehouse,
    old_counter_pool: &old_counter::pool::Pool<...>,
    oracle: &witness_oracle::oracle::Oracle,
    clock: &Clock,
): u128 {
    let price = witness_oracle::oracle::price_e6(oracle);

    let selected_bin =
        old_counter::pool::quote_bin_from_price(price);

    old_counter::pool::refresh_position_info_v1(
        old_counter_pool,
        sharehouse::old_counter_position_mut(house),
        price,
    );

    let (position_base, position_quote) =
        old_counter::pool::last_amounts(
            sharehouse::old_counter_position(house),
        );

    let (buffer_base, buffer_quote) =
        sharehouse::buffer_amounts(house);

    math::base_value_in_quote(
        position_base + buffer_base,
        price,
    ) + ((position_quote + buffer_quote) as u128)
}
```

There are two important consequences.

First, the configured price makes the old quote calculation select bin `101`.
The position only covers bin `100`, so the accounting falls back to tiny
maintenance amounts:

```move
position.accounted_a = MAINTENANCE_MARGIN_A;
position.accounted_b = MAINTENANCE_MARGIN_B;
```

Second, v1 was written before the travel counter existed. It does not include
the travel position at all.

The travel pool initially holds:

```text
14 WAX
55,000 GOLD
```

Yet v1's initial recorded AUM is only:

```text
51,002,501 raw GOLD units
```

Since GOLD has six decimal places, that is about `51 GOLD`.

The old cashier thinks the warehouse is worth roughly 51 GOLD while tens of
thousands of GOLD and many WAX are actually available.

---

## Bug 3: v3 accepts the cheaply minted shares

After v1 records the tiny AUM, we deposit through v1:

```move
let lp_amount = math::mul_div_floor(
    before_supply as u128,
    deposit_value_quote,
    denominator,
);
```

The denominator is the incorrect v1 AUM. A low denominator means the deposit
mints far too many claim marks.

We then pass those tokens to v3:

```move
sharehouse::withdraw::new_withdraw_cert(...)
```

The v3 withdrawal profile processes every asset source:

```move
process_old_counter(...)
withdraw_travel_counter(...)
collect_position_fees(...)
collect_position_rewards(...)
process_buffer(...)
complete_withdraw(...)
```

Nothing records that the LP was priced using v1 rules. To v3, it is simply a
valid `Coin<CLAIM_MARK>`.

---

## Building the exploit

The exploit begins by claiming the player's starter coins:

```text
0.001 WAX
1 GOLD
```

One attack round then performs:

```text
v1::accounting::refresh_aum
v1::accounting::deposit
v3::withdraw::new_withdraw_cert
v3::withdraw::process_old_counter
v3::withdraw::withdraw_travel_counter
v3::withdraw::collect_position_fees
v3::withdraw::collect_position_rewards
v3::withdraw::process_buffer
v3::withdraw::complete_withdraw
```

The output coins become the deposit for the next round.

All three rounds fit in one Sui programmable transaction block, or PTB. This is
helpful because the entire attack is atomic: either every step succeeds, or
none of the state changes are committed.

The complete PTB builder is in [`solve.sh`](./solve.sh).

---

## Why three rounds?

The first deposit is small, so it only creates a modest share. However, that
share is redeemed against the massive travel pool, giving us much more money
than we started with.

We then feed that money back into the same bad v1 pricing calculation. Each
round gives us a dramatically larger percentage of the remaining assets.

The observed rounds were:

| Round | Deposit value used by v1 | Claim marks minted |
|---:|---:|---:|
| 1 | 3,500,000 | 411,744 |
| 2 | 6,110,345,480 | 386,786,598 |
| 3 | 93,602,497,407 | 5,925,026,762 |

After three rounds, every balance checked by `is_solved` was below its limit:

| Location | Remaining WAX | Remaining GOLD |
|---|---:|---:|
| Sharehouse buffer | 14,978,925,745,857,256 | 57,339,597 |
| Fees | 0 | 0 |
| Old counter | 14,352,585,350,395 | 35,882 |
| Travel counter | 202,404,240,558,160 | 795,226 |

Remember that these are raw integer amounts. The WAX limit is
`25,000,000,000,000,000`, while the GOLD limit is `100,000,000`, so all four
rows pass.

---

## Remote result

The final atomic transaction succeeded with digest:

```text
B1SHzRC8sfaizxbSvCES6zH44qzH7j4BRfSsVz7GvfkS
```

The instance returned:

```text
HTB{w1th_gr34t_upgr4d34b1l1ty_c0m3s_gr34t_cr0ss-v3rs10n_r1sk_1c1c0ce153edeca56331de214181671f}
```

---

## How this should be fixed

Several protections should be used together:

1. **Bump the shared version during every upgrade.**
2. **Require exact version equality**, not `version <= supported_version`.
3. **Put the version check on every state-changing public function.**
4. **Do not let old accounting output remain redeemable under new rules.**
5. **Migrate or explicitly invalidate old claim marks when their backing model
   changes.**
6. **Test old package IDs after upgrades.** An upgrade review should ask, “What
   happens if someone deliberately calls v1?”

The lesson is that an upgrade does not automatically make old rules disappear.
When old and new code can touch the same assets, version compatibility becomes
part of the security boundary.
