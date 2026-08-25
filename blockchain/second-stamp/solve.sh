#!/usr/bin/env bash
set -euo pipefail

# Required package storage IDs and challenge object IDs.
: "${SETUP_PACKAGE:?set SETUP_PACKAGE}"
: "${V1_PACKAGE:?set V1_PACKAGE to the original/v1 sharehouse package ID}"
: "${V3_PACKAGE:?set V3_PACKAGE to the v3 sharehouse package ID}"
: "${CHALLENGE:?set CHALLENGE}"
: "${SHAREHOUSE:?set SHAREHOUSE}"
: "${GLOBAL_CONFIG:?set GLOBAL_CONFIG}"
: "${VERSIONED:?set VERSIONED}"
: "${OLD_COUNTER_POOL:?set OLD_COUNTER_POOL}"
: "${TRAVEL_COUNTER_POOL:?set TRAVEL_COUNTER_POOL}"
: "${ORACLE:?set ORACLE}"

SUI="${SUI:-sui}"
CLIENT_CONFIG_ARGS=()
if [[ -n "${SUI_CLIENT_CONFIG:-}" ]]; then
    CLIENT_CONFIG_ARGS=(--client.config "$SUI_CLIENT_CONFIG")
fi

PLAYER="${PLAYER:-$("$SUI" client "${CLIENT_CONFIG_ARGS[@]}" active-address)}"
GAS_BUDGET="${GAS_BUDGET:-500000000}"

# Claim the starter coins, mint an old-v1 claim mark using the understated v1
# AUM, redeem it using the v3 travel-aware withdrawal, and reinvest the loot.
# Three rounds put every checked reserve below the challenge residual limits.
ptb=(
    --move-call "$SETUP_PACKAGE::setup::claim" "@$CHALLENGE"
    --assign funds
)

for _round in 1 2 3; do
    ptb+=(
        --move-call "$V1_PACKAGE::accounting::refresh_aum"
            "@$SHAREHOUSE" "@$VERSIONED" "@$OLD_COUNTER_POOL" "@$ORACLE" @0x6

        --move-call "$V1_PACKAGE::accounting::deposit"
            "@$SHAREHOUSE" "@$GLOBAL_CONFIG" "@$VERSIONED" funds.0 funds.1
        --assign lp

        --move-call "$V3_PACKAGE::withdraw::new_withdraw_cert"
            "@$SHAREHOUSE" "@$GLOBAL_CONFIG" "@$VERSIONED" lp
        --assign receipt

        --move-call "$V3_PACKAGE::withdraw::process_old_counter"
            "@$SHAREHOUSE" receipt "@$OLD_COUNTER_POOL"
        --move-call "$V3_PACKAGE::withdraw::withdraw_travel_counter"
            "@$SHAREHOUSE" receipt "@$TRAVEL_COUNTER_POOL"
        --move-call "$V3_PACKAGE::withdraw::collect_position_fees"
            "@$SHAREHOUSE" receipt "@$OLD_COUNTER_POOL" "@$TRAVEL_COUNTER_POOL"
        --move-call "$V3_PACKAGE::withdraw::collect_position_rewards"
            "@$SHAREHOUSE" receipt "@$OLD_COUNTER_POOL" "@$TRAVEL_COUNTER_POOL"
        --move-call "$V3_PACKAGE::withdraw::process_buffer"
            "@$SHAREHOUSE" receipt
        --move-call "$V3_PACKAGE::withdraw::complete_withdraw"
            "@$SHAREHOUSE" receipt
        --assign funds
    )
done

ptb+=(
    --transfer-objects '[funds.0,funds.1]' "@$PLAYER"
    --gas-budget "$GAS_BUDGET"
)

if [[ "${DRY_RUN:-0}" == 1 ]]; then
    ptb+=(--dry-run)
elif [[ "${JSON:-0}" == 1 ]]; then
    ptb+=(--json)
fi

"$SUI" client "${CLIENT_CONFIG_ARGS[@]}" ptb "${ptb[@]}"
