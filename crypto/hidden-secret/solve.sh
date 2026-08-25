#!/usr/bin/env bash
set -euo pipefail

# The 210-dimensional lattice reduction is intentionally offloaded.
remote=/tmp/hidden_secret_solve
ssh kracken "command -v sage-run >/dev/null && command -v flatter >/dev/null; rm -rf '$remote'; mkdir -p '$remote'"
scp output.txt dump_lattice.sage parse_flatter.sage recover_coeffs.sage \
    extract_secret.sage "kracken:$remote/" >/dev/null

ssh kracken "cd '$remote' &&
    sage-run dump_lattice.sage &&
    flatter -delta 0.99 lattice.fplll lattice_reduced.fplll &&
    sage-run parse_flatter.sage &&
    sage-run recover_coeffs.sage &&
    sage-run extract_secret.sage"

scp "kracken:$remote/flag.txt" flag.txt >/dev/null
cat flag.txt
