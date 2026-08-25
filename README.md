# Cyber Apocalypse CTF 2026: The Salt Crown — Writeups

Writeups and solve scripts for **Hack The Box — Cyber Apocalypse CTF 2026: *The Salt Crown***.

Each challenge folder contains a full writeup (`README.md`) plus the exploit / solve
scripts used to capture the flag. The writeups are written to be beginner-friendly —
they explain not just *what* was done, but *why* each step works.

- **Event:** Cyber Apocalypse CTF 2026: The Salt Crown (Hack The Box)
- **Flag format:** `HTB{...}`
- **Solved:** 20 challenges across 11 categories

---

## Challenges

### 🤖 AI / ML
| Challenge | Flag | Writeup |
|---|---|---|
| Custody Engine | `HTB{5k1lls_h4rn355_5t33r1ng_pr1s0n_br34k}` | [writeup](ai-ml/custody-engine/) |
| Forked Tongue | `HTB{th3_h3r4ld_l13s_but_th3_m3rg35_d0nt}` | [writeup](ai-ml/forked-tongue/) |

*Custody Engine — steer an AI prison-administrator agent by editing a "field report" skill so it runs attacker instructions and leaks the flag. Forked Tongue — a malicious tokenizer hides a second vocabulary; the innocent-looking model actually emits the flag.*

### ⛓️ Blockchain
| Challenge | Flag | Writeup |
|---|---|---|
| Caldrin's Day Away | `HTB{inquir3y_0ne_c4ldr1n_s0lv3d_f91f16f39a20a60c10361d75ae9b359d}` | [writeup](blockchain/caldrins-day-away/) |
| Second Stamp | `HTB{w1th_gr34t_upgr4d34b1l1ty_c0m3s_gr34t_cr0ss-v3rs10n_r1sk_1c1c0ce153edeca56331de214181671f}` | [writeup](blockchain/second-stamp/) |
| The Far Orchard | `HTB{d4m4s_f4r_s34ls_br0k3_b3n34th_g0ld_l34v3s_2662911efb20f0867cf54be8359b9f74}` | [writeup](blockchain/the-far-orchard/) |

*Second Stamp — an upgradeable proxy still exposes callable v1 code while the shared `Versioned` object reports version 1, enabling a cross-version exploit. The Far Orchard — a ZK/Merkle-circuit challenge where a forged witness breaks the seal.*

### 🔐 Crypto
| Challenge | Flag | Writeup |
|---|---|---|
| Ancient Artifacts | `HTB{zl1b_func710n5_r34lly_5houldn7_b3_us3d_1n_cryp70!}` | [writeup](crypto/ancient-artifacts/) |
| Hidden Secret | `HTB{too_few_samples_too_much_lattice_42874424b5e32fabd174491e1ba6cc85}` | [writeup](crypto/hidden-secret/) |

*Ancient Artifacts — `zlib.adler32` / `crc32` are (mis)used as cryptographic hashes; they're trivially forgeable. Hidden Secret — a lattice attack recovers secret degree-39 ternary polynomials from just seven evaluations, then a polynomial GCD yields the AES key.*

### 🔎 Forensics
| Challenge | Flag | Writeup |
|---|---|---|
| Harvesting Severed Threads | `HTB{v0l4t1l3_1uk52_d3crypt10n_w1th_k3rn3l_k3yr1ng_4nd_w1r3gu4rd_3xf1l_brrr_brrr_brrr!!}` | [writeup](forensics/harvesting-severed-threads/) |

*Volatility memory forensics: pull a LUKS key from the kernel keyring, decrypt a Serpent-XTS disk, and decrypt WireGuard exfil traffic from the capture.*

### 🔧 Hardware
| Challenge | Flag | Writeup |
|---|---|---|
| A Fault in the Cinder | `HTB{a_f4ls3_n0t3_0p3ns_th3_tru3_s34l}` | [writeup](hardware/a-fault-in-the-cinder/) |

*A fault-injection challenge against a custody coffer — a "false note" (glitch) opens the true seal without burning the protected record.*

### 🏭 ICS
| Challenge | Flag | Writeup |
|---|---|---|
| Ash-Vault Interlock | `HTB{4sh_v4ult_1nt3rl0ck_s3aled_cef4c0c1fc45fb974a9ce41bfb885c73}` | [writeup](ics/ash-vault-interlock/) |

*A simulated industrial plant: a broken level sensor tricks the PLC into overfilling a brine tank — abuse the interlock logic to release the sealed gate.*

### 📱 Mobile
| Challenge | Flag | Writeup |
|---|---|---|
| Mobile Overstrike | `HTB{0v3rstr1k3_r3cut_th3_w0rld_s34l_by_f0rg1ng_th3_mark}` | [writeup](mobile/mobile-overstrike/) |
| Proofmark | `HTB{p3rf3ct_f4c3_tru3_sp1n3}` | [writeup](mobile/proofmark/) |
| SaltCrown | `HTB{p3rf3ct_f4c3_wr0ng_sp1n3}` | [writeup](mobile/saltcrown/) |

*SaltCrown — a Godot 4.7 + C# Android game; reverse a stripped native GDExtension PRNG to derive "phase buckets" and unseal an XOR-locked blob. Proofmark & Overstrike — forge the "true seal" mark that the in-game Registry will accept.*

### 💥 Pwn
| Challenge | Flag | Writeup |
|---|---|---|
| Heavy is the Krown | `HTB{h34vy_15_th3_kr0wn_7h4t_w34r5_th3_w31gh7_0f_4uth0r17y}` | [writeup](pwn/heavy-is-the-krown/) |
| Words from the Past | `HTB{f1v3_byt3s_0f_pr3c1s10n_t0 rul3_th3m_4ll_11aa4118ee4cd2c62d41e23868aea1e5}` | [writeup](pwn/words-from-the-past/) |

*Heavy is the Krown — a custom Linux kernel driver (`/dev/krown`) with a memory-corruption bug, escalated to root to read the flag. Words from the Past — chain two stages of *exactly five bytes* of shellcode (the first must start with a `call`) into a working exploit.*

### 🔬 Reversing
| Challenge | Flag | Writeup |
|---|---|---|
| CorpSyncAudit | `HTB{d473_71m3_4nd_64ckd00r5}` | [writeup](rev/corpsyncaudit/) |
| Secondhand | `HTB{WHY_S00_345Y_H0N}` | [writeup](rev/secondhand/) |

*CorpSyncAudit — a fake AD-replication auditor smuggles shellcode inside bogus timestamps/regions; decode it to a Windows stager and recover a base64 flag from a `net user` command. Secondhand — ignore the obvious decoy flags; the real path needs a strange 8-byte input that self-decrypts a function and prints the true flag.*

### 🛡️ Secure Coding
| Challenge | Flag | Writeup |
|---|---|---|
| Phantom Burn | `HTB{gh0st_t0uching_sh4rds_7f90adef03f615e17a0b1af777a28fe1}` | [writeup](secure-coding/phantom-burn/) |

*An on-chain "shard receipt" app — a validation flaw lets you forge a receipt and open the protected source bundle. Includes the fix as a patch.*

### 🌐 Web
| Challenge | Flag | Writeup |
|---|---|---|
| Signetry | `HTB{the_se4l_certifies_canon_n0t_contraband_4c758db499a41e839f50a0584f709581}` | [writeup](web/signetry/) |
| CrownSpire Bellworks | `HTB{d0n't_trust_th3_libraries_y0u_us3_a9b818a230e45982dbf2448f13a8715e}` | [writeup](web/crownspire-bellworks/) |

*Signetry — a multi-service chain starting from an empty-HMAC-key JWT that lets you forge a password-reset token (Go gateway + React + Apache + Redis + Java/DL4J registry). CrownSpire Bellworks — a parser-differential chain: confuse Node.js and PHP about where an email ends, steal the API key, become admin, then reach SQL.*

---

## Repository Layout

```
<category>/<challenge>/
├── README.md          # the writeup
└── solve.*            # exploit / solve script(s), where applicable
```

Large challenge artifacts (binaries, APKs, disk images, memory dumps, PCAPs,
`node_modules`, etc.) are intentionally **not** committed — the writeups explain
where they come from and how to reproduce the solve.

## Disclaimer

These writeups are for educational purposes. All techniques target intentionally
vulnerable challenges built for the CTF. The CTF has concluded; nothing here is
intended for use against systems you do not own or have permission to test.
