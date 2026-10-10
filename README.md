# BidTrace: Cryptographic Deadline-Lock Protocol for Competitive Procurement

[![Tests](https://img.shields.io/badge/tests-32%20passed-brightgreen.svg)]()
[![Solana Integration](https://img.shields.io/badge/anchor--test-8%20passed-brightgreen.svg)]()
[![Framework](https://img.shields.io/badge/Solana-Anchor%200.30-blue.svg)]()
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()

> **Master Technical & Hackathon Vetting Dossier:**  
> For the complete, all-inclusive architectural specification, Anchor account layouts, cryptographic formulas, hybrid bond engine, and Colosseum audit rubric, see:  
> 📄 **[`BIDTRACE_MASTER_DOSSIER.md`](file:///C:/Users/ujjwa/.gemini/antigravity/scratch/bidtrace/BIDTRACE_MASTER_DOSSIER.md)**

BidTrace makes one critical procurement property mathematically and independently verifiable: **after the bid submission deadline, can any participant, auditor, or public monitor prove whether a specific bid belonged to the set of bids committed prior to the deadline, and whether the set of bids subsequently evaluated matches that frozen set without relying on trust in the procurement database?**

---

## 1. Core Architectural Flaw Resolutions

* **Flaw A (Selective Exclusion / Censorship) Resolved:**  
  Eliminated centralized operator intake. Bidders write directly to individual, non-custodial Program Derived Addresses (PDAs) on Solana derived from `[b"bid", tender_pda, bidder_pubkey]`. The Anchor program checks `clock.slot <= tender.submission_deadline_slot`. A malicious database administrator cannot delete, omit, or censor any bidder's commitment.

* **Flaw B (All-or-Nothing Opening Deadlock) Resolved:**  
  Replaced brittle single-root comparisons with **independent leaf-by-leaf reveals** and on-chain state counters (`total_committed`, `total_revealed`). If a bidder disappears, loses their private key, or defaults, other honest bidders reveal cleanly and the tender proceeds without deadlocking.

* **Flaw C (Early-Award Lockout) Resolved:**  
  Introduced an explicit **Reveal Window** (`reveal_deadline_slot`) and gated `record_award`. An authority cannot prematurely award a tender to an early revealer while unrevealed bids remain within the active reveal window (`clock.slot > reveal_deadline_slot || total_revealed == total_committed`).

* **Flaw D (Free Option Walkaway) Resolved:**  
  Integrated an escrowed **Bid Bond** (`bid_deposit`) into each commitment. Bidders who reveal successfully receive their deposit refund; unrevealed defaulters forfeit their bond.

* **Domain-Separated Cryptographic Binding:**  
  Every commitment hash explicitly binds `TENDER_PUBKEY`, `BIDDER_PUBKEY`, `SALT`, `CIPHERTEXT_HASH`, and `BID_AMOUNT` under `"BIDTRACE_V1"` to prevent cross-tender replay attacks.

* **Air-Gapped Offline Verifier:**  
  Anyone holding a `proof_bundle.json` can verify bid validity against raw Solana accounts with the BidTrace server completely powered down.

---

## 2. Protocol Architecture & Layers

The repository cleanly separates the protocol specification from its reference simulator:

| Layer | Component | Path | Description |
| :--- | :--- | :--- | :--- |
| **Layer 1** | **Anchor Smart Contract (Rust)** | `programs/bidtrace/` | Canonical on-chain state machine enforcing slot deadlines, PDA derivations, bond escrow, and anti-lockout gating. |
| **Layer 2** | **Reference Model & Simulator (Python)** | `bidtrace_py/` | Deterministic local simulation of the Solana ledger, PDA derivations, and AES-256-GCM / SHA-256 cryptographic pipeline. |
| **Layer 3** | **Air-Gapped Offline Verifier** | `bidtrace_py/verifier.py` & `verifier/verify.ts` | Independent audit tools verifying standalone JSON bundles against public ledger accounts with zero backend dependency. |

### 2.1 Live On-Chain Devnet Deployment

* **Network:** Solana Devnet
* **Program ID:** [`x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ`](https://explorer.solana.com/address/x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ?cluster=devnet)
* **Deployment Transaction:** [`oNcnMJcLo8HV...7kgpg8`](https://explorer.solana.com/tx/oNcnMJcLo8HV6ZByYYL9d5JeAzG6UzohbHyYNLJFbzkBBhHw53oUZnDE2WYPLWUbxrxuqzoqTnoPWA2CP7kgpg8?cluster=devnet)
* **Deployed Slot:** `508,757,167`
* **ProgramData Address:** [`31T65nDyKp5Jyok1AE4YsCLH1nxEbnGWVBqvZjtf9iYp`](https://explorer.solana.com/address/31T65nDyKp5Jyok1AE4YsCLH1nxEbnGWVBqvZjtf9iYp?cluster=devnet)
* **Upgrade Authority:** [`GFRRqHMPekLkEUPDzwLXnBoETUU1EFrfFoZxiCWUwSzU`](https://explorer.solana.com/address/GFRRqHMPekLkEUPDzwLXnBoETUU1EFrfFoZxiCWUwSzU?cluster=devnet)
* **Program Loader:** `BPFLoaderUpgradeab1e11111111111111111111111`
* **Compiled SBF Binary:** `target/deploy/bidtrace.so` (280,608 bytes)

---

## 3. Project Directory Structure

```text
bidtrace/
├── Anchor.toml                     # Anchor workspace configuration
├── Cargo.toml                      # Workspace Cargo configuration
├── README.md                       # Protocol overview & quickstart
├── PROJECT_DOCUMENTATION.md        # Comprehensive technical specification & dossier
├── run_demo.py                     # 3-minute end-to-end live demonstration script
├── server.py                       # Local protocol server & browser UI backend
├── public/                         # Web dashboard interface (HTML/JS/Tailwind)
│   └── index.html
├── programs/
│   └── bidtrace/                   # Solana Anchor Program (Rust)
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs              # Instruction entrypoints
│           ├── state.rs            # Tender & BidCommitment account structures
│           ├── errors.rs           # Error definitions (RevealWindowActive, etc.)
│           └── instructions/
│               ├── initialize_tender.rs
│               ├── commit_bid.rs
│               ├── lock_tender.rs
│               ├── reveal_bid.rs
│               └── record_award.rs
├── tests/
│   ├── test_engine.py              # Unit & adversarial test suite (6 tests)
│   ├── test_exploit.py             # Anti-lockout & bid bond verification tests (2 tests)
│   └── bidtrace.ts                 # Anchor TypeScript integration tests
├── bidtrace_py/                    # Python Reference Engine & CLI
│   ├── crypto.py                   # AES-256-GCM, SHA-256 domain hashing, Ed25519
│   ├── ledger.py                   # Deterministic reference state machine & ledger
│   ├── cli.py                      # Interactive CLI for bidders & authorities
│   └── verifier.py                 # Standalone air-gapped offline verifier
└── verifier/
    └── verify.ts                   # Standalone TypeScript verifier
```

---

## 4. Quickstart & Verification

### 1. Run the Full Automated Test Suite
Executes 8 tests covering happy paths, adversarial attacks, anti-lockout gating, and air-gapped verification:
```bash
python -m unittest tests/test_engine.py
python -m unittest tests/test_exploit.py
```

### 2. Run the 3-Minute Live Terminal Demo
Demonstrates tender creation, 3 bidder commitments, deadline freeze, two live adversarial attack failures, award recording, and air-gapped offline audit:
```bash
python run_demo.py
```

### 3. Launch the Interactive Dashboard
```bash
python server.py
# Open your browser at: http://localhost:8000
```

### 4. Using the BidTrace CLI
```bash
# 1. Authority initializes tender with submission deadline (+50 slots) and reveal deadline (+100 slots)
python -m bidtrace_py.cli init-tender --id "T-2026-001" --submission-deadline-slots 50 --reveal-deadline-slots 100 --bid-deposit 1000

# 2. Bidder submits encrypted bid before submission deadline
python -m bidtrace_py.cli submit --tender <TENDER_PDA> --bidder-name "ACME Corp" --amount 4200000

# 3. Advance consensus slot clock past submission deadline
python -m bidtrace_py.cli advance-slots --slots 60

# 4. Anyone locks the tender (opens reveal window)
python -m bidtrace_py.cli lock-tender --tender <TENDER_PDA>

# 5. Bidder reveals bid post-deadline using receipt
python -m bidtrace_py.cli reveal --receipt bidder_receipt.json

# 6. Standalone Offline Verifier (zero backend needed)
python -m bidtrace_py.verifier bidder_receipt.json ledger_state.json
```

---

## 5. Security & Governance Notes

* **Upgrade Authority:** In production, smart contract upgrade authority must be permanently revoked (`solana program set-upgrade-authority <PROGRAM_ID> --final`) or managed via a multi-signature timelock (e.g., Squads Protocol).
* **Consensus Slot Timing:** Deadlines are enforced using strictly monotonic Solana validator consensus slots (`Clock::get()?.slot`), avoiding Unix timestamp drift. Bidders should account for nominal slot times ($\approx 400\text{ms}$) and network conditions when submitting.
