# BidTrace

**The Incorruptible Cryptographic Deadline-Lock Protocol for Procurement**

BidTrace makes one critical procurement claim independently verifiable: **after the bid submission deadline, can a bidder, auditor, or public monitor prove whether a particular bid belonged to the set of bids committed before the deadline, and whether the set of bids later opened matches that frozen set without relying on trust in the procurement database?**

---

## 1. Key Architectural Problem Resolutions

* **Flaw A (Selective Exclusion / Censorship) Resolved:**  
  Eliminated centralized operator intake. Bidders write directly to individual, non-custodial PDAs on Solana derived from `[b"bid", tender_pda, bidder_pubkey]`. The Anchor program checks `clock.slot <= tender.deadline_slot`. A malicious database administrator cannot delete, omit, or censor any bidder's commitment.
* **Flaw B (All-or-Nothing Opening Deadlock) Resolved:**  
  Replaced fragile single-root comparisons with **independent leaf-by-leaf reveals** and on-chain state counters (`total_committed`, `total_revealed`). If a bidder vanishes, loses their key, or defaults, other honest bidders reveal cleanly and the tender proceeds without deadlocking.
* **Domain Separation:**  
  Every commitment hash explicitly binds `TENDER_PUBKEY`, `BIDDER_PUBKEY`, `SALT`, `CIPHERTEXT_HASH`, and `BID_AMOUNT` to prevent cross-tender replay attacks.
* **Zero-Backend Air-Gapped Verifier:**  
  Anyone holding a `proof_bundle.json` can verify bid validity against raw Solana accounts with the BidTrace backend completely shut down.

---

## 2. Project Layout

```text
bidtrace/
├── Anchor.toml                     # Anchor configuration
├── Cargo.toml                      # Workspace Cargo configuration
├── README.md                       # Documentation & usage guide
├── run_demo.py                     # 3-minute live hackathon demo script
├── package.json                    # Node.js dependencies
├── tsconfig.json                   # TypeScript configuration
├── programs/
│   └── bidtrace/                   # Solana Anchor Program (Rust)
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs              # Program instructions entrypoint
│           ├── state.rs            # Tender & BidCommitment account structures
│           ├── errors.rs           # Error definitions (DeadlineExceeded, etc.)
│           └── instructions/
│               ├── initialize_tender.rs
│               ├── commit_bid.rs
│               ├── lock_tender.rs
│               ├── reveal_bid.rs
│               └── record_award.rs
├── tests/
│   ├── test_engine.py              # Automated test suite (6 tests covering attacks)
│   └── bidtrace.ts                 # Anchor Mocha integration tests
├── bidtrace_py/                    # Python Protocol Engine & CLI
│   ├── crypto.py                   # AES-256-GCM, SHA-256 domain hashing, Ed25519
│   ├── ledger.py                   # Simulated Solana Ledger & Anchor runtime
│   ├── cli.py                      # Interactive CLI for bidders & authorities
│   └── verifier.py                 # Standalone air-gapped offline verifier
└── verifier/
    └── verify.ts                   # Standalone TypeScript verifier
```

---

## 3. Quickstart & Verification

### Run the 3-Minute Live Hackathon Demo
Walks through tender creation, 3 bidder commitments, deadline freeze, two live adversarial attack failures, award recording, and air-gapped offline audit:
```bash
python run_demo.py
```

### Run the Full Test Suite
Executes 6 comprehensive tests including happy paths and adversarial attacks:
```bash
python -m unittest tests/test_engine.py
```

### Using the BidTrace CLI
```bash
# 1. Authority initializes tender with 50-slot deadline
python -m bidtrace_py.cli init-tender --id "T-2026-001" --deadline-slots 50

# 2. Bidder submits encrypted bid before deadline
python -m bidtrace_py.cli submit --tender <TENDER_PDA> --bidder-name "ACME Corp" --amount 4200000

# 3. Advance consensus slot clock past deadline
python -m bidtrace_py.cli advance-slots --slots 60

# 4. Anyone locks the tender
python -m bidtrace_py.cli lock-tender --tender <TENDER_PDA>

# 5. Bidder reveals bid post-deadline using receipt
python -m bidtrace_py.cli reveal --receipt bidder_receipt.json

# 6. Standalone Offline Verifier (zero backend needed)
python -m bidtrace_py.verifier bidder_receipt.json ledger_state.json
```
