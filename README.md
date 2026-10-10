# BidTrace 3.0: The Incorruptible Cryptographic Global Standard for Public & Enterprise Procurement

[![Tests](https://img.shields.io/badge/python--tests-32%20passed-brightgreen.svg)]()
[![Solana Integration](https://img.shields.io/badge/anchor--tests-8%20passed-brightgreen.svg)]()
[![Solana Devnet](https://img.shields.io/badge/solana--devnet-deployed-blue.svg)](https://explorer.solana.com/address/x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ?cluster=devnet)
[![Framework](https://img.shields.io/badge/Anchor-0.30.1-purple.svg)]()
[![Standard](https://img.shields.io/badge/OCDS-1.1%20Compliant-orange.svg)]()
[![Serialization](https://img.shields.io/badge/RFC%208785-JCS%20Canonical-yellow.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()

> 📄 **Master Audit & Vetting Dossier:**  
> For the exhaustive technical specification, Anchor account layouts, cryptographic domain formulas, Olympic Trimmed Mean math, and Colosseum hackathon rubric, see:  
> **[`BIDTRACE_MASTER_DOSSIER.md`](file:///C:/Users/ujjwa/.gemini/antigravity/scratch/bidtrace/BIDTRACE_MASTER_DOSSIER.md)**  
> **GitHub Repository:** [https://github.com/Ujjwal1396/BitTrace.git](https://github.com/Ujjwal1396/BitTrace.git)

---

## 1. Executive Summary

Every year, **\$13 Trillion USD** (15–20% of global GDP) is transacted through public works, sovereign infrastructure, and multilateral loans (World Bank, ADB, UN). Empirical anti-corruption research confirms that the most devastating failure point across traditional e-procurement (SAP Ariba, Oracle Cloud, sovereign e-GP portals) is **The Post-Deadline Insider Exploitation Window**: the interval between the submission deadline and the public bid opening.

During this window, an insider holding database administrator credentials can inspect submitted pricing, identify the lowest compliant quote, and retroactively insert or backdate a favored submission. When challenged, the authority points to their internal database: *"That is what our database recorded."*

**BidTrace 3.0** replaces centralized database trust with an **incorruptible, mathematically verifiable cryptographic state machine** anchored to Solana's consensus clock.

---

## 2. Core Architectural Breakthroughs

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   BIDTRACE 3.0 PROTOCOL ENGINE                                   │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 1. FIAT-TO-GAS DECOUPLING                                                                        │
│    Buyers and contractors interact via standard web portals, PDFs, and fiat invoicing.           │
│    BidTrace's backend relayer sponsors all on-chain Solana gas. 100% legally compliant in        │
│    jurisdictions where corporate treasuries are prohibited from holding crypto tokens.           │
│                                                                                                  │
│ 2. TWO-PLANE ARCHITECTURE                                                                        │
│    • Semantic Plane (Off-Chain): Open Contracting Data Standard (OCDS 1.1) serialized via        │
│      RFC 8785 (JSON Canonicalization Scheme - JCS) to produce deterministic SHA-256 anchors.    │
│    • Enforcement Plane (On-Chain Solana): Anchor state machine enforcing temporal slot           │
│      boundaries, PDA commitments, trimmed mean scoring, and programmatic award formulas.        │
│                                                                                                  │
│ 3. THE COMMERCIAL SECRECY INVARIANT                                                              │
│    Envelope A (Technical Specs: K_tech) and Envelope B (Financial Pricing: K_fin) are encrypted │
│    independently. Disqualified contractors (S_tech < 75.00%) are permanently blocked on-chain    │
│    from unsealing Envelope B. Proprietary pricing and BoQs remain sealed forever.                │
│                                                                                                  │
│ 4. MULTI-EVALUATOR BLINDED SCORING & OLYMPIC TRIMMED MEAN                                        │
│    5 certified evaluators submit salted score commitments in isolation across 5 sub-criteria.    │
│    On-chain Olympic Trimmed Mean drops min/max grades, calculates trimmed mean, and flags        │
│    rogue evaluators deviating >20% from the median (is_outlier_flagged = true).                  │
│                                                                                                  │
│ 5. MULTI-JURISDICTION HYBRID BOND ENGINE                                                         │
│    Mode 0: Solana Escrow (native lamports).                                                      │
│    Mode 1: Surety-as-a-Service (TradFi MGA General Indemnity Agreement JCS hash).               │
│    Mode 2: Bank Guarantee Attestation (SWIFT MT760 / ICC URDG 758 attestation hash).            │
│    Mode 3: World Bank Bid-Securing Declaration (BSD) (statutory 3-year procurement suspension).   │
│                                                                                                  │
│ 6. AIR-GAPPED STANDALONE TRIBUNAL DOSSIER & VERIFIER CLI                                         │
│    Auditors download tribunal_dossier.zip and execute a 5-phase mathematical verification        │
│    offline using python -m bidtrace.verifier without trusting the BidTrace backend.              │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Live On-Chain Solana Devnet Deployment

* **Network:** Solana Devnet
* **Canonical Program ID:** [`x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ`](https://explorer.solana.com/address/x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ?cluster=devnet)
* **ProgramData Address:** [`31T65nDyKp5Jyok1AE4YsCLH1nxEbnGWVBqvZjtf9iYp`](https://explorer.solana.com/address/31T65nDyKp5Jyok1AE4YsCLH1nxEbnGWVBqvZjtf9iYp?cluster=devnet)
* **Upgrade / Relayer Authority:** [`GFRRqHMPekLkEUPDzwLXnBoETUU1EFrfFoZxiCWUwSzU`](https://explorer.solana.com/address/GFRRqHMPekLkEUPDzwLXnBoETUU1EFrfFoZxiCWUwSzU?cluster=devnet)
* **Deployment Transaction:** [`oNcnMJcLo8HV6ZByYYL9d5JeAzG6UzohbHyYNLJFbzkBBhHw53oUZnDE2WYPLWUbxrxuqzoqTnoPWA2CP7kgpg8`](https://explorer.solana.com/tx/oNcnMJcLo8HV6ZByYYL9d5JeAzG6UzohbHyYNLJFbzkBBhHw53oUZnDE2WYPLWUbxrxuqzoqTnoPWA2CP7kgpg8?cluster=devnet)
* **Deployed Slot:** `508,757,167`
* **BPF Loader:** `BPFLoaderUpgradeab1e11111111111111111111111`

---

## 4. Repository Structure

```text
bidtrace/
├── Anchor.toml                     # Anchor configuration (Solana Devnet & Localnet)
├── Cargo.toml                      # Workspace Cargo configuration
├── README.md                       # High-level protocol documentation
├── BIDTRACE_MASTER_DOSSIER.md      # Comprehensive technical specification & audit dossier
├── BIDTRACE_GLOBAL_STANDARD_MASTER_PLAN.md # 5-phase engineering roadmap
├── server.py                       # Gas-sponsoring relayer API & web server (port 8000)
├── build_idl.py                    # Deterministic Anchor IDL & TypeScript generator
│
├── programs/bidtrace/src/          # Solana Anchor Smart Contract (Rust)
│   ├── lib.rs                      # 10 instruction entrypoints
│   ├── state.rs                    # Tender, DualBidCommitment, TenderCommittee, EvaluatorGrade
│   ├── errors.rs                   # BidTraceError enum (codes 6000-6033)
│   └── instructions/
│       ├── initialize_tender.rs    # Phase 1: Initialize tender with slot deadlines
│       ├── initialize_committee.rs # Phase 1: Lock 5 accredited evaluators
│       ├── commit_dual_bid.rs      # Phase 2: Non-custodial dual-envelope intake + bonds
│       ├── advance_tender_phase.rs # Phase 2: Permissionless slot progression
│       ├── reveal_technical_bid.rs # Phase 3: Unseal Envelope A (blueprints)
│       ├── commit_evaluator_grade.rs # Phase 3: Blinded salted rubric grade commit
│       ├── reveal_evaluator_grade.rs # Phase 3: Preimage verify sub-scores & report
│       ├── finalize_technical_scores.rs # Phase 3: Olympic Trimmed Mean & outlier flagging
│       ├── reveal_financial_envelope.rs # Phase 4: Commercial Secrecy unsealing
│       └── record_award_qcbs.rs    # Phase 5: Programmatic QCBS award & anti-lockout gate
│
├── bidtrace_py/                    # Python Cryptographic Engine & Reference Simulator
│   ├── ocds.py                     # RFC 8785 JCS canonicalizer & OCDS 1.1 release builders
│   ├── crypto.py                   # AES-256-GCM, domain-separated SHA-256, Ed25519
│   ├── merkle.py                   # Sorted-pair Merkle whitelist tree (Model A)
│   ├── bonds.py                    # Hybrid bond engine (Surety, MT760, BSD, Escrow)
│   ├── relayer.py                  # Gas-sponsoring fee_payer coordinator
│   ├── ledger.py                   # Deterministic Anchor state machine simulator
│   └── verifier.py                 # 5-phase air-gapped standalone tribunal verifier
│
├── verifier/                       # Standalone Air-Gapped CLI Tools
│   ├── verify_ocds.py              # CLI entrypoint for tribunal_dossier.zip verification
│   └── verify.ts                   # Standalone TypeScript auditor
│
├── public/                         # Multi-Portal Web Dashboard & UI (Phase 5)
│   ├── index.html                  # Multi-portal responsive dashboard
│   └── ocds.js                     # Browser RFC 8785 JCS & OCDS canonical engine
│
└── tests/                          # Automated Verification Test Suites
    ├── test_ocds.py                # OCDS 1.1 & RFC 8785 JCS cross-language tests
    ├── test_engine.py              # Cryptographic pipeline & adversarial attacks
    ├── test_exploit.py             # Early-award lockout & bond forfeiture tests
    ├── test_phase3_relayer.py      # Gateway REST API & relayer gas sponsorship tests
    ├── test_phase4_verifier.py     # Standalone air-gapped dossier verification tests
    └── bidtrace.ts                 # Anchor TypeScript integration tests (Solana localnet)
```

---

## 5. Verification & Automated Test Suites

BidTrace features **100% pass rates across both Python and Solana Anchor test runners**:

### 1. Run Complete Python Verification Suite (32 Tests)
```bash
python -m unittest discover tests
```
*Output:*
```text
Ran 32 tests in 2.198s
OK
[CROSS-LANG SUCCESS] Python & Node.js hash parity verified: 64b57de7...5884b376
```

### 2. Run Anchor Integration Tests on Solana Validator (8 Tests)
```bash
wsl -e /bin/bash -l -c "cd /mnt/c/Users/ujjwa/.gemini/antigravity/scratch/bidtrace && anchor test --skip-build"
```
*Output:*
```text
  BidTrace 3.0: Incorruptible Two-Envelope & Blinded Scoring Protocol
    ✔ Test 1: Authority initializes Two-Envelope QCBS Tender with OCDS Hash and Deadlines
    ✔ Test 2: Authority initializes Tender Committee with 5 accredited evaluators
    ✔ Test 3: Contractors submit confidential Dual-Envelope Bids (A & B)
    ✔ Test 4: Tender advances to Technical Evaluation and unseals Envelope A
    ✔ Test 5: Evaluators submit and unseal blinded grades (including adversarial outlier)
    ✔ Test 6: On-chain Olympic Trimmed Mean flags Rogue Evaluator & Qualifies Bidder A while Disqualifying Bidder B
    ✔ Test 7 (Commercial Secrecy Invariant): Disqualified Bidder B is strictly prevented from unsealing Financial Envelope
    ✔ Test 8: Qualified Bidder A unseals Financial Envelope and wins QCBS Award

  8 passing (6s)
```

### 3. Launch Gateway Server & Interactive Web Dashboard
```bash
python server.py
# Open http://localhost:8000 in your browser
```
Access the Buyer Portal, Bidder Portal, Evaluator Grading Studio, Commercial Secrecy Visualizer, and **1-Click Live Attack Simulation Studio**.

### 4. Execute Standalone Air-Gapped Tribunal Audit
```bash
python -m bidtrace.verifier --dossier tribunal_dossier.zip
```
Verifies all 5 procurement lifecycle phases offline against raw Solana account proofs without contacting any central server.

---

## 6. Adversarial Attack Defenses Matrix

| Attack Scenario | Adversary Action | BidTrace Cryptographic / On-Chain Defense |
| :--- | :--- | :--- |
| **Late Bid Injection** | Insider attempts to submit bid at `slot > submission_deadline_slot`. | Smart contract verifies `Clock::get()?.slot <= submission_deadline_slot`; throws `SubmissionDeadlineExceeded`. |
| **Merkle Whitelist Fraud** | Unauthorized bidder submits forged credentials. | On-chain Keccak-256 sorted-pair proof verification fails; throws `InvalidMerkleProof`. |
| **Price Tampering** | Bidder attempts to alter quotation during reveal. | SHA-256 preimage check fails against `fin_commitment_hash`; throws `InvalidRevealHash`. |
| **Rogue Evaluator Favoritism** | Corrupt evaluator submits 98% grade to artificially inflate friend. | Olympic Trimmed Mean drops max score; automatically flags evaluator (`is_outlier_flagged = true`). |
| **Commercial Secrecy Breach** | Competitor/operator tries to reveal disqualified bidder's Envelope B. | Smart contract enforces `bid.is_tech_qualified == true`; throws `BidderTechnicallyDisqualified`. |
| **Early-Award Lockout** | Corrupt buyer agency tries to award tender early to favored bidder. | Anti-lockout gate enforces `slot > fin_reveal_deadline_slot || total_fin_revealed == total_tech_qualified`. |
| **Tampered Tender Notice** | Agency alters tender scope or evaluation rubrics post-publication. | Recomputed RFC 8785 JCS hash fails match against immutable on-chain `ocds_notice_hash`. |

---

## 7. License & Credits

Distributed under the **MIT License**.  
Developed for the **Solana Renaissance / Radar Hackathon** and public procurement integrity global standard.
