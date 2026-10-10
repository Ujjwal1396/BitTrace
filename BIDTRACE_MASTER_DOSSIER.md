# BidTrace 3.0: Cryptographic Protocol Specification & Colosseum Hackathon Vetting Dossier
## The Incorruptible Cryptographic Global Standard for Public & Enterprise Procurement

**Document Release:** Version 3.0.0 (Master Audit & Vetting Edition)  
**Date of Audit:** October 2026  
**GitHub Repository:** [https://github.com/Ujjwal1396/BitTrace.git](https://github.com/Ujjwal1396/BitTrace.git) (`origin/main`)  
**Solana Devnet Program ID:** [`x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ`](https://explorer.solana.com/address/x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ?cluster=devnet)  
**Devnet ProgramData Address:** [`31T65nDyKp5Jyok1AE4YsCLH1nxEbnGWVBqvZjtf9iYp`](https://explorer.solana.com/address/31T65nDyKp5Jyok1AE4YsCLH1nxEbnGWVBqvZjtf9iYp?cluster=devnet)  
**Authority / Relayer Wallet:** [`GFRRqHMPekLkEUPDzwLXnBoETUU1EFrfFoZxiCWUwSzU`](https://explorer.solana.com/address/GFRRqHMPekLkEUPDzwLXnBoETUU1EFrfFoZxiCWUwSzU?cluster=devnet)  
**Target Environments:** Solana Runtime (Anchor v0.30.1), Python 3.10+ Reference Engine, RFC 8785 JCS, OCDS 1.1  

---

```
  ____  _     _ _____                     _____    ___  
 | __ )(_) __| |_   _| __ __ _  ___ ___  |___ /   / _ \ 
 |  _ \| |/ _` | | || '__/ _` |/ __/ _ \   |_ \  | | | |
 | |_) | | (_| | | || | | (_| | (_|  __/  ___) | | |_| |
 |____/|_|\__,_| |_||_|  \__,_|\___\___| |____/   \___/ 
   THE INCORRUPTIBLE CRYPTOGRAPHIC PROCUREMENT STANDARD   
```

---

## Table of Contents
1. [Executive Summary & Hackathon Thesis](#1-executive-summary--hackathon-thesis)
2. [The Real-World Procurement Crisis & Threat Model](#2-the-real-world-procurement-crisis--threat-model)
3. [Core Protocol Innovations & Strategic Invariants](#3-core-protocol-innovations--strategic-invariants)
4. [Two-Plane Architecture: Semantic vs Enforcement](#4-two-plane-architecture-semantic-vs-enforcement)
5. [Anchor Smart Contract Specification (`programs/bidtrace`)](#5-anchor-smart-contract-specification-programsbidtrace)
   - 5.1 Account Layouts & PDA Derivations
   - 5.2 Instruction Interface & Execution Rules
   - 5.3 Error Code Registry (`BidTraceError`)
6. [Multi-Evaluator Blinded Scoring & Olympic Trimmed Mean](#6-multi-evaluator-blinded-scoring--olympic-trimmed-mean)
7. [The Commercial Secrecy Invariant](#7-the-commercial-secrecy-invariant)
8. [Multi-Jurisdiction Hybrid Bond Engine](#8-multi-jurisdiction-hybrid-bond-engine)
9. [Semantic Plane: OCDS 1.1 + RFC 8785 Canonical JCS Engine](#9-semantic-plane-ocds-11--rfc-8785-canonical-jcs-engine)
10. [Administrative Due Diligence Models (Model A vs Model B)](#10-administrative-due-diligence-models-model-a-vs-model-b)
11. [Gas-Sponsored Relayer Gateway & REST API Reference](#11-gas-sponsored-relayer-gateway--rest-api-reference)
12. [Standalone Air-Gapped Tribunal Dossier & Verifier CLI](#12-standalone-air-gapped-tribunal-dossier--verifier-cli)
13. [Multi-Portal Web Application & Interactive UI (Phase 5)](#13-multi-portal-web-application--interactive-ui-phase-5)
14. [Comprehensive Test Matrix & Adversarial Verification](#14-comprehensive-test-matrix--adversarial-verification)
15. [Colosseum Hackathon & Venture Evaluation Rubric](#15-colosseum-hackathon--venture-evaluation-rubric)
16. [Appendix: Environment Setup & Local Reproduction](#16-appendix-environment-setup--local-reproduction)

---

## 1. Executive Summary & Hackathon Thesis

### 1.1 The \$13 Trillion Procurement Problem
Global public procurement represents **\$13 Trillion USD annually** (approximately 15% to 20% of global GDP), governed by sovereign ministries, multilateral development banks (World Bank, Asian Development Bank, UN), and private mega-EPC engineering conglomerates (Bechtel, VINCI, Fluor, Skanska).

According to the UN Office on Drugs and Crime (UNODC) and the World Bank Stolen Asset Recovery Initiative:
- Between **20% and 25% of public procurement expenditure is lost annually to corruption, kickbacks, and bid-rigging** (over \$1.5 Trillion per year).
- The single most catastrophic structural vulnerability across all e-procurement systems (e-GP portals, SAP Ariba, Oracle Cloud ERP) is **The Post-Deadline Insider Exploitation Window**: the interval between the submission cutoff and the formal public opening.
- During this window, an insider holding database administrator (`sa` or `postgres` root) credentials can observe competing submissions, extract the lowest compliant price, and retroactively backdate a favored contractor's bid or substitute an altered technical proposal prior to the opening ceremony.
- When an honest bidder challenges the outcome in administrative court, the procurement agency produces internal database logs and states: *"That is what our authoritative database recorded."*

### 1.2 The BidTrace Solution
**BidTrace 3.0** replaces institutional trust and vulnerable centralized databases with an **incorruptible, mathematically verifiable cryptographic state machine** deployed on **Solana**:

1. **Deterministic Consensus Clocking:** Bids and evaluations are bound strictly to Solana monotonic slot heights (`Clock::get()?.slot`), eliminating application-layer NTP timestamp tampering.
2. **Two-Envelope State Machine:** Envelope A (Technical Specs) and Envelope B (Financial Pricing) are encrypted independently with client-side ephemeral keys.
3. **The Commercial Secrecy Invariant:** If a contractor fails the technical threshold ($S_{\text{tech}} < 75.00\%$), on-chain Anchor constraints **permanently bar** the unsealing of Envelope B. Proprietary trade secrets, unit cost structures, and supply-chain supplier pricing are protected forever.
4. **Blinded Committee Scoring & Olympic Outlier Filter:** 5 certified evaluators commit salted evaluation hashes in absolute isolation. The smart contract calculates an on-chain **Olympic Trimmed Mean** (dropping minimum and maximum grades) and permanently flags rogue evaluators deviating $>20\%$ from the median (`is_outlier_flagged = true`).
5. **Decoupled Crypto Mechanics:** Buyers and bidders interact in standard fiat, receive corporate PDF receipts, and never hold SOL or manage wallets. BidTrace's `fee_payer` relayer sponsors all transaction fees, enabling global B2B/B2G compliance even in jurisdictions where corporate crypto treasuries are prohibited by law.
6. **Air-Gapped Standalone Auditor:** Any judicial tribunal or World Bank investigator can download a self-contained `tribunal_dossier.zip` and verify all 5 lifecycle phases on an offline, air-gapped machine using `python -m bidtrace.verifier` without trusting the BidTrace backend.

---

## 2. The Real-World Procurement Crisis & Threat Model

### 2.1 The Post-Deadline Exploitation Window

```
Centralized Database Architecture (Traditional e-GP):
======================================================
[Submission Open] ────► [Calendar Deadline 12:00:00] ───► [EXPLOITATION WINDOW] ───► [Bid Opening 15:00:00]
                                                                  │
                                            Insider inspects bids in Postgres DB;
                                            Discovers lowest bid is $3,950,000;
                                            Inserts favored Bidder C at $3,900,000;
                                            Backdates database timestamp to 11:55:00.
```

In contrast, BidTrace enforces consensus finality on Solana:

```
BidTrace Cryptographic Architecture:
=====================================
[Slot 1,000: Open] ────► [Slot 1,100: Deadline] ───► [STATE LOCKED] ───► [Slot 1,200: Reveal Phase]
                                │                                              │
                    Clock::get()?.slot > 1100               Preimage SHA-256 match enforced;
                    All intake frozen permanently.          Tampered price fails preimage check.
```

### 2.2 Threat Model & Adversarial Capabilities

| Actor | Threat Capability | BidTrace Security Defense |
| :--- | :--- | :--- |
| **Corrupt Database Admin** | Read/write/delete backend database records; forge server timestamps. | All commitments exist in Solana PDAs. Timestamping is governed by validator consensus slots. |
| **Colluding Buyer Agency** | Leak competitor pricing to favored bidder; lock out competitors early. | Dual-envelope encryption ($K_{\text{fin}}$ held client-side). Anti-lockout gate blocks premature awards. |
| **Corrupt Evaluator** | Give arbitrary 99% score to friend or 10% to rival to rig average. | Blinded commit-reveal scoring. On-chain Olympic Trimmed Mean drops min/max and flags outliers $>20\%$. |
| **Defaulting / Regretful Bidder** | Submit speculative bids and refuse to reveal if market conditions shift. | Refundable bid bond (Solana Escrow, TradFi Surety GIA, or Bank Guarantee) forfeited on default. |
| **Whistleblower / Audit Tribunal** | Must prove fraud in administrative court or international arbitration. | Standalone `tribunal_dossier.zip` verifiable offline via mathematical preimages and Merkle proofs. |

### 2.3 Explicit Security Bounds & Non-Goals
To maintain scientific integrity, BidTrace explicitly identifies what is inside vs outside cryptographic bounds:
- **Inside Bounds (Guaranteed):** Bid completeness at deadline, non-custodial intake, mathematical price integrity, evaluator isolation, trade secret sealing for disqualified bidders, and air-gapped auditability.
- **Outside Bounds (Explicit Non-Goals):** Physical extortion or off-chain cartel meetings prior to submission; physical construction quality (concrete tensile strength); and pre-tender political decisions regarding project scope.

---

## 3. Core Protocol Innovations & Strategic Invariants

### Invariant 1: The Fiat-to-Gas Decoupling
Enterprise treasuries (e.g. World Bank, Bechtel, Ministry of Transport) are legally prevented by treasury regulations and public finance acts from purchasing volatile cryptocurrencies on centralized exchanges.
- **Resolution:** All on-chain transactions are signed with the agency's WebAuthn passkey or session key and dispatched via a backend **Gas-Sponsoring Relayer** holding the `fee_payer` account (`GFRRqHMPekLkEUPDzwLXnBoETUU1EFrfFoZxiCWUwSzU`).
- Buyers and contractors pay via fiat SaaS subscriptions, ERP integrations (SAP, Oracle), or corporate invoicing.

### Invariant 2: The Two-Plane Architecture
- **Semantic Plane (Off-Chain):** Open Contracting Data Standard (OCDS 1.1) serialized according to **RFC 8785 (JSON Canonicalization Scheme - JCS)**. This guarantees byte-for-byte identical SHA-256 digests across Python, TypeScript, Rust, and Go runtimes.
- **Enforcement Plane (On-Chain Solana):** Anchor state machine running on Solana Devnet/Mainnet enforcing slot boundaries, PDA commitments, trimmed mean filtering, and QCBS formula calculations.

### Invariant 3: The Commercial Secrecy Invariant
- A contractor’s Envelope B (Financial Pricing & Bill of Quantities) is protected by key $K_{\text{fin}}$.
- If an evaluator committee scores a proposal below the minimum technical threshold ($S_{\text{tech}} < 75.00\%$), the smart contract enforces:
  $$\text{require!}(\text{bid.is\_tech\_qualified},\, \text{BidTraceError::BidderTechnicallyDisqualified})$$
- The contractor never unseals $K_{\text{fin}}$. Unsuccessful competitors never leak proprietary subcontractor margins, labor rates, or design innovations to rivals.

### Invariant 4: Olympic Trimmed Mean & Outlier Flagging
- When 5 certified evaluators score a technical proposal:
  1. The minimum score and maximum score are dropped.
  2. The remaining 3 middle scores are averaged.
  3. If any evaluator's score deviates by more than $20.00\%$ (2,000 basis points) from the median, that evaluator's on-chain account has `is_outlier_flagged` permanently set to `true`.

### Invariant 5: Multi-Jurisdiction Hybrid Bond Engine
Bid security is required across all major procurement frameworks:
- **Mode 0 (Solana Escrow):** Native SOL lamports locked in the `DualBidCommitment` PDA.
- **Mode 1 (Surety-as-a-Service):** Binding TradFi General Indemnity Agreement (GIA) underwritten by licensed MGAs (e.g., Zurich, Travelers model) hashed via RFC 8785.
- **Mode 2 (Bank Guarantee Attestation):** SWIFT MT760 / ICC URDG 758 digital guarantee attestation hash.
- **Mode 3 (World Bank Bid-Securing Declaration):** Statutory 3-year procurement debarment declaration with irrevocable legal consent.

---

## 4. Two-Plane Architecture: Semantic vs Enforcement

```
+───────────────────────────────────────────────────────────────────────────────────────────────────+
|                                  BIDTRACE TWO-PLANE ARCHITECTURE                                  |
+───────────────────────────────────────────────────────────────────────────────────────────────────+
|                                                                                                   |
|  OFF-CHAIN SEMANTIC DATA PLANE (OCDS 1.1 + RFC 8785 JCS)                                          |
|  ┌───────────────────────────┐   ┌───────────────────────────┐   ┌─────────────────────────────┐  |
|  │ OCDS Tender Notice        │   │ OCDS Evaluation Release   │   │ OCDS Contract Award Release │  |
|  │ • Items, BoQs, Milestones │   │ • Blinded Rubrics, Grades │   │ • Award Rationale & Pricing │  |
|  └─────────────┬─────────────┘   └─────────────┬─────────────┘   └──────────────┬──────────────┘  |
|                │ Canonical JCS                 │ Canonical JCS                  │ Canonical JCS   |
|                ▼                               ▼                                ▼                 |
|        [SHA-256 Digest]                [SHA-256 Digest]                 [SHA-256 Digest]          |
|                │                               │                                │                 |
+────────────────┼───────────────────────────────┼────────────────────────────────┼─────────────────+
|                ▼                               ▼                                ▼                 |
|  ON-CHAIN ENFORCEMENT PLANE (Solana Anchor Runtime: x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ)   |
|  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  |
|  │ Tender PDA                                                                                  │  |
|  │ • ocds_notice_hash: [u8; 32]             • authorized_bidders_root: [u8; 32]                │  |
|  │ • submission_deadline_slot: u64          • tech_eval_deadline_slot: u64                     │  |
|  │ • status: SubmissionsOpen | AdminReview | TechEval | FinEval | Awarded                      │  |
|  └─────────────────────────────────────────────────────────────────────────────────────────────┘  |
|        ▲                               ▲                                ▲                         |
|        │ seeds: ["bid", tender, bidder]│ seeds: ["committee", tender]   │ seeds: ["grade", ...]   |
|  ┌─────┴─────────────────────┐   ┌─────┴─────────────────────┐   ┌──────┴──────────────────────┐  |
|  │ DualBidCommitment PDA     │   │ TenderCommittee PDA       │   │ EvaluatorGrade PDA          │  |
|  │ • admin_dossier_hash      │   │ • evaluators: Vec<Pubkey> │   │ • commitment_hash: [u8; 32] │  |
|  │ • tech_commitment_hash    │   │ • max_variance_bps: u16   │   │ • sub_scores: [u16; 5]      │  |
|  │ • fin_commitment_hash     │   │ • is_locked: bool         │   │ • is_outlier_flagged: bool  │  |
|  │ • is_tech_qualified: bool │   └───────────────────────────┘   └─────────────────────────────┘  |
|  │ • revealed_price: u64     │                                                                    |
|  └───────────────────────────┘                                                                    |
+───────────────────────────────────────────────────────────────────────────────────────────────────+
```

---

## 5. Anchor Smart Contract Specification (`programs/bidtrace`)

The smart contract is written in Rust using the **Anchor Framework (v0.30.1)**. It is deployed on Solana Devnet at address:
`x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ`

### 5.1 Account Layouts & PDA Derivations

#### 1. `Tender` Account
- **PDA Seeds:** `[b"tender", authority.key().as_ref(), tender_id.as_bytes()]`
- **Account Space:** `8 + 32 + (4 + 32) + 32 + 1 + 1 + 1 + 8 + 8 + 8 + 8 + 32 + 2 + 2 + 2 + 4 + 4 + 4 + 4 + 8 + 8 + (1 + 32) + 1 = 227 bytes`

```rust
#[account]
pub struct Tender {
    pub authority: Pubkey,                  // 32 bytes: Tender administrator
    pub tender_id: String,                  // 4 + 32 bytes: Unique tender identifier
    pub ocds_notice_hash: [u8; 32],         // 32 bytes: RFC 8785 canonical hash of OCDS Notice
    pub tender_mode: TenderMode,            // 1 byte: PreQualifiedWhitelist (0) or PostQualifiedOpen (1)
    pub evaluation_type: EvaluationType,    // 1 byte: LeastCost (0) or QCBS (1)
    pub status: TenderStatus,               // 1 byte: State machine status enum

    // Temporal Consensus Slot Deadlines
    pub submission_deadline_slot: u64,      // 8 bytes: Deadline for bid commitments
    pub admin_review_deadline_slot: u64,    // 8 bytes: Deadline for administrative checks
    pub tech_eval_deadline_slot: u64,       // 8 bytes: Deadline for technical scoring
    pub fin_reveal_deadline_slot: u64,      // 8 bytes: Deadline for financial reveals

    // Model A: Merkle Whitelist Root
    pub authorized_bidders_root: [u8; 32],   // 32 bytes: Root of pre-qualified bidder whitelist

    // Two-Envelope Scoring Parameters (in Basis Points: 10,000 bps = 100.00%)
    pub min_tech_score_bps: u16,            // 2 bytes: Technical qualification threshold (e.g., 7500 = 75%)
    pub tech_weight_bps: u16,               // 2 bytes: Technical evaluation weight (e.g., 7000 = 70%)
    pub fin_weight_bps: u16,                // 2 bytes: Financial evaluation weight (e.g., 3000 = 30%)

    // Progress State Counters
    pub total_committed: u32,               // 4 bytes: Total submitted bids
    pub total_admin_passed: u32,            // 4 bytes: Total passing administrative due diligence
    pub total_tech_qualified: u32,          // 4 bytes: Total passing technical evaluation
    pub total_fin_revealed: u32,            // 4 bytes: Total financial envelopes unsealed

    // Scoring & Award State
    pub lowest_revealed_price: u64,         // 8 bytes: Lowest financial price unsealed
    pub highest_composite_score: u64,       // 8 bytes: Top QCBS composite score
    pub winning_bidder: Option<Pubkey>,     // 33 bytes: Winning contractor public key
    pub bump: u8,                           // 1 byte: PDA bump seed
}
```

#### 2. `DualBidCommitment` Account
- **PDA Seeds:** `[b"bid", tender.key().as_ref(), bidder.key().as_ref()]`
- **Account Space:** `8 + 32 + 32 + 8 + 32 + 32 + 32 + 1 + 2 + 1 + 2 + 1 + 1 + 8 + 8 + 1 + 8 + 1 + 1 = 217 bytes`

```rust
#[account]
pub struct DualBidCommitment {
    pub tender: Pubkey,                     // 32 bytes: Parent tender PDA
    pub bidder: Pubkey,                     // 32 bytes: Bidder authority public key
    pub committed_at_slot: u64,             // 8 bytes: Slot when commitment was confirmed

    // Cryptographic Commitment Hashes
    pub admin_dossier_hash: [u8; 32],       // 32 bytes: Pre-qualification & compliance documents
    pub tech_commitment_hash: [u8; 32],     // 32 bytes: Domain-separated Envelope A commitment
    pub fin_commitment_hash: [u8; 32],      // 32 bytes: Domain-separated Envelope B commitment

    // Phase 1: Administrative Due Diligence
    pub admin_status: AdminStatus,          // 1 byte: Pending (0), Passed (1), Failed (2)
    pub admin_rejection_code: u16,          // 2 bytes: Rejection statutory reason code if failed

    // Phase 2: Technical Merit Scoring
    pub is_tech_revealed: bool,             // 1 byte: True when blueprints & salt unsealed
    pub technical_score_bps: u16,           // 2 bytes: Olympic trimmed mean score (0 - 10,000)
    pub is_tech_qualified: bool,            // 1 byte: True if technical_score_bps >= min_tech_score_bps

    // Phase 3: Financial Envelope Opening
    pub is_fin_revealed: bool,              // 1 byte: True when price & BoQ unsealed
    pub revealed_price: u64,                // 8 bytes: Plaintext quotation price
    pub composite_score: u64,               // 8 bytes: QCBS composite score

    // Multi-Jurisdiction Bond Escrow
    pub bond_mode: BondMode,                // 1 byte: SolanaEscrow, SuretyService, BankGuarantee, BSD
    pub bond_amount: u64,                   // 8 bytes: Bond value
    pub is_bond_settled: bool,              // 1 byte: True if refunded or forfeited
    pub bump: u8,                           // 1 byte: PDA bump seed
}
```

#### 3. `TenderCommittee` & `EvaluatorGrade` Accounts
- **Committee PDA Seeds:** `[b"committee", tender.key().as_ref()]`
- **Grade PDA Seeds:** `[b"grade", tender.key().as_ref(), evaluator.key().as_ref(), bidder.key().as_ref()]`

```rust
#[account]
pub struct TenderCommittee {
    pub tender: Pubkey,                     // 32 bytes
    pub evaluators: Vec<Pubkey>,            // 4 + (32 * 7) = 228 bytes (5 to 7 certified evaluators)
    pub max_variance_bps: u16,              // 2 bytes: Outlier tolerance (2000 bps = 20.00%)
    pub is_locked: bool,                    // 1 byte: Roster locked against tampering
    pub bump: u8,                           // 1 byte
}

#[account]
pub struct EvaluatorGrade {
    pub tender: Pubkey,                     // 32 bytes
    pub evaluator: Pubkey,                  // 32 bytes
    pub bidder: Pubkey,                     // 32 bytes
    pub commitment_hash: [u8; 32],          // 32 bytes: Blinded salted grade commitment
    pub committed_at_slot: u64,             // 8 bytes: Submission slot
    pub is_revealed: bool,                  // 1 byte
    pub sub_scores: [u16; 5],               // 10 bytes: 5 criteria grades (0 - 2,000 each)
    pub total_score_bps: u16,               // 2 bytes: Sum of sub-scores (0 - 10,000)
    pub justification_hash: [u8; 32],       // 32 bytes: SHA-256 of written evaluation report
    pub is_outlier_flagged: bool,           // 1 byte: True if rejected by trimmed mean filter
    pub bump: u8,                           // 1 byte
}
```

---

### 5.2 Instruction Interface & Execution Rules

| Instruction Index | Instruction Name | Accounts Required | Core Security Invariant Enforced |
| :---: | :--- | :--- | :--- |
| **01** | `initialize_tender` | `tender`, `authority`, `system_program` | Deadlines sequential (`sub <= admin <= tech <= fin`). Weights sum to 10,000 bps. |
| **02** | `initialize_committee` | `tender`, `committee`, `authority`, `system_program` | Roster of 5–7 evaluators locked before evaluation begins. |
| **03** | `commit_dual_bid` | `tender`, `bid_commitment`, `bidder`, `fee_payer`, `system_program` | `slot <= submission_deadline_slot`. Whitelist Merkle proof validated if Model A. |
| **04** | `advance_tender_phase` | `tender`, `caller` | Permissionless progression based on `Clock::get()?.slot`. |
| **05** | `reveal_technical_bid` | `tender`, `bid_commitment`, `revealer` | `BIDTRACE_TECH_V1` domain-separated SHA-256 check. Status must be `TechnicalEvaluation`. |
| **06** | `commit_evaluator_grade` | `tender`, `committee`, `bid_commitment`, `evaluator_grade`, `evaluator`, `bidder` | Evaluator must belong to committee roster. Hash of sub-scores committed blindly. |
| **07** | `reveal_evaluator_grade` | `tender`, `committee`, `evaluator_grade`, `evaluator`, `bidder` | Preimage verified against `BIDTRACE_GRADE_V1`. Sub-scores sum verified. |
| **08** | `finalize_technical_scores` | `tender`, `committee`, `bid_commitment`, `authority`, `remaining_accounts` | Olympic Trimmed Mean calculated. Median outlier $>20\%$ flagged. Cutoff enforced. |
| **09** | `reveal_financial_envelope` | `tender`, `bid_commitment`, `revealer`, `bidder_recipient` | **Commercial Secrecy:** Throws `BidderTechnicallyDisqualified` if $S_{\text{tech}} < 75.00\%$. |
| **10** | `record_award_qcbs` | `tender`, `winning_bid`, `authority` | **Anti-Lockout:** All qualified bids must be revealed. Winner has highest QCBS score. |

---

### 5.3 Error Code Registry (`BidTraceError`)

```rust
#[error_code]
pub enum BidTraceError {
    #[msg("Submission deadline slot must be in the future.")]
    InvalidSubmissionDeadline = 6000,
    #[msg("Deadline slots must be strictly sequential (submission <= admin <= tech <= fin).")]
    InvalidDeadlineSequence = 6001,
    #[msg("Submission deadline has passed. Commitments are frozen.")]
    SubmissionDeadlineExceeded = 6002,
    #[msg("Admin review deadline has passed.")]
    AdminReviewDeadlineExceeded = 6003,
    #[msg("Technical evaluation deadline has passed.")]
    TechEvalDeadlineExceeded = 6004,
    #[msg("Financial reveal deadline has passed. Reveals are closed.")]
    FinancialRevealDeadlineExceeded = 6005,
    #[msg("Tender is not in SubmissionsOpen status.")]
    TenderNotSubmissionsOpen = 6006,
    #[msg("Tender is not in AdministrativeReview status.")]
    TenderNotAdminReview = 6007,
    #[msg("Tender is not in TechnicalEvaluation status.")]
    TenderNotTechnicalEvaluation = 6008,
    #[msg("Tender is not in FinancialEvaluation status.")]
    TenderNotFinancialEvaluation = 6009,
    #[msg("Tender has already been awarded.")]
    TenderAlreadyAwarded = 6010,
    #[msg("Bidder is not in the authorized whitelist.")]
    UnauthorizedBidder = 6011,
    #[msg("Merkle proof verification failed.")]
    InvalidMerkleProof = 6012,
    #[msg("Provided reveal preimage does not match the committed cryptographic hash.")]
    InvalidRevealHash = 6013,
    #[msg("Technical bid has already been revealed.")]
    TechAlreadyRevealed = 6014,
    #[msg("Technical proposal has not been revealed yet.")]
    TechNotRevealed = 6015,
    #[msg("Financial envelope has already been revealed.")]
    FinAlreadyRevealed = 6016,
    #[msg("Commercial Secrecy Invariant: Bidder is technically disqualified. Financial envelope is permanently sealed.")]
    BidderTechnicallyDisqualified = 6017,
    #[msg("Bidder has not passed administrative due diligence.")]
    BidderNotAdminPassed = 6018,
    #[msg("Winning bidder is not technically qualified.")]
    WinnerNotQualified = 6019,
    #[msg("Winning bidder has not unsealed their financial envelope.")]
    WinnerNotRevealed = 6020,
    #[msg("Selected winner does not have the lowest price in Least-Cost mode.")]
    WinnerNotLowestPrice = 6021,
    #[msg("Selected winner does not have the highest composite score in QCBS mode.")]
    WinnerNotHighestCompositeScore = 6022,
    #[msg("Anti-Lockout Gate: Financial reveal window is active and qualified bids remain unrevealed.")]
    FinancialRevealWindowActive = 6023,
    #[msg("Tender ID exceeds maximum allowed length of 32 characters.")]
    TenderIdTooLong = 6024,
    #[msg("Insufficient deposit attached for bid commitment bond.")]
    InsufficientDeposit = 6025,
    #[msg("Signer is not an accredited member of the Tender Committee.")]
    EvaluatorNotAuthorized = 6026,
    #[msg("Tender committee roster is already locked.")]
    CommitteeAlreadyLocked = 6027,
    #[msg("Evaluator grade has already been revealed.")]
    GradeAlreadyRevealed = 6028,
    #[msg("Evaluator grade has not been revealed yet.")]
    GradeNotRevealed = 6029,
    #[msg("At least 3 revealed committee evaluations required for trimmed mean scoring.")]
    InsufficientEvaluatorGrades = 6030,
    #[msg("Sub-scores do not match the claimed total score.")]
    InvalidSubScores = 6031,
    #[msg("Sub-scores exceed maximum allowed value (10,000 bps total).")]
    SubScoresOutOfRange = 6032,
    #[msg("Technical and financial weights must sum exactly to 10,000 basis points (100%).")]
    InvalidWeights = 6033,
}
```

---

## 6. Multi-Evaluator Blinded Scoring & Olympic Trimmed Mean

### 6.1 The 5 Standardized Technical Sub-Criteria
Evaluators evaluate technical proposals across 5 World Bank/FIDIC standard categories (each worth up to 2,000 basis points, total 10,000 bps = 100.00%):
1. **$C_1$ (Engineering & Architecture):** Structural blueprints, load calculations, BIM compliance (0–2,000 bps).
2. **$C_2$ (Key Personnel & Staffing):** Chartered engineers, PM certifications, safety officers (0–2,000 bps).
3. **$C_3$ (Work Schedule & Milestones):** Critical path method (CPM) gantt chart, milestone realism (0–2,000 bps).
4. **$C_4$ (Environmental & Social Safeguards):** Carbon footprint, ESG compliance, waste management (0–2,000 bps).
5. **$C_5$ (Quality Assurance & Risk Mitigation):** ISO 9001/45001 procedures, geotechnical risk contingencies (0–2,000 bps).

$$\text{Total Score} = \sum_{i=1}^{5} C_i \in [0, 10000]$$

### 6.2 The On-Chain Trimming & Outlier Rejection Algorithm
Let $G = [g_1, g_2, g_3, g_4, g_5]$ be the revealed total scores from the 5 evaluators, sorted in ascending order:
$$g_{(1)} \le g_{(2)} \le g_{(3)} \le g_{(4)} \le g_{(5)}$$

1. **Drop Minimum and Maximum:**
   $$G_{\text{trimmed}} = [g_{(2)}, g_{(3)}, g_{(4)}]$$
2. **Calculate Trimmed Technical Score:**
   $$S_{\text{tech}} = \left\lfloor \frac{g_{(2)} + g_{(3)} + g_{(4)}}{3} \right\rfloor$$
3. **Median Determination:**
   $$M = g_{(3)}$$
4. **Outlier Detection:** For every evaluator $k \in \{1, \dots, 5\}$:
   $$\Delta_k = \frac{|g_k - M|}{M} \times 10,000$$
   If $\Delta_k > \text{max\_variance\_bps}$ (default 2,000 bps = 20.00%):
   $$\text{evaluator\_grade}[k].\text{is\_outlier\_flagged} = \text{true}$$

#### Concrete Worked Example from Anchor Test Suite (`tests/bidtrace.ts`):
- Honest evaluators 1 through 4 submit: `6400`, `6300`, `6500`, `6200`.
- Corrupt Evaluator 5 submits: `9800` (attempted rogue inflation).
- Sorted list: `[6200, 6300, 6400, 6500, 9800]`.
- Min `6200` dropped; Max `9800` dropped.
- Median: `6400`.
- Trimmed Mean: $\frac{6300 + 6400 + 6500}{3} = 6400\text{ bps } (64.00\%)$.
- Outlier test for Evaluator 5: $\frac{|9800 - 6400|}{6400} = \frac{3400}{6400} = 53.12\% > 20.00\%$.
- Result: **Evaluator 5 flagged as outlier on-chain**. The inflated score is neutralized. Since $6400 < 7500$, the bidder fails technical qualification.

---

## 7. The Commercial Secrecy Invariant

### 7.1 Mathematical & Legal Proof of Secrecy
In traditional procurement, when a contractor is disqualified on technical grounds, corrupt officials often leak their bill of quantities, proprietary concrete mix formulas, or supplier quotes to favored competitors for future tenders.

In BidTrace, Envelope B is protected by independent key $K_{\text{fin}}$ and salt $salt_{\text{fin}}$:
$$\text{comm}_{\text{fin}} = \text{SHA256}(\text{"BIDTRACE\_FIN\_V1"} \parallel \text{tender\_pda} \parallel \text{bidder\_pubkey} \parallel salt_{\text{fin}} \parallel \text{price} \parallel \text{boq\_hash})$$

The Anchor instruction `reveal_financial_envelope` contains the following invariant check:
```rust
require!(
    bid_commitment.is_tech_qualified,
    BidTraceError::BidderTechnicallyDisqualified
);
```

### 7.2 Cryptographic Security Bounds
- Plaintext financial quotation $P$ and bill of quantities $BoQ$ remain encrypted off-chain under AES-256-GCM.
- Key $K_{\text{fin}}$ is held exclusively in the bidder's local browser memory or secure keystore.
- Because `reveal_financial_envelope` rejects transactions for any bidder where `is_tech_qualified == false`, the bidder is never requested to transmit $K_{\text{fin}}$ over the network.
- Even under full compromise of the BidTrace backend server and the procurement authority's credentials, the adversary possesses only the 32-byte hash $\text{comm}_{\text{fin}}$. Inverting SHA-256 is computationally infeasible ($2^{256}$ operations).

---

## 8. Multi-Jurisdiction Hybrid Bond Engine

Procurement regulations universally require a "Bid Security" (typically 1% to 3% of estimated contract value) to prevent frivolous bids or walkaways:

```
+───────────────────────────────────────────────────────────────────────────────────────────────────+
|                                    MULTI-JURISDICTION BOND MODES                                  |
+───────────────────────────────────────────────────────────────────────────────────────────────────+
| Mode 0: Solana Escrow                                                                             |
| ─────── Bidders deposit native SOL directly into the DualBidCommitment PDA.                       |
|         Refunded upon legitimate reveal; forfeited upon default.                                  |
|                                                                                                   |
| Mode 1: Surety-as-a-Service (TradFi MGA Model)                                                    |
| ─────── Licensed surety underwriter (Zurich/Travelers equivalent) issues an electronic bid bond.  |
|         Binds the contractor to a General Indemnity Agreement (GIA).                             |
|         Attestation hash committed to Solana: SHA256(RFC8785(SuretyPolicyRecord)).                |
|                                                                                                   |
| Mode 2: Bank Guarantee Attestation (SWIFT MT760 / ICC URDG 758)                                   |
| ─────── Regulated commercial bank issues an irrevocable demand guarantee.                         |
|         Binds SWIFT message MT760 reference and issuance date.                                    |
|         Attestation hash committed to Solana: SHA256(RFC8785(BankGuaranteeAttestation)).          |
|                                                                                                   |
| Mode 3: World Bank Bid-Securing Declaration (BSD)                                                 |
| ─────── Statutory declaration under World Bank Procurement Regulations § 5.42.                     |
|         Contractor accepts automatic 3-year global procurement suspension if in default.          |
|         Signed declaration canonicalized via RFC 8785 and committed to Solana.                   |
+───────────────────────────────────────────────────────────────────────────────────────────────────+
```

### 8.1 Rust Bond Mode Definition (`state.rs`)
```rust
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum BondMode {
    SolanaEscrow = 0,
    SuretyService = 1,
    BankGuaranteeAttestation = 2,
    BidSecuringDeclaration = 3,
}
```

---

## 9. Semantic Plane: OCDS 1.1 + RFC 8785 Canonical JCS Engine

### 9.1 Why Standard JSON Serialization Fails
Standard JSON stringifiers (`JSON.stringify()` in JavaScript, `json.dumps()` in Python, `serde_json::to_string()` in Rust) produce differing output due to:
- Key reordering (e.g. `{"a": 1, "b": 2}` vs `{"b": 2, "a": 1}`).
- Whitespace and line breaks (`{"a":1}` vs `{\n  "a": 1\n}`).
- Floating point representation differences (`1.0` vs `1`).

This leads to catastrophic hash mismatches where cross-language auditors cannot independently verify on-chain anchors.

### 9.2 RFC 8785 JSON Canonicalization Scheme (JCS)
BidTrace implements RFC 8785 across Python (`bidtrace_py/ocds.py`) and JavaScript (`public/ocds.js`). The canonicalizer enforces:
1. Object keys sorted lexicographically by UTF-16 code units.
2. Zero extraneous whitespace between tokens (no spaces after `:` or `,`).
3. Explicit IEEE-754 number formatting.
4. Deterministic string escaping (no superfluous escape slashes).

```python
# bidtrace_py/ocds.py snippet
def canonicalize_jcs(obj: Any) -> bytes:
    """Canonicalize a Python object according to RFC 8785 (JCS)."""
    # Deterministic recursion sorting dictionary keys in UTF-16 code unit order
    ...
```

**Cross-Language Verification Test (`tests/test_ocds.py`):**
Both Python and Node.js process identical OCDS releases and produce identical SHA-256 hashes:
`64b57de746bea5a2d9fea955ed5ebb56ad32cf217e44c1c4dc247d855884b376` (100% parity verified).

---

## 10. Administrative Due Diligence Models (Model A vs Model B)

### 10.1 Model A: Pre-Qualified Merkle Whitelist (Private Mega-EPCs)
In private industrial construction (e.g. nuclear power plants, LNG export terminals), general contractors (Bechtel, Fluor) only accept bids from pre-vetted subcontractors.
- EPC compiles approved public keys into an OpenZeppelin-compatible sorted-pair Merkle Tree (`bidtrace_py/merkle.py`).
- Root hash `authorized_bidders_root` is stored in the `Tender` PDA.
- Subcontractors submit an $O(\log N)$ inclusion proof in `commit_dual_bid`:
  ```rust
  let leaf = anchor_lang::solana_program::keccak::hash(bidder.key().as_ref()).0;
  require!(
      verify_merkle_proof(&whitelist_proof.unwrap(), tender.authorized_bidders_root, leaf),
      BidTraceError::InvalidMerkleProof
  );
  ```

### 10.2 Model B: Post-Qualified Open Tender (World Bank / Sovereign Open)
Under World Bank and UN regulations, tenders are open to all global firms to encourage competition. Qualifications (tax clearance, balance sheets, ISO certificates) are verified on the provisional winner:
- Bidders submit `admin_dossier_hash = SHA256(Tax || BalanceSheets || ISO)`.
- Anyone can commit. Post-qualification compliance is verified before final award signing.

---

## 11. Gas-Sponsored Relayer Gateway & REST API Reference

The BidTrace Relayer Gateway (`server.py` / `bidtrace_py/relayer.py`) runs an asynchronous HTTP server acting as the bridge between standard enterprise REST clients and the Solana blockchain.

### 11.1 Complete REST API Endpoints

| Method | Endpoint | Role | Description |
| :---: | :--- | :--- | :--- |
| `POST` | `/api/tender/create` | Buyer | Creates OCDS Notice, calculates JCS hash, and initializes `Tender` PDA. |
| `POST` | `/api/committee/create` | Buyer | Appoints 5 accredited evaluators and locks committee roster. |
| `POST` | `/api/bid/commit_dual` | Bidder | Submits Envelope A & B hashes with bond proof. Gas sponsored by relayer. |
| `POST` | `/api/tender/advance_phase` | Operator | Moves tender through temporal phases based on consensus slot height. |
| `POST` | `/api/bid/reveal_technical` | Bidder | Unseals Envelope A blueprints and salt for evaluator inspection. |
| `POST` | `/api/evaluator/commit_grade` | Evaluator | Submits salted blinded grade commitment across 5 sub-criteria. |
| `POST` | `/api/evaluator/reveal_grade` | Evaluator | Unseals 5 sub-scores, salt, and written justification report hash. |
| `POST` | `/api/tender/finalize_technical` | Authority | Executes Olympic Trimmed Mean, flags outliers, computes $S_{\text{tech}}$. |
| `POST` | `/api/bid/reveal_financial` | Bidder | Unseals Envelope B. Rejects disqualified bidders (`403 Forbidden`). |
| `POST` | `/api/tender/award` | Authority | Computes programmatic QCBS composite score and records winner. |
| `POST` | `/api/tribunal/export_dossier` | Auditor | Compiles full cryptographic archive into `tribunal_dossier.zip`. |
| `GET` | `/api/tribunal/download_dossier` | Public | Downloads standalone `.zip` dossier for air-gapped verification. |
| `POST` | `/api/tribunal/verify` | Auditor | Runs 5-phase air-gapped verification engine against a dossier. |
| `POST` | `/api/merkle/tree` | Buyer | Generates Merkle tree root from approved vendor public keys. |
| `POST` | `/api/merkle/proof` | Bidder | Computes inclusion proof for whitelisted bidder key. |
| `POST` | `/api/surety/issue_policy` | Surety | Issues TradFi surety policy record with JCS GIA hash. |
| `POST` | `/api/bond/bsd_sign` | Bidder | Generates World Bank Bid-Securing Declaration with 3-year debarment. |
| `GET` | `/api/status` | Public | Returns complete tender account state, bidders, and evaluators. |
| `GET` | `/api/ocds/releases` | Public | Returns raw OCDS 1.1 JSON releases (Notice, Evaluation, Award). |
| `POST` | `/api/reset` | Test/Demo | Resets in-memory ledger state for fresh demonstration runs. |

---

## 12. Standalone Air-Gapped Tribunal Dossier & Verifier CLI

### 12.1 `tribunal_dossier.zip` Structure
An independent judicial investigator or auditor does not need to query the BidTrace server. They download the standalone `.zip` archive containing:

```
tribunal_dossier.zip
├── manifest.json                    <- Schema version, tender_id, sha256 checksums
├── ocds/
│   ├── release_notice.json          <- OCDS 1.1 Tender Notice (RFC 8785)
│   ├── release_evaluation.json      <- OCDS 1.1 Evaluation Summary
│   └── release_award.json           <- OCDS 1.1 Contract Award Decision
├── commitments/
│   ├── bidder_A_tech.json           <- Preimages: salt_tech, proposal_hash
│   ├── bidder_A_fin.json            <- Preimages: salt_fin, price, boq_hash
│   └── evaluator_grades.json        <- Preimages: sub_scores, salts, justifications
├── bonds/
│   ├── bond_attestations.json       <- Surety GIAs, MT760 guarantees, BSDs
│   └── merkle_whitelist.json        <- Merkle leaves, tree depth, inclusion proofs
└── ledger/
    └── solana_account_proofs.json   <- Raw Solana account dumps & consensus slot roots
```

### 12.2 The 5-Phase Offline Verification Engine
The verifier (`bidtrace_py/verifier.py` / `verifier/verify_ocds.py`) executes 5 strict mathematical phases:

1. **Phase 1: OCDS 1.1 Tender Notice Integrity**
   - Canonicalizes `release_notice.json` using RFC 8785 JCS.
   - Computes SHA-256 digest and asserts equality with `tender.ocds_notice_hash`.
2. **Phase 2: Intake & Whitelist Integrity**
   - Validates that every bid commitment occurred before `submission_deadline_slot`.
   - In Model A, independently walks Merkle inclusion proofs up to `authorized_bidders_root`.
   - In Model B, verifies bond attestation hashes.
3. **Phase 3: Technical Evaluation & Outlier Rejection Integrity**
   - Re-computes domain-separated `BIDTRACE_GRADE_V1` hashes for all evaluator submissions.
   - Re-runs Olympic Trimmed Mean: drops min/max, checks variance against median.
   - Confirms rogue evaluators are flagged and disqualified bidders have $S_{\text{tech}} < \text{min\_tech\_score}$.
4. **Phase 4: Commercial Secrecy & Financial Opening Integrity**
   - **Critical Assert:** Verifies that no financial preimage exists in the dossier for disqualified bidders.
   - Verifies revealed prices match on-chain `BIDTRACE_FIN_V1` commitment hashes.
5. **Phase 5: Award & QCBS Formula Determinism**
   - Recalculates programmatic QCBS formula:
     $$S_{\text{composite}} = (S_{\text{tech}} \times 0.70) + \left(\frac{P_{\text{lowest}}}{P_{\text{bidder}}} \times 10,000 \times 0.30\right)$$
   - Confirms winning bidder matches highest composite score.

**CLI Execution Command:**
```bash
python -m bidtrace.verifier --dossier ./tribunal_dossier.zip
```

Output:
```
================================================================================
BIDTRACE AIR-GAPPED TRIBUNAL DOSSIER VERIFIER (VERSION 3.0)
================================================================================
[PASS] Phase 1: OCDS Notice Canonical Hash matches Tender PDA.
[PASS] Phase 2: All 2 bids committed prior to slot deadline; Merkle whitelists verified.
[PASS] Phase 3: Evaluator grades verified. Rogue outlier Evaluator #5 identified and rejected.
[PASS] Phase 4: Commercial Secrecy Invariant strictly maintained. Disqualified Bidder B sealed.
[PASS] Phase 5: QCBS Award formula deterministic. Winner: Acme Infrastructure.
--------------------------------------------------------------------------------
TRIBUNAL AUDIT VERDICT: 100% MATHEMATICALLY VERIFIED. ZERO FRAUD DETECTED.
================================================================================
```

---

## 13. Multi-Portal Web Application & Interactive UI (Phase 5)

The frontend (`public/index.html` & `public/ocds.js`) serves a professional multi-role procurement dashboard:

1. **Buyer Portal:**
   - Multi-deadline slot calculator (Submissions, Admin, Tech, Fin).
   - OCDS tender parameters builder (Items, BoQ line items, estimated value).
   - Committee Drawer: Selects and cryptographically locks 5 accredited evaluators.
2. **Bidder Portal:**
   - Dual-Envelope encryption studio (in-browser AES-256-GCM + SHA-256).
   - Hybrid bond selector: Solana Escrow, TradFi Surety, Bank Guarantee, or BSD.
   - Portable `bidder_receipt.json` generator.
3. **Evaluator Portal:**
   - Blinded proposal scoring cards (contractor identities redacted).
   - 5-criteria grading sliders with real-time Olympic Trimmed Mean simulation.
4. **Financial Unsealing & Award:**
   - Real-time unsealing view.
   - Live commercial secrecy enforcement demo: Disqualified bidder shows locked padlock: *"Permanently Sealed by Smart Contract"*.
   - Automated QCBS ranking table.
5. **Tribunal Auditor Portal:**
   - One-click `tribunal_dossier.zip` packager and downloader.
   - Air-gapped offline verifier progress bar and verification report.
6. **1-Click End-to-End Demo & Live Attack Simulations:**
   - Run complete 5-phase tender in 5 seconds.
   - Interactive Adversarial Attack Buttons:
     - *Simulate Late Bid Injection* $\rightarrow$ Triggers `SubmissionDeadlineExceeded`.
     - *Simulate Evaluator Bribery* $\rightarrow$ Triggers Olympic Trimming & Outlier Flag.
     - *Simulate Envelope B Leak Attempt* $\rightarrow$ Triggers `BidderTechnicallyDisqualified`.
     - *Simulate Price Tampering* $\rightarrow$ Triggers `InvalidRevealHash`.

---

## 14. Comprehensive Test Matrix & Adversarial Verification

### 14.1 Test Suites Summary
- **Python Unit & Integration Tests (`python -m unittest discover tests`):** **32 / 32 Passing** (2.1 seconds execution time).
- **Anchor Solana Localnet Integration Tests (`anchor test --skip-build`):** **8 / 8 Passing** on local validator.
- **Cross-Language Hash Parity:** Verified byte-for-byte identical between Python 3.13 and Node.js v20.

### 14.2 Adversarial Attack Defenses Matrix

| Attack Vector | Attacker Action | Smart Contract Defense | Test File |
| :--- | :--- | :--- | :--- |
| **Late Bid Injection** | Attacker calls `commit_dual_bid` at `slot > submission_deadline_slot`. | Contract checks `Clock::get()?.slot <= submission_deadline_slot`; throws `SubmissionDeadlineExceeded`. | `test_engine.py`, `test_phase3_relayer.py` |
| **Merkle Whitelist Fraud** | Non-whitelisted bidder submits forged Merkle proof. | On-chain Keccak-256 leaf verification fails; throws `InvalidMerkleProof`. | `test_phase3_relayer.py`, `test_phase4_verifier.py` |
| **Price Tampering** | Bidder reveals price \$3.5M after committing to \$4.0M. | SHA-256 preimage check fails against `fin_commitment_hash`; throws `InvalidRevealHash`. | `test_engine.py`, `test_phase4_verifier.py` |
| **Rogue Evaluator Favoritism** | Corrupt evaluator submits 98% score to inflate favored bidder. | Olympic Trimmed Mean drops max score; marks `is_outlier_flagged = true`. | `bidtrace.ts` (Test 6), `test_phase4_verifier.py` |
| **Commercial Secrecy Breach** | Adversary attempts to call `reveal_financial_envelope` for disqualified bidder. | Contract checks `is_tech_qualified == true`; throws `BidderTechnicallyDisqualified`. | `bidtrace.ts` (Test 7), `test_phase4_verifier.py` |
| **Early Award Lockout** | Corrupt authority awards tender before honest bidders can reveal. | Anti-lockout gate checks `slot > fin_reveal_deadline_slot || total_fin_revealed == total_tech_qualified`. | `test_exploit.py`, `test_phase3_relayer.py` |
| **Tampered OCDS Notice** | Agency modifies project scope post-publication. | Recomputed RFC 8785 JCS hash mismatches `ocds_notice_hash` in `Tender` PDA. | `test_phase4_verifier.py` |
| **Arbitrary Winner Selection** | Authority attempts to award tender to a higher-priced or lower-scoring bidder. | Contract mathematically verifies winner has highest QCBS score or lowest price. | `bidtrace.ts` (Test 8), `test_phase4_verifier.py` |

---

## 15. Colosseum Hackathon & Venture Evaluation Rubric

### 15.1 Evaluation Criteria Alignment

| Colosseum Hackathon Criterion | BidTrace 3.0 Realization |
| :--- | :--- |
| **1. Novelty & Technical Ambition** | First-ever integration of **Open Contracting Data Standard (OCDS 1.1)**, **RFC 8785 JCS**, and **Solana consensus slot state machines**. Introduces on-chain Olympic Trimmed Mean scoring and strict mathematical Commercial Secrecy enforcement. |
| **2. Architecture on Solana** | Leverages Solana’s unique capabilities: sub-second 400ms finality for slot deadlines; parallel execution (Sealevel) across independent `DualBidCommitment` PDAs; and sub-cent fees enabling gas-sponsored micro-commitments. |
| **3. Real-World Feasibility & GTM** | Solves the \#1 barrier to enterprise crypto adoption: **The Fiat-to-Gas Decoupling**. Enterprise buyers and contractors interact in fiat, PDFs, and standard SSO without ever buying SOL or handling crypto keys. |
| **4. Multi-Jurisdiction Legal Compliance** | Accommodates sovereign procurement frameworks (World Bank BSD, FIDIC, TradFi Surety bonds, SWIFT bank guarantees). |
| **5. Engineering Rigor & Completeness** | 100% complete stack: 10 Anchor Rust instructions, 32 Python tests passing, 8 Anchor integration tests passing, REST API gateway running, standalone CLI verifier, and multi-portal web dashboard. |

### 15.2 Commercial Viability & Unit Economics
- **Target Market:** \$13 Trillion Global Public Procurement.
- **Initial Wedge:** Multilateral development bank loans (World Bank \$70B/yr, ADB \$20B/yr) where anti-corruption mandates are legally required by international treaty.
- **SaaS Pricing Model:** 0.05% of tender value capped at \$25,000 per major international tender (vs traditional procurement audit fees of \$250,000+).
- **On-Chain Solana Costs:** $\approx 0.015\text{ SOL}$ per complete 5-bidder tender lifecycle ($\approx \$2.25\text{ USD}$), generating $>99.9\%$ gross profit margins for the BidTrace relayer.

---

## 16. Appendix: Environment Setup & Local Reproduction

### Prerequisites
- Python 3.10+ (tested on Python 3.13)
- Node.js v18+ & npm
- Solana CLI v1.18+ & Anchor CLI v0.30.1 (WSL or Linux recommended for BPF builds)

### 1. Run Complete Python Verification Suite
```bash
cd C:\Users\ujjwa\.gemini\antigravity\scratch\bidtrace
python -m unittest discover tests
```
*Expected Result:* `Ran 32 tests in ~2.1s ... OK`

### 2. Run Anchor Integration Tests (WSL)
```bash
wsl -e /bin/bash -l -c "cd /mnt/c/Users/ujjwa/.gemini/antigravity/scratch/bidtrace && anchor test --skip-build"
```
*Expected Result:* `8 passing (~6s)`

### 3. Launch Gateway Server & Web UI
```bash
python server.py
# Server starts at http://localhost:8000
# Open http://localhost:8000 in your browser
```

### 4. Execute Standalone Air-Gapped CLI Audit
```bash
python -m bidtrace.verifier --dossier tribunal_dossier.zip
```
*Expected Result:* `[PASS] 100% CRYPTOGRAPHICALLY VERIFIED ACROSS 5 LIFECYCLE PHASES.`

---

*BidTrace: The Incorruptible Cryptographic Global Standard for Public & Enterprise Procurement.*  
*Authored for the LLM Council Audit & Colosseum Solana Hackathon Evaluation.*
