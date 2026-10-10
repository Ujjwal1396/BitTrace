# BidTrace 3.0: The Global Standard for Public & Enterprise Procurement
## Master Architecture Specification & Phased Engineering Roadmap

**Document Version:** 3.0.0  
**Target Ledger:** Solana (Anchor v0.30+)  
**Semantic Standard:** Open Contracting Data Standard (OCDS 1.1)  
**Serialization Standard:** RFC 8785 (JSON Canonicalization Scheme - JCS)  
**Target Market:** Multilateral Development Banks (World Bank, ADB, UN), Sovereign Ministries, and Private Mega-EPC Contractors (Bechtel, VINCI, Fluor, Skanska).

---

## 1. Executive Summary & Core Strategic Positioning

BidTrace transforms public and enterprise procurement from an adversarial, paper-based, corruption-prone process into an **incorruptible, mathematically verifiable cryptographic state machine**.

### The Breakthrough Strategic Invariants:
1. **The Fiat-to-Gas Decoupling:** Bidders and buyers never touch cryptocurrency, holding tokens, or managing crypto exchange accounts. They interact via standard web portals and pay via corporate invoicing / credit cards. BidTrace’s `fee_payer` relayer sponsors all on-chain gas. This ensures 100% legal compliance even in jurisdictions where cryptocurrency transactions are restricted or banned.
2. **The Two-Plane Architecture:**
   * **The Semantic Data Plane (Off-Chain):** Standard OCDS 1.1 JSON format storing all project descriptions, bills of quantities, milestones, and parties.
   * **The Cryptographic Enforcement Plane (On-Chain Solana):** Enforces temporal deadlines (slots), non-custodial commitments (PDAs), blinded evaluator scoring, and programmatic award formulas.
3. **The Multi-Jurisdiction Bond Engine:** Supports native crypto escrows, TradFi **Surety-as-a-Service** (licensed underwriters with full legal indemnity recourse), digital bank guarantees (Lygon/SWIFT model), and World Bank **Bid-Securing Declarations (BSD)**.

---

## 2. High-Level System Architecture

```
+---------------------------------------------------------------------------------------------------------+
|                                    BIDTRACE 3.0 FULL ARCHITECTURAL STACK                                |
+---------------------------------------------------------------------------------------------------------+
|                                                                                                         |
|  [PORTAL LAYER]              Buyer Portal         Bidder Portal       Evaluator Portal    Auditor View  |
|  (WebAuthn / Passkeys)       (OCDS Notice)        (Dual Envelopes)    (Blinded Rubrics)   (Tribunal)    |
|                                     │                   │                    │                 │        |
|                                     ▼                   ▼                    ▼                 ▼        |
|  [GATEWAY & RELAYER]        ┌──────────────────────────────────────────────────────────────────┐        |
|  (Fiat-to-Gas Abstraction)  │  BidTrace Relayer API (Sponsors Gas / Manages Fee-Payer Keypair) │        |
|                             └─────────────────────────────────┬────────────────────────────────┘        |
|                                                               │                                         |
|  [SEMANTIC PLANE]           ┌─────────────────────────────────▼────────────────────────────────┐        |
|  (Off-Chain / Decentralized)│  OCDS 1.1 JCS Engine (RFC 8785 Canonical Hashing) & IPFS / S3   │        |
|                             └─────────────────────────────────┬────────────────────────────────┘        |
|                                                               │                                         |
|  [ENFORCEMENT PLANE]        ┌─────────────────────────────────▼────────────────────────────────┐        |
|  (Solana Anchor Runtime)    │  programs/bidtrace (Solana Program ID: x3iSm5BCo...ESjZ)         │        |
|                             │  * State Accounts: Tender, DualBidCommitment, TenderCommittee    │        |
|                             │  * Slot Deadline Engine: Submissions -> Review -> Financial -> Award      │
|                             │  * On-Chain Olympic Trimmed Mean Evaluator Filter                │        |
|                             │  * Programmatic QCBS Composite Scoring Formula                   │        |
|                             └──────────────────────────────────────────────────────────────────┘        |
+---------------------------------------------------------------------------------------------------------+
```

---

## 3. The On-Chain State Machine & Account Layouts

### 3.1. Account Layout 1: `Tender` PDA
* **Seeds:** `[b"tender", authority.key().as_ref(), tender_id.as_bytes()]`
```rust
#[account]
pub struct Tender {
    pub authority: Pubkey,                  // 32 bytes
    pub tender_id: String,                  // 4 + 32 bytes
    pub ocds_notice_hash: [u8; 32],         // 32 bytes (RFC 8785 hash of OCDS Notice)
    pub tender_mode: TenderMode,            // 1 byte (Model A: PreQualified vs Model B: PostQualified)
    pub evaluation_type: EvaluationType,    // 1 byte (LCS vs QCBS)
    pub status: TenderStatus,               // 1 byte

    // Slot Boundaries (Solana Consensus Time)
    pub submission_deadline_slot: u64,      // 8 bytes
    pub admin_review_deadline_slot: u64,    // 8 bytes
    pub tech_eval_deadline_slot: u64,       // 8 bytes
    pub fin_reveal_deadline_slot: u64,      // 8 bytes

    // Model A: Pre-Qualified Merkle Whitelist Root
    pub authorized_bidders_root: [u8; 32],   // 32 bytes

    // Two-Envelope Scoring Parameters (Basis Points: 10,000 = 100%)
    pub min_tech_score_bps: u16,            // 2 bytes (e.g., 7500 = 75.00% cutoff)
    pub tech_weight_bps: u16,               // 2 bytes (e.g., 7000 = 70%)
    pub fin_weight_bps: u16,                // 2 bytes (e.g., 3000 = 30%)

    // Progress Counters
    pub total_committed: u32,               // 4 bytes
    pub total_admin_passed: u32,            // 4 bytes
    pub total_tech_qualified: u32,          // 4 bytes
    pub total_fin_revealed: u32,            // 4 bytes

    // Pricing & Award Tracking
    pub lowest_revealed_price: u64,         // 8 bytes
    pub highest_composite_score: u64,       // 8 bytes
    pub winning_bidder: Option<Pubkey>,     // 1 + 32 bytes
    pub bump: u8,                           // 1 byte
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum TenderStatus {
    SubmissionsOpen = 0,
    AdministrativeReview = 1,
    TechnicalEvaluation = 2,
    FinancialEvaluation = 3,
    Awarded = 4,
    Cancelled = 5,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum TenderMode {
    PreQualifiedWhitelist = 0, // Model A (Private EPCs / Merkle Root)
    PostQualifiedOpen = 1,     // Model B (World Bank / Bond Escrow)
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum EvaluationType {
    LeastCost = 0,
    QCBS = 1,
}
```

### 3.2. Account Layout 2: `DualBidCommitment` PDA
* **Seeds:** `[b"bid", tender.key().as_ref(), bidder.key().as_ref()]`
```rust
#[account]
pub struct DualBidCommitment {
    pub tender: Pubkey,                     // 32 bytes
    pub bidder: Pubkey,                     // 32 bytes
    pub committed_at_slot: u64,             // 8 bytes

    // Cryptographic Hashes
    pub admin_dossier_hash: [u8; 32],       // 32 bytes (Tax, Balance Sheets, ISO)
    pub tech_commitment_hash: [u8; 32],     // 32 bytes (Envelope A: Blueprints + salt_tech)
    pub fin_commitment_hash: [u8; 32],      // 32 bytes (Envelope B: Price + BoQ + salt_fin)

    // Phase 1: Administrative Qualification
    pub admin_status: AdminStatus,          // 1 byte (Pending, Passed, Failed)
    pub admin_rejection_code: u16,          // 2 bytes (Statutory code if failed)

    // Phase 2: Technical Merit Scoring
    pub is_tech_revealed: bool,             // 1 byte
    pub technical_score_bps: u16,           // 2 bytes (Trimmed mean result)
    pub is_tech_qualified: bool,            // 1 byte (True if score >= min_tech_score)

    // Phase 3: Financial Unsealing & Scoring
    pub is_fin_revealed: bool,              // 1 byte
    pub revealed_price: u64,                // 8 bytes
    pub composite_score: u64,               // 8 bytes

    // Bond & Security Escrow
    pub bond_mode: BondMode,                // 1 byte (CryptoEscrow, SuretyService, BankGuarantee, BSD)
    pub bond_amount: u64,                   // 8 bytes
    pub is_bond_settled: bool,              // 1 byte
    pub bump: u8,                           // 1 byte
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AdminStatus {
    Pending = 0,
    Passed = 1,
    Failed = 2,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum BondMode {
    SolanaEscrow = 0,
    SuretyService = 1,
    BankGuaranteeAttestation = 2,
    BidSecuringDeclaration = 3,
}
```

### 3.3. Account Layout 3: `TenderCommittee` & `EvaluatorGrade` PDAs
* **Committee PDA Seeds:** `[b"committee", tender.key().as_ref()]`
* **Grade PDA Seeds:** `[b"grade", tender.key().as_ref(), evaluator.key().as_ref(), bidder.key().as_ref()]`
```rust
#[account]
pub struct TenderCommittee {
    pub tender: Pubkey,                     // 32 bytes
    pub evaluators: Vec<Pubkey>,            // 4 + (32 * 7) = 228 bytes (5 to 7 drawn evaluators)
    pub max_variance_bps: u16,              // 2 bytes (2000 bps = 20.00% outlier rejection)
    pub is_locked: bool,                    // 1 byte
    pub bump: u8,                           // 1 byte
}

#[account]
pub struct EvaluatorGrade {
    pub tender: Pubkey,                     // 32 bytes
    pub evaluator: Pubkey,                  // 32 bytes
    pub bidder: Pubkey,                     // 32 bytes
    pub commitment_hash: [u8; 32],          // 32 bytes (Salted commitment of 5 sub-criteria)
    pub committed_at_slot: u64,             // 8 bytes
    pub is_revealed: bool,                  // 1 byte
    pub sub_scores: [u16; 5],               // 10 bytes
    pub total_score_bps: u16,               // 2 bytes
    pub justification_hash: [u8; 32],       // 32 bytes (SHA-256 of written justification report)
    pub is_outlier_flagged: bool,           // 1 byte (Flagged if rejected by trimmed mean)
    pub bump: u8,                           // 1 byte
}
```

---

## 4. The 8 Role-Based Action & Verification User Stories

### Story 1: Procurement Authority (OCDS Tender Notice & Committee Draw)
* **Goal:** Publish an international Two-Envelope tender in standard OCDS 1.1 and establish the evaluation committee without touching cryptocurrency.
* **Flow:**
  1. Authority enters tender parameters in the BidTrace Buyer Portal.
  2. The portal compiles `ocds_tender_release.json` and canonicalizes it using RFC 8785 (JCS) to produce `ocds_notice_hash`.
  3. Authority signs via WebAuthn/corporate SSO; the BidTrace Relayer dispatches `initialize_tender` with gas sponsored.
  4. Once submissions close, slot randomness draws 5 certified evaluators from the accredited pool into `TenderCommittee`.
* **Acceptance Criteria:** `Tender` PDA is initialized on Solana; OCDS release is published with explorer verification links.

### Story 2: The Contractor / Bidder (Dual-Envelope Commit & Portable Receipt)
* **Goal:** Submit a confidential technical proposal and financial quotation before the slot deadline and receive an air-gapped receipt.
* **Flow:**
  1. Contractor uploads Technical Specs (PDF blueprints) and Financial Quotation (\$3.85M, bill of quantities).
  2. Local browser generates $K_{\text{tech}}, salt_{\text{tech}}$ and $K_{\text{fin}}, salt_{\text{fin}}$, encrypting Envelope A and Envelope B independently.
  3. Relayer dispatches `commit_dual_bid(admin_hash, tech_hash, fin_hash)` before `submission_deadline_slot`.
  4. Contractor downloads portable `bidder_receipt.json`.
* **Acceptance Criteria:** Both hashes land in the `DualBidCommitment` PDA; plaintext files and keys never leave the contractor's browser.

### Story 3: Private EPC General Contractor (Model A: Pre-Qualified Merkle Whitelist)
* **Goal:** Launch an invited tender restricted strictly to subcontractors on the EPC's pre-approved vendor list (e.g. from Procore or SAP).
* **Flow:**
  1. EPC exports approved subcontractor public keys into a Merkle Tree.
  2. `initialize_tender` stores `authorized_bidders_root` in the `Tender` PDA.
  3. When an invited subcontractor bids, their client includes a Merkle inclusion proof.
* **Acceptance Criteria:** Smart contract rejects any bid not belonging to the Merkle tree in $< 1\text{ ms}$; zero manual clerk review required.

### Story 4: The Technical Evaluator (Blinded Isolation Scoring)
* **Goal:** Review an anonymized proposal in complete isolation and commit a binding score without seeing peer evaluations.
* **Flow:**
  1. Evaluator reviews `Proposal-74X` (company identity redacted).
  2. Evaluator scores 5 standardized sub-criteria totaling 0–10,000 bps and attaches a written justification report.
  3. Evaluator commits `eval_commitment_hash = SHA256(tender || bidder || evaluator || salt || sub_scores || report_hash)`.
  4. Post-deadline, evaluator reveals the preimage; Anchor verifies the hash.
* **Acceptance Criteria:** Evaluator scores cannot be observed or modified prior to the simultaneous reveal.

### Story 5: The Corrupt Evaluator / Adversary (Automated Outlier Rejection)
* **Goal:** Ensure rogue score manipulation is neutralized mathematically.
* **Flow:**
  1. Honest evaluators score `Proposal-74X` at 62%, 65%, 63%, and 66%. Rogue Evaluator #5 gives 98% to inflate their friend.
  2. `finalize_technical_scores()` applies the Olympic trimming filter: drops the minimum (62%) and maximum (98%).
  3. Contract detects deviation $> 20\%$ from the median, discards the rogue score, and marks `is_outlier_flagged = true`.
* **Acceptance Criteria:** Favoritism fails; rogue evaluator's profile receives an indelible on-chain audit flag.

### Story 6: The Disqualified Bidder (The Commercial Secrecy Guarantee)
* **Goal:** Guarantee that failing bidders never have their proprietary pricing inspected or leaked.
* **Flow:**
  1. Bidder fails technical qualification ($S_{\text{tech}} = 64.66\% < 75.00\%$).
  2. Tender transitions to `FinancialEvaluation`.
  3. Competitor or buyer attempts to call `reveal_financial_envelope` for the disqualified bidder.
  4. Contract throws `BidTraceError::BidderTechnicallyDisqualified`.
* **Acceptance Criteria:** Financial encryption key $K_{\text{fin}}$ is never published; proprietary pricing remains unbreakable on Solana forever.

### Story 7: The Qualified Winner (Financial Opening & QCBS Award)
* **Goal:** Unseal financial envelopes for qualified bidders and execute programmatic QCBS contract award.
* **Flow:**
  1. Qualified Bidders A and B reveal $K_{\text{fin}}$ and prices ($P_A = \$4.2\text{M}, P_B = \$3.8\text{M}$).
  2. Contract computes on-chain QCBS:
     $$S_{\text{composite}} = (S_{\text{tech}} \times 0.70) + \left(\frac{P_{\text{lowest}}}{P_{\text{bidder}}} \times 10,000 \times 0.30\right)$$
  3. Authority invokes `record_award()`. The contract confirms the highest score mathematically and sets `winning_bidder`.
* **Acceptance Criteria:** Award is 100% deterministic; compliant bidders receive bond refunds.

### Story 8: World Bank / Tribunal Auditor (Air-Gapped OCDS Verification)
* **Goal:** Audit the entire procurement lifecycle without trusting the BidTrace backend.
* **Flow:**
  1. Auditor downloads `tribunal_dossier.zip` from the public portal.
  2. On an air-gapped laptop, auditor runs:
     ```bash
     python -m bidtrace.verifier --dossier ./tribunal_dossier.zip
     ```
  3. Verifier independently checks OCDS hashes, slot boundaries, trimmed mean math, and QCBS scores against raw Solana RPC snapshots.
* **Acceptance Criteria:** Returns `[PASS] 100% CRYPTOGRAPHICALLY VERIFIED ACROSS 5 LIFECYCLE PHASES`.

---

## 5. The Phased Implementation Roadmap

```
PHASE 1: OCDS 1.1 + RFC 8785 Canonical JCS Engine
├── Create python & typescript OCDS schemas
├── Implement RFC 8785 JSON canonicalizer & SHA-256 hasher
└── Unit tests verifying cross-language deterministic hash parity

PHASE 2: Anchor Two-Envelope & Committee Smart Contract
├── Upgrade programs/bidtrace with DualBidCommitment & TenderCommittee PDAs
├── Implement commit_dual_bid, reveal_tech, commit_grade, reveal_grade
├── Implement on-chain Olympic trimmed mean & QCBS math
└── Test in local validator with 8 integration tests

PHASE 3: Multi-Jurisdiction Bond & Relayer Gateway Server
├── Integrate fee_payer relayer into server.py
├── Implement Model A (Merkle Root) and Model B (Post-Qualification) handlers
└── Implement Surety-as-a-Service fiat API endpoints

PHASE 4: Standalone Air-Gapped OCDS Verifier CLI
├── Build verifier/verify_ocds.py and verifier/verify_ocds.ts
└── Implement tribunal dossier packaging and verification suite

PHASE 5: Multi-Portal Web Dashboard & Interactive Demo
├── Buyer Portal: Tender creator with OCDS fields & committee drawer
├── Bidder Portal: Dual-envelope browser encryption & receipt exporter
├── Evaluator Portal: Blinded rubric grading interface
└── Public Explorer: OCDS API and live Solana transaction feed
```

---

## 6. Execution Decision

We are ready to build **Phase 1: The OCDS 1.1 + RFC 8785 Canonical Hashing Engine**. This provides the data backbone that will power our upgraded smart contracts, relayers, and frontend.
