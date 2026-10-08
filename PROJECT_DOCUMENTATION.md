# BidTrace: Cryptographic Protocol Specification & Architectural Evaluation Dossier

**Protocol Name:** BidTrace  
**Specification Version:** 1.1.0  
**Repository:** [https://github.com/Ujjwal1396/BitTrace](https://github.com/Ujjwal1396/BitTrace)  
**Target Platform:** Solana / Anchor Framework (Anchor 0.30+)  
**Reference Implementation:** Python 3.10+ Cryptographic Engine & Deterministic State Machine  

---

## 1. Executive Summary

Every year, trillions of dollars are transacted through public works, infrastructure concessions, and multilateral loans (World Bank, ADB). Empirical analysis of public procurement fraud indicates that the most critical vulnerability window is operational: **the interval between the bid submission deadline and the public bid evaluation.**

In centralized e-procurement architectures (e-GP portals, enterprise ERP databases), bids are collected and stored on database servers managed by system administrators. An insider with administrative credentials or a compromised database account can observe competing bids after submissions close, discover the lowest compliant price, and backdate a favored submission or alter an existing record prior to the official opening. When challenged by honest bidders, the operator appeals to the authoritative record of their database: *"That is what our database recorded."*

**BidTrace** addresses this integrity breakdown through an adversarial, tamper-evident commit-reveal architecture anchored to Solana's consensus clock. Bidders write 32-byte domain-separated cryptographic commitments directly to non-custodial Program Derived Addresses (PDAs). Once consensus passes the submission deadline slot, the intake window freezes immutably. Furthermore, BidTrace enforces an explicit reveal window with anti-lockout gating, lowest-bidder verification, and refundable bid bond deposits to eliminate premature award collusion and free-option defaults.

---

## 2. Core Problem & Explicit Threat Boundaries

### 2.1 The Post-Deadline Exploitation Window
Traditional electronic procurement relies on trusted infrastructure providers:
1. **Submission Window:** Bids are uploaded before a calendar deadline (e.g., Friday at 12:00:00 UTC).
2. **Evaluation Window:** Bids remain stored on a database until official decryption and evaluation (e.g., hours or days later).
3. **The Attack Vector:** 
   * An administrator with root database access inspects submitted values at 12:05 UTC.
   * If Bidder A bid \$4,200,000 and Bidder B bid \$3,950,000, a colluding operator can construct a synthetic submission for Bidder C at \$3,900,000, backdate the database timestamp to 11:55 UTC, and update audit tables retroactively.

### 2.2 Explicit Threat Boundaries & Non-Goals
To maintain scientific and systems rigor, BidTrace explicitly bounds its security guarantees:

* **What BidTrace DOES Guarantee:**
  1. **Bid-Set Completeness at Deadline:** Proof that any bid considered in evaluation was committed prior to `submission_deadline_slot`.
  2. **Non-Custodial Intake (Censorship Resistance):** Bidders commit directly to Solana PDAs; a procurement operator cannot drop, omit, or censor a valid commitment.
  3. **Cryptographic Binding:** A bidder cannot alter their revealed pricing or technical specifications without causing a SHA-256 preimage verification failure.
  4. **Anti-Lockout Gating:** An authority and a colluding bidder cannot prematurely record an award before honest bidders have had the opportunity to reveal within the active reveal window.
  5. **Air-Gapped Auditability:** An independent auditor holding a standalone `proof_bundle.json` can verify bid validity directly against raw on-chain state without communicating with the procurement server.

* **What BidTrace Does NOT Claim (Explicit Non-Goals):**
  * **Off-Chain Physical Corruption:** BidTrace cannot prevent physical bribery, extortion, or off-chain cartel arrangements formed prior to submission.
  * **Contractor Competence:** BidTrace does not verify the physical engineering quality of concrete, steel, or construction execution.
  * **Pre-Qualification Administrative Decisions:** The Merkle whitelist root (`authorized_bidders_root`) enforces that only approved public keys can commit bids; it does not evaluate whether the authority's initial paperwork review of qualifying contractors was impartial.
  * **Public Ledger Confidentiality Leakage:** Sensitive corporate commercial strategies and trade secrets are never written in plaintext to the public ledger. Plaintext stays strictly off-chain until reveal.

---

## 3. Threat Model & Security Properties

### 3.1 Adversarial Model
* **The Adversary:** A colluding, coerced, or compromised procurement authority holding administrative database and server access.
* **Adversary Capabilities:** Can modify off-chain database rows, forge application-level timestamps, delete competitors' off-chain records, and shut down public web servers.
* **Adversary Limits:** Cannot invert SHA-256 preimages, cannot forge Ed25519 digital signatures, cannot forge AES-256-GCM authentication tags, and cannot rewrite consensus history confirmed by Solana validators.

### 3.2 Core Security Invariants
1. **Submission Deadline Invariant:** No commitment transaction is valid if confirmed at `Clock::get()?.slot > submission_deadline_slot`.
2. **Pre-Deadline Confidentiality:** Bid prices and specifications are protected under AES-256-GCM with locally held 256-bit symmetric keys.
3. **Domain Separation:** Every commitment preimage explicitly binds `"BIDTRACE_V1"`, `tender_pda`, `bidder_pubkey`, `salt`, `ciphertext_hash`, and `bid_amount`. Commitments cannot be replayed across different tenders or bidders.
4. **Anti-Lockout Invariant:** An award cannot be recorded while `clock.slot <= reveal_deadline_slot` unless 100% of committed bids have revealed (`total_revealed == total_committed`).
5. **Lowest-Bidder Invariant:** The awarded winner must match the lowest compliant revealed bid recorded on-chain.
6. **Economic Commitment (Bid Bond):** A refundable deposit (`bid_deposit`) is escrowed during `commit_bid` and refunded only upon valid reveal, discouraging unrevealed free options.

---

## 4. Architectural Solutions to Critical Procurement Flaws

### 4.1 Flaw A: The "Selective Exclusion" Censorship Trap
* **Naive Architecture:** An off-chain server collects all encrypted bids, computes an aggregate Merkle tree root, and posts that single root on-chain. If the operator wishes to exclude Contractor C, they omit Contractor C from the Merkle tree and claim: *"We suffered network congestion and never received your packet."*
* **BidTrace Resolution — Direct PDA Intake:**
  Bidders do not submit commitments to an intermediary server. Bidders sign and broadcast a 32-byte commitment directly to a deterministic Program Derived Address (PDA):
  $$\text{PDA} = \text{findProgramAddress}([\text{"bid"},\, \text{tender\_pda},\, \text{bidder\_pubkey}],\, \text{program\_id})$$
  Because validators process transactions directly, the procurement operator possesses zero gatekeeping or censorship capability.

### 4.2 Flaw B: The "All-or-Nothing" Opening Deadlock
* **Naive Architecture:** Systems requiring a single composite root comparison ($\text{DEADLINE\_ROOT} \stackrel{?}{=} \text{OPENING\_ROOT}$) fail catastrophically if a single bidder defaults, loses their key, or intentionally withholds their reveal.
* **BidTrace Resolution — Leaf-by-Leaf Independent State Machine:**
  Each bid is tracked in its own `BidCommitment` account. Bidders reveal individually. Defaulting bidders do not obstruct honest participants; once the reveal deadline elapses, evaluation proceeds among compliant revealed bids.

### 4.3 Flaw C: The "Early-Award Lockout" Vulnerability
* **The Vulnerability Identified:** If a protocol permits the procurement authority to record an award as soon as any single bidder reveals, a corrupt authority colluding with Bidder B could coordinate for Bidder B to reveal first, immediately execute `record_award`, flip the tender state to `Awarded`, and lock out lower-priced honest Bidder A.
* **BidTrace Resolution — Two-Deadline Phasing & Gated Award:**
  The protocol splits the process into two distinct consensus slots:
  1. `submission_deadline_slot`: Intake closes; tender flips to `Locked`.
  2. `reveal_deadline_slot`: Window for bidders to submit reveal proofs.
  
  The instruction `record_award` strictly enforces:
  $$\text{require!}(\text{slot} > \text{reveal\_deadline\_slot} \lor \text{total\_revealed} == \text{total\_committed},\, \text{RevealWindowActive})$$
  Honest bidders are guaranteed the full duration of `reveal_deadline_slot` to reveal their submissions.

### 4.4 Flaw D: The "Free Option" Walkaway Exploit
* **The Vulnerability:** Without an attached commitment bond, a bidder who commits to multiple price scenarios or realizes market conditions changed can withhold their reveal with zero penalty.
* **BidTrace Resolution — Escrowed Bid Bonds (`bid_deposit`):**
  When `commit_bid` is called, the bidder must escrow `bid_deposit` lamports into the `BidCommitment` PDA.
  Upon successful preimage verification in `reveal_bid`, the deposit is refunded to the bidder. If the bidder fails to reveal before `reveal_deadline_slot`, the bond is forfeited.

---

## 5. System Architecture & Cryptographic Construction

```
+---------------------------------------------------------------------------------------+
| 1. PRE-DEADLINE COMMITMENT (Local Bidder Client)                                      |
|                                                                                       |
|  Plaintext Payload: { "bidder": "ACME Corp", "amount": 4200000, "specs": "..." }     |
|                                                                                       |
|  Local Encryption (AES-256-GCM):                                                      |
|    key = CSPRNG(256-bit)                                                              |
|    nonce = CSPRNG(96-bit)                                                             |
|    ciphertext = AES-256-GCM(key, nonce, plaintext)                                    |
|    ciphertext_hash = SHA256(nonce || ciphertext)                                      |
|                                                                                       |
|  Domain-Separated Cryptographic Commitment:                                          |
|    commitment_hash = SHA256(                                                          |
|        "BIDTRACE_V1" || tender_pda || bidder_pubkey || salt ||                         |
|        ciphertext_hash || bid_amount.to_le_bytes(8)                                   |
|    )                                                                                  |
|                                                                                       |
|  Anchor Instruction: commit_bid(commitment_hash) [Escrows bid_deposit]                |
|  -> On-Chain Check: clock.slot <= tender.submission_deadline_slot                      |
+---------------------------------------------------------------------------------------+
                                          │
                                          ▼
+---------------------------------------------------------------------------------------+
| 2. SUBMISSION DEADLINE FREEZE                                                         |
|                                                                                       |
|  Consensus slot advances past submission_deadline_slot.                               |
|  Permissionless instruction lock_tender() flips status to LOCKED.                     |
|  No further commitments can execute. Reveal window is now open.                       |
+---------------------------------------------------------------------------------------+
                                          │
                                          ▼
+---------------------------------------------------------------------------------------+
| 3. REVEAL WINDOW (clock.slot <= tender.reveal_deadline_slot)                          |
|                                                                                       |
|  Bidder broadcasts reveal proof: { salt, ciphertext_hash, bid_amount }                |
|  Anchor instruction: reveal_bid(salt, ciphertext_hash, bid_amount)                     |
|  On-Chain Check: clock.slot <= tender.reveal_deadline_slot                             |
|  On-Chain Check: computed_hash == bid.commitment_hash                                 |
|  -> On Match:                                                                         |
|     - bid.is_revealed = true                                                          |
|     - tender.total_revealed += 1                                                      |
|     - tender tracks lowest compliant bid                                              |
|     - bid_deposit is refunded to bidder account                                       |
+---------------------------------------------------------------------------------------+
                                          │
                                          ▼
+---------------------------------------------------------------------------------------+
| 4. GATED AWARD RECORDING                                                              |
|                                                                                       |
|  Authority invokes record_award(winning_bidder)                                       |
|  Anti-Lockout Gate: clock.slot > reveal_deadline_slot || total_revealed == committed    |
|  Lowest-Bidder Gate: winning_bidder == tender.lowest_bidder                            |
|  Status flips to AWARDED. Defaulted unrevealed deposits remain forfeited.             |
+---------------------------------------------------------------------------------------+
```

---

## 6. On-Chain Smart Contract Specification (`programs/bidtrace/`)

The Anchor program is organized into decoupled instructions with explicit security constraints:

### 6.1 State Accounts (`state.rs`)
* **`Tender` PDA:** Derived from `[b"tender", authority.key(), tender_id.as_bytes()]`
  * `authority: Pubkey`
  * `tender_id: String` (max 32 chars)
  * `submission_deadline_slot: u64`
  * `reveal_deadline_slot: u64`
  * `bid_deposit: u64`
  * `authorized_bidders_root: [u8; 32]`
  * `total_committed: u32`
  * `total_revealed: u32`
  * `lowest_revealed_amount: u64`
  * `lowest_bidder: Option<Pubkey>`
  * `status: TenderStatus` (`Active`, `Locked`, `Awarded`, `Cancelled`)
  * `winning_bidder: Option<Pubkey>`
* **`BidCommitment` PDA:** Derived from `[b"bid", tender.key(), bidder.key()]`
  * `tender: Pubkey`
  * `bidder: Pubkey`
  * `commitment_hash: [u8; 32]`
  * `committed_at_slot: u64`
  * `escrowed_deposit: u64`
  * `is_revealed: bool`
  * `revealed_at_slot: u64`
  * `revealed_amount: u64`

### 6.2 Instruction Specifications
1. **`initialize_tender(tender_id, submission_deadline_slot, reveal_deadline_slot, bid_deposit, authorized_bidders_root)`**
   * Enforces `submission_deadline_slot > clock.slot`.
   * Enforces `reveal_deadline_slot > submission_deadline_slot`.
   * Initializes `Tender` PDA with `TenderStatus::Active`.
2. **`commit_bid(commitment_hash, whitelist_proof)`**
   * Enforces `tender.status == TenderStatus::Active`.
   * Enforces `clock.slot <= tender.submission_deadline_slot`.
   * Escrows `tender.bid_deposit` from fee payer into the `BidCommitment` PDA via System CPI.
   * Increments `tender.total_committed`.
3. **`lock_tender()`**
   * Permissionless caller.
   * Enforces `tender.status == TenderStatus::Active`.
   * Enforces `clock.slot > tender.submission_deadline_slot`.
   * Transitions status to `TenderStatus::Locked`.
4. **`reveal_bid(salt, ciphertext_hash, bid_amount)`**
   * Enforces `tender.status == TenderStatus::Locked`.
   * Enforces `clock.slot <= tender.reveal_deadline_slot`.
   * Computes domain-separated SHA-256 and asserts equality to `bid.commitment_hash`.
   * Sets `bid.is_revealed = true`, updates `tender.lowest_bidder` if lowest.
   * Directly refunds `escrowed_deposit` lamports from `BidCommitment` PDA to `bidder_recipient`.
5. **`record_award(rationale_hash)`**
   * Enforces `tender.status == TenderStatus::Locked` and caller is `tender.authority`.
   * Enforces `clock.slot > tender.reveal_deadline_slot || tender.total_revealed == tender.total_committed`.
   * Enforces `winning_bid.bidder == tender.lowest_bidder.unwrap()`.
   * Transitions status to `TenderStatus::Awarded`.

---

## 7. Protocol Layers: Clarifying Specification vs Reference Engine

To maintain clarity during evaluation, the repository cleanly differentiates between protocol layers:

| Layer | Component | Path | Purpose |
| :--- | :--- | :--- | :--- |
| **Layer 1** | **Anchor Smart Contract (Rust)** | `programs/bidtrace/` | Canonical on-chain state machine enforcing slot deadlines, PDA derivations, bond escrow, and anti-lockout gating. |
| **Layer 2** | **Reference Model & Simulator (Python)** | `bidtrace_py/` | Standalone reference implementation simulating the Solana runtime, executing identical cryptographic math, and powering local testing and interactive demos. |
| **Layer 3** | **Air-Gapped Offline Verifier** | `bidtrace_py/verifier.py` & `verifier/verify.ts` | Independent audit tools verifying standalone JSON bundles against public ledger accounts with zero reliance on backend servers. |

---

## 8. Governance, Upgrade Authority, and Network Considerations

### 8.1 Upgrade Authority Lifecycle
Under the Solana BPF Upgradeable Loader, smart contracts retain an upgrade authority key unless explicitly finalized.
* **Development / Audit Phase:** Multi-signature governance (e.g., Squads Protocol 3-of-5 threshold) with an on-chain timelock to permit non-breaking bug fixes while preventing unilateral administrative tampering.
* **Mainnet Production Deployment:** Revocation of upgrade authority via:
  ```bash
  solana program set-upgrade-authority <PROGRAM_ID> --final
  ```
  Once finalized, the program bytecode is permanently immutable on Solana; no authority or developer can modify the deadline or consensus logic.

### 8.2 Consensus Slots vs. Wall-Clock Time
* Solana slots execute at approximately 400 milliseconds under nominal network conditions.
* BidTrace relies on `Clock::get()?.slot` rather than `Clock::get()?.unix_timestamp` because consensus slots are strictly monotonic and determined by validator slot leaders, whereas Unix timestamps can experience minor clock drift across validator nodes.
* **Operational Recommendation:** Procurement authorities should specify slot deadlines with a margin (e.g., 150 slots $\approx 60$ seconds) to accommodate transient slot-skipping during high network load.

---

## 9. Verification & Automated Test Suites

The test harness provides comprehensive verification across all edge cases:

### 1. Run the Complete Adversarial Test Suite
```bash
python -m unittest tests/test_engine.py
```
* **Test 01:** Full tender lifecycle across multiple bidders.
* **Test 02:** Late bid injection post-submission-deadline rejected.
* **Test 03:** Price tampering during reveal rejected with `InvalidRevealHash`.
* **Test 04:** Censorship-resistant non-custodial PDA intake.
* **Test 05:** Partial reveal resilience without deadlock.
* **Test 06:** Air-gapped offline verifier audit pass.

### 2. Run the Early-Award Lockout Mitigation Tests
```bash
python -m unittest tests/test_exploit.py
```
* Verifies `record_award` fails with `RevealWindowActive` when an authority attempts early award during an active reveal window.
* Verifies honest bidders reveal safely and lowest bidder is awarded.
* Verifies deposit bond forfeiture for unrevealed default bids.

### 3. Run the Live End-to-End Terminal Demonstration
```bash
python run_demo.py
```

### 4. Interactive Protocol Server & Browser UI
```bash
python server.py
# Open http://localhost:8000 in your browser
```
