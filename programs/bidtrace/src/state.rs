use anchor_lang::prelude::*;

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
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

#[account]
pub struct Tender {
    /// The procurement authority who created the tender
    pub authority: Pubkey,
    /// Unique human/system tender identifier (max 32 ASCII chars)
    pub tender_id: String,
    /// Canonical RFC 8785 SHA-256 hash of the OCDS 1.1 Tender Release notice
    pub ocds_notice_hash: [u8; 32],
    /// Mode: Pre-qualified whitelist (Model A) or Post-qualified open (Model B)
    pub tender_mode: TenderMode,
    /// Evaluation scoring formula: LeastCost or QCBS
    pub evaluation_type: EvaluationType,
    /// Current state machine status
    pub status: TenderStatus,

    // Temporal Slot Boundaries (Solana Consensus Time)
    pub submission_deadline_slot: u64,
    pub admin_review_deadline_slot: u64,
    pub tech_eval_deadline_slot: u64,
    pub fin_reveal_deadline_slot: u64,

    /// Merkle root of pre-authorized bidders (Model A; [0; 32] for open tender)
    pub authorized_bidders_root: [u8; 32],

    // Two-Envelope Scoring Parameters (Basis points: 10,000 = 100.00%)
    pub min_tech_score_bps: u16,  // Cutoff threshold (e.g. 7500 = 75.00%)
    pub tech_weight_bps: u16,     // Technical weight (e.g. 7000 = 70.00%)
    pub fin_weight_bps: u16,      // Financial weight (e.g. 3000 = 30.00%)

    // Progress Counters
    pub total_committed: u32,
    pub total_admin_passed: u32,
    pub total_tech_qualified: u32,
    pub total_fin_revealed: u32,

    // Pricing & Award Tracking
    pub lowest_revealed_price: u64,
    pub highest_composite_score: u64,
    pub winning_bidder: Option<Pubkey>,
    pub bump: u8,
}

impl Tender {
    // 8 (disc) + 32 (auth) + (4 + 32) (id) + 32 (ocds) + 1 (mode) + 1 (eval) + 1 (status)
    // + 8*4 (deadlines) + 32 (merkle) + 2*3 (weights) + 4*4 (counters) + 8*2 (scores)
    // + 33 (Option<Pubkey>) + 1 (bump) + 64 (headroom) = 370
    pub const LEN: usize = 8 + 32 + (4 + 32) + 32 + 1 + 1 + 1 + 32 + 32 + 6 + 16 + 16 + 33 + 1 + 64;
}

#[account]
pub struct DualBidCommitment {
    /// Reference to the parent Tender PDA
    pub tender: Pubkey,
    /// Public key of the bidder
    pub bidder: Pubkey,
    /// Solana slot when the dual commitment was recorded
    pub committed_at_slot: u64,

    // Cryptographic Hashes
    pub admin_dossier_hash: [u8; 32],
    pub tech_commitment_hash: [u8; 32],
    pub fin_commitment_hash: [u8; 32],

    // Phase 1: Administrative Due Diligence
    pub admin_status: AdminStatus,
    pub admin_rejection_code: u16,

    // Phase 2: Technical Merit Scoring
    pub is_tech_revealed: bool,
    pub technical_score_bps: u16,
    pub is_tech_qualified: bool,

    // Phase 3: Financial Unsealing & Scoring
    pub is_fin_revealed: bool,
    pub revealed_price: u64,
    pub composite_score: u64,

    // Bond & Security Escrow
    pub bond_mode: BondMode,
    pub bond_amount: u64,
    pub is_bond_settled: bool,
    pub bump: u8,
}

impl DualBidCommitment {
    // 8 + 32 + 32 + 8 + 32*3 + 1 + 2 + 1 + 2 + 1 + 1 + 8 + 8 + 1 + 8 + 1 + 1 + 64 = 305
    pub const LEN: usize = 8 + 32 + 32 + 8 + 96 + 3 + 4 + 17 + 11 + 64;
}

#[account]
pub struct TenderCommittee {
    /// Reference to the parent Tender PDA
    pub tender: Pubkey,
    /// List of certified evaluator public keys (up to 7 members)
    pub evaluators: Vec<Pubkey>,
    /// Maximum allowed variance from median in basis points (e.g. 2000 = 20.00%)
    pub max_variance_bps: u16,
    /// Whether the committee roster is finalized
    pub is_locked: bool,
    pub bump: u8,
}

impl TenderCommittee {
    // 8 + 32 + (4 + 32 * 10) + 2 + 1 + 1 + 64 = 432
    pub const LEN: usize = 8 + 32 + (4 + 32 * 10) + 2 + 1 + 1 + 64;
}

#[account]
pub struct EvaluatorGrade {
    /// Reference to the parent Tender PDA
    pub tender: Pubkey,
    /// Evaluator public key
    pub evaluator: Pubkey,
    /// Bidder public key being evaluated
    pub bidder: Pubkey,
    /// Salted commitment hash of the 5 sub-scores + justification report
    pub commitment_hash: [u8; 32],
    /// Slot when the blinded grade was submitted
    pub committed_at_slot: u64,
    /// Reveal status
    pub is_revealed: bool,
    /// 5 standardized sub-criteria scores (sum <= 10,000 bps)
    pub sub_scores: [u16; 5],
    /// Total score in basis points (0 - 10,000)
    pub total_score_bps: u16,
    /// SHA-256 hash of written justification report
    pub justification_hash: [u8; 32],
    /// Whether this grade was flagged and dropped as an adversarial outlier
    pub is_outlier_flagged: bool,
    pub bump: u8,
}

impl EvaluatorGrade {
    // 8 + 32*4 + 8 + 1 + 10 + 2 + 32 + 1 + 1 + 32 = 231
    pub const LEN: usize = 8 + 32 + 32 + 32 + 32 + 8 + 1 + 10 + 2 + 32 + 1 + 1 + 32;
}
