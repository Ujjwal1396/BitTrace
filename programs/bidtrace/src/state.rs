use anchor_lang::prelude::*;

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum TenderStatus {
    Active = 0,    // Accepting commitments (slot <= submission_deadline_slot)
    Locked = 1,    // Submissions frozen; in reveal window (slot <= reveal_deadline_slot)
    Awarded = 2,   // Tender evaluated and winning bidder recorded (slot > reveal_deadline_slot || all revealed)
    Cancelled = 3, // Revoked by authority before submission deadline
}

#[account]
pub struct Tender {
    /// The procurement authority who created the tender
    pub authority: Pubkey,
    /// Human/system identifier (max 32 characters)
    pub tender_id: String,
    /// Consensus slot at which submissions freeze
    pub submission_deadline_slot: u64,
    /// Consensus slot at which reveals close (must be > submission_deadline_slot)
    pub reveal_deadline_slot: u64,
    /// Mandatory refundable deposit bond per commitment in lamports (anti-Sybil / anti-free-option)
    pub bid_deposit: u64,
    /// Merkle root of pre-authorized bidders ([0u8; 32] for open tender)
    pub authorized_bidders_root: [u8; 32],
    /// Running counter of total accepted commitments
    pub total_committed: u32,
    /// Running counter of successfully revealed commitments
    pub total_revealed: u32,
    /// Lowest revealed numeric bid amount observed so far
    pub lowest_revealed_amount: u64,
    /// Lowest bidder public key observed so far
    pub lowest_bidder: Option<Pubkey>,
    /// Lifecycle state enum
    pub status: TenderStatus,
    /// Winning bidder public key (set upon formal award)
    pub winning_bidder: Option<Pubkey>,
    /// Canonical bump seed
    pub bump: u8,
}

impl Tender {
    // 8 + 32 + (4 + 32) + 8 + 8 + 8 + 32 + 4 + 4 + 8 + 33 + 1 + 33 + 1 + 32 = 245
    pub const LEN: usize = 8 + 32 + (4 + 32) + 8 + 8 + 8 + 32 + 4 + 4 + 8 + 33 + 1 + 33 + 1 + 32;
}

#[account]
pub struct BidCommitment {
    /// Reference to the parent Tender PDA
    pub tender: Pubkey,
    /// Public key of the bidder
    pub bidder: Pubkey,
    /// Domain-separated SHA256 commitment of the encrypted bid payload
    pub commitment_hash: [u8; 32],
    /// Exact Solana slot when the commitment was confirmed on-chain
    pub committed_at_slot: u64,
    /// Amount of lamports escrowed as commitment bond
    pub escrowed_deposit: u64,
    /// Whether the bidder has revealed and verified their bid
    pub is_revealed: bool,
    /// Exact Solana slot when reveal occurred (0 if unrevealed)
    pub revealed_at_slot: u64,
    /// Unencrypted numeric bid amount (recorded at reveal for ranking)
    pub revealed_amount: u64,
    /// Canonical bump seed
    pub bump: u8,
}

impl BidCommitment {
    // 8 + 32 + 32 + 32 + 8 + 8 + 1 + 8 + 8 + 1 + 24 = 172
    pub const LEN: usize = 8 + 32 + 32 + 32 + 8 + 8 + 1 + 8 + 8 + 1 + 32;
}
