use anchor_lang::prelude::*;

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum TenderStatus {
    Active = 0,    // Accepting commitments (slot <= deadline_slot)
    Locked = 1,    // Deadline passed, ready for reveals (slot > deadline_slot)
    Awarded = 2,   // Tender evaluated and winning bidder recorded
    Cancelled = 3, // Revoked by authority before deadline
}

#[account]
pub struct Tender {
    /// The procurement authority / admin who created the tender
    pub authority: Pubkey,
    /// Human/system identifier (max 32 characters)
    pub tender_id: String,
    /// Consensus slot at which submissions freeze
    pub deadline_slot: u64,
    /// Merkle root of pre-authorized bidders ([0u8; 32] if open tender)
    pub authorized_bidders_root: [u8; 32],
    /// Running counter of total accepted commitments
    pub total_committed: u32,
    /// Running counter of revealed commitments
    pub total_revealed: u32,
    /// Lifecycle state enum
    pub status: TenderStatus,
    /// Winning bidder public key (set upon award)
    pub winning_bidder: Option<Pubkey>,
    /// Canonical bump seed
    pub bump: u8,
}

impl Tender {
    // 8 (discriminator) + 32 + (4 + 32) + 8 + 32 + 4 + 4 + 1 + (1 + 32) + 1 = 155 -> allocate 200 for safety
    pub const LEN: usize = 8 + 32 + (4 + 32) + 8 + 32 + 4 + 4 + 1 + 33 + 1 + 32;
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
    // 8 + 32 + 32 + 32 + 8 + 1 + 8 + 8 + 1 = 130 -> allocate 160
    pub const LEN: usize = 8 + 32 + 32 + 32 + 8 + 1 + 8 + 8 + 1 + 30;
}
