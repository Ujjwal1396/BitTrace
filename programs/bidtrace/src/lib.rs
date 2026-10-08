use anchor_lang::prelude::*;

pub mod errors;
pub mod instructions;
pub mod state;

use instructions::*;

declare_id!("BidTrace111111111111111111111111111111111111");

#[program]
pub mod bidtrace {
    use super::*;

    /// 1. Initialize a new tender with strictly enforced submission and reveal deadline slots
    pub fn initialize_tender(
        ctx: Context<InitializeTender>,
        tender_id: String,
        submission_deadline_slot: u64,
        reveal_deadline_slot: u64,
        bid_deposit: u64,
        authorized_bidders_root: [u8; 32],
    ) -> Result<()> {
        instructions::initialize_tender::handle_initialize_tender(
            ctx,
            tender_id,
            submission_deadline_slot,
            reveal_deadline_slot,
            bid_deposit,
            authorized_bidders_root,
        )
    }

    /// 2. Bidder directly commits a 32-byte cryptographic commitment to a PDA before the deadline
    pub fn commit_bid(
        ctx: Context<CommitBid>,
        commitment_hash: [u8; 32],
        whitelist_proof: Option<Vec<[u8; 32]>>,
    ) -> Result<()> {
        instructions::commit_bid::handle_commit_bid(
            ctx,
            commitment_hash,
            whitelist_proof,
        )
    }

    /// 3. Permissionlessly freeze the tender once the deadline slot has passed
    pub fn lock_tender(ctx: Context<LockTender>) -> Result<()> {
        instructions::lock_tender::handle_lock_tender(ctx)
    }

    /// 4. Reveal and verify an individual bid against its on-chain commitment PDA
    pub fn reveal_bid(
        ctx: Context<RevealBid>,
        salt: [u8; 32],
        ciphertext_hash: [u8; 32],
        bid_amount: u64,
    ) -> Result<()> {
        instructions::reveal_bid::handle_reveal_bid(
            ctx,
            salt,
            ciphertext_hash,
            bid_amount,
        )
    }

    /// 5. Record the final award decision for a verified, revealed bid
    pub fn record_award(
        ctx: Context<RecordAward>,
        rationale_hash: [u8; 32],
    ) -> Result<()> {
        instructions::record_award::handle_record_award(ctx, rationale_hash)
    }
}
