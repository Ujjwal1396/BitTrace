use anchor_lang::prelude::*;
use sha2::{Digest, Sha256};
use crate::errors::BidTraceError;
use crate::state::{BidCommitment, Tender, TenderStatus};

#[derive(Accounts)]
pub struct RevealBid<'info> {
    #[account(
        mut,
        constraint = tender.status == TenderStatus::Locked @ BidTraceError::TenderNotLocked,
    )]
    pub tender: Account<'info, Tender>,

    #[account(
        mut,
        seeds = [b"bid", tender.key().as_ref(), bid_commitment.bidder.as_ref()],
        bump = bid_commitment.bump,
        constraint = !bid_commitment.is_revealed @ BidTraceError::BidAlreadyRevealed,
    )]
    pub bid_commitment: Account<'info, BidCommitment>,

    /// Can be the bidder themselves, or a relayer submitting the reveal proof
    pub revealer: Signer<'info>,
}

pub fn handle_reveal_bid(
    ctx: Context<RevealBid>,
    salt: [u8; 32],
    ciphertext_hash: [u8; 32],
    bid_amount: u64,
) -> Result<()> {
    let clock = Clock::get()?;
    let tender = &mut ctx.accounts.tender;
    let bid = &mut ctx.accounts.bid_commitment;

    // Cryptographic preimage recomputation with strict domain separation
    let mut hasher = Sha256::new();
    hasher.update(b"BIDTRACE_V1");
    hasher.update(tender.key().as_ref());
    hasher.update(bid.bidder.as_ref());
    hasher.update(&salt);
    hasher.update(&ciphertext_hash);
    hasher.update(&bid_amount.to_le_bytes());
    let computed_hash: [u8; 32] = hasher.finalize().into();

    require!(
        computed_hash == bid.commitment_hash,
        BidTraceError::InvalidRevealHash
    );

    bid.is_revealed = true;
    bid.revealed_at_slot = clock.slot;
    bid.revealed_amount = bid_amount;

    tender.total_revealed += 1;

    msg!(
        "Bid revealed: bidder={}, amount={}, revealed={}/{}",
        bid.bidder,
        bid_amount,
        tender.total_revealed,
        tender.total_committed
    );

    Ok(())
}
