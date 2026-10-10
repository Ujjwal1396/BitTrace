use anchor_lang::prelude::*;
use sha2::{Digest, Sha256};
use crate::errors::BidTraceError;
use crate::state::{DualBidCommitment, Tender, TenderStatus};

#[derive(Accounts)]
pub struct RevealTechnicalBid<'info> {
    #[account(
        mut,
        constraint = tender.status == TenderStatus::TechnicalEvaluation @ BidTraceError::TenderNotTechnicalEvaluation,
    )]
    pub tender: Account<'info, Tender>,

    #[account(
        mut,
        seeds = [b"bid", tender.key().as_ref(), bid_commitment.bidder.as_ref()],
        bump = bid_commitment.bump,
        constraint = !bid_commitment.is_tech_revealed @ BidTraceError::TechAlreadyRevealed,
    )]
    pub bid_commitment: Account<'info, DualBidCommitment>,

    /// Can be the bidder or sponsored relayer
    pub revealer: Signer<'info>,
}

pub fn handle_reveal_technical_bid(
    ctx: Context<RevealTechnicalBid>,
    salt_tech: [u8; 32],
    proposal_hash: [u8; 32],
) -> Result<()> {
    let tender = &ctx.accounts.tender;
    let bid = &mut ctx.accounts.bid_commitment;

    // Cryptographic domain-separated preimage check for Envelope A (Technical)
    let mut hasher = Sha256::new();
    hasher.update(b"BIDTRACE_TECH_V1");
    hasher.update(tender.key().as_ref());
    hasher.update(bid.bidder.as_ref());
    hasher.update(&salt_tech);
    hasher.update(&proposal_hash);
    let computed_hash: [u8; 32] = hasher.finalize().into();

    require!(
        computed_hash == bid.tech_commitment_hash,
        BidTraceError::InvalidRevealHash
    );

    bid.is_tech_revealed = true;

    msg!(
        "Technical proposal unsealed: bidder={}, proposal_hash={:?}",
        bid.bidder,
        &proposal_hash[..4]
    );

    Ok(())
}
