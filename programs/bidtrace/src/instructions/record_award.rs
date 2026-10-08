use anchor_lang::prelude::*;
use crate::errors::BidTraceError;
use crate::state::{BidCommitment, Tender, TenderStatus};

#[derive(Accounts)]
pub struct RecordAward<'info> {
    #[account(
        mut,
        has_one = authority,
        constraint = tender.status == TenderStatus::Locked @ BidTraceError::TenderNotLocked,
    )]
    pub tender: Account<'info, Tender>,

    #[account(
        seeds = [b"bid", tender.key().as_ref(), winning_bid.bidder.as_ref()],
        bump = winning_bid.bump,
        constraint = winning_bid.is_revealed @ BidTraceError::WinnerNotRevealed,
    )]
    pub winning_bid: Account<'info, BidCommitment>,

    pub authority: Signer<'info>,
}

pub fn handle_record_award(
    ctx: Context<RecordAward>,
    _rationale_hash: [u8; 32],
) -> Result<()> {
    let clock = Clock::get()?;
    let tender = &mut ctx.accounts.tender;
    let winning_bid = &ctx.accounts.winning_bid;

    // Strict Anti-Lockout Gate:
    // Award can ONLY be recorded if the reveal window has expired OR 100% of committed bids have revealed.
    require!(
        clock.slot > tender.reveal_deadline_slot || tender.total_revealed == tender.total_committed,
        BidTraceError::RevealWindowActive
    );

    // Enforce that the winning bidder is the lowest compliant revealed bid
    if let Some(lowest_bidder) = tender.lowest_bidder {
        require!(
            winning_bid.bidder == lowest_bidder,
            BidTraceError::WinnerNotLowestBid
        );
    }

    tender.winning_bidder = Some(winning_bid.bidder);
    tender.status = TenderStatus::Awarded;

    msg!(
        "Tender awarded: id={}, winner={}, winning_amount={}, total_revealed={}/{}",
        tender.tender_id,
        winning_bid.bidder,
        winning_bid.revealed_amount,
        tender.total_revealed,
        tender.total_committed
    );

    Ok(())
}
