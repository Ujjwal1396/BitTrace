use anchor_lang::prelude::*;
use crate::errors::BidTraceError;
use crate::state::{Tender, TenderStatus};

#[derive(Accounts)]
#[instruction(tender_id: String)]
pub struct InitializeTender<'info> {
    #[account(
        init,
        payer = authority,
        space = Tender::LEN,
        seeds = [b"tender", authority.key().as_ref(), tender_id.as_bytes()],
        bump
    )]
    pub tender: Account<'info, Tender>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handle_initialize_tender(
    ctx: Context<InitializeTender>,
    tender_id: String,
    submission_deadline_slot: u64,
    reveal_deadline_slot: u64,
    bid_deposit: u64,
    authorized_bidders_root: [u8; 32],
) -> Result<()> {
    require!(tender_id.len() <= 32, BidTraceError::TenderIdTooLong);

    let clock = Clock::get()?;
    require!(
        submission_deadline_slot > clock.slot,
        BidTraceError::InvalidSubmissionDeadline
    );
    require!(
        reveal_deadline_slot > submission_deadline_slot,
        BidTraceError::InvalidRevealDeadline
    );

    let tender = &mut ctx.accounts.tender;
    tender.authority = ctx.accounts.authority.key();
    tender.tender_id = tender_id;
    tender.submission_deadline_slot = submission_deadline_slot;
    tender.reveal_deadline_slot = reveal_deadline_slot;
    tender.bid_deposit = bid_deposit;
    tender.authorized_bidders_root = authorized_bidders_root;
    tender.total_committed = 0;
    tender.total_revealed = 0;
    tender.lowest_revealed_amount = u64::MAX;
    tender.lowest_bidder = None;
    tender.status = TenderStatus::Active;
    tender.winning_bidder = None;
    tender.bump = ctx.bumps.tender;

    msg!(
        "Tender initialized: id={}, submission_deadline={}, reveal_deadline={}, deposit={}",
        tender.tender_id,
        tender.submission_deadline_slot,
        tender.reveal_deadline_slot,
        tender.bid_deposit
    );

    Ok(())
}
