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
    deadline_slot: u64,
    authorized_bidders_root: [u8; 32],
) -> Result<()> {
    require!(tender_id.len() <= 32, BidTraceError::TenderIdTooLong);

    let clock = Clock::get()?;
    require!(deadline_slot > clock.slot, BidTraceError::InvalidDeadlineSlot);

    let tender = &mut ctx.accounts.tender;
    tender.authority = ctx.accounts.authority.key();
    tender.tender_id = tender_id;
    tender.deadline_slot = deadline_slot;
    tender.authorized_bidders_root = authorized_bidders_root;
    tender.total_committed = 0;
    tender.total_revealed = 0;
    tender.status = TenderStatus::Active;
    tender.winning_bidder = None;
    tender.bump = ctx.bumps.tender;

    msg!(
        "Tender initialized: id={}, deadline_slot={}",
        tender.tender_id,
        tender.deadline_slot
    );

    Ok(())
}
