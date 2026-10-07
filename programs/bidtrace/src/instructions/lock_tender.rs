use anchor_lang::prelude::*;
use crate::errors::BidTraceError;
use crate::state::{Tender, TenderStatus};

#[derive(Accounts)]
pub struct LockTender<'info> {
    #[account(
        mut,
        constraint = tender.status == TenderStatus::Active @ BidTraceError::TenderAlreadyLocked,
    )]
    pub tender: Account<'info, Tender>,

    /// Anyone can call this instruction once the deadline slot has passed
    pub caller: Signer<'info>,
}

pub fn handle_lock_tender(ctx: Context<LockTender>) -> Result<()> {
    let clock = Clock::get()?;
    let tender = &mut ctx.accounts.tender;

    require!(
        clock.slot > tender.deadline_slot,
        BidTraceError::DeadlineNotReached
    );

    tender.status = TenderStatus::Locked;

    msg!(
        "Tender locked at slot {}: total_committed={}",
        clock.slot,
        tender.total_committed
    );

    Ok(())
}
