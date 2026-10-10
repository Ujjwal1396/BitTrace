use anchor_lang::prelude::*;
use crate::errors::BidTraceError;
use crate::state::{Tender, TenderCommittee};

#[derive(Accounts)]
pub struct InitializeCommittee<'info> {
    #[account(
        has_one = authority,
    )]
    pub tender: Account<'info, Tender>,

    #[account(
        init,
        payer = authority,
        space = TenderCommittee::LEN,
        seeds = [b"committee", tender.key().as_ref()],
        bump
    )]
    pub committee: Account<'info, TenderCommittee>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handle_initialize_committee(
    ctx: Context<InitializeCommittee>,
    evaluators: Vec<Pubkey>,
    max_variance_bps: u16,
) -> Result<()> {
    require!(evaluators.len() >= 3, BidTraceError::InsufficientEvaluatorGrades);

    let committee = &mut ctx.accounts.committee;
    committee.tender = ctx.accounts.tender.key();
    committee.evaluators = evaluators;
    committee.max_variance_bps = max_variance_bps;
    committee.is_locked = true;
    committee.bump = ctx.bumps.committee;

    msg!(
        "Tender committee initialized: tender={}, evaluators_count={}, max_variance_bps={}",
        committee.tender,
        committee.evaluators.len(),
        committee.max_variance_bps
    );

    Ok(())
}
