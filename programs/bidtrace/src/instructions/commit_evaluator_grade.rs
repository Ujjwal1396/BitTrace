use anchor_lang::prelude::*;
use crate::errors::BidTraceError;
use crate::state::{DualBidCommitment, EvaluatorGrade, Tender, TenderCommittee, TenderStatus};

#[derive(Accounts)]
pub struct CommitEvaluatorGrade<'info> {
    #[account(
        constraint = tender.status == TenderStatus::TechnicalEvaluation @ BidTraceError::TenderNotTechnicalEvaluation,
    )]
    pub tender: Account<'info, Tender>,

    #[account(
        seeds = [b"committee", tender.key().as_ref()],
        bump = committee.bump,
    )]
    pub committee: Account<'info, TenderCommittee>,

    #[account(
        seeds = [b"bid", tender.key().as_ref(), bidder.key().as_ref()],
        bump = bid_commitment.bump,
        constraint = bid_commitment.is_tech_revealed @ BidTraceError::TechNotRevealed,
    )]
    pub bid_commitment: Account<'info, DualBidCommitment>,

    #[account(
        init,
        payer = evaluator,
        space = EvaluatorGrade::LEN,
        seeds = [b"grade", tender.key().as_ref(), evaluator.key().as_ref(), bidder.key().as_ref()],
        bump
    )]
    pub evaluator_grade: Account<'info, EvaluatorGrade>,

    #[account(mut)]
    pub evaluator: Signer<'info>,

    /// CHECK: Target bidder being scored
    pub bidder: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handle_commit_evaluator_grade(
    ctx: Context<CommitEvaluatorGrade>,
    commitment_hash: [u8; 32],
) -> Result<()> {
    let clock = Clock::get()?;
    let tender = &ctx.accounts.tender;
    let committee = &ctx.accounts.committee;
    let evaluator_key = ctx.accounts.evaluator.key();

    // 1. Verify evaluator is an authorized committee member
    require!(
        committee.evaluators.contains(&evaluator_key),
        BidTraceError::EvaluatorNotAuthorized
    );

    // 2. Verify technical evaluation deadline hasn't elapsed
    require!(
        clock.slot <= tender.tech_eval_deadline_slot,
        BidTraceError::TechEvalDeadlineExceeded
    );

    // 3. Initialize EvaluatorGrade PDA
    let grade = &mut ctx.accounts.evaluator_grade;
    grade.tender = tender.key();
    grade.evaluator = evaluator_key;
    grade.bidder = ctx.accounts.bidder.key();
    grade.commitment_hash = commitment_hash;
    grade.committed_at_slot = clock.slot;
    grade.is_revealed = false;
    grade.sub_scores = [0; 5];
    grade.total_score_bps = 0;
    grade.justification_hash = [0; 32];
    grade.is_outlier_flagged = false;
    grade.bump = ctx.bumps.evaluator_grade;

    msg!(
        "Blinded evaluator grade committed: evaluator={}, bidder={}, slot={}",
        evaluator_key,
        grade.bidder,
        grade.committed_at_slot
    );

    Ok(())
}
