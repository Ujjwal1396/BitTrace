use anchor_lang::prelude::*;
use sha2::{Digest, Sha256};
use crate::errors::BidTraceError;
use crate::state::{EvaluatorGrade, Tender, TenderCommittee, TenderStatus};

#[derive(Accounts)]
pub struct RevealEvaluatorGrade<'info> {
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
        mut,
        seeds = [b"grade", tender.key().as_ref(), evaluator.key().as_ref(), bidder.key().as_ref()],
        bump = evaluator_grade.bump,
        constraint = !evaluator_grade.is_revealed @ BidTraceError::GradeAlreadyRevealed,
    )]
    pub evaluator_grade: Account<'info, EvaluatorGrade>,

    pub evaluator: Signer<'info>,

    /// CHECK: Target bidder being scored
    pub bidder: AccountInfo<'info>,
}

pub fn handle_reveal_evaluator_grade(
    ctx: Context<RevealEvaluatorGrade>,
    sub_scores: [u16; 5],
    salt: [u8; 32],
    justification_hash: [u8; 32],
) -> Result<()> {
    let tender = &ctx.accounts.tender;
    let evaluator_key = ctx.accounts.evaluator.key();
    let bidder_key = ctx.accounts.bidder.key();
    let grade = &mut ctx.accounts.evaluator_grade;

    // 1. Validate sum of sub-scores
    let total_sum: u32 = sub_scores.iter().map(|&s| s as u32).sum();
    require!(total_sum <= 10000, BidTraceError::SubScoresOutOfRange);

    // 2. Cryptographic preimage recomputation with strict domain separation
    let mut hasher = Sha256::new();
    hasher.update(b"BIDTRACE_GRADE_V1");
    hasher.update(tender.key().as_ref());
    hasher.update(bidder_key.as_ref());
    hasher.update(evaluator_key.as_ref());
    hasher.update(&salt);
    for score in sub_scores.iter() {
        hasher.update(&score.to_le_bytes());
    }
    hasher.update(&justification_hash);
    let computed_hash: [u8; 32] = hasher.finalize().into();

    require!(
        computed_hash == grade.commitment_hash,
        BidTraceError::InvalidRevealHash
    );

    grade.is_revealed = true;
    grade.sub_scores = sub_scores;
    grade.total_score_bps = total_sum as u16;
    grade.justification_hash = justification_hash;

    msg!(
        "Evaluator grade revealed: evaluator={}, bidder={}, total_score_bps={}",
        evaluator_key,
        bidder_key,
        grade.total_score_bps
    );

    Ok(())
}
