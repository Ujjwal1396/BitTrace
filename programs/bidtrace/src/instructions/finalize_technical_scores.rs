use anchor_lang::prelude::*;
use crate::errors::BidTraceError;
use crate::state::{DualBidCommitment, EvaluatorGrade, Tender, TenderCommittee, TenderStatus};

#[derive(Accounts)]
pub struct FinalizeTechnicalScores<'info> {
    #[account(
        mut,
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
        seeds = [b"bid", tender.key().as_ref(), bid_commitment.bidder.as_ref()],
        bump = bid_commitment.bump,
        constraint = bid_commitment.is_tech_revealed @ BidTraceError::TechNotRevealed,
    )]
    pub bid_commitment: Account<'info, DualBidCommitment>,

    pub authority: Signer<'info>,
}

pub fn handle_finalize_technical_scores<'info>(
    ctx: Context<'_, '_, '_, 'info, FinalizeTechnicalScores<'info>>,
) -> Result<()> {
    let tender = &mut ctx.accounts.tender;
    let committee = &ctx.accounts.committee;
    let bid_commitment = &mut ctx.accounts.bid_commitment;

    let remaining = ctx.remaining_accounts;
    require!(
        remaining.len() >= 3,
        BidTraceError::InsufficientEvaluatorGrades
    );

    // 1. Parse and validate all submitted EvaluatorGrade accounts
    struct GradeEntry {
        acc_index: usize,
        _evaluator: Pubkey,
        total_score_bps: u16,
    }

    let mut entries: Vec<GradeEntry> = Vec::with_capacity(remaining.len());
    let mut seen_evaluators: Vec<Pubkey> = Vec::with_capacity(remaining.len());

    for (idx, acc) in remaining.iter().enumerate() {
        require!(
            acc.owner == &crate::ID,
            BidTraceError::EvaluatorNotAuthorized
        );

        let data = acc.try_borrow_data()?;
        let grade = EvaluatorGrade::try_deserialize(&mut &data[..])?;

        require!(grade.tender == tender.key(), BidTraceError::EvaluatorNotAuthorized);
        require!(grade.bidder == bid_commitment.bidder, BidTraceError::EvaluatorNotAuthorized);
        require!(grade.is_revealed, BidTraceError::GradeNotRevealed);
        require!(
            committee.evaluators.contains(&grade.evaluator),
            BidTraceError::EvaluatorNotAuthorized
        );
        require!(
            !seen_evaluators.contains(&grade.evaluator),
            BidTraceError::EvaluatorNotAuthorized
        );

        seen_evaluators.push(grade.evaluator);
        entries.push(GradeEntry {
            acc_index: idx,
            _evaluator: grade.evaluator,
            total_score_bps: grade.total_score_bps,
        });
    }

    let n = entries.len();

    // 2. Sort scores to compute median
    let mut scores: Vec<u32> = entries.iter().map(|e| e.total_score_bps as u32).collect();
    scores.sort();

    let median: u32 = if n % 2 == 1 {
        scores[n / 2]
    } else {
        (scores[n / 2 - 1] + scores[n / 2]) / 2
    };

    let max_allowed_delta = (median * committee.max_variance_bps as u32) / 10000;

    // 3. Mark outliers in account state
    let mut outlier_count = 0;
    for entry in entries.iter() {
        let score = entry.total_score_bps as u32;
        let delta = if score >= median { score - median } else { median - score };

        let is_outlier = delta > max_allowed_delta;
        if is_outlier {
            outlier_count += 1;
        }

        // Update the outlier flag on the EvaluatorGrade account
        let acc = &remaining[entry.acc_index];
        let mut data = acc.try_borrow_mut_data()?;
        let mut grade = EvaluatorGrade::try_deserialize(&mut &data[..])?;
        grade.is_outlier_flagged = is_outlier;
        grade.try_serialize(&mut &mut data[..])?;
    }

    // 4. Olympic Trimmed Mean:
    // Drop single highest and single lowest if N >= 4, plus any flagged outliers
    let final_score: u32 = if n >= 4 {
        let mut accepted: Vec<u32> = Vec::new();
        // scores is sorted: scores[0] is min, scores[n-1] is max
        // Middle elements:
        for &s in scores[1..n - 1].iter() {
            let delta = if s >= median { s - median } else { median - s };
            if delta <= max_allowed_delta {
                accepted.push(s);
            }
        }

        if accepted.is_empty() {
            median
        } else {
            let sum: u32 = accepted.iter().sum();
            sum / accepted.len() as u32
        }
    } else {
        // N == 3: filter outliers
        let mut accepted: Vec<u32> = Vec::new();
        for &s in scores.iter() {
            let delta = if s >= median { s - median } else { median - s };
            if delta <= max_allowed_delta {
                accepted.push(s);
            }
        }
        if accepted.is_empty() {
            median
        } else {
            let sum: u32 = accepted.iter().sum();
            sum / accepted.len() as u32
        }
    };

    let final_score_bps = final_score as u16;
    let was_qualified = bid_commitment.is_tech_qualified;
    let is_qualified = final_score_bps >= tender.min_tech_score_bps;

    bid_commitment.technical_score_bps = final_score_bps;
    bid_commitment.is_tech_qualified = is_qualified;

    if is_qualified && !was_qualified {
        tender.total_tech_qualified += 1;
    } else if !is_qualified && was_qualified {
        tender.total_tech_qualified -= 1;
    }

    msg!(
        "Olympic Trimmed Mean finalized: bidder={}, median={}, trimmed_mean={}, qualified={}, outliers_pruned={}",
        bid_commitment.bidder,
        median,
        final_score_bps,
        is_qualified,
        outlier_count
    );

    Ok(())
}
