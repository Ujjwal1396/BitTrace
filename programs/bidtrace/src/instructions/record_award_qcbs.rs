use anchor_lang::prelude::*;
use crate::errors::BidTraceError;
use crate::state::{DualBidCommitment, EvaluationType, Tender, TenderStatus};

#[derive(Accounts)]
pub struct RecordAwardQcbs<'info> {
    #[account(
        mut,
        has_one = authority,
        constraint = tender.status == TenderStatus::FinancialEvaluation @ BidTraceError::TenderNotFinancialEvaluation,
    )]
    pub tender: Account<'info, Tender>,

    #[account(
        mut,
        seeds = [b"bid", tender.key().as_ref(), winning_bid.bidder.as_ref()],
        bump = winning_bid.bump,
        constraint = winning_bid.is_tech_qualified @ BidTraceError::WinnerNotQualified,
        constraint = winning_bid.is_fin_revealed @ BidTraceError::WinnerNotRevealed,
    )]
    pub winning_bid: Account<'info, DualBidCommitment>,

    pub authority: Signer<'info>,
}

pub fn handle_record_award_qcbs(
    ctx: Context<RecordAwardQcbs>,
    _rationale_hash: [u8; 32],
) -> Result<()> {
    let clock = Clock::get()?;
    let tender = &mut ctx.accounts.tender;
    let winning_bid = &mut ctx.accounts.winning_bid;

    // 1. Anti-Lockout Gate:
    // Award can only be recorded if the financial reveal window has expired
    // OR 100% of technically qualified bidders have unsealed their financial envelopes.
    require!(
        clock.slot > tender.fin_reveal_deadline_slot
            || tender.total_fin_revealed == tender.total_tech_qualified,
        BidTraceError::FinancialRevealWindowActive
    );

    // 2. Programmatic Evaluation Calculation
    let composite_score: u64 = match tender.evaluation_type {
        EvaluationType::LeastCost => {
            require!(
                winning_bid.revealed_price == tender.lowest_revealed_price,
                BidTraceError::WinnerNotLowestPrice
            );
            10000 // 100% relative rank
        }
        EvaluationType::QCBS => {
            // S_composite = (S_tech * W_tech / 10000) + ((P_lowest * 10000 / P_bidder) * W_fin / 10000)
            let tech_part = (winning_bid.technical_score_bps as u128
                * tender.tech_weight_bps as u128)
                / 10000;

            let fin_score_ratio = (tender.lowest_revealed_price as u128 * 10000)
                / winning_bid.revealed_price as u128;

            let fin_part = (fin_score_ratio * tender.fin_weight_bps as u128) / 10000;

            let total = tech_part + fin_part;
            total as u64
        }
    };

    winning_bid.composite_score = composite_score;
    tender.highest_composite_score = composite_score;
    tender.winning_bidder = Some(winning_bid.bidder);
    tender.status = TenderStatus::Awarded;

    msg!(
        "Tender Award Recorded: id={}, winner={}, price={}, composite_score_bps={}",
        tender.tender_id,
        winning_bid.bidder,
        winning_bid.revealed_price,
        composite_score
    );

    Ok(())
}
