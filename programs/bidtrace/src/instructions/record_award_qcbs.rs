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

pub fn handle_record_award_qcbs<'info>(
    ctx: Context<'_, '_, '_, 'info, RecordAwardQcbs<'info>>,
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

    // 2. Division-by-Zero & Zero-Price Guards (SEC-04)
    require!(
        winning_bid.revealed_price > 0,
        BidTraceError::ZeroPriceNotAllowed
    );
    require!(
        tender.lowest_revealed_price > 0 && tender.lowest_revealed_price <= winning_bid.revealed_price,
        BidTraceError::ZeroPriceNotAllowed
    );

    // 3. Programmatic Evaluation Calculation for Designated Winner
    let winning_composite_score: u64 = match tender.evaluation_type {
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

    // 4. Cryptographic Assertion Against All Competing Revealed Qualified Bidders (SEC-04)
    // The tender has recorded exactly tender.total_fin_revealed unsealed qualified bids.
    // One is winning_bid; all other (total_fin_revealed - 1) competing bids must be supplied in remaining_accounts.
    let expected_competing_count = tender.total_fin_revealed.saturating_sub(1) as usize;
    require!(
        ctx.remaining_accounts.len() == expected_competing_count,
        BidTraceError::MissingCompetingBids
    );

    let mut seen_competing_bidders: Vec<Pubkey> = Vec::with_capacity(expected_competing_count);

    for acc in ctx.remaining_accounts.iter() {
        require!(
            acc.owner == ctx.program_id,
            BidTraceError::InvalidCompetingBid
        );

        let competing_bid = {
            let data = acc.try_borrow_data()?;
            DualBidCommitment::try_deserialize(&mut &data[..])?
        };

        // Must belong to this tender
        require!(
            competing_bid.tender == tender.key(),
            BidTraceError::InvalidCompetingBid
        );

        // Verify canonical PDA derivation
        let (expected_pda, expected_bump) = Pubkey::find_program_address(
            &[b"bid", tender.key().as_ref(), competing_bid.bidder.as_ref()],
            ctx.program_id,
        );
        require!(
            acc.key() == expected_pda && competing_bid.bump == expected_bump,
            BidTraceError::InvalidCompetingBid
        );

        // Cannot duplicate the winning bid
        require!(
            competing_bid.bidder != winning_bid.bidder,
            BidTraceError::InvalidCompetingBid
        );

        // Must be unique within remaining_accounts
        require!(
            !seen_competing_bidders.contains(&competing_bid.bidder),
            BidTraceError::InvalidCompetingBid
        );
        seen_competing_bidders.push(competing_bid.bidder);

        // Competing bidder must be qualified and revealed
        require!(
            competing_bid.is_tech_qualified && competing_bid.is_fin_revealed,
            BidTraceError::InvalidCompetingBid
        );

        // Guard against zero-price division in competing bids
        require!(
            competing_bid.revealed_price > 0,
            BidTraceError::ZeroPriceNotAllowed
        );

        // Compute competing bid composite score and verify winning bidder is not inferior
        let competing_composite_score: u64 = match tender.evaluation_type {
            EvaluationType::LeastCost => {
                require!(
                    winning_bid.revealed_price <= competing_bid.revealed_price,
                    BidTraceError::WinnerNotLowestPrice
                );
                if competing_bid.revealed_price == tender.lowest_revealed_price {
                    10000
                } else {
                    0
                }
            }
            EvaluationType::QCBS => {
                let tech_part = (competing_bid.technical_score_bps as u128
                    * tender.tech_weight_bps as u128)
                    / 10000;

                let fin_score_ratio = (tender.lowest_revealed_price as u128 * 10000)
                    / competing_bid.revealed_price as u128;

                let fin_part = (fin_score_ratio * tender.fin_weight_bps as u128) / 10000;

                let comp_total = (tech_part + fin_part) as u64;

                // SEC-04 CORE ASSERTION: Authority cannot award an inferior scoring bidder
                require!(
                    winning_composite_score >= comp_total,
                    BidTraceError::WinnerNotHighestCompositeScore
                );

                comp_total
            }
        };

        // If the competing bid account was passed as writable, record its programmatic composite score
        if acc.is_writable {
            let mut mut_data = acc.try_borrow_mut_data()?;
            let mut mutable_bid = DualBidCommitment::try_deserialize(&mut &mut_data[..])?;
            mutable_bid.composite_score = competing_composite_score;
            mutable_bid.try_serialize(&mut &mut mut_data[..])?;
        }
    }

    winning_bid.composite_score = winning_composite_score;
    tender.highest_composite_score = winning_composite_score;
    tender.winning_bidder = Some(winning_bid.bidder);
    tender.status = TenderStatus::Awarded;

    msg!(
        "Tender Award Recorded: id={}, winner={}, price={}, composite_score_bps={}",
        tender.tender_id,
        winning_bid.bidder,
        winning_bid.revealed_price,
        winning_composite_score
    );

    Ok(())
}
