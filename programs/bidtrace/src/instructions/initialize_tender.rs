use anchor_lang::prelude::*;
use crate::errors::BidTraceError;
use crate::state::{EvaluationType, Tender, TenderMode, TenderStatus};

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
    ocds_notice_hash: [u8; 32],
    tender_mode: TenderMode,
    evaluation_type: EvaluationType,
    submission_deadline_slot: u64,
    admin_review_deadline_slot: u64,
    tech_eval_deadline_slot: u64,
    fin_reveal_deadline_slot: u64,
    authorized_bidders_root: [u8; 32],
    min_tech_score_bps: u16,
    tech_weight_bps: u16,
    fin_weight_bps: u16,
) -> Result<()> {
    require!(tender_id.len() <= 32, BidTraceError::TenderIdTooLong);

    let clock = Clock::get()?;
    require!(
        submission_deadline_slot > clock.slot,
        BidTraceError::InvalidSubmissionDeadline
    );
    require!(
        admin_review_deadline_slot >= submission_deadline_slot
            && tech_eval_deadline_slot >= admin_review_deadline_slot
            && fin_reveal_deadline_slot >= tech_eval_deadline_slot,
        BidTraceError::InvalidDeadlineSequence
    );

    if evaluation_type == EvaluationType::QCBS {
        require!(
            tech_weight_bps + fin_weight_bps == 10000,
            BidTraceError::InvalidWeights
        );
    }

    let tender = &mut ctx.accounts.tender;
    tender.authority = ctx.accounts.authority.key();
    tender.tender_id = tender_id;
    tender.ocds_notice_hash = ocds_notice_hash;
    tender.tender_mode = tender_mode;
    tender.evaluation_type = evaluation_type;
    tender.status = TenderStatus::SubmissionsOpen;

    tender.submission_deadline_slot = submission_deadline_slot;
    tender.admin_review_deadline_slot = admin_review_deadline_slot;
    tender.tech_eval_deadline_slot = tech_eval_deadline_slot;
    tender.fin_reveal_deadline_slot = fin_reveal_deadline_slot;

    tender.authorized_bidders_root = authorized_bidders_root;
    tender.min_tech_score_bps = min_tech_score_bps;
    tender.tech_weight_bps = tech_weight_bps;
    tender.fin_weight_bps = fin_weight_bps;

    tender.total_committed = 0;
    tender.total_admin_passed = 0;
    tender.total_tech_qualified = 0;
    tender.total_fin_revealed = 0;

    tender.lowest_revealed_price = u64::MAX;
    tender.highest_composite_score = 0;
    tender.winning_bidder = None;
    tender.bump = ctx.bumps.tender;

    msg!(
        "Tender initialized: id={}, mode={:?}, eval={:?}, sub_deadline={}",
        tender.tender_id,
        tender.tender_mode,
        tender.evaluation_type,
        tender.submission_deadline_slot
    );

    Ok(())
}
