use anchor_lang::prelude::*;
use crate::errors::BidTraceError;
use crate::state::{Tender, TenderStatus};

#[derive(Accounts)]
pub struct AdvanceTenderPhase<'info> {
    #[account(mut)]
    pub tender: Account<'info, Tender>,

    pub caller: Signer<'info>,
}

pub fn handle_advance_tender_phase(ctx: Context<AdvanceTenderPhase>) -> Result<()> {
    let clock = Clock::get()?;
    let tender = &mut ctx.accounts.tender;

    match tender.status {
        TenderStatus::SubmissionsOpen => {
            require!(
                clock.slot > tender.submission_deadline_slot || ctx.accounts.caller.key() == tender.authority,
                BidTraceError::SubmissionDeadlineNotReached
            );
            // If admin review slot equals submission deadline slot, advance directly to TechnicalEvaluation
            if tender.admin_review_deadline_slot == tender.submission_deadline_slot {
                tender.status = TenderStatus::TechnicalEvaluation;
            } else {
                tender.status = TenderStatus::AdministrativeReview;
            }
        }
        TenderStatus::AdministrativeReview => {
            require!(
                clock.slot > tender.admin_review_deadline_slot || ctx.accounts.caller.key() == tender.authority,
                BidTraceError::SubmissionDeadlineNotReached
            );
            tender.status = TenderStatus::TechnicalEvaluation;
        }
        TenderStatus::TechnicalEvaluation => {
            require!(
                clock.slot > tender.tech_eval_deadline_slot || ctx.accounts.caller.key() == tender.authority,
                BidTraceError::SubmissionDeadlineNotReached
            );
            tender.status = TenderStatus::FinancialEvaluation;
        }
        _ => return Err(BidTraceError::TenderAlreadyAwarded.into()),
    }

    msg!(
        "Tender phase advanced to {:?} at slot {}",
        tender.status,
        clock.slot
    );

    Ok(())
}
