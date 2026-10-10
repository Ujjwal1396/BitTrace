use anchor_lang::prelude::*;
use crate::errors::BidTraceError;
use crate::state::{BondMode, DualBidCommitment, Tender, TenderStatus};

#[derive(Accounts)]
pub struct RefundDisqualifiedBond<'info> {
    #[account(
        constraint = tender.status >= TenderStatus::FinancialEvaluation @ BidTraceError::TenderNotFinancialEvaluation,
    )]
    pub tender: Account<'info, Tender>,

    #[account(
        mut,
        seeds = [b"bid", tender.key().as_ref(), bid_commitment.bidder.as_ref()],
        bump = bid_commitment.bump,
        // Commercial Secrecy Protection: ONLY technically disqualified bidders use this instruction!
        constraint = !bid_commitment.is_tech_qualified @ BidTraceError::BidderIsTechQualified,
        constraint = !bid_commitment.is_bond_settled @ BidTraceError::BondAlreadySettled,
        constraint = bid_commitment.bond_mode == BondMode::SolanaEscrow @ BidTraceError::InvalidBondMode,
    )]
    pub bid_commitment: Account<'info, DualBidCommitment>,

    /// CHECK: Must match original bidder public key to receive refunded lamports
    #[account(
        mut,
        constraint = bidder_recipient.key() == bid_commitment.bidder
    )]
    pub bidder_recipient: AccountInfo<'info>,

    /// Can be the bidder themselves or a sponsored relayer
    pub caller: Signer<'info>,
}

pub fn handle_refund_disqualified_bond(ctx: Context<RefundDisqualifiedBond>) -> Result<()> {
    let bid = &mut ctx.accounts.bid_commitment;
    let refund_amount = bid.bond_amount;

    require!(refund_amount > 0, BidTraceError::InsufficientDeposit);

    // Mark bond as settled
    bid.is_bond_settled = true;

    // Transfer lamports from the DualBidCommitment PDA to bidder_recipient
    **bid.to_account_info().try_borrow_mut_lamports()? -= refund_amount;
    **ctx.accounts.bidder_recipient.try_borrow_mut_lamports()? += refund_amount;

    msg!(
        "Disqualified bidder bond refunded: bidder={}, amount={}, tender={}",
        bid.bidder,
        refund_amount,
        bid.tender
    );

    Ok(())
}
