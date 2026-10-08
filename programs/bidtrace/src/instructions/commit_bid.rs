use anchor_lang::prelude::*;
use anchor_lang::system_program;
use crate::errors::BidTraceError;
use crate::state::{BidCommitment, Tender, TenderStatus};

#[derive(Accounts)]
#[instruction(commitment_hash: [u8; 32])]
pub struct CommitBid<'info> {
    #[account(
        mut,
        constraint = tender.status == TenderStatus::Active @ BidTraceError::TenderAlreadyLocked,
    )]
    pub tender: Account<'info, Tender>,

    #[account(
        init,
        payer = fee_payer,
        space = BidCommitment::LEN,
        seeds = [b"bid", tender.key().as_ref(), bidder.key().as_ref()],
        bump
    )]
    pub bid_commitment: Account<'info, BidCommitment>,

    /// The bidder keypair establishing ownership of the commitment
    pub bidder: Signer<'info>,

    /// Transaction fee and rent payer (can be bidder or sponsored relayer)
    #[account(mut)]
    pub fee_payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handle_commit_bid(
    ctx: Context<CommitBid>,
    commitment_hash: [u8; 32],
    _whitelist_proof: Option<Vec<[u8; 32]>>,
) -> Result<()> {
    let clock = Clock::get()?;
    let tender = &mut ctx.accounts.tender;

    // Strict consensus slot deadline check
    require!(
        clock.slot <= tender.submission_deadline_slot,
        BidTraceError::SubmissionDeadlineExceeded
    );

    // If bid deposit is required, escrow it into the bid_commitment account
    if tender.bid_deposit > 0 {
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.fee_payer.to_account_info(),
                    to: ctx.accounts.bid_commitment.to_account_info(),
                },
            ),
            tender.bid_deposit,
        )?;
    }

    // Populate the BidCommitment PDA
    let bid = &mut ctx.accounts.bid_commitment;
    bid.tender = tender.key();
    bid.bidder = ctx.accounts.bidder.key();
    bid.commitment_hash = commitment_hash;
    bid.committed_at_slot = clock.slot;
    bid.escrowed_deposit = tender.bid_deposit;
    bid.is_revealed = false;
    bid.revealed_at_slot = 0;
    bid.revealed_amount = 0;
    bid.bump = ctx.bumps.bid_commitment;

    // Increment aggregate counter
    tender.total_committed += 1;

    msg!(
        "Bid committed: bidder={}, slot={}, total_committed={}, deposit_escrowed={}",
        bid.bidder,
        bid.committed_at_slot,
        tender.total_committed,
        bid.escrowed_deposit
    );

    Ok(())
}
