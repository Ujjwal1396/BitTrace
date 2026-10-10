use anchor_lang::prelude::*;
use sha2::{Digest, Sha256};
use crate::errors::BidTraceError;
use crate::state::{BondMode, DualBidCommitment, Tender, TenderStatus};

#[derive(Accounts)]
pub struct RevealFinancialEnvelope<'info> {
    #[account(
        mut,
        constraint = tender.status == TenderStatus::FinancialEvaluation @ BidTraceError::TenderNotFinancialEvaluation,
    )]
    pub tender: Account<'info, Tender>,

    #[account(
        mut,
        seeds = [b"bid", tender.key().as_ref(), bid_commitment.bidder.as_ref()],
        bump = bid_commitment.bump,
        constraint = !bid_commitment.is_fin_revealed @ BidTraceError::FinAlreadyRevealed,
        // THE COMMERCIAL SECRECY GUARANTEE:
        // Disqualified bidders are strictly barred from opening their financial envelopes!
        constraint = bid_commitment.is_tech_qualified @ BidTraceError::BidderTechnicallyDisqualified,
    )]
    pub bid_commitment: Account<'info, DualBidCommitment>,

    pub revealer: Signer<'info>,

    /// CHECK: Must match the original bidder for bond refund
    #[account(
        mut,
        constraint = bidder_recipient.key() == bid_commitment.bidder
    )]
    pub bidder_recipient: AccountInfo<'info>,
}

pub fn handle_reveal_financial_envelope(
    ctx: Context<RevealFinancialEnvelope>,
    salt_fin: [u8; 32],
    price: u64,
    boq_hash: [u8; 32],
) -> Result<()> {
    let clock = Clock::get()?;
    let tender = &mut ctx.accounts.tender;
    let bid = &mut ctx.accounts.bid_commitment;

    // 1. Enforce temporal reveal slot boundary
    require!(
        clock.slot <= tender.fin_reveal_deadline_slot,
        BidTraceError::FinancialRevealDeadlineExceeded
    );

    // 2. Cryptographic domain-separated preimage check for Envelope B (Financial)
    let mut hasher = Sha256::new();
    hasher.update(b"BIDTRACE_FIN_V1");
    hasher.update(tender.key().as_ref());
    hasher.update(bid.bidder.as_ref());
    hasher.update(&salt_fin);
    hasher.update(&price.to_le_bytes());
    hasher.update(&boq_hash);
    let computed_hash: [u8; 32] = hasher.finalize().into();

    require!(
        computed_hash == bid.fin_commitment_hash,
        BidTraceError::InvalidRevealHash
    );

    bid.is_fin_revealed = true;
    bid.revealed_price = price;

    tender.total_fin_revealed += 1;

    // 3. Track lowest compliant price observed
    if price < tender.lowest_revealed_price {
        tender.lowest_revealed_price = price;
    }

    // 4. Refund escrowed bond deposit if applicable
    if bid.bond_mode == BondMode::SolanaEscrow && bid.bond_amount > 0 && !bid.is_bond_settled {
        let refund_lamports = bid.bond_amount;
        bid.is_bond_settled = true;
        **bid.to_account_info().try_borrow_mut_lamports()? -= refund_lamports;
        **ctx.accounts.bidder_recipient.try_borrow_mut_lamports()? += refund_lamports;
    }

    msg!(
        "Financial envelope unsealed: bidder={}, price={}, lowest_price={}, fin_revealed={}/{}",
        bid.bidder,
        price,
        tender.lowest_revealed_price,
        tender.total_fin_revealed,
        tender.total_tech_qualified
    );

    Ok(())
}
