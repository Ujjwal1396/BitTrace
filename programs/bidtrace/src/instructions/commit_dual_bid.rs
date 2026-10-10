use anchor_lang::prelude::*;
use anchor_lang::system_program;
use sha2::{Digest, Sha256};
use crate::errors::BidTraceError;
use crate::state::{AdminStatus, BondMode, DualBidCommitment, Tender, TenderMode, TenderStatus};

#[derive(Accounts)]
pub struct CommitDualBid<'info> {
    #[account(
        mut,
        constraint = tender.status == TenderStatus::SubmissionsOpen @ BidTraceError::TenderNotSubmissionsOpen,
    )]
    pub tender: Account<'info, Tender>,

    #[account(
        init,
        payer = fee_payer,
        space = DualBidCommitment::LEN,
        seeds = [b"bid", tender.key().as_ref(), bidder.key().as_ref()],
        bump
    )]
    pub bid_commitment: Account<'info, DualBidCommitment>,

    /// The bidder keypair establishing ownership of the dual commitment
    pub bidder: Signer<'info>,

    /// Transaction fee and rent payer (relayer or bidder)
    #[account(mut)]
    pub fee_payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handle_commit_dual_bid(
    ctx: Context<CommitDualBid>,
    admin_dossier_hash: [u8; 32],
    tech_commitment_hash: [u8; 32],
    fin_commitment_hash: [u8; 32],
    bond_mode: BondMode,
    bond_amount: u64,
    whitelist_proof: Option<Vec<[u8; 32]>>,
) -> Result<()> {
    let clock = Clock::get()?;
    let tender = &mut ctx.accounts.tender;
    let bidder_key = ctx.accounts.bidder.key();

    // 1. Strict consensus slot submission deadline check
    require!(
        clock.slot <= tender.submission_deadline_slot,
        BidTraceError::SubmissionDeadlineExceeded
    );

    // 2. Model A: Pre-Qualified Merkle Whitelist Verification
    let mut admin_status = AdminStatus::Pending;
    if tender.tender_mode == TenderMode::PreQualifiedWhitelist {
        require!(
            tender.authorized_bidders_root != [0u8; 32],
            BidTraceError::UnauthorizedBidder
        );
        let proof = whitelist_proof.ok_or(BidTraceError::UnauthorizedBidder)?;

        // Leaf = SHA256(bidder_pubkey)
        let mut leaf_hasher = Sha256::new();
        leaf_hasher.update(bidder_key.as_ref());
        let mut current_hash: [u8; 32] = leaf_hasher.finalize().into();

        for sibling in proof {
            let mut node_hasher = Sha256::new();
            if current_hash <= sibling {
                node_hasher.update(&current_hash);
                node_hasher.update(&sibling);
            } else {
                node_hasher.update(&sibling);
                node_hasher.update(&current_hash);
            }
            current_hash = node_hasher.finalize().into();
        }

        require!(
            current_hash == tender.authorized_bidders_root,
            BidTraceError::InvalidMerkleProof
        );

        admin_status = AdminStatus::Passed;
        tender.total_admin_passed += 1;
    }

    // 3. Solana Escrow Bond Handling (if applicable)
    if bond_mode == BondMode::SolanaEscrow && bond_amount > 0 {
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.fee_payer.to_account_info(),
                    to: ctx.accounts.bid_commitment.to_account_info(),
                },
            ),
            bond_amount,
        )?;
    }

    // 4. Initialize DualBidCommitment PDA
    let bid = &mut ctx.accounts.bid_commitment;
    bid.tender = tender.key();
    bid.bidder = bidder_key;
    bid.committed_at_slot = clock.slot;

    bid.admin_dossier_hash = admin_dossier_hash;
    bid.tech_commitment_hash = tech_commitment_hash;
    bid.fin_commitment_hash = fin_commitment_hash;

    bid.admin_status = admin_status;
    bid.admin_rejection_code = 0;

    bid.is_tech_revealed = false;
    bid.technical_score_bps = 0;
    bid.is_tech_qualified = false;

    bid.is_fin_revealed = false;
    bid.revealed_price = 0;
    bid.composite_score = 0;

    bid.bond_mode = bond_mode;
    bid.bond_amount = bond_amount;
    bid.is_bond_settled = false;
    bid.bump = ctx.bumps.bid_commitment;

    tender.total_committed += 1;

    msg!(
        "Dual bid committed: bidder={}, slot={}, total_committed={}",
        bid.bidder,
        bid.committed_at_slot,
        tender.total_committed
    );

    Ok(())
}
