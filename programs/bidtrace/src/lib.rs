use anchor_lang::prelude::*;

pub mod errors;
pub mod instructions;
pub mod state;

use instructions::*;
use state::{BondMode, EvaluationType, TenderMode};

declare_id!("x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ");

#[program]
pub mod bidtrace {
    use super::*;

    /// 1. Initialize a two-envelope tender with temporal slot deadlines, OCDS notice hash, and scoring parameters
    pub fn initialize_tender(
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
        instructions::initialize_tender::handle_initialize_tender(
            ctx,
            tender_id,
            ocds_notice_hash,
            tender_mode,
            evaluation_type,
            submission_deadline_slot,
            admin_review_deadline_slot,
            tech_eval_deadline_slot,
            fin_reveal_deadline_slot,
            authorized_bidders_root,
            min_tech_score_bps,
            tech_weight_bps,
            fin_weight_bps,
        )
    }

    /// 2. Initialize the evaluation committee with certified evaluators and outlier variance threshold
    pub fn initialize_committee(
        ctx: Context<InitializeCommittee>,
        evaluators: Vec<Pubkey>,
        max_variance_bps: u16,
    ) -> Result<()> {
        instructions::initialize_committee::handle_initialize_committee(
            ctx,
            evaluators,
            max_variance_bps,
        )
    }

    /// 3. Bidder commits a dual-envelope cryptographic proposal (Envelope A + Envelope B)
    pub fn commit_dual_bid(
        ctx: Context<CommitDualBid>,
        admin_dossier_hash: [u8; 32],
        tech_commitment_hash: [u8; 32],
        fin_commitment_hash: [u8; 32],
        bond_mode: BondMode,
        bond_amount: u64,
        whitelist_proof: Option<Vec<[u8; 32]>>,
    ) -> Result<()> {
        instructions::commit_dual_bid::handle_commit_dual_bid(
            ctx,
            admin_dossier_hash,
            tech_commitment_hash,
            fin_commitment_hash,
            bond_mode,
            bond_amount,
            whitelist_proof,
        )
    }

    /// 4. Advance tender phase based on temporal consensus slot deadlines
    pub fn advance_tender_phase(ctx: Context<AdvanceTenderPhase>) -> Result<()> {
        instructions::advance_tender_phase::handle_advance_tender_phase(ctx)
    }

    /// 5. Unseal Envelope A: Reveal technical proposal specification and blueprints
    pub fn reveal_technical_bid(
        ctx: Context<RevealTechnicalBid>,
        salt_tech: [u8; 32],
        proposal_hash: [u8; 32],
    ) -> Result<()> {
        instructions::reveal_technical_bid::handle_reveal_technical_bid(
            ctx,
            salt_tech,
            proposal_hash,
        )
    }

    /// 6. Evaluator commits a blinded cryptographic score across 5 sub-criteria
    pub fn commit_evaluator_grade(
        ctx: Context<CommitEvaluatorGrade>,
        commitment_hash: [u8; 32],
    ) -> Result<()> {
        instructions::commit_evaluator_grade::handle_commit_evaluator_grade(
            ctx,
            commitment_hash,
        )
    }

    /// 7. Evaluator reveals sub-scores and justification report hash
    pub fn reveal_evaluator_grade(
        ctx: Context<RevealEvaluatorGrade>,
        sub_scores: [u16; 5],
        salt: [u8; 32],
        justification_hash: [u8; 32],
    ) -> Result<()> {
        instructions::reveal_evaluator_grade::handle_reveal_evaluator_grade(
            ctx,
            sub_scores,
            salt,
            justification_hash,
        )
    }

    /// 8. Finalize technical scores using the on-chain Olympic Trimmed Mean and outlier rejection filter
    pub fn finalize_technical_scores<'info>(
        ctx: Context<'_, '_, '_, 'info, FinalizeTechnicalScores<'info>>,
    ) -> Result<()> {
        instructions::finalize_technical_scores::handle_finalize_technical_scores(ctx)
    }

    /// 9. Unseal Envelope B: Strictly gated to technically qualified bidders (Commercial Secrecy Invariant)
    pub fn reveal_financial_envelope(
        ctx: Context<RevealFinancialEnvelope>,
        salt_fin: [u8; 32],
        price: u64,
        boq_hash: [u8; 32],
    ) -> Result<()> {
        instructions::reveal_financial_envelope::handle_reveal_financial_envelope(
            ctx,
            salt_fin,
            price,
            boq_hash,
        )
    }

    /// 10. Record tender award with programmatic QCBS composite scoring formula
    pub fn record_award_qcbs(
        ctx: Context<RecordAwardQcbs>,
        rationale_hash: [u8; 32],
    ) -> Result<()> {
        instructions::record_award_qcbs::handle_record_award_qcbs(ctx, rationale_hash)
    }
}
