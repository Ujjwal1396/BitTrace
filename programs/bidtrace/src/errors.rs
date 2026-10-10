use anchor_lang::prelude::*;

#[error_code]
pub enum BidTraceError {
    #[msg("Submission deadline slot must be in the future.")]
    InvalidSubmissionDeadline,

    #[msg("Deadline slots must be strictly sequential (submission <= admin <= tech <= fin).")]
    InvalidDeadlineSequence,

    #[msg("Submission deadline has passed. Commitments are frozen.")]
    SubmissionDeadlineExceeded,

    #[msg("Submission deadline has not been reached yet.")]
    SubmissionDeadlineNotReached,

    #[msg("Admin review deadline has passed.")]
    AdminReviewDeadlineExceeded,

    #[msg("Technical evaluation deadline has passed.")]
    TechEvalDeadlineExceeded,

    #[msg("Financial reveal deadline has passed. Reveals are closed.")]
    FinancialRevealDeadlineExceeded,

    #[msg("Tender is not in SubmissionsOpen status.")]
    TenderNotSubmissionsOpen,

    #[msg("Tender is not in AdministrativeReview status.")]
    TenderNotAdminReview,

    #[msg("Tender is not in TechnicalEvaluation status.")]
    TenderNotTechnicalEvaluation,

    #[msg("Tender is not in FinancialEvaluation status.")]
    TenderNotFinancialEvaluation,

    #[msg("Tender has already been awarded.")]
    TenderAlreadyAwarded,

    #[msg("Bidder is not in the authorized whitelist.")]
    UnauthorizedBidder,

    #[msg("Merkle proof verification failed.")]
    InvalidMerkleProof,

    #[msg("Provided reveal preimage does not match the committed cryptographic hash.")]
    InvalidRevealHash,

    #[msg("Technical bid has already been revealed.")]
    TechAlreadyRevealed,

    #[msg("Technical proposal has not been revealed yet.")]
    TechNotRevealed,

    #[msg("Financial envelope has already been revealed.")]
    FinAlreadyRevealed,

    #[msg("Commercial Secrecy Invariant: Bidder is technically disqualified. Financial envelope is permanently sealed.")]
    BidderTechnicallyDisqualified,

    #[msg("Bidder has not passed administrative due diligence.")]
    BidderNotAdminPassed,

    #[msg("Winning bidder is not technically qualified.")]
    WinnerNotQualified,

    #[msg("Winning bidder has not unsealed their financial envelope.")]
    WinnerNotRevealed,

    #[msg("Selected winner does not have the lowest price in Least-Cost mode.")]
    WinnerNotLowestPrice,

    #[msg("Selected winner does not have the highest composite score in QCBS mode.")]
    WinnerNotHighestCompositeScore,

    #[msg("Anti-Lockout Gate: Financial reveal window is active and qualified bids remain unrevealed.")]
    FinancialRevealWindowActive,

    #[msg("Tender ID exceeds maximum allowed length of 32 characters.")]
    TenderIdTooLong,

    #[msg("Insufficient deposit attached for bid commitment bond.")]
    InsufficientDeposit,

    #[msg("Signer is not an accredited member of the Tender Committee.")]
    EvaluatorNotAuthorized,

    #[msg("Tender committee roster is already locked.")]
    CommitteeAlreadyLocked,

    #[msg("Evaluator grade has already been revealed.")]
    GradeAlreadyRevealed,

    #[msg("Evaluator grade has not been revealed yet.")]
    GradeNotRevealed,

    #[msg("At least 3 revealed committee evaluations required for trimmed mean scoring.")]
    InsufficientEvaluatorGrades,

    #[msg("Sub-scores do not match the claimed total score.")]
    InvalidSubScores,

    #[msg("Sub-scores exceed maximum allowed value (10,000 bps total).")]
    SubScoresOutOfRange,

    #[msg("Technical and financial weights must sum exactly to 10,000 basis points (100%).")]
    InvalidWeights,

    #[msg("Bond deposit has already been refunded or settled.")]
    BondAlreadySettled,

    #[msg("Bidder is technically qualified. Financial envelope must be unsealed to settle bond.")]
    BidderIsTechQualified,

    #[msg("Bond mode is not SolanaEscrow.")]
    InvalidBondMode,
}
