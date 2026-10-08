use anchor_lang::prelude::*;

#[error_code]
pub enum BidTraceError {
    #[msg("Submission deadline slot must be in the future.")]
    InvalidSubmissionDeadline,

    #[msg("Reveal deadline slot must be strictly after the submission deadline slot.")]
    InvalidRevealDeadline,

    #[msg("Submission deadline has passed. Commitments are frozen.")]
    SubmissionDeadlineExceeded,

    #[msg("Tender is already locked.")]
    TenderAlreadyLocked,

    #[msg("Submission deadline has not been reached yet.")]
    SubmissionDeadlineNotReached,

    #[msg("Tender is not in locked state.")]
    TenderNotLocked,

    #[msg("Bidder is not in the authorized whitelist.")]
    UnauthorizedBidder,

    #[msg("Provided reveal data does not match the committed hash.")]
    InvalidRevealHash,

    #[msg("Bid has already been revealed.")]
    BidAlreadyRevealed,

    #[msg("Reveal window has expired. Reveals are closed.")]
    RevealWindowExpired,

    #[msg("Reveal window is still active and unrevealed bids remain. Early award is prohibited.")]
    RevealWindowActive,

    #[msg("Winning bidder has not revealed their bid.")]
    WinnerNotRevealed,

    #[msg("Selected winner is not the lowest compliant revealed bid.")]
    WinnerNotLowestBid,

    #[msg("Tender ID exceeds maximum allowed length of 32 characters.")]
    TenderIdTooLong,

    #[msg("Insufficient deposit attached for bid commitment bond.")]
    InsufficientDeposit,
}
