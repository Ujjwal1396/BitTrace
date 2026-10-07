use anchor_lang::prelude::*;

#[error_code]
pub enum BidTraceError {
    #[msg("The deadline slot must be in the future.")]
    InvalidDeadlineSlot,

    #[msg("Submission deadline has passed. Commitments are frozen.")]
    DeadlineExceeded,

    #[msg("Tender is already locked.")]
    TenderAlreadyLocked,

    #[msg("Tender deadline has not been reached yet.")]
    DeadlineNotReached,

    #[msg("Tender is not in locked state.")]
    TenderNotLocked,

    #[msg("Bidder is not in the authorized whitelist.")]
    UnauthorizedBidder,

    #[msg("Provided reveal data does not match the committed hash.")]
    InvalidRevealHash,

    #[msg("Bid has already been revealed.")]
    BidAlreadyRevealed,

    #[msg("Winning bidder has not revealed their bid.")]
    WinnerNotRevealed,

    #[msg("Tender ID exceeds maximum allowed length of 32 characters.")]
    TenderIdTooLong,
}
