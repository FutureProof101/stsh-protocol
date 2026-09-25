// R2-1 (a), ruled: a value carried in the ERROR half of a return `Result` is the
// disclosure of a public governance parameter the caller failed against — public
// by design under the fee model, not an amount boundary in C4's sense. The Ok
// half is still walked, which is what the sibling fixture proves.
pub enum WithdrawError {
    BelowMinimum { minimum: u128 },
}

#[update]
fn withdraw() -> Result<(), WithdrawError> { Ok(()) }
