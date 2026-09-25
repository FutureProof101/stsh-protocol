// The class-row names a struct nothing publishes any more.
pub struct Report { pub total: u128, pub fees: u128 }

#[query]
fn unrelated() -> u64 { 0 }
