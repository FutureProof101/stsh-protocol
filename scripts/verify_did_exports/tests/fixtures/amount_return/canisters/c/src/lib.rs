// R2-1: a raw amount LEAVING the canister is the same boundary as one entering
// it — the direction only changes who reads it. Before R2-1 the census built
// endpoints from `sig.inputs` alone, so this endpoint was invisible to it.
#[query]
fn balance() -> u128 { 0 }
