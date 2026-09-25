// A deliberately-published reporting surface: two raw-amount fields, adjudicated
// by ONE class-row naming the struct and its field count (R2-1 (c)).
pub struct Report { pub total: u128, pub fees: u128 }

#[query]
fn report() -> Report { todo!() }
