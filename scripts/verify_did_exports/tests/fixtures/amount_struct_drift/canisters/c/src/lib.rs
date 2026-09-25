// The SAME class-row, but the struct has grown a third amount field since review.
// The count is the drift lock: this must RED rather than ride the existing row.
pub struct Report { pub total: u128, pub fees: u128, pub sneaked_in: u128 }

#[query]
fn report() -> Report { todo!() }
