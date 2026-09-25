use foreign_crate::ForeignBytes;

pub struct Snapshot { pub payload: ForeignBytes }

#[query]
fn snapshot() -> Snapshot { todo!() }
