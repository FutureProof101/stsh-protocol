pub struct Allocation { pub amount: u128 }
pub struct InitArgs { pub allocations: Vec<Allocation> }

#[ic_cdk_macros::init]
fn init(args: InitArgs) {}

#[query]
fn ping() -> u64 { 0 }
