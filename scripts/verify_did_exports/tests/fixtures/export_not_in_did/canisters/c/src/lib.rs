#[query]
fn ping() -> u64 { 0 }

#[update]
fn undeclared_mutator() {}
