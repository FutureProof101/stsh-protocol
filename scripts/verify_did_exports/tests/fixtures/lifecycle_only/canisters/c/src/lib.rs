#[init]
fn init(seed: u64) { let _ = seed; }

#[ic_cdk::post_upgrade]
fn post_upgrade() {}

#[ic_cdk::pre_upgrade]
fn pre_upgrade() {}

#[ic_cdk_macros::heartbeat]
fn heartbeat() {}
