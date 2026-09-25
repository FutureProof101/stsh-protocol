// SSA landed-diff F2: the endpoint takes `external::Shared`, but a harmless
// local type shares the basename. Discarding the qualification resolves to the
// wrong definition and the raw amount disappears.
pub struct Shared { pub harmless: u64 }

#[update]
fn submit(arg: external::Shared) {}
