// No `mod stray;` anywhere: the file below is unreachable, and an
// unreachable file is a place an endpoint can hide.
#[update]
fn real_export() {}
