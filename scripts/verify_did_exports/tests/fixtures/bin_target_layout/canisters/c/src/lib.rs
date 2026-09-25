// SSA F1g: `src/bin/helper.rs` is a separate Cargo target. Requiring every .rs
// to hang off the library's module graph called valid Cargo layout a violation.
#[update]
fn real_export() {}
