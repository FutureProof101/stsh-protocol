// SSA F1f: `#![cfg(test)]` inside tests.rs disables the whole file, including
// the modules it declares. Skipping only the file itself left its children
// unreachable and failed a legal graph.
mod tests;

#[update]
fn real_export() {}
