// SSA F1e: the skipped subtree must follow the DECLARED path. Recording only
// the conventional `tests.rs` / `tests/` left the real file looking unreachable
// and failed a legal, production-disabled module graph.
#[cfg(test)]
#[path = "special/test_impl.rs"]
mod tests;

#[update]
fn real_export() {}
