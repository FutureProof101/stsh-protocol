// SSA F1k: the skip candidate for a cfg-disabled `#[path]` is recorded
// lexically, because a disabled declaration need not resolve. The final walk
// then demanded a physical identity for every .rs on disk and aborted on the
// dangling entry before it could consult the skip that already explained it.
#[cfg(test)]
#[path = "dangling.rs"]
mod off;

#[update]
fn real_export() {}
