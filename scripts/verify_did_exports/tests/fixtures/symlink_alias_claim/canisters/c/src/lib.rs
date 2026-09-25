// SSA F1i: `alias.rs` is a symlink to `foo.rs`. Comparing lexical paths made one
// physical file look like two, so the duplicate-claim guard never fired and the
// endpoint was emitted twice — the F1h promise, evaded by a filesystem alias.
mod foo;

#[path = "alias.rs"]
mod alias;
