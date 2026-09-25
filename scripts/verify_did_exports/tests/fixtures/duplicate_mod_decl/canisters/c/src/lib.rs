// SSA F1h: Rust rejects this; the scanner deduplicated it through its traversal
// cache and completed. A tool that claims to fail closed cannot quietly accept
// an invalid module topology.
mod foo;
mod foo;
