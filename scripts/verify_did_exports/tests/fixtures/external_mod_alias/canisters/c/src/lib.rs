// SSA landed-diff F1d: `foo.rs` is a module, not a root. Parsing it standalone
// gives it an empty import map, so the alias declared here is lost and the
// endpoint in `foo` goes uncensused — F1 again, across a file boundary.
use ic_cdk_macros::update as endpoint;

mod foo;
