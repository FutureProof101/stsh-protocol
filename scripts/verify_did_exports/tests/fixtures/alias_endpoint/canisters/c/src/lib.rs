// SSA landed-diff F1: the endpoint macro is imported under a different name.
// The attribute is not spelled `update`, so a last-segment test never sees it.
use ic_cdk_macros::update as endpoint;

#[endpoint]
fn hidden_export() {}
