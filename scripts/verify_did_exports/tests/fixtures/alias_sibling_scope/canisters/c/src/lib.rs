// SSA landed-diff F1c: two sibling modules legally bind the same local name to
// different things. A file-wide alias map lets `b`'s binding overwrite `a`'s and
// the endpoint in `a` disappears — the original F1 exit-0, restored by a legal
// import. Sibling scopes must not see each other.
mod a {
    use ic_cdk_macros::update as endpoint;

    #[endpoint]
    fn hidden_export() {}
}

mod b {
    use std::fmt as endpoint;

    pub fn _quiet(_: &dyn endpoint::Debug) {}
}
