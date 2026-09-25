// bare
#[query]
fn bare_query() -> u64 { 0 }

#[update]
fn bare_update() {}

// qualified, both spellings
#[ic_cdk_macros::query]
fn qualified_macros_query() -> u64 { 0 }

#[ic_cdk::update]
fn qualified_cdk_update() {}

// parameterised
#[query(composite_query)]
fn composite() -> u64 { 0 }

#[update(guard = "some_guard")]
fn guarded() {}

// rename override — the EXPORTED name is what the .did must carry
#[query(name = "exported_alias")]
fn internal_name() -> u64 { 0 }

// nested in a module — the scan is AST-recursive, not file-shallow
mod inner {
    #[query]
    fn nested_query() -> u64 { 0 }
}

// test-only: absent from the production build, so never demanded of the .did
#[cfg(feature = "testing")]
#[update]
fn probe_for_test() {}

#[cfg(test)]
#[query]
fn unit_test_only() -> u64 { 0 }
