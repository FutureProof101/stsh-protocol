// The other half of F1d: the `#[cfg]` lives on the DECLARATION, not in the
// file. `testing` is not a default feature, so `foo` is absent from the
// production build and its endpoint must not be demanded of the .did.
#[cfg(feature = "testing")]
mod foo;

#[update]
fn real_export() {}
