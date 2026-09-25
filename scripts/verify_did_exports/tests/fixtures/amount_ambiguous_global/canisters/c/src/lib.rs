// The inverse collision: the endpoint names a type it does not define, and TWO
// other crates define that name. Picking either is a guess; a guess about an
// amount boundary is exactly what must never happen silently.
#[update]
fn submit(arg: Shared) {}
