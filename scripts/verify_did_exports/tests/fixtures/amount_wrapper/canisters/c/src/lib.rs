pub struct Inner { pub value: u128 }

pub enum Wrapper { Spend(Inner), Noop }

pub type Wrapped = Wrapper;

#[update]
fn act(req: Vec<Wrapped>) {}
