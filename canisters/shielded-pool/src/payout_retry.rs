// R-15 payout state. Stable identities outlive executors and key provisioning.
use super::*;
use hmac::{Hmac, Mac};
use std::collections::BTreeMap;

const MEM_PAYOUT_CONTROL: MemoryId = MemoryId::new(25);
pub(super) const MAX_LIVE_PAYOUT_ATTEMPTS: usize = 64;
const CONTROL_MAGIC: &[u8; 8] = b"STSHR15\x01";

#[derive(Clone)]
struct Control {
    boot: u64,
    next: u128,
    key: Option<[u8; 32]>,
}
impl Control {
    fn encode(&self) -> Vec<u8> {
        let mut b = CONTROL_MAGIC.to_vec();
        b.extend_from_slice(&self.boot.to_le_bytes());
        b.extend_from_slice(&self.next.to_le_bytes());
        b.push(u8::from(self.key.is_some()));
        b.extend_from_slice(&self.key.unwrap_or([0; 32]));
        b
    }
    fn decode(b: &[u8]) -> Self {
        if b.len() != 65 || &b[..8] != CONTROL_MAGIC || b[32] > 1 {
            ic_cdk::trap("R15 payout control corrupt or missing");
        }
        let boot = u64::from_le_bytes(b[8..16].try_into().unwrap());
        if boot == 0 || (b[32] == 0 && b[33..].iter().any(|v| *v != 0)) {
            ic_cdk::trap("R15 payout control invalid");
        }
        Self {
            boot,
            next: u128::from_le_bytes(b[16..32].try_into().unwrap()),
            key: if b[32] == 1 {
                Some(b[33..65].try_into().unwrap())
            } else {
                None
            },
        }
    }
}
thread_local! {
    static CONTROL: RefCell<Cell<Vec<u8>, Mem>> = RefCell::new(Cell::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MEM_PAYOUT_CONTROL)), Vec::new()
    ).expect("R15 control cell init"));
    static LIVE: RefCell<BTreeMap<u64, Attempt>> = RefCell::new(BTreeMap::new());
}
fn payout_record(id: u64) -> Option<PendingSpend> {
    #[cfg(feature = "testing")]
    RECORD_READS.with(|r| *r.borrow_mut() += 1);
    PENDING_SPENDS.with(|m| m.borrow().get(&id))
}
#[cfg(feature = "testing")]
thread_local! { static RECORD_READS: RefCell<u64> = RefCell::new(0); }
fn control() -> Control {
    CONTROL.with(|c| Control::decode(c.borrow().get()))
}
fn write_control(c: Control) {
    CONTROL.with(|cell| {
        cell.borrow_mut()
            .set(c.encode())
            .expect("R15 control write");
    });
}
pub(super) fn payout_control_init() {
    write_control(Control {
        boot: 1,
        next: 0,
        key: None,
    });
}
pub(super) fn payout_control_upgrade(predecessor: u32) {
    if predecessor == 3 {
        if CONTROL.with(|c| !c.borrow().get().is_empty()) {
            ic_cdk::trap("R15 ambiguous legacy adoption");
        }
        payout_control_init();
    } else {
        let mut c = control();
        c.boot = c
            .boot
            .checked_add(1)
            .unwrap_or_else(|| ic_cdk::trap("R15 boot exhausted"));
        write_control(c);
    }
    // No payout-record/index enumeration. The verified new module has no old futures.
    LIVE.with(|l| l.borrow_mut().clear());
}

#[update]
async fn initialize_payout_memo_key() -> Result<bool, PoolError> {
    assert_operator_controller();
    ensure_payout_memo_key().await
}
pub(super) async fn ensure_payout_memo_key() -> Result<bool, PoolError> {
    let initial = control();
    if initial.key.is_some() {
        return Ok(true);
    }
    #[cfg(feature = "testing")]
    let ticket = PROVISION_CALLS.with(|n| {
        let mut n = n.borrow_mut();
        *n += 1;
        *n
    });
    let reply: Result<(Vec<u8>,), _> = call(Principal::management_canister(), "raw_rand", ()).await;
    let bytes = reply.map_err(|_| PoolError::PayoutMemoKeyNotReady)?.0;
    #[cfg(feature = "testing")]
    let bytes = match PROVISION_FAULT.with(|f| *f.borrow()) {
        1 => return Err(PoolError::PayoutMemoKeyNotReady),
        2 => bytes[..31].to_vec(),
        _ => bytes,
    };
    #[cfg(feature = "testing")]
    if PROVISION_FAULT.with(|f| *f.borrow()) == 3 && ticket == 2 {
        wait_for_test(0, 4).await;
    }
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PoolError::PayoutMemoKeyNotReady)?;
    let mut latest = control();
    if latest.boot != initial.boot {
        return Err(PoolError::PayoutStateInvalid);
    }
    if latest.key.is_none() {
        latest.key = Some(key);
        write_control(latest);
    }
    Ok(true)
}
#[query]
fn payout_memo_key_ready() -> Option<bool> {
    if !is_controller(ic_cdk::caller()) {
        return None;
    }
    Some(control().key.is_some())
}

/// Update-transport twin used by the Vault's typed read model. Inter-canister
/// queries are not assumed; the same controller gate and value shape apply.
#[update]
fn payout_memo_key_ready_for_controller_update() -> Option<bool> {
    if !is_controller(ic_cdk::caller()) {
        return None;
    }
    Some(control().key.is_some())
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum PayoutPhase {
    PreDispatch,
    MayHaveDispatched,
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct FrozenPayout {
    pub ledger: Principal,
    pub from_subaccount: Option<[u8; 32]>,
    pub destination: Principal,
    pub destination_subaccount: Option<[u8; 32]>,
    pub amount: Nat,
    pub fee: Option<Nat>,
    pub memo: Option<Vec<u8>>,
    pub created_at_time: Option<u64>,
}
impl FrozenPayout {
    fn args(&self) -> IcrcTransferArgs {
        IcrcTransferArgs {
            from_subaccount: self.from_subaccount,
            to: IcrcAccount {
                owner: self.destination,
                subaccount: self.destination_subaccount,
            },
            amount: self.amount.clone(),
            fee: self.fee.clone(),
            memo: self.memo.clone(),
            created_at_time: self.created_at_time,
        }
    }
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct PayoutRetryState {
    pub memo_sequence: Nat,
    pub generation: u64,
    pub boot: u64,
    pub phase: PayoutPhase,
    pub prior_ambiguity: bool,
    pub dispatched: bool,
    pub frozen: Option<FrozenPayout>,
}
pub(super) fn reserve_payout_sequence() -> Result<PayoutRetryState, PoolError> {
    let mut c = control();
    if c.key.is_none() {
        return Err(PoolError::PayoutMemoKeyNotReady);
    }
    let seq = c.next;
    c.next = c.next.checked_add(1).ok_or(PoolError::PayoutStateInvalid)?;
    let boot = c.boot;
    write_control(c);
    Ok(PayoutRetryState {
        memo_sequence: Nat::from(seq),
        generation: 0,
        boot,
        phase: PayoutPhase::PreDispatch,
        prior_ambiguity: false,
        dispatched: false,
        frozen: None,
    })
}
fn memo(key: &[u8; 32], pool: Principal, ledger: Principal, id: u64, sequence: u128) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 32 bytes");
    mac.update(b"stsh.private-payout.memo.v1");
    for p in [pool, ledger] {
        mac.update(&[p.as_slice().len() as u8]);
        mac.update(p.as_slice());
    }
    mac.update(&id.to_le_bytes());
    mac.update(&sequence.to_le_bytes());
    mac.finalize().into_bytes().to_vec()
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Attempt {
    id: u64,
    sequence: u128,
    generation: u64,
    boot: u64,
}
pub(super) struct PayoutGuard(Attempt);
impl Drop for PayoutGuard {
    fn drop(&mut self) {
        // Full async-future lifetime; no stable decoding and no trapping borrow.
        LIVE.with(|l| {
            if let Ok(mut m) = l.try_borrow_mut() {
                if m.get(&self.0.id) == Some(&self.0) {
                    m.remove(&self.0.id);
                }
            }
        });
    }
}
fn attempt(id: u64, r: &PayoutRetryState) -> Result<Attempt, PoolError> {
    Ok(Attempt {
        id,
        sequence: r
            .memo_sequence
            .0
            .to_u128()
            .ok_or(PoolError::PayoutStateInvalid)?,
        generation: r.generation,
        boot: r.boot,
    })
}

fn owned(g: &PayoutGuard) -> Result<PendingSpend, PoolError> {
    let rec = payout_record(g.0.id).ok_or(PoolError::SpendNotFound)?;
    let r = rec
        .public_payout
        .as_ref()
        .and_then(|p| p.retry.as_ref())
        .ok_or(PoolError::PayoutLegacyHold)?;
    if rec.status != SpendStatus::PayoutSubmitting
        || attempt(g.0.id, r)? != g.0
        || !LIVE.with(|m| m.borrow().get(&g.0.id) == Some(&g.0))
    {
        return Err(PoolError::PayoutStateInvalid);
    }
    Ok(rec)
}
fn validate_retry(p: &PendingPublicPayout) -> Result<(), PoolError> {
    let Some(r) = &p.retry else {
        return Ok(());
    };
    let c = control();
    if r.boot == 0
        || r.boot > c.boot
        || r.memo_sequence
            .0
            .to_u128()
            .ok_or(PoolError::PayoutStateInvalid)?
            >= c.next
        || (r.dispatched && r.frozen.is_none())
        || (r.phase == PayoutPhase::MayHaveDispatched && (!r.dispatched || r.generation == 0))
    {
        return Err(PoolError::PayoutStateInvalid);
    }
    if let Some(f) = &r.frozen {
        let amount = f.amount.0.to_u128().ok_or(PoolError::PayoutStateInvalid)?;
        let fee = f
            .fee
            .as_ref()
            .and_then(|n| n.0.to_u128())
            .ok_or(PoolError::PayoutStateInvalid)?;
        if amount == 0
            || amount.checked_add(fee) != Some(p.public_amount)
            || f.destination != p.destination
            || f.destination_subaccount != p.destination_subaccount
            || f.memo.as_ref().map(Vec::len) != Some(32)
            || f.created_at_time.is_none()
            || f.created_at_time != p.ledger_created_at_time_ns
            || r.generation == 0
        {
            return Err(PoolError::PayoutStateInvalid);
        }
    }
    Ok(())
}
// Exactly one keyed read per normalization, with no history/active-index scans.
pub(super) fn normalize_payout(id: u64) -> Result<PendingSpend, PoolError> {
    let mut rec = payout_record(id).ok_or(PoolError::SpendNotFound)?;
    if let Some(p) = &rec.public_payout {
        validate_retry(p)?;
    }
    if rec.status != SpendStatus::PayoutSubmitting {
        return Ok(rec);
    }
    // Even malformed/legacy-looking data cannot force-clear a live executor.
    if LIVE.with(|m| m.borrow().contains_key(&id)) {
        return Ok(rec);
    }
    let Some(r) = rec.public_payout.as_ref().and_then(|p| p.retry.as_ref()) else {
        // Predecessor futures are gone only after the actual upgrade. Legacy data
        // does not authorize replay; reconciliation Executed is operator assertion.
        rec.status = SpendStatus::PayoutUnknown {
            reason: "legacy payout identity unavailable".into(),
        };
        PENDING_SPENDS.with(|m| m.borrow_mut().insert(id, rec.clone()));
        return Ok(rec);
    };
    let boot = control().boot;
    if r.boot > boot || r.generation == 0 {
        return Err(PoolError::PayoutStateInvalid);
    }
    let ambiguous = r.phase == PayoutPhase::MayHaveDispatched || r.prior_ambiguity;
    if ambiguous {
        // Retain prior dispatch uncertainty when a later claim resets its own
        // phase to PreDispatch; guard cleanup is not ledger settlement evidence.
        rec.public_payout
            .as_mut()
            .unwrap()
            .retry
            .as_mut()
            .unwrap()
            .prior_ambiguity = true;
    }
    rec.status = if ambiguous {
        SpendStatus::PayoutUnknown {
            reason: "quiescent payout requires reconciliation".into(),
        }
    } else {
        SpendStatus::PayoutPending {
            reason: "quiescent preflight may retry".into(),
        }
    };
    PENDING_SPENDS.with(|m| m.borrow_mut().insert(id, rec.clone()));
    Ok(rec)
}
pub(super) fn claim_payout(id: u64) -> Result<PayoutGuard, PoolError> {
    let mut rec = normalize_payout(id)?;
    if !matches!(rec.status, SpendStatus::PayoutPending { .. }) {
        return Err(PoolError::PayoutNotPending);
    }
    let r = rec
        .public_payout
        .as_mut()
        .and_then(|p| p.retry.as_mut())
        .ok_or(PoolError::PayoutLegacyHold)?;
    let g = LIVE.with(|m| {
        let mut m = m.borrow_mut();
        if m.len() >= MAX_LIVE_PAYOUT_ATTEMPTS {
            return Err(PoolError::PayoutExecutorBusy);
        }
        if m.contains_key(&id) {
            return Err(PoolError::PayoutNotPending);
        }
        r.generation = r
            .generation
            .checked_add(1)
            .ok_or(PoolError::PayoutStateInvalid)?;
        r.boot = control().boot;
        r.phase = PayoutPhase::PreDispatch;
        let a = attempt(id, r)?;
        m.insert(id, a);
        Ok(PayoutGuard(a))
    })?;
    rec.status = SpendStatus::PayoutSubmitting;
    PENDING_SPENDS.with(|m| m.borrow_mut().insert(id, rec));
    Ok(g)
}
fn finish_error(g: &PayoutGuard, error: PoolError, ambiguous: bool) -> Result<Nat, PoolError> {
    let mut rec = owned(g)?;
    let r = rec.public_payout.as_mut().unwrap().retry.as_mut().unwrap();
    r.prior_ambiguity |= ambiguous;
    rec.status = if r.prior_ambiguity {
        SpendStatus::PayoutUnknown {
            reason: format!("{:?}", error),
        }
    } else {
        SpendStatus::PayoutPending {
            reason: format!("{:?}", error),
        }
    };
    PENDING_SPENDS.with(|m| m.borrow_mut().insert(g.0.id, rec));
    Err(error)
}
pub(super) fn terminal_payout(id: u64, block: Option<Nat>) -> Result<(), PoolError> {
    let mut rec = payout_record(id).ok_or(PoolError::SpendNotFound)?;
    if rec.status == SpendStatus::Finalized {
        return Ok(());
    }
    if let Some(b) = block {
        rec.public_payout
            .as_mut()
            .ok_or(PoolError::WrongSpendStatus)?
            .block_index = Some(b);
    }
    let split = match (
        rec.fee_split_ops,
        rec.fee_split_insurance,
        rec.fee_split_staking,
    ) {
        (Some(o), Some(i), Some(s)) => Some((o, i, s)),
        _ => None,
    };
    // Same no-await message segment: traps roll back terminal state and accrual.
    PENDING_SPENDS.with(|m| m.borrow_mut().insert(id, rec));
    mark_spend_terminal(id, SpendStatus::Finalized, time())?;
    accrue_private_transfer_fee(split);
    Ok(())
}

async fn query_payout_balance(
    ledger: Principal,
    from_subaccount: Option<[u8; 32]>,
) -> Result<u128, PoolError> {
    let reply: Result<(Nat,), _> = call(
        ledger,
        "icrc1_balance_of",
        (IcrcAccount {
            owner: ic_cdk::id(),
            subaccount: from_subaccount,
        },),
    )
    .await;
    let value = reply
        .map_err(|(_, e)| PoolError::TransferFailed(format!("payout balance query: {}", e)))?
        .0;
    value
        .0
        .to_u128()
        .ok_or_else(|| PoolError::TransferFailed("payout balance exceeds u128".into()))
}
pub(super) async fn run_payout(
    g: PayoutGuard,
    configured_ledger: Principal,
) -> Result<Nat, PoolError> {
    #[cfg(feature = "testing")]
    wait_for_test(g.0.id, 4).await;
    let rec = owned(&g)?;
    let p = rec.public_payout.as_ref().unwrap();
    validate_retry(p)?;
    let r = p.retry.as_ref().unwrap();
    let ledger = r
        .frozen
        .as_ref()
        .map(|f| f.ledger)
        .unwrap_or(configured_ledger);
    if !r.dispatched {
        let balance =
            query_payout_balance(ledger, r.frozen.as_ref().and_then(|f| f.from_subaccount)).await;
        owned(&g)?;
        #[cfg(feature = "testing")]
        if fault(g.0.id) == 3 {
            ic_cdk::trap("R15 injected pre-dispatch callback trap");
        }
        match balance {
            Err(e) => return finish_error(&g, e, false),
            Ok(available) if available < p.public_amount => {
                return finish_error(
                    &g,
                    PoolError::EscrowUnderfunded {
                        required: p.public_amount,
                        available,
                    },
                    false,
                )
            }
            _ => {}
        }
    }
    if r.frozen.is_none() {
        let fee_result = query_ledger_fee(ledger).await;
        let mut latest = owned(&g)?;
        let fee = match fee_result {
            Ok(f) => f,
            Err(e) => return finish_error(&g, e, false),
        };
        let payout = latest.public_payout.as_mut().unwrap();
        if payout.public_amount <= fee {
            return finish_error(
                &g,
                PoolError::GrossAmountBelowFees {
                    withdraw_gross_amount: payout.public_amount,
                    total_fee: fee,
                },
                false,
            );
        }
        let retry = payout.retry.as_mut().unwrap();
        let Some(key) = control().key else {
            return finish_error(&g, PoolError::PayoutMemoKeyNotReady, false);
        };
        let stamp = time();
        retry.frozen = Some(FrozenPayout {
            ledger,
            from_subaccount: None,
            destination: payout.destination,
            destination_subaccount: payout.destination_subaccount,
            amount: Nat::from(payout.public_amount - fee),
            fee: Some(Nat::from(fee)),
            memo: Some(memo(
                &key,
                ic_cdk::id(),
                ledger,
                g.0.id,
                retry
                    .memo_sequence
                    .0
                    .to_u128()
                    .ok_or(PoolError::PayoutStateInvalid)?,
            )),
            created_at_time: Some(stamp),
        });
        payout.ledger_created_at_time_ns = Some(stamp);
        PENDING_SPENDS.with(|m| m.borrow_mut().insert(g.0.id, latest));
    }
    // Legacy lease-only seam: no transfer occurs, but the identity is frozen so
    // its controller recovery still exercises the same immutable replay path.
    #[cfg(feature = "testing")]
    if FORCE_PAYOUT_TRANSPORT_UNKNOWN.with(|f| *f.borrow()) {
        return finish_error(&g, PoolError::PayoutOutcomeUnknown, true);
    }
    let mut latest = owned(&g)?;
    let retry = latest
        .public_payout
        .as_mut()
        .unwrap()
        .retry
        .as_mut()
        .unwrap();
    let frozen = retry.frozen.clone().ok_or(PoolError::PayoutStateInvalid)?;
    retry.phase = PayoutPhase::MayHaveDispatched;
    retry.dispatched = true;
    PENDING_SPENDS.with(|m| m.borrow_mut().insert(g.0.id, latest));
    // No await between authoritative ownership check, dispatch boundary and call.
    let reply: Result<(Result<Nat, IcrcTransferError>,), _> =
        call(frozen.ledger, "icrc1_transfer", (frozen.args(),)).await;
    #[cfg(feature = "testing")]
    wait_for_test(g.0.id, 5).await;
    owned(&g)?;
    #[cfg(feature = "testing")]
    match fault(g.0.id) {
        1 => return finish_error(&g, PoolError::PayoutOutcomeUnknown, true),
        2 => ic_cdk::trap("R15 injected post-dispatch callback trap"),
        _ => {}
    }
    match reply {
        Ok((Ok(b),)) | Ok((Err(IcrcTransferError::Duplicate { duplicate_of: b }),)) => {
            terminal_payout(g.0.id, Some(b.clone()))?;
            Ok(b)
        }
        Ok((Err(e),)) => {
            let ambiguous = matches!(
                e,
                IcrcTransferError::BadFee { .. }
                    | IcrcTransferError::TooOld
                    | IcrcTransferError::CreatedInFuture { .. }
            );
            finish_error(
                &g,
                PoolError::TransferFailed(format!("frozen payout rejected: {:?}", e)),
                ambiguous,
            )
        }
        Err((_, e)) => finish_error(
            &g,
            PoolError::TransferFailed(format!("payout transport unknown: {}", e)),
            true,
        ),
    }
}

#[cfg(feature = "testing")]
thread_local! { static FAULTS: RefCell<BTreeMap<u64,u8>> = RefCell::new(BTreeMap::new()); }
#[cfg(feature = "testing")]
fn fault(id: u64) -> u8 {
    FAULTS.with(|f| f.borrow().get(&id).copied().unwrap_or(0))
}
#[cfg(feature = "testing")]
#[update]
fn r15_fault_for_test(id: u64, mode: u8) {
    assert_operator_controller();
    FAULTS.with(|f| f.borrow_mut().insert(id, mode));
}
#[cfg(feature = "testing")]
#[query]
fn r15_live_for_test() -> u64 {
    assert_operator_controller();
    LIVE.with(|l| l.borrow().len() as u64)
}
#[cfg(feature = "testing")]
#[update]
fn r15_fixture_split_for_test(id: u64, ops: u128, ins: u128, staking: u128) {
    assert_operator_controller();
    PENDING_SPENDS.with(|m| {
        let mut m = m.borrow_mut();
        let mut r = m.get(&id).unwrap();
        r.fee_split_ops = Some(ops);
        r.fee_split_insurance = Some(ins);
        r.fee_split_staking = Some(staking);
        m.insert(id, r);
    });
}
#[cfg(feature = "testing")]
#[query]
fn r15_accrual_for_test() -> [u128; 3] {
    assert_operator_controller();
    read_fee_accrual()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hmac_canonical_vector_and_sequence_domain_separation() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let a = memo(
            &key,
            Principal::from_slice(&[1]),
            Principal::from_slice(&[2]),
            42,
            7,
        );
        let hex: String = a.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "9652237f8dc8bc5f262d885cf7c0bb235972d87f59301cf686e74628398b274f"
        );
        assert_ne!(
            a,
            memo(
                &key,
                Principal::from_slice(&[1]),
                Principal::from_slice(&[2]),
                42,
                8
            )
        );
        assert_ne!(
            a,
            memo(
                &key,
                Principal::from_slice(&[2]),
                Principal::from_slice(&[1]),
                42,
                7
            )
        );
        assert_eq!(a.len(), 32);
    }
    #[test]
    fn control_fixed_encoding_preserves_key_and_full_counters() {
        let c = Control {
            boot: u64::MAX,
            next: u128::MAX,
            key: Some([37; 32]),
        };
        let d = Control::decode(&c.encode());
        assert_eq!(d.boot, c.boot);
        assert_eq!(d.next, c.next);
        assert_eq!(d.key, c.key);
        assert_eq!(c.encode().len(), 65);
    }
    #[test]
    fn frozen_request_candid_roundtrip_preserves_option_tags() {
        let f = FrozenPayout {
            ledger: Principal::from_slice(&[1]),
            from_subaccount: Some([0; 32]),
            destination: Principal::from_slice(&[2]),
            destination_subaccount: None,
            amount: Nat::from(17u8),
            fee: Some(Nat::from(0u8)),
            memo: Some(vec![7; 32]),
            created_at_time: Some(0),
        };
        let bytes = candid::encode_one(&f.args()).unwrap();
        let g: FrozenPayout = candid::decode_one(&candid::encode_one(&f).unwrap()).unwrap();
        assert_eq!(bytes, candid::encode_one(&g.args()).unwrap());
        let mut changed = g.clone();
        changed.fee = None;
        assert_ne!(bytes, candid::encode_one(&changed.args()).unwrap());
        changed = g.clone();
        changed.from_subaccount = None;
        assert_ne!(bytes, candid::encode_one(&changed.args()).unwrap());
        changed = g;
        changed.destination_subaccount = Some([0; 32]);
        assert_ne!(bytes, candid::encode_one(&changed.args()).unwrap());
    }
}

#[cfg(feature = "testing")]
async fn wait_for_test(id: u64, mode: u8) {
    if fault(id) == mode {
        // PocketIC holds this actual management-call future until the harness
        // supplies the HTTP response. No polling loop, timers or fake guard.
        use ic_cdk::api::management_canister::http_request::{
            http_request, CanisterHttpRequestArgument,
        };
        let arg = CanisterHttpRequestArgument {
            url: format!("https://r15.invalid/{}", id),
            max_response_bytes: Some(1),
            ..Default::default()
        };
        http_request(arg, 50_000_000_000)
            .await
            .expect("R15 held callback fixture");
    }
}
#[cfg(feature = "testing")]
#[query]
fn r15_record_reads_for_test() -> u64 {
    assert_operator_controller();
    RECORD_READS.with(|r| *r.borrow())
}
#[cfg(feature = "testing")]
#[update]
fn r15_corrupt_frozen_for_test(id: u64, mode: u8) {
    assert_operator_controller();
    let mut rec = payout_record(id).unwrap();
    if mode == 6 {
        rec.public_payout
            .as_mut()
            .unwrap()
            .retry
            .as_mut()
            .unwrap()
            .memo_sequence = Nat::from(u128::MAX) + Nat::from(1u8);
        rec.status = SpendStatus::PayoutPending {
            reason: "malformed ordinal fixture".into(),
        };
        PENDING_SPENDS.with(|m| m.borrow_mut().insert(id, rec));
        return;
    }
    let f = rec
        .public_payout
        .as_mut()
        .unwrap()
        .retry
        .as_mut()
        .unwrap()
        .frozen
        .as_mut()
        .unwrap();
    match mode {
        0 => f.amount = Nat::from(u128::MAX) + Nat::from(1u8),
        1 => f.memo = Some(vec![1; 31]),
        2 => f.created_at_time = None,
        3 => f.destination = Principal::anonymous(),
        4 => f.fee = None,
        _ => f.amount = Nat::from(1u8),
    }
    rec.status = SpendStatus::PayoutPending {
        reason: "malformed fixture".into(),
    };
    PENDING_SPENDS.with(|m| m.borrow_mut().insert(id, rec));
}
#[cfg(feature = "testing")]
#[update]
fn r15_control_fault_for_test(mode: u8) {
    assert_operator_controller();
    match mode {
        0 => CONTROL.with(|c| {
            c.borrow_mut().set(Vec::new()).unwrap();
        }),
        1 => {
            let mut c = control();
            c.next = u128::MAX;
            write_control(c);
        }
        2 => {
            let mut c = control();
            c.key = Some([91; 32]);
            write_control(c);
        }
        4 => {
            let mut c = control();
            c.key = None;
            write_control(c);
        }
        _ => CONTROL.with(|c| {
            c.borrow_mut().set(vec![7; 65]).unwrap();
        }),
    }
}
#[cfg(feature = "testing")]
#[update]
fn r15_release_all_for_test() {
    assert_operator_controller();
    FAULTS.with(|f| f.borrow_mut().clear());
}

#[cfg(feature = "testing")]
thread_local! { static PROVISION_FAULT: RefCell<u8> = RefCell::new(0); static PROVISION_CALLS: RefCell<u64> = RefCell::new(0); }
#[cfg(feature = "testing")]
#[update]
fn r15_provision_fault_for_test(mode: u8) {
    assert_operator_controller();
    PROVISION_FAULT.with(|f| *f.borrow_mut() = mode);
}
#[cfg(feature = "testing")]
#[query]
fn r15_control_public_for_test() -> (u64, u128, bool) {
    assert_operator_controller();
    let c = control();
    (c.boot, c.next, c.key.is_some())
}
#[cfg(feature = "testing")]
#[update]
fn r15_seed_history_for_test(template: u64, start: u64, count: u32) {
    assert_operator_controller();
    assert!(count <= 5000);
    let prototype = payout_record(template).unwrap();
    PENDING_SPENDS.with(|m| {
        let mut m = m.borrow_mut();
        for offset in 0..count {
            let id = start + u64::from(offset);
            assert!(!m.contains_key(&id));
            let mut r = prototype.clone();
            r.spend_id = id;
            r.public_payout = None;
            r.status = SpendStatus::Finalized;
            r.finalized_at_ns = Some(time());
            m.insert(id, r);
        }
    });
}
#[cfg(test)]
mod guard_tests {
    use super::*;
    #[test]
    fn stale_or_repeated_guard_drop_never_releases_a_new_incarnation() {
        let old = Attempt {
            id: 7,
            sequence: 1,
            generation: 1,
            boot: 1,
        };
        let new = Attempt {
            id: 7,
            sequence: 2,
            generation: 1,
            boot: 1,
        };
        LIVE.with(|m| m.borrow_mut().insert(7, new));
        drop(PayoutGuard(old));
        assert_eq!(LIVE.with(|m| m.borrow().get(&7).copied()), Some(new));
        drop(PayoutGuard(new));
        drop(PayoutGuard(new));
        assert_eq!(LIVE.with(|m| m.borrow().len()), 0);
    }
}

#[cfg(feature = "testing")]
#[update]
fn r15_no_payout_for_test(id: u64) {
    assert_operator_controller();
    let mut rec = payout_record(id).unwrap();
    rec.public_payout = None;
    PENDING_SPENDS.with(|m| m.borrow_mut().insert(id, rec));
}
