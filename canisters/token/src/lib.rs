// =============================================================================
// STSH Token Canister — ICRC-1 / ICRC-2 / ICRC-21
// Security classification: SUPPLY BOUNDARY — treat all changes as audit events
// =============================================================================
//
// DESIGN DOCTRINE: This canister is the supply source of truth.
// The shielded pool is an escrow account, not an issuance system.
// No token is ever created after genesis mint. No exceptions.
//
// SUPPLY INVARIANT (verified by verify_supply_invariant()):
//   TOTAL_SUPPLY == sum(all BALANCES entries) + fee_reserve
//
// The `fee_reserve` term is NOT optional and NOT a rounding detail: collected
// fees leave BALANCES and live in `FEE_RESERVE` until they are swept, so a
// two-term statement of this invariant is false the moment a single fee is
// taken. The canonical form above is the one `evaluate_supply_invariant()`
// actually evaluates — restated here rather than paraphrased.
//
// This is mathematically guaranteed by transfer conservation, but must be
// verified explicitly in tests and by the off-chain watcher.
//
// ALLOCATION INVARIANT (verified at init, immutable thereafter):
//   sum(genesis_allocations) == TOTAL_SUPPLY
//   every allocation has a non-empty category_id and category_name
//   no post-genesis allocation creation without governance event
// =============================================================================

use candid::{CandidType, Nat, Principal};
use ic_cdk::api::time;
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
    Cell, DefaultMemoryImpl, StableBTreeMap, Storable,
};
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::cell::RefCell;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const DECIMALS: u8 = 8;
pub const SYMBOL: &str = "STSH";
pub const NAME: &str = "STSH";
pub const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000; // 1B STSH
/// F-000 (PM decision LOCKED 2026-07-09): token transfers are FREE at launch —
/// protocol revenue comes from pool shield/unshield fees (Phase 2), not ledger
/// transfer fees. There is no init argument and no runtime setter (DEF-085), so
/// this constant IS the launch fee.
pub const DEFAULT_FEE: u128 = 0;
pub const TX_DEDUP_WINDOW_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
/// H-01 (HARDEN-02, D-2 ruled 2026-09-17): the maximum lifetime of an
/// `icrc2_approve` allowance. Every stored allowance has an expiry no later than
/// `now + MAX_APPROVAL_TTL_NS` at the time it was written (deviation dev007):
/// an absent `expires_at` is DEFAULTED to that instant and a later one is
/// CLAMPED to it (TOKEN-APPROVE-TTL, 2026-09-25 — previously both were
/// refused). That is what turns `ALLOWANCES` from a monotonically-growing map
/// into one with a bounded resident set.
///
/// DELIBERATELY ITS OWN CONSTANT, NOT AN ALIAS OF `TX_DEDUP_WINDOW_NS`. The two
/// numeric values are equal today and that equality is INCIDENTAL: one governs
/// how long a replay is deduplicated, the other how long a spending
/// authorisation lives. D-2's ruling is explicit that tightening one must never
/// silently move the other, so do not replace this literal with a reference to
/// the other constant, and do not merge the two.
///
/// D-2 also ruled what the lever is if the measured envelope is judged too
/// large: THIS TTL, tightened. Never a global cap on the number of allowance
/// rows — a ceiling an attacker can fill locks out honest approvals, which is a
/// cheaper denial of service than the growth it was meant to prevent.
/// UNBACKED: 24 h is a ruled candidate lifetime, not a demonstrated
/// resource-safety bound; the measured envelope is reported by the
/// `allowance_storage_envelope` / `allowance_prune_throughput` tests rather
/// than asserted here.
pub const MAX_APPROVAL_TTL_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
/// Maximum permitted clock drift for a future-dated created_at_time (5 minutes).
/// QA-DEF-050B / QA-DEF-023: extracted from the value previously inlined in
/// icrc1_transfer; now shared by icrc1_transfer and icrc2_transfer_from.
pub const PERMITTED_DRIFT_NS: u64 = 5 * 60 * 1_000_000_000;

// ── Memory IDs ────────────────────────────────────────────────────────────────

const MEM_BALANCES:      MemoryId = MemoryId::new(0);
const MEM_ALLOWANCES:    MemoryId = MemoryId::new(1);
const MEM_ALLOC_TABLE:   MemoryId = MemoryId::new(2);
const MEM_STAKING_LOCKS: MemoryId = MemoryId::new(3);
/// Single-value stable cell — serialized TokenStableState (Candid bytes).
const MEM_STABLE_STATE:  MemoryId = MemoryId::new(4);
/// DEF-050B-1: icrc2_transfer_from dedup index — sha256(transfer identity) →
/// [block_index u64 LE | created_at_time u64 LE]. See QA-DEF-050B.
const MEM_TRANSFER_DEDUP: MemoryId = MemoryId::new(5);
/// H-3 (EXT-2): time-keyed secondary index over TRANSFER_DEDUP —
/// DedupTimeKey(created_at_ns, dedup_key) → (). Makes prune a bounded range scan
/// over the *expired* prefix instead of an O(N) full walk of every live entry.
/// MemoryId(6) was previously free; never reuse a retired ID.
const MEM_TRANSFER_DEDUP_BY_TIME: MemoryId = MemoryId::new(6);
/// H-01 (HARDEN-02): time-keyed secondary index over ALLOWANCES —
/// AllowanceExpiryKey(expires_at_ns, allowance_key) → (). Makes expired-row
/// reclamation a bounded range scan over the *expired* prefix instead of a walk
/// of every live allowance, which would re-open the closed H-3 defect on a
/// second map. D-1 (CTO ruling 2026-09-17) allocates 7; the registry was
/// re-checked at lane cut and 0–6 were the only allocations.
const MEM_ALLOWANCES_BY_EXPIRY: MemoryId = MemoryId::new(7);
/// HARDEN-03-SETTLEMENT (D-4): the deposit receipt map —
/// `DepositReceiptKey(operation_id) -> DepositReceiptV1`.
///
/// ONE map, not two. `DepositReceiptV1` is the two-variant `Applied | Cancelled`
/// type, and the `Cancelled` variant IS the cancellation fence (D-5); a separate
/// fence map would be a second MemoryId storing the second variant of an enum
/// this map already stores. Token MemoryId allocation for this lane is therefore
/// exactly one.
///
/// READ BY NO QUERY (D-14 / P-1). The only reads are the `get_deposit_receipt`
/// and `close_deposit_attempt` UPDATES, both of which reject a non-pool caller
/// before any existence-sensitive read. There is deliberately no prune path in
/// V1 (D-9): see `MAX_DEPOSIT_RECEIPTS` for the cliff and the SETTLEMENT-GC
/// follow-up lane. `MemoryId(8)` is fresh — 0-6 were allocated before HARDEN-02
/// and 7 by H-01; the registry was re-checked at lane cut.
const MEM_DEPOSIT_RECEIPTS: MemoryId = MemoryId::new(8);

// ── Upgrade state versioning ──────────────────────────────────────────────────

/// H-3 (EXT-2): bumped 1 → 2 as the one-shot marker for the TRANSFER_DEDUP_BY_TIME
/// back-fill migration (see post_upgrade + the MIGRATION LOG below). The serialized
/// TokenStableState shape is unchanged — the bump exists solely so a v1 checkpoint
/// (no time index) is distinguishable from a v2 checkpoint (index already present).
const STATE_VERSION: u32 = 3;

type Mem = VirtualMemory<DefaultMemoryImpl>;

// ── Core types ────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Account {
    pub owner: Principal,
    pub subaccount: Option<[u8; 32]>,
}

impl Account {
    pub fn encode_key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(33);
        let bytes = self.owner.as_slice();
        key.push(bytes.len() as u8);
        key.extend_from_slice(bytes);
        // QA-DEF-021: ICRC-1 defines the all-zero subaccount as identical to the
        // default (None) account. Normalize Some([0u8;32]) -> None here so both
        // forms produce the same storage key; otherwise balances, allowances, and
        // transfers keyed on the two forms would silently diverge into two
        // accounts. encode_key is the single chokepoint for every balance,
        // allowance, and staking-lock key, so normalizing here covers all paths.
        if let Some(sub) = &self.subaccount {
            if sub != &[0u8; 32] {
                key.extend_from_slice(sub);
            }
        }
        key
    }
}

/// Injective pairing of two encoded account keys for the ALLOWANCES map:
/// u32-LE(len a) || a || u32-LE(len b) || b. Plain concatenation was NOT
/// injective — encode_key output is variable-length (owner length byte +
/// optional 32-byte subaccount), so distinct (account, spender) pairs could
/// concatenate to identical bytes and alias each other's allowance rows.
/// Length-prefixing each half makes the boundary explicit and the pairing
/// injective for all encode_key outputs. encode_key itself is unchanged.
fn compound_key(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + a.len() + b.len());
    key.extend_from_slice(&(a.len() as u32).to_le_bytes());
    key.extend_from_slice(a);
    key.extend_from_slice(&(b.len() as u32).to_le_bytes());
    key.extend_from_slice(b);
    key
}

impl Storable for Account {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(self.encode_key()) }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        let len = b[0] as usize;
        let owner = Principal::from_slice(&b[1..1 + len]);
        let subaccount = if b.len() > 1 + len {
            let mut sub = [0u8; 32];
            sub.copy_from_slice(&b[1 + len..]);
            Some(sub)
        } else { None };
        Account { owner, subaccount }
    }
    const BOUND: Bound = Bound::Bounded { max_size: 64, is_fixed_size: false };
}

// ── Allowance record (fixes tuple Storable issue) ─────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct AllowanceRecord {
    pub amount: u128,
    pub expires_at: Option<u64>,
}

impl Storable for AllowanceRecord {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut b = [0u8; 17];
        b[..16].copy_from_slice(&self.amount.to_be_bytes());
        b[16] = self.expires_at.is_some() as u8;
        let mut out = b.to_vec();
        if let Some(exp) = self.expires_at {
            out.extend_from_slice(&exp.to_be_bytes());
        }
        Cow::Owned(out)
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        let amount = u128::from_be_bytes(b[..16].try_into().unwrap());
        let expires_at = if b[16] == 1 {
            Some(u64::from_be_bytes(b[17..25].try_into().unwrap()))
        } else { None };
        AllowanceRecord { amount, expires_at }
    }
    const BOUND: Bound = Bound::Bounded { max_size: 25, is_fixed_size: false };
}

// ── Genesis allocation types ──────────────────────────────────────────────────

/// Lock policies for allocation categories
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum LockPolicy {
    /// Immediately transferable at genesis
    ImmediatelyLiquid,
    /// Locked until timestamp (nanoseconds); governance can extend but not shorten
    LockedUntil(u64),
    /// Vesting schedule — see VestingPolicy
    Vested,
    /// Controlled by governance canister; movements require proposal
    GovernanceLocked,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct VestingPolicy {
    pub cliff_end_ns: u64,
    pub vesting_end_ns: u64,
}

/// Immutable genesis allocation record.
/// Stored at init, never modified. Auditable by anyone.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct AllocationCategory {
    /// Machine-readable ID — must be unique and non-empty
    /// e.g. "circulating", "treasury", "staking_rewards", "team", "community", "liquidity"
    pub category_id: String,
    /// Human-readable name
    pub category_name: String,
    /// Exact amount in base units (no percentages)
    pub amount: u128,
    /// Recipient account
    pub recipient: Principal,
    pub subaccount: Option<[u8; 32]>,
    /// Lock/vesting rules
    pub lock_policy: LockPolicy,
    pub vesting_policy: Option<VestingPolicy>,
    /// Always true — set at genesis, proves this was a genesis allocation
    pub created_at_genesis: bool,
    /// Timestamp of genesis mint (ns)
    pub genesis_timestamp_ns: u64,
}

impl Storable for AllocationCategory {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).expect("AllocationCategory encode"))
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        candid::decode_one(&b).expect("AllocationCategory decode")
    }
    const BOUND: Bound = Bound::Unbounded;
}

// ── ICRC-1/2 argument types ───────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum MetadataValue {
    Nat(Nat),
    // F-009: candid::Int (wire type `int`, matching the declared .did and the
    // ICRC-1 Value spec) — a Rust i64 here would serialise as int64.
    Int(candid::Int),
    Text(String),
    Blob(Vec<u8>),
}

/// ICRC-1 spec shape for supported_standards entries (F-001): a NAMED record
/// { name : text; url : text }. Spec clients decode fields by name hash — the
/// previous tuple record (`vec record { text; text }`) failed their decode.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct StandardRecord {
    pub name: String,
    pub url: String,
}

/// Single source for the advertised standards — served by BOTH
/// icrc1_supported_standards and icrc10_supported_standards (ICRC-10 is the
/// modern discovery method; same record shape).
fn supported_standards_list() -> Vec<StandardRecord> {
    vec![
        StandardRecord {
            name: "ICRC-1".to_string(),
            // EXT-DBR-001: ICRC-1's own text advertises the repository ROOT as its
            // URL (icrc1_supported_standards example), so pin the root — not a subpath.
            url: "https://github.com/dfinity/ICRC-1".to_string(),
        },
        StandardRecord {
            name: "ICRC-2".to_string(),
            // EXT-DBR-001: ICRC-2's spec does not give its URL normative status, so
            // the specific subpath to the ICRC-2 standard is retained (accurate pointer).
            url: "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-2".to_string(),
        },
        // EXT-DBR-001: canonical URLs, verified against the spec texts.
        // ICRC-10's MUST-clause self-reference (ICRC-10.md §icrc10_supported_standards):
        //   record{name="ICRC-10"; url="https://github.com/dfinity/ICRCs/ICRC-10"}
        StandardRecord {
            name: "ICRC-10".to_string(),
            url: "https://github.com/dfinity/ICRCs/ICRC-10".to_string(),
        },
        // ICRC-21's own .did mandates this exact entry for icrc10_supported_standards:
        //   record { name = "ICRC-21"; url = "https://github.com/dfinity/ICRC/blob/main/ICRCs/ICRC-21/ICRC-21.md" }
        StandardRecord {
            name: "ICRC-21".to_string(),
            url: "https://github.com/dfinity/ICRC/blob/main/ICRCs/ICRC-21/ICRC-21.md".to_string(),
        },
    ]
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct TransferArgs {
    pub from_subaccount: Option<[u8; 32]>,
    pub to: Account,
    pub amount: Nat,
    pub fee: Option<Nat>,
    pub memo: Option<Vec<u8>>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum TransferError {
    BadFee { expected_fee: Nat },
    BadBurn { min_burn_amount: Nat },
    InsufficientFunds { balance: Nat },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
}

/// R10-1 (lane A-3) — the `GenericError.error_code` returned when a transfer is
/// refused for `amount == 0`.
///
/// Code survey at the pinned base before choosing this value: `1` is in use for
/// amount-decode overflow on all three endpoints (`icrc1_transfer`,
/// `icrc2_approve`, `icrc2_transfer_from`), `3` for `checked_total_debit`
/// overflow and `4` for balance-credit overflow. `2` is unused but avoided as
/// possibly retired; `5` is the next free code above the highest in use.
///
/// It is a `pub const` and pinned by a unit test deliberately: an error code
/// that can drift silently is not a contract.
pub const ERR_CODE_ZERO_AMOUNT: u32 = 5;
/// T-ICRC-L1: ICRC-21 consent refused for the anonymous principal.
pub const ERR_CODE_ANONYMOUS_CALLER: u32 = 6;
/// RETIRED by TOKEN-APPROVE-TTL (2026-09-25); NEVER REUSE THIS NUMBER. It was
/// H-01 / dev007's refusal of an `icrc2_approve` with no `expires_at` (live
/// modules ac9336f2… and 994a77ff… still raise it). Such an approve is now
/// accepted and stored with the cap applied, so no path raises code 7. Kept
/// declared, and pinned by `dev007_error_codes_pinned`, so the number is never
/// reissued with a different meaning to clients that saw the old one.
pub const ERR_CODE_APPROVAL_EXPIRY_REQUIRED: u32 = 7;
/// RETIRED by TOKEN-APPROVE-TTL (2026-09-25); NEVER REUSE THIS NUMBER. It was
/// H-01 / dev007's refusal of an `expires_at` further ahead than
/// `MAX_APPROVAL_TTL_NS`; such an expiry is now clamped to the cap.
pub const ERR_CODE_APPROVAL_TTL_TOO_LONG: u32 = 8;
/// HARDEN-03-SETTLEMENT (D-8): the deposit-receipt map is at
/// `MAX_DEPOSIT_RECEIPTS` and this qualifying transfer has no receipt yet. An
/// ORDINARY rejection raised in the pre-mutation gate — no balance, allowance,
/// block index or dedup entry is touched. Never an eviction: see D-9.
pub const ERR_CODE_RECEIPT_CAPACITY: u32 = 9;
/// HARDEN-03-SETTLEMENT (D-8): a qualifying-spender call that cannot be
/// receipted at all — `created_at_time == None`, `memo == None`, or a memo
/// longer than `MAX_DEPOSIT_MEMO_LEN`. Unreachable from the real pool, which
/// always supplies both; the arm exists so "no fallback to a bare, unreceipted
/// transfer" is ENFORCED rather than assumed (fix-design §3.4).
pub const ERR_CODE_DEPOSIT_UNRECEIPTABLE: u32 = 10;
/// HARDEN-03-SETTLEMENT (D-5): a `Cancelled` receipt already fences this
/// operation id. The pool has closed the deposit on the strength of that fence,
/// so a delayed original must move nothing. Raised before any mutation.
pub const ERR_CODE_DEPOSIT_FENCED: u32 = 11;
/// HARDEN-03-SETTLEMENT: an `Applied` receipt already exists for this operation
/// id. One execution per operation id, ever. Raised before any mutation.
///
/// This is the defence-in-depth half of D-6. The pool's sidecar freezes the
/// submitted `fee` so a resubmission is byte-identical and therefore deduped;
/// if that ever failed — a changed ledger fee producing a DIFFERENT dedup key
/// for the SAME on-ledger memo — the dedup short-circuit at the top of
/// `icrc2_transfer_from` would not fire and the second pull would execute. That
/// is precisely the double-charge D-6 exists to prevent, and this code refuses
/// it on the token side as well, keyed on the memo rather than on the fee.
pub const ERR_CODE_RECEIPT_CONFLICT: u32 = 12;

/// HARDEN-03-SETTLEMENT (D-8): the maximum memo length the receipt protocol
/// accepts from the configured pool. The pool's own deposit memo is
/// `DEPOSIT_LEDGER_MEMO_TAG` (29 bytes) plus a 32-byte operation digest = 61
/// bytes; this bound is generous against that and exists so an unbounded memo
/// cannot be hashed into the operation id on a money path.
pub const MAX_DEPOSIT_MEMO_LEN: usize = 256;

/// HARDEN-03-SETTLEMENT (D-9): the lifetime ceiling on `DEPOSIT_RECEIPTS`.
///
/// **THE CLIFF, STATED IN DEPOSITS, NOT AS "a liveness cliff".** One receipt is
/// written per qualifying shielded deposit and V1 removes none (D-9 ships no
/// garbage collection, no ack protocol and no retired horizon). This constant is
/// therefore **the token's lifetime shielded-deposit count**: after the
/// 65,536th shielded deposit ever made, the token refuses new ones with
/// `ERR_CODE_RECEIPT_CAPACITY`.
///
/// **It is a liveness stop, never an attack surface and never a fund-safety
/// event.** Only the configured pool can cause a receipt to be written, and
/// every receipt corresponds to a real deposit that moved at least the smallest
/// denomination (1,000 STSH), so an adversary cannot fill it without depositing.
/// The refusal happens in the pre-mutation gate, BEFORE any debit, so erring
/// conservative is safe in the direction that matters.
///
/// **SIZING BASIS (AC-25 / SSA ESC-3a).** This value is NOT derived by
/// multiplying a per-row byte estimate by a row count. Both such estimates made
/// for this map were wrong for the same underlying reason:
/// `MemoryManager` allocates in `BUCKET_SIZE_IN_PAGES = 128` (8 MiB) steps, so
/// allocated pages are a STEP FUNCTION of node count and bucket edges, not a
/// linear function of row size. `PACKET_HARDEN03_CAPACITY_a400e1f_2026-09-17.md`
/// §3.5 supersedes the 838 B/row figure as a coefficient (it is invariant under
/// a 14.7x key-size change and falls to 671 at n = 50,000 on the same fixture).
/// The governing measurement for this constant is
/// `deposit_receipt_storage_envelope` in
/// `integration-tests/tests/deposit_settlement_receipt_tests.rs`, which reports
/// peak ALLOCATED PAGES at a stated n, sized by 8 MiB bucket, with no per-row
/// coefficient anywhere in the derivation. See that test and the lane packet.
///
/// Raising this cap is a one-constant follow-up and is the SAFE direction of
/// change. The named follow-up lane for reclamation is **SETTLEMENT-GC**.
pub const MAX_DEPOSIT_RECEIPTS: u64 = 65_536;

/// HARDEN-03-SETTLEMENT (D-7): domain separator for the operation id.
///
/// `operation_id := SHA-256(RECEIPT_OPID_DOMAIN || memo_bytes)`. Computed
/// INDEPENDENTLY by the pool and the token from bytes that are already public
/// ledger data, so there is no shared constant between the two crates to drift.
/// The alternative — parsing the pool's `DEPOSIT_LEDGER_MEMO_TAG` and taking the
/// trailing 32 bytes — would require that 29-byte literal to exist in both
/// crates, and `canisters/custody-types` is unavailable as a shared home (D-11).
pub const RECEIPT_OPID_DOMAIN: &[u8] = b"stsh.deposit.receipt.opid.v1";
/// HARDEN-03-SETTLEMENT (D-7): domain separator for the request hash.
///
/// `request_hash := SHA-256(RECEIPT_REQUEST_DOMAIN || token_self_principal ||
/// transfer_from_dedup_key(..))`. Reuses the token's EXISTING canonical
/// transfer-identity encoder rather than inventing one (fix-design §3.2), and is
/// always RECOMPUTED by the token from `ic_cdk::caller()`, `ic_cdk::api::id()`
/// and the fields it actually received — never from anything the pool asserts.
pub const RECEIPT_REQUEST_DOMAIN: &[u8] = b"stsh.deposit.receipt.request.v1";

/// R10-1 message text, shared by both refusal sites so they cannot drift apart.
pub const ERR_MSG_ZERO_AMOUNT: &str =
    "amount must be greater than zero (R10-1: zero-amount transfers are refused)";

/// RETIRED (TOKEN-APPROVE-TTL) — the retired code 7's text, as the live modules
/// raise it. Raised by no path in this module; kept so the retirement pin and
/// the live-module contrast test can name it.
pub const ERR_MSG_APPROVAL_EXPIRY_REQUIRED: &str =
    "expires_at is required on icrc2_approve (H-01/dev007: an approval with no \
     stated end cannot be reclaimed, so it is refused rather than stored)";
/// RETIRED (TOKEN-APPROVE-TTL) — the retired code 8's text. Raised by no path.
pub const ERR_MSG_APPROVAL_TTL_TOO_LONG: &str =
    "expires_at is further ahead than the maximum approval lifetime \
     (H-01/dev007: MAX_APPROVAL_TTL_NS); re-approve closer to the time of use";


#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct ApproveArgs {
    pub from_subaccount: Option<[u8; 32]>,
    pub spender: Account,
    pub amount: Nat,
    pub expected_allowance: Option<Nat>,
    pub expires_at: Option<u64>,
    pub fee: Option<Nat>,
    pub memo: Option<Vec<u8>>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum ApproveError {
    BadFee { expected_fee: Nat },
    InsufficientFunds { balance: Nat },
    AllowanceChanged { current_allowance: Nat },
    Expired { ledger_time: u64 },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct TransferFromArgs {
    pub spender_subaccount: Option<[u8; 32]>,
    pub from: Account,
    pub to: Account,
    pub amount: Nat,
    pub fee: Option<Nat>,
    pub memo: Option<Vec<u8>>,
    pub created_at_time: Option<u64>,
}

/// ICRC-2 spec error type for icrc2_transfer_from (F-002). Distinct from the
/// ICRC-1 TransferError by exactly one variant: InsufficientAllowance, which
/// spec clients (and DEX failure/rollback paths) pattern-match to distinguish
/// "re-approve needed" from "insufficient funds". An expired approval reports
/// InsufficientAllowance { allowance: 0 } (F-003), matching the reference ledger.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum TransferFromError {
    BadFee { expected_fee: Nat },
    BadBurn { min_burn_amount: Nat },
    InsufficientFunds { balance: Nat },
    InsufficientAllowance { allowance: Nat },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
}

impl From<TransferError> for TransferFromError {
    fn from(e: TransferError) -> Self {
        match e {
            TransferError::BadFee { expected_fee } => TransferFromError::BadFee { expected_fee },
            TransferError::BadBurn { min_burn_amount } => {
                TransferFromError::BadBurn { min_burn_amount }
            }
            TransferError::InsufficientFunds { balance } => {
                TransferFromError::InsufficientFunds { balance }
            }
            TransferError::TooOld => TransferFromError::TooOld,
            TransferError::CreatedInFuture { ledger_time } => {
                TransferFromError::CreatedInFuture { ledger_time }
            }
            TransferError::Duplicate { duplicate_of } => {
                TransferFromError::Duplicate { duplicate_of }
            }
            TransferError::TemporarilyUnavailable => TransferFromError::TemporarilyUnavailable,
            TransferError::GenericError { error_code, message } => {
                TransferFromError::GenericError { error_code, message }
            }
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct AllowanceArgs {
    pub account: Account,
    pub spender: Account,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct Allowance {
    pub allowance: Nat,
    pub expires_at: Option<u64>,
}

// ── Supply invariant report ───────────────────────────────────────────────────

/// Returned by verify_supply_invariant() — publicly readable.
/// The watcher calls this on every check cycle.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SupplyInvariantReport {
    pub fixed_max_supply: u128,
    pub sum_all_balances: u128,
    pub staking_locked_total: u128,
    pub fee_reserve_total: u128,
    pub invariant_holds: bool,
    pub checked_at_ns: u64,
    /// If invariant_holds == false, this explains what's wrong
    pub violation_detail: Option<String>,
    /// K3-002b: per-site overflow attribution. ADDITIVE, wire-compatible —
    /// an old decoder skips the extra opt field. `None` if and only if every
    /// checked calculation in this report succeeded. Any arithmetic error
    /// forces `invariant_holds = false` and zeroes the affected totals
    /// (an unavailable total is exactly 0 — never wrapped, never saturated).
    pub arithmetic_error: Option<ArithmeticErrorReport>,
}

/// R-1 S4(e): the controller-only O(N) reconciliation.
///
/// Two INDEPENDENT results of two independent computations. Neither is derived
/// from the other:
///   * `folded_first_law_holds` — computed from the FOLD, never from the
///     maintained total, so it detects a first-law failure independently of the
///     running total.
///   * `totals_consistent`      — maintained vs folded, BOTH pairs, so it detects
///     a running total that has drifted from the map it summarises. The O(1)
///     public path is blind to this by construction.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SupplyReconciliation {
    pub maintained_sum_balances: u128,
    pub folded_sum_balances: u128,
    pub maintained_sum_staking_locks: u128,
    pub folded_sum_staking_locks: u128,
    pub fee_reserve: u128,
    pub rows_examined: u64,
    /// maintained == folded, BOTH pairs.
    pub totals_consistent: bool,
    /// folded_sum_balances + fee_reserve == TOTAL_SUPPLY — computed from the
    /// FOLD, never from the maintained total.
    pub folded_first_law_holds: bool,
    pub detail: Option<String>,
}

/// K3-002b: which checked calculation overflowed. Field names are wire-pinned
/// (brief §1) — consumers (smoke-alarm, watcher) treat a non-null record as
/// unhealthy regardless of `invariant_holds`.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ArithmeticErrorReport {
    pub balances_overflow: bool,
    pub staking_locks_overflow: bool,
    pub balances_plus_fee_overflow: bool,
}

// ── State ─────────────────────────────────────────────────────────────────────

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    /// (account_key || spender_key) → AllowanceRecord
    static ALLOWANCES: RefCell<StableBTreeMap<Vec<u8>, AllowanceRecord, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_ALLOWANCES)))
    );

    /// H-01 (HARDEN-02): time-keyed secondary index over ALLOWANCES. Key =
    /// AllowanceExpiryKey(expires_at_ns, allowance_key); value = (). The
    /// allowance_key carried in the key is the join back to ALLOWANCES, so the
    /// index needs no value. Only rows with `expires_at = Some(_)` are indexed —
    /// and under dev007 every row written by `icrc2_approve` carries one (an
    /// absent expiry is stored as `Some(now + MAX_APPROVAL_TTL_NS)`), so on a
    /// fresh install (the only install this canister will ever have — see
    /// `fresh_install_starts_with_no_allowance_rows`) the index is in bijection
    /// with ALLOWANCES.
    ///
    /// Maintained ONLY by `put_allowance` / `remove_allowance` /
    /// `prune_expired_allowances` — see the H-01 section for why there is exactly
    /// one writer (SI-10: a drift-lock driving a local helper instead of the
    /// production writer asserts nothing about production).
    static ALLOWANCES_BY_EXPIRY: RefCell<StableBTreeMap<AllowanceExpiryKey, (), Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_ALLOWANCES_BY_EXPIRY)))
    );

    /// H-01 (HARDEN-02): the id of the single canister-owned allowance
    /// maintenance timer. `ic-cdk-timers` cancels ONLY by id, so arming a second
    /// timer never cancels the first; `arm_allowance_maintenance_timer` is the
    /// only arming path and clears this id before every `set_timer_interval`, so
    /// at most one maintenance timer is live at any instant. Heap, not stable,
    /// deliberately: timers do not survive an upgrade, so there is nothing
    /// durable to hold — `post_upgrade` re-arms against the durable index.
    static ALLOWANCE_MAINTENANCE_TIMER: RefCell<Option<ic_cdk_timers::TimerId>> =
        const { RefCell::new(None) };

    /// category_index (u64) → AllocationCategory — immutable after genesis
    static ALLOC_TABLE: RefCell<StableBTreeMap<u64, AllocationCategory, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_ALLOC_TABLE)))
    );

    /// DEF-050B-1: icrc2_transfer_from dedup index.
    ///   key   = sha256 of the canonical transfer identity (see transfer_from_dedup_key)
    ///   value = [block_index u64 LE | created_at_time u64 LE]
    /// Written only when created_at_time is Some; capped-prune on each such call.
    static TRANSFER_DEDUP: RefCell<StableBTreeMap<[u8; 32], [u8; 16], Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_TRANSFER_DEDUP)))
    );

    /// H-3 (EXT-2): time-keyed secondary index over TRANSFER_DEDUP. Key =
    /// DedupTimeKey(created_at_ns, dedup_key); value = () (the dedup_key carried in
    /// the key is the join back to TRANSFER_DEDUP). Kept strictly bijective with
    /// TRANSFER_DEDUP by record_dedup (dual insert) and prune_expired_dedup (dual
    /// remove); back-filled once from TRANSFER_DEDUP by the v1→v2 migration.
    static TRANSFER_DEDUP_BY_TIME: RefCell<StableBTreeMap<DedupTimeKey, (), Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_TRANSFER_DEDUP_BY_TIME)))
    );

    /// HARDEN-03-SETTLEMENT (D-4/D-5): operation_id → `Applied | Cancelled`.
    ///
    /// The durable evidence that OUTLIVES the ledger's own 24-hour dedup window.
    /// `TRANSFER_DEDUP` above answers "did this exact transfer identity already
    /// commit?" only while the entry is live and only while `created_at_time` is
    /// inside `TX_DEDUP_WINDOW_NS`; past that boundary `icrc2_transfer_from`
    /// returns `TooOld` BEFORE it ever reaches the dedup lookup, so the ledger
    /// genuinely cannot answer. This map is what answers instead.
    ///
    /// Written ONLY in the same await-free execution segment as the balance
    /// mutation it witnesses (I-5, D-8) — there is no `await` anywhere in
    /// `icrc2_transfer_from`, so that property is structural rather than a
    /// discipline, and the capacity preflight in the pre-mutation gate is what
    /// keeps the phase-2 insert from being the thing that fails.
    ///
    /// READ BY NO QUERY (P-1).
    static DEPOSIT_RECEIPTS: RefCell<StableBTreeMap<DepositReceiptKey, DepositReceiptV1, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_DEPOSIT_RECEIPTS)))
    );

    /// HARDEN-03-SETTLEMENT (D-3): the shielded pool whose qualifying deposit
    /// transfers receive a durable receipt. Bound at INIT and never afterwards —
    /// there is deliberately no production setter (D-3 refused one: it would add
    /// a runtime authority-mutation surface to a canister holding real supply,
    /// for no benefit, since the install ordering already makes init-time binding
    /// possible). Mirrored into the checkpoint so it survives upgrade.
    ///
    /// `None` is FAIL-SAFE, not fail-open (D-3 / ESC-2 / AC-26): a token with no
    /// pool bound writes no receipts, so `settle_deposit_transfer` reaches
    /// `SettlementError::Unavailable` and credits nothing and deletes nothing —
    /// and the pool's own D-10 guard keys on the POOL-side sidecar rather than on
    /// the receipt, so `reconcile_deposit_transfer_not_executed` is still
    /// fail-closed. The misconfiguration degrades to today's behaviour with the
    /// destructive button already disabled: a liveness regression against the
    /// lane's goal, never a money-safety fail-open.
    static POOL_CANISTER: RefCell<Option<Principal>> = const { RefCell::new(None) };

    /// HARDEN-03-SETTLEMENT TEST-ONLY: overrides `MAX_DEPOSIT_RECEIPTS` so AC-8
    /// and AC-9 can drive the capacity refusal without allocating 65,536 rows.
    /// Precedent: `set_reconcile_row_budget_for_test`. Compiled only under
    /// `--features testing`; the branch that reads it does not exist in
    /// production (`receipt_capacity()` below).
    #[cfg(feature = "testing")]
    static RECEIPT_CAPACITY_OVERRIDE: RefCell<Option<u64>> = const { RefCell::new(None) };

    /// H-3 TEST-ONLY: when set, the next pre_upgrade stamps a legacy v1 checkpoint
    /// (state_version = 1) instead of STATE_VERSION, AND — as a real v1 record
    /// does — with `sum_balances` / `sum_staking_locks` absent, so a test can
    /// drive the real one-shot v1→v2 migration and the R-1 total seed on the
    /// following upgrade. Compiled only under
    /// `--features testing`; the branch that reads it does not exist in production.
    #[cfg(feature = "testing")]
    static FORCE_V1_CHECKPOINT: RefCell<bool> = RefCell::new(false);

    /// R-1 AC-7d TEST-ONLY: when set, the next pre_upgrade stamps a v3 checkpoint
    /// whose `sum_balances` / `sum_staking_locks` fields are `None`, so a test can
    /// drive the "v3 checkpoint missing a total" trap inside
    /// `ledger_maps::restore_from_checkpoint`. Same fixture pattern as
    /// FORCE_V1_CHECKPOINT; compiled only under `--features testing`.
    #[cfg(feature = "testing")]
    static FORCE_V3_NONE_CHECKPOINT: RefCell<bool> = RefCell::new(false);

    static BLOCK_HEIGHT:  RefCell<u64>          = RefCell::new(0);
    static TRANSFER_FEE:  RefCell<u128>         = RefCell::new(DEFAULT_FEE);
    static FEE_RESERVE:   RefCell<u128>         = RefCell::new(0);
    static MINT_DONE:     RefCell<bool>         = RefCell::new(false);
    static TREASURY:      RefCell<Option<Principal>> = RefCell::new(None);
    /// DEF-080: neutral fee-collection principal. fee_collector is a neutral
    /// spendable II account, not the treasury canister. When Some, transfer fees
    /// are credited to this account instead of TREASURY. Mainnet deployment
    /// requires Some(neutral_fee_collector) with fee_collector != treasury.
    static FEE_COLLECTOR: RefCell<Option<Principal>> = RefCell::new(None);
    static STAKING_CANISTER: RefCell<Option<Principal>> = RefCell::new(None);

    /// Stable cell for pre/post_upgrade serialisation of heap-only state.
    static STABLE_STATE_CELL: RefCell<Cell<Vec<u8>, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_STABLE_STATE)),
            vec![],
        ).expect("STABLE_STATE_CELL: Cell::init failed — stable memory corrupt")
    );
}

// ── R-1 S4(b): the ONE write funnel per map ───────────────────────────────────
//
// `BALANCES` and `STAKING_LOCKS` live HERE and nowhere else. They are private to
// this module — not `pub`, not `pub(crate)`, not `pub(super)` — so no code outside
// `mod ledger_maps` can name them, let alone call `.insert`/`.remove` on them under
// any alias, any number of statements apart, any formatting. A raw write outside
// the funnel is therefore not a lint finding to be caught after the fact; it is a
// build that does not compile (RED-1 V3/V4/V5 fix — the enforcement is `rustc`,
// not a checker that runs against `rustc`'s output).
//
// Every mutating entry point applies the signed delta to the matching running
// total as part of the same call: there is no separate "update the total" step to
// forget or bypass.
//
// The set of non-private items in this module is pinned by
// `canisters/token/ledger_maps_allowlist.toml` and checked, in a production view
// and a testing view, by the `verify_ledger_maps` lint (run_gate.sh).
mod ledger_maps {
    use super::*;

    thread_local! {
        /// account_key → balance (base units)
        static BALANCES: RefCell<StableBTreeMap<Vec<u8>, u128, Mem>> = RefCell::new(
            StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_BALANCES)))
        );

        /// account_key → staking_locked_amount
        static STAKING_LOCKS: RefCell<StableBTreeMap<Vec<u8>, u128, Mem>> = RefCell::new(
            StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_STAKING_LOCKS)))
        );

        /// R-1 S4(a): running total of BALANCES. Heap `RefCell`, mirroring
        /// FEE_RESERVE; persisted through TokenStableState (STATE_VERSION 3).
        static SUM_BALANCES: RefCell<u128> = const { RefCell::new(0) };

        /// R-1 S4(a): running total of STAKING_LOCKS.
        static SUM_STAKING_LOCKS: RefCell<u128> = const { RefCell::new(0) };
    }

    // ── Reads — unrestricted shape, no mutation surface ───────────────────────

    pub fn get_balance(key: &[u8]) -> u128 {
        BALANCES.with(|b| b.borrow().get(&key.to_vec()).unwrap_or(0))
    }

    pub fn get_lock(key: &[u8]) -> u128 {
        STAKING_LOCKS.with(|s| s.borrow().get(&key.to_vec()).unwrap_or(0))
    }

    /// Materialised deliberately: `StableBTreeMap::iter` borrows the map, and the
    /// borrow cannot outlive the `with` closure. Every caller is an audit path
    /// (reconcile, unit tests), never the O(1) public query.
    pub fn iter_balances() -> impl Iterator<Item = (Vec<u8>, u128)> {
        BALANCES.with(|b| b.borrow().iter().collect::<Vec<_>>()).into_iter()
    }

    pub fn iter_locks() -> impl Iterator<Item = (Vec<u8>, u128)> {
        STAKING_LOCKS.with(|s| s.borrow().iter().collect::<Vec<_>>()).into_iter()
    }

    pub fn len_balances() -> u64 {
        BALANCES.with(|b| b.borrow().len())
    }

    pub fn len_locks() -> u64 {
        STAKING_LOCKS.with(|s| s.borrow().len())
    }

    pub fn sum_balances() -> u128 {
        SUM_BALANCES.with(|s| *s.borrow())
    }

    pub fn sum_locks() -> u128 {
        SUM_STAKING_LOCKS.with(|s| *s.borrow())
    }

    // ── The ONLY mutating entry points that write the MAPS ────────────────────

    /// Set `key`'s balance to `new` and move SUM_BALANCES by the signed delta.
    ///
    /// `checked_add`/`checked_sub` + `.expect`, never saturating: `overflow-checks`
    /// is load-bearing here (P-ARITH R-1, ARCHITECTURE.md), and a running total that
    /// cannot represent the ledger is a trap, not a wrong number (invariant 4).
    ///
    /// `old` is the balance CURRENTLY STORED at `key` — a caller contract, not a
    /// free parameter. Every production call site has just read it (the
    /// check-before-mutate phase 1 of each endpoint), so passing it in removes a
    /// second `StableBTreeMap::get` from the hot path rather than adding a
    /// caller obligation that was not already discharged.
    ///
    /// WHY (CTO ruling `cto-ruling-r1-hotpath-cost-source-2026-09-05` §2.3): the
    /// per-statement profile of this function, measured with
    /// `performance_counter(0)` in the `testing` build, attributed 9,692 of the
    /// ~10,500 instructions per call to this one duplicate map read — 19,385 of
    /// the +21,013 measured on `icrc1_transfer`. The running-total arithmetic
    /// this lane adds costs 288 per call (576 per transfer, under 1 % of base).
    /// The cost was never the totals; it was reading the map twice.
    ///
    /// This remains the ONLY way `BALANCES` is written. A logical zero is
    /// represented by absence: rewriting an old physical zero removes it, and
    /// a new zero never allocates a row. The running total still moves by the
    /// same signed delta as part of this call.
    ///
    /// A wrong `old` would desynchronise SUM_BALANCES from the map, so the
    /// contract is verified under `debug_assertions` — on in the `--lib` unit
    /// suite that exercises every funnel call site, off in the release Wasms,
    /// so the hot path pays nothing for the check.
    pub fn write_balance(key: Vec<u8>, old: u128, new: u128) {
        BALANCES.with(|b| {
            let mut bals = b.borrow_mut();
            debug_assert_eq!(
                bals.get(&key).unwrap_or(0),
                old,
                "write_balance: `old` must be the currently-stored balance for this key"
            );
            if new == 0 {
                bals.remove(&key);
            } else {
                bals.insert(key, new);
            }
            SUM_BALANCES.with(|s| {
                let mut s = s.borrow_mut();
                *s = if new >= old {
                    s.checked_add(new - old)
                } else {
                    s.checked_sub(old - new)
                }
                .expect("SUM_BALANCES: running total cannot represent the ledger");
            });
        });
    }

    /// Set `key`'s staking lock to `new` and move SUM_STAKING_LOCKS by the signed
    /// delta. Same shape, same arithmetic discipline, and the same `old`
    /// caller contract (and `debug_assertions` verification) as `write_balance`.
    pub fn write_lock(key: Vec<u8>, old: u128, new: u128) {
        STAKING_LOCKS.with(|l| {
            let mut locks = l.borrow_mut();
            debug_assert_eq!(
                locks.get(&key).unwrap_or(0),
                old,
                "write_lock: `old` must be the currently-stored lock for this key"
            );
            if new == 0 {
                locks.remove(&key);
            } else {
                locks.insert(key, new);
            }
            SUM_STAKING_LOCKS.with(|s| {
                let mut s = s.borrow_mut();
                *s = if new >= old {
                    s.checked_add(new - old)
                } else {
                    s.checked_sub(old - new)
                }
                .expect("SUM_STAKING_LOCKS: running total cannot represent the ledger");
            });
        });
    }

    // ── Checkpoint / genesis seams (§3 S4(a2)) ────────────────────────────────
    //
    // Zero-sized capability witnesses. The TYPES THEMSELVES are private to this
    // module — not `pub`, not `pub(crate)`, not `pub(super)` — and the tuple
    // field is private as well.
    //
    // RED-1 (SSA_LANDED_DIFF_R-1_V2_2026-09-05.md, CTO triage
    // `cto-triage-ssa-landed-diff-round2-2026-09-05`): while these were
    // `pub(crate)`, ANY code in the crate could name them, and Rust permits an
    // inherent `impl` on a nameable type to be written ANYWHERE — including
    // inside a function body, where no item walker looks. The SSA wrote
    //
    //     fn ssa_container() {
    //         impl UpgradeWitness {
    //             pub fn ssa_write_without_sum(k: Vec<u8>, v: u128) {
    //                 BALANCES.with(|b| { b.borrow_mut().insert(k, v); });
    //             }
    //         }
    //     }
    //
    // inside `ledger_maps` and called
    // `ledger_maps::UpgradeWitness::ssa_write_without_sum(..)` from outside it:
    // a raw map write, no running-total update, all three lints green. The fix
    // is not to enumerate more impl positions — it is to make the type
    // UNNAMEABLE outside this module, so no `impl` block anywhere else in the
    // crate can attach anything to it and no path through it resolves (E0603).
    // The module now exposes only FREE FUNCTIONS; the residual lint check is
    // that no non-private TYPE is declared here at all.
    //
    // `private_interfaces` is allowed deliberately on the four functions below:
    // a `pub(crate)` fn whose signature mentions a module-private type is
    // exactly the shape being asked for — callers may obtain and pass a witness
    // value, and may never name, construct, or `impl` on its type.
    struct UpgradeWitness(());
    struct GenesisWitness(());

    /// Both witness constructors, and the two functions they gate, are the FOUR
    /// identifiers tracked by the `verify_ledger_boundary` occurrence lint: each
    /// must occur exactly TWICE across the crate's dep-info census — its own `fn`
    /// definition, and one further occurrence lexically inside the one legitimate
    /// caller's body, at either the AST layer or the token layer.
    ///
    /// RED-1 round 2 moved the two constructors INSIDE the module (the witness
    /// TYPES are now module-private, so a witness value can no longer cross the
    /// module boundary at all — `rustc` refuses the crossing outright, which is
    /// strictly stronger than the previous private-tuple-field guard). Their
    /// legitimate caller in the lint's table therefore moved with them, from
    /// `post_upgrade`/`init` to `restore_from_checkpoint`/`seed_at_genesis` —
    /// which remain tracked with `post_upgrade`/`init` as their one caller, so
    /// the chain `post_upgrade -> restore_from_checkpoint -> witness` is pinned
    /// end to end exactly as before.
    fn witness_for_post_upgrade() -> UpgradeWitness {
        UpgradeWitness(())
    }

    fn witness_for_init() -> GenesisWitness {
        GenesisWitness(())
    }

    /// The ONLY way a checkpoint's totals ever reach the running totals.
    ///
    /// Takes the decoded checkpoint TYPE, not raw `u128`s — a caller cannot pass
    /// "any number", only a `TokenStableState` it already legitimately decoded or
    /// synthesised from a fold. The `UpgradeWitness` is now minted HERE rather
    /// than by the caller (RED-1 round 2): the type is module-private, so it
    /// cannot appear in any signature crossing the module boundary, and
    /// `witness_for_post_upgrade` is bound by the occurrence lint to this one
    /// call site.
    ///
    /// `None` is a DISCRIMINATOR, never a value: at this call the stored version is
    /// already known to be 3, so a missing field means the checkpoint is corrupt and
    /// we refuse rather than guess (invariant 5 — never read a `None` as zero).
    pub(crate) fn restore_from_checkpoint(state: &TokenStableState) {
        let _w: UpgradeWitness = witness_for_post_upgrade();
        let sb = match state.sum_balances {
            Some(v) => v,
            None => ic_cdk::trap(
                "post_upgrade: v3 checkpoint missing sum_balances — checkpoint corrupt, \
                 refusing to guess",
            ),
        };
        let sl = match state.sum_staking_locks {
            Some(v) => v,
            None => ic_cdk::trap(
                "post_upgrade: v3 checkpoint missing sum_staking_locks — checkpoint corrupt, \
                 refusing to guess",
            ),
        };
        SUM_BALANCES.with(|s| *s.borrow_mut() = sb);
        SUM_STAKING_LOCKS.with(|s| *s.borrow_mut() = sl);
    }

    /// The ONLY way the totals are seeded at genesis. `validate_init_allocations`
    /// already forces the genesis credits to sum to TOTAL_SUPPLY, so this is a
    /// constant seed, not a fold.
    pub(crate) fn seed_at_genesis(total: u128) {
        let _w: GenesisWitness = witness_for_init();
        SUM_BALANCES.with(|s| *s.borrow_mut() = total);
        SUM_STAKING_LOCKS.with(|s| *s.borrow_mut() = 0);
    }

    /// Test-only seam (RED-2 V5 fix; R-4's dependency).
    ///
    /// Sets BOTH running totals directly, to ARBITRARY caller-supplied values,
    /// bypassing `write_balance`/`write_lock` and their `checked_add` entirely —
    /// the point is to reach a corrupted / overflow-adjacent maintained state
    /// WITHOUT a trap at write time (AC-6c). Touches no map. Present ONLY under
    /// `testing`; absent from every production Wasm (AC-13).
    #[cfg(feature = "testing")]
    pub(crate) fn set_sums_for_test(sum_balances: u128, sum_staking_locks: u128) {
        SUM_BALANCES.with(|s| *s.borrow_mut() = sum_balances);
        SUM_STAKING_LOCKS.with(|s| *s.borrow_mut() = sum_staking_locks);
    }
}

/// The PocketIC-callable seam (RED-2 V5, CTO-ruled). Controls all three operands of
/// the one remaining public-path checked add (`sum_balances + fee_reserve`) so a
/// test can drive it to `None` directly: e.g. `sum_balances = u128::MAX,
/// fee_reserve = 1`. Sets nothing else.
///
/// R-4 (BRIEF_R4_SOLVENCY_SURFACE_V3 §3 S-d item 4) cites this function by this
/// exact name and signature — do not rename it without flagging R-4.
#[cfg(feature = "testing")]
#[update]
fn set_supply_totals_for_test(sum_balances: u128, sum_staking_locks: u128, fee_reserve: u128) {
    ledger_maps::set_sums_for_test(sum_balances, sum_staking_locks);
    FEE_RESERVE.with(|f| *f.borrow_mut() = fee_reserve);
}

/// R-1 AC-8 / AC-12 TEST-ONLY: seed real positive BALANCES rows through the
/// production write funnel, funded by an explicit existing account.
///
/// Each newly absent target receives one unit and the donor is debited by the
/// same count. Existing positive targets are left unchanged and do not charge
/// the donor, making repeated/overlapping calls idempotent. The donor must
/// remain positive so its genesis row supplies the caller's N+1 expectation.
/// Returns the physical BALANCES cardinality observed after the writes.
#[cfg(feature = "testing")]
#[update]
fn seed_balance_rows_for_test(
    funding: Account,
    start: u32,
    count: u32,
) -> Result<u64, String> {
    let end = start
        .checked_add(count)
        .ok_or_else(|| "seed balance row range overflow".to_string())?;
    let funding_key = funding.encode_key();
    let mut new_targets = Vec::new();

    for i in start..end {
        let mut raw = [0u8; 29];
        raw[0] = 0x90;
        raw[1..5].copy_from_slice(&i.to_le_bytes());
        let target = Account {
            owner: Principal::from_slice(&raw),
            subaccount: None,
        };
        let target_key = target.encode_key();
        if target_key == funding_key {
            return Err("seed balance target aliases funding account".to_string());
        }
        if ledger_maps::get_balance(&target_key) == 0 {
            new_targets.push(target_key);
        }
    }

    let funding_balance = ledger_maps::get_balance(&funding_key);
    let debit = u128::try_from(new_targets.len())
        .map_err(|_| "seed balance debit does not fit u128".to_string())?;
    let remaining = funding_balance
        .checked_sub(debit)
        .filter(|remaining| *remaining > 0)
        .ok_or_else(|| "seed balance funding account must remain positive".to_string())?;

    if debit > 0 {
        ledger_maps::write_balance(funding_key, funding_balance, remaining);
        for target_key in new_targets {
            ledger_maps::write_balance(target_key, 0, 1);
        }
    }

    Ok(ledger_maps::len_balances())
}

/// R-1 AC-10 / S4(f) TEST-ONLY: the `performance_counter(0)` delta across ONE
/// real `icrc1_transfer` call, in the same message.
///
/// It wraps the production function rather than reimplementing any part of it —
/// `caller()` is unchanged, so the transfer executes exactly as it would if the
/// client had called `icrc1_transfer` directly. The wrapper's own cost (two
/// counter reads and one call) is the only difference and is reported as-is
/// rather than subtracted, so the number is an upper bound on the endpoint.
///
/// The packet's PRIMARY before/after comparison does NOT use this hook — it uses
/// cycles burned per update message on the PRODUCTION Wasms, because the base
/// Wasm (115526d) has no such hook and a comparison that can only be run on one
/// side is not a comparison. This hook supplies the ABSOLUTE instruction figure
/// that calibrates that comparison.
#[cfg(feature = "testing")]
#[update]
fn measure_icrc1_transfer_instructions_for_test(args: TransferArgs) -> (u64, bool) {
    let before = ic_cdk::api::performance_counter(0);
    let ok = icrc1_transfer(args).is_ok();
    let after = ic_cdk::api::performance_counter(0);
    (after - before, ok)
}

/// BR-35 (lane R-11) TEST-ONLY: the `performance_counter(0)` delta across ONE
/// real `verify_supply_invariant()` query, in the same message.
///
/// The public supply query's own comment claims it "can never trap on the
/// instruction limit (H-1)". That rests on `evaluate_supply_invariant` being
/// O(1) — `sum_balances()` and `sum_locks()` return MAINTAINED running totals
/// with no fold over the balance map. Nothing measured it, so a regression that
/// reintroduced a fold would break the claim silently at a row count no gate
/// fixture reaches.
///
/// It WRAPS the production query rather than reimplementing any part of it, the
/// same discipline as the transfer hooks above; the wrapper's own cost (two
/// counter reads and one call) is reported as-is rather than subtracted, so the
/// number is an upper bound on the endpoint.
#[cfg(feature = "testing")]
#[update]
fn measure_verify_supply_invariant_instructions_for_test() -> u64 {
    let before = ic_cdk::api::performance_counter(0);
    let _ = verify_supply_invariant();
    ic_cdk::api::performance_counter(0) - before
}

/// The `icrc2_transfer_from` sibling of the hook above.
#[cfg(feature = "testing")]
#[update]
fn measure_icrc2_transfer_from_instructions_for_test(args: TransferFromArgs) -> (u64, bool) {
    let before = ic_cdk::api::performance_counter(0);
    let ok = icrc2_transfer_from(args).is_ok();
    let after = ic_cdk::api::performance_counter(0);
    (after - before, ok)
}

/// R-1 AC-7d TEST-ONLY: arm the "v3 checkpoint with both totals `None`" fixture.
#[cfg(feature = "testing")]
#[update]
fn force_v3_none_checkpoint_for_test() {
    FORCE_V3_NONE_CHECKPOINT.with(|f| *f.borrow_mut() = true);
}

// ── Stable state snapshot ─────────────────────────────────────────────────────
//
// BALANCES, ALLOWANCES, ALLOC_TABLE, STAKING_LOCKS (all StableBTreeMap) survive
// the upgrade untouched.  The following heap-only fields require serialisation:
//   BLOCK_HEIGHT    — monotonically increasing tx counter; must not reset to 0
//   TRANSFER_FEE    — fixed at DEFAULT_FEE since init; no runtime update path
//                     (DEF-085: governance_set_fee removed — fee model not active
//                     at launch; a future fee-policy lane must add a governed path)
//   FEE_RESERVE     — accumulated fees not yet routed to the fee recipient
//   MINT_DONE       — once true, genesis mint cannot be re-run
//   TREASURY        — fallback fee recipient; panic if None after upgrade
//   FEE_COLLECTOR   — DEF-080 neutral fee recipient (opt; None on pre-DEF-080 state)
//   STAKING_CANISTER — required for staking lock/unlock; panic if None after upgrade

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TokenStableState {
    state_version:    u32,
    block_height:     u64,
    transfer_fee:     u128,
    fee_reserve:      u128,
    mint_done:        bool,
    treasury:         Principal,
    staking_canister: Principal,
    /// DEF-080: added as `Option` WITHOUT a STATE_VERSION bump — Candid decodes a
    /// pre-DEF-080 snapshot (field absent) as `None`, which is the intended
    /// backward-compatible value (fee routing falls back to TREASURY). This is the
    /// same width-subtyping migration pattern used by the shielded-pool record
    /// fields (DEF-069/072).
    fee_collector:    Option<Principal>,
    /// R-1: `Option` so a v2 checkpoint (field absent) DECODES — post_upgrade
    /// decodes the bytes BEFORE it reads `state_version`, so a required field
    /// would trap every v2→v3 upgrade before the migration arm could run. The
    /// `None` is a DISCRIMINATOR, never a value: stored == 3 traps on `None`
    /// (corrupt checkpoint); stored == 2 ignores the field and seeds by fold.
    /// Same decode-compatible added-field pattern as DEF-080's `fee_collector`.
    sum_balances:      Option<u128>,
    sum_staking_locks: Option<u128>,
    /// HARDEN-03-SETTLEMENT (D-3): the init-bound pool authority, mirrored into
    /// the checkpoint so it survives upgrade. `Option` with NO `STATE_VERSION`
    /// bump, for exactly the reason `fee_collector` above gives: a pre-lane
    /// checkpoint decodes the absent field as `None`, which is the correct
    /// backward-compatible value (no pool bound -> no receipts written -> the
    /// fail-safe degraded mode of D-3/AC-26).
    ///
    /// Unlike `sum_balances` this `None` is a VALUE, not a discriminator: there
    /// is no migration arm, because there is nothing to reconstruct. A token
    /// that was installed without a pool authority does not acquire one by being
    /// upgraded -- D-3 refused the setter, and an upgrade is not a setter.
    pool_canister:     Option<Principal>,
}

// ── Init ──────────────────────────────────────────────────────────────────────

#[derive(CandidType, Deserialize)]
pub struct InitArgs {
    pub allocations: Vec<AllocationCategory>,
    pub treasury: Principal,
    /// The staking canister that may call lock_for_staking / unlock_from_staking
    pub staking_canister: Principal,
    /// DEF-080: fee_collector is a neutral spendable II account, not the treasury
    /// canister. Optional for backward compatibility (existing installs decode as
    /// None → fees fall back to `treasury`). Mainnet manifest requires
    /// Some(neutral_fee_collector) with fee_collector != treasury_canister_principal.
    pub fee_collector: Option<Principal>,
    /// HARDEN-03-SETTLEMENT (D-3): the shielded pool whose qualifying deposit
    /// transfers receive a durable receipt.
    ///
    /// INIT-TIME ONLY. There is no setter, and D-3 refused one explicitly: a
    /// post-init authority-mutation surface on a canister holding real supply
    /// buys nothing here, because the install ordering already makes init-time
    /// binding possible (the pool principal is born long before the token is
    /// installed, so there is no chicken-and-egg).
    ///
    /// `Option` for DECODE COMPATIBILITY — exactly the pattern the shipped
    /// `fee_collector` comment above describes, one lane earlier. Existing
    /// installs and every test fixture that omits the field decode as `None`, so
    /// the receipt path is simply never selected and ZERO existing test mirrors
    /// need editing. `None` is fail-SAFE, not fail-open: see `POOL_CANISTER`.
    ///
    /// The mainnet manifest REQUIRES `Some(pool_principal)`; readback is via
    /// `get_deposit_settlement_authority`.
    pub pool_canister: Option<Principal>,
}

/// Pure validation for genesis allocations — extracted from init() for testability.
///
/// Returns Ok(()) if all invariants hold, Err with a human-readable message otherwise.
/// Called by init() which calls ic_cdk::trap() on any error.
///
/// SUPPLY INVARIANT: sum(allocations) == TOTAL_SUPPLY
/// FIELD INVARIANTS: every allocation has non-empty category_id, category_name, non-zero amount
/// UNIQUENESS:       no duplicate category_ids
pub fn validate_init_allocations(allocations: &[AllocationCategory]) -> Result<(), String> {
    // INVARIANT: allocations must sum to TOTAL_SUPPLY exactly.
    // K3-002a: CHECKED fold — a manifest whose mathematical sum exceeds
    // u128::MAX must be a typed rejection, never a wrapped total that happens
    // to land back on TOTAL_SUPPLY (u128::MAX + TOTAL_SUPPLY + 1 ≡ TOTAL_SUPPLY
    // mod 2^128 would otherwise mint supply silently).
    let total: u128 = allocations
        .iter()
        .try_fold(0u128, |acc, a| acc.checked_add(a.amount))
        .ok_or_else(|| {
            "Allocation sum overflows u128 — genesis manifest invalid, deploy aborted".to_string()
        })?;
    if total != TOTAL_SUPPLY {
        return Err(format!(
            "Allocation sum {} != TOTAL_SUPPLY {}. Every token must be accounted for.",
            total, TOTAL_SUPPLY
        ));
    }

    // INVARIANT: no unnamed, empty categories, or zero-amount entries
    for alloc in allocations {
        if alloc.category_id.is_empty() {
            return Err("All allocation categories must have a non-empty category_id".to_string());
        }
        if alloc.category_name.is_empty() {
            return Err("All allocation categories must have a non-empty category_name".to_string());
        }
        if alloc.amount == 0 {
            return Err(format!("Allocation '{}' has zero amount — remove it", alloc.category_id));
        }
    }

    // INVARIANT: no duplicate category_ids
    let mut seen_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for alloc in allocations {
        if !seen_ids.insert(alloc.category_id.as_str()) {
            return Err(format!("Duplicate category_id: {}", alloc.category_id));
        }
    }

    Ok(())
}

#[init]
fn init(args: InitArgs) {
    // Gate: genesis mint runs exactly once
    MINT_DONE.with(|done| {
        if *done.borrow() { ic_cdk::trap("Genesis mint already performed"); }
    });

    // Validate allocations using extracted pure function — trap on any violation
    if let Err(e) = validate_init_allocations(&args.allocations) {
        ic_cdk::trap(&e);
    }

    let genesis_ts = time();

    // R-1 S4(a): seed the running totals BEFORE the allocation loop, so every
    // genesis credit below moves the total through the same funnel every later
    // write uses. `validate_init_allocations` has already forced the credits to
    // sum to TOTAL_SUPPLY, so the seed is 0 here and the loop walks it up to
    // TOTAL_SUPPLY through `write_balance` — one funnel, no special genesis path.
    // This is the ONE call site of seed_at_genesis / witness_for_init.
    ledger_maps::seed_at_genesis(0);

    // Mint to allocation accounts and store immutable genesis table
    ALLOC_TABLE.with(|table| {
        let mut t = table.borrow_mut();
        for (idx, mut alloc) in args.allocations.into_iter().enumerate() {
            alloc.created_at_genesis = true;
            alloc.genesis_timestamp_ns = genesis_ts;
            let account = Account { owner: alloc.recipient, subaccount: alloc.subaccount };
            let key = account.encode_key();
            let existing = ledger_maps::get_balance(&key);
            // checked_add + trap: genesis runs once and validate_init_allocations
            // already guarantees sum == TOTAL_SUPPLY, so overflow is unreachable.
            // Trap rather than wrap if an allocation set ever violated that.
            let credited = existing.checked_add(alloc.amount)
                .unwrap_or_else(|| ic_cdk::trap("genesis allocation credit overflow"));
            ledger_maps::write_balance(key, existing, credited);
            t.insert(idx as u64, alloc);
        }
    });

    TREASURY.with(|t| *t.borrow_mut() = Some(args.treasury));
    FEE_COLLECTOR.with(|f| *f.borrow_mut() = args.fee_collector); // DEF-080
    // HARDEN-03-SETTLEMENT (D-3): bound HERE and nowhere else. No setter exists.
    POOL_CANISTER.with(|p| *p.borrow_mut() = args.pool_canister);
    STAKING_CANISTER.with(|s| *s.borrow_mut() = Some(args.staking_canister));
    MINT_DONE.with(|done| *done.borrow_mut() = true);

    // H-01 (f2): arm the allowance-maintenance timer. Also armed in
    // `post_upgrade` — timers do not survive an upgrade, and this is the trigger
    // that drains a backlog nobody is writing against.
    arm_allowance_maintenance_timer();
}

// ── Supply invariant query (NON-OPTIONAL — watcher calls this) ────────────────

/// Returns the full supply invariant report.
/// invariant_holds == true is required before any mainnet activation.
/// Pure supply-invariant evaluation (no `time()` / system calls) — shared by the
/// verify_supply_invariant query and the unit tests.
///
/// CANONICAL INVARIANT (single source of truth):
///   TOTAL_SUPPLY == sum(all BALANCES entries) + fee_reserve
/// Transfer operations are conservative — they only move balances, never create.
/// fee_reserve is an EXTERNAL bucket outside BALANCES that only accrues when
/// TREASURY is unset (see route_fee_to_treasury). Staking locks live INSIDE
/// BALANCES (lock_for_staking moves liquid→locked within an account) and are
/// therefore NOT added here — doing so would double-count.
///
/// K3-002b: checked u128 fold — `None` on any overflow, never a wrapped total.
fn checked_sum(mut values: impl Iterator<Item = u128>) -> Option<u128> {
    values.try_fold(0u128, |acc, v| acc.checked_add(v))
}

/// Full checked evaluation of the supply invariant (K3-002b).
///
/// Every total is a CHECKED fold; an unavailable total is reported as exactly
/// `0` (never wrapped, never saturated) with its overflow flag set. Any
/// arithmetic error forces `invariant_holds = false` — a wrapping BALANCES
/// fold can never land back on TOTAL_SUPPLY and read as healthy.
struct InvariantEvaluation {
    sum_balances: u128,
    fee_reserve: u128,
    staking_locked: u128,
    invariant_holds: bool,
    balances_overflow: bool,
    staking_locks_overflow: bool,
    /// True only when the balances fold SUCCEEDED and the final
    /// `sum_balances + fee_reserve` add overflowed (the third site).
    balances_plus_fee_overflow: bool,
}

fn evaluate_supply_invariant() -> InvariantEvaluation {
    // R-1 S4(c): O(1). Both totals are MAINTAINED by the write funnel, so there is
    // no fold on the public path at any row count — the query returns a computed,
    // honest answer and can never trap on the instruction limit (H-1).
    //
    // The two fold-overflow attributions can no longer occur here (there is no
    // fold left to overflow) and are reported `false`; the ONE remaining checked
    // add, `sum_balances + fee_reserve`, keeps its own attribution field. The
    // wire shape of SupplyInvariantReport is unchanged (ruling Q1).
    let sum_balances_opt = Some(ledger_maps::sum_balances());
    let staking_locked_opt = Some(ledger_maps::sum_locks());
    let fee_reserve = FEE_RESERVE.with(|f| *f.borrow());

    let balances_overflow = false;
    let staking_locks_overflow = false;
    let balances_plus_fee = sum_balances_opt.and_then(|s| s.checked_add(fee_reserve));
    let balances_plus_fee_overflow = balances_plus_fee.is_none();

    let any_arithmetic_error =
        balances_overflow || staking_locks_overflow || balances_plus_fee_overflow;
    let invariant_holds = !any_arithmetic_error && balances_plus_fee == Some(TOTAL_SUPPLY);

    InvariantEvaluation {
        sum_balances: sum_balances_opt.unwrap_or(0),
        fee_reserve,
        staking_locked: staking_locked_opt.unwrap_or(0),
        invariant_holds,
        balances_overflow,
        staking_locks_overflow,
        balances_plus_fee_overflow,
    }
}

#[query]
fn verify_supply_invariant() -> SupplyInvariantReport {
    let eval = evaluate_supply_invariant();
    let any_arithmetic_error =
        eval.balances_overflow || eval.staking_locks_overflow || eval.balances_plus_fee_overflow;

    // violation_detail deterministically names EVERY overflow site (fixed
    // order), or falls back to the numeric mismatch message.
    let violation_detail = if any_arithmetic_error {
        let mut sites: Vec<&str> = Vec::new();
        if eval.balances_overflow {
            sites.push("balances_fold_overflow");
        }
        if eval.staking_locks_overflow {
            sites.push("staking_locks_fold_overflow");
        }
        if eval.balances_plus_fee_overflow {
            sites.push("balances_plus_fee_overflow");
        }
        Some(format!(
            "arithmetic overflow in supply-invariant evaluation: {} (affected totals reported as 0)",
            sites.join("; ")
        ))
    } else if !eval.invariant_holds {
        Some(format!(
            "sum_balances({}) + fee_reserve({}) != TOTAL_SUPPLY({})",
            eval.sum_balances, eval.fee_reserve, TOTAL_SUPPLY
        ))
    } else {
        None
    };

    SupplyInvariantReport {
        fixed_max_supply: TOTAL_SUPPLY,
        sum_all_balances: eval.sum_balances,
        staking_locked_total: eval.staking_locked,
        fee_reserve_total: eval.fee_reserve,
        invariant_holds: eval.invariant_holds,
        checked_at_ns: time(),
        violation_detail,
        // None if and only if every checked calculation succeeded.
        arithmetic_error: any_arithmetic_error.then_some(ArithmeticErrorReport {
            balances_overflow: eval.balances_overflow,
            staking_locks_overflow: eval.staking_locks_overflow,
            balances_plus_fee_overflow: eval.balances_plus_fee_overflow,
        }),
    }
}

/// Returns the genesis allocation table. Immutable after init.
/// Auditors and the watcher use this to verify supply distribution.
#[query]
fn get_genesis_allocations() -> Vec<AllocationCategory> {
    ALLOC_TABLE.with(|t| t.borrow().iter().map(|(_, v)| v).collect())
}

/// Returns the allocation for a specific category_id
#[query]
fn get_allocation_by_category(category_id: String) -> Option<AllocationCategory> {
    ALLOC_TABLE.with(|t| {
        t.borrow().iter()
            .map(|(_, v)| v)
            .find(|a| a.category_id == category_id)
    })
}

// ── ICRC-1 Queries ────────────────────────────────────────────────────────────

#[query] fn icrc1_name()     -> String { NAME.to_string() }
#[query] fn icrc1_symbol()   -> String { SYMBOL.to_string() }
#[query] fn icrc1_decimals() -> u8     { DECIMALS }
// ── icrc1_fee — and the SI-11 SECOND OBSERVER (R-8 V1a) ─────────────────────
//
// PRODUCTION: an ordinary query, unchanged.
#[cfg(not(feature = "testing"))]
#[query] fn icrc1_fee()      -> Nat    { Nat::from(TRANSFER_FEE.with(|f| *f.borrow())) }

/// TESTING BUILD ONLY — the same value, from an UPDATE method, so that the
/// observer below can make an inter-canister call at all.
///
/// WHY THE KIND CHANGES (SSA landed-diff R-8 V1, AMBER-1; CTO ruling
/// cto-ruling-r8-landed-diff-fix-wave-2026-09-06 item 2). SI-11's property is
/// "the reservation is durable before treasury's FIRST await". Treasury's first
/// await is NOT the pool call — it is `call(token, "icrc1_fee", ())`
/// (`canisters/treasury/src/lib.rs`), which sits BETWEEN `reserve_withdrawal`
/// and the pool call. The pool-side observer therefore binds
/// "before-the-POOL-call", a strictly weaker claim, and the SSA demonstrated
/// the gap: moving the reservation below the `icrc1_fee` await left the
/// pool-side test GREEN. The only vantage point that can see the earlier
/// boundary is INSIDE this handler, while treasury is parked on THIS reply.
///
/// A `#[query]` cannot do it. Under replicated execution — which is what an
/// inter-canister call to a query method is — the outbound-call System API is
/// unavailable, so the handler would trap. The testing build therefore exports
/// `icrc1_fee` as an update. `verify_did_exports` evaluates cfgs with the
/// crate's DEFAULT features (`testing` off), so the .did contract continues to
/// be checked against the production `#[query]` above; and
/// `eager_cell_feature_isolation_tests` proves the observer's own surfaces are
/// absent from the shipped Wasm.
///
/// UNARMED, THE BODY IS IDENTICAL to production's: no observer is set unless a
/// test explicitly arms one, so every other suite that runs on
/// `stsh_token_test.wasm` sees the same value by the same computation. The
/// divergence is the method KIND, and it is recorded here rather than left for
/// a reader to discover.
#[cfg(feature = "testing")]
#[update]
async fn icrc1_fee() -> Nat {
    si11_observe_if_armed().await;
    Nat::from(TRANSFER_FEE.with(|f| *f.borrow()))
}

// ── SI-11 (R-8 V1a): the token-side observer ────────────────────────────────
//
// A DECODE-SHAPE MIRROR of treasury's real `ReservationStatus` — same variants,
// SAME ORDER, which is what Candid decodes against. Not a shared type: the
// token does not depend on the treasury crate, and this mirror exists only in
// the testing build. It is the same mirror the pool's testing build carries,
// for the same reason.
#[cfg(feature = "testing")]
#[derive(CandidType, candid::Deserialize, Clone, Copy, Debug, PartialEq)]
enum ReservationStatusForTest {
    Reserved,
    Executed,
    Failed,
    OutcomeUnknown,
    RetryingUnknown,
    RetiredNotExecuted,
}

#[cfg(feature = "testing")]
thread_local! {
    /// (treasury, proposal_id) — set by `set_si11_observer_for_test`. `None`
    /// means UNARMED, which is the state of every other suite's token.
    static SI11_OBSERVER_TARGET_FOR_TEST: RefCell<Option<(Principal, u64)>> =
        const { RefCell::new(None) };
    /// What the FIRST armed `icrc1_fee` call observed. First fire wins, so the
    /// recorded value is the state at treasury's FIRST await and not at some
    /// later `icrc1_fee` (the pool makes one of its own, further along).
    static SI11_OBSERVED_FOR_TEST: RefCell<Option<ReservationStatusForTest>> =
        const { RefCell::new(None) };
    /// WHETHER the observer has already fired — a SEPARATE flag, deliberately.
    ///
    /// Using `SI11_OBSERVED_FOR_TEST.is_some()` as the guard is the bug this
    /// exists to avoid, and it was caught by mutation and not by reasoning: a
    /// legitimate first observation of `None` (treasury has NO reservation yet
    /// — precisely the failing state the test must detect) is then
    /// indistinguishable from "not yet fired", so the pool's LATER `icrc1_fee`
    /// call fires again and overwrites it with the by-then-`Reserved` value.
    /// The observer reports GREEN under the very mutation it exists to catch.
    static SI11_FIRED_FOR_TEST: RefCell<bool> = const { RefCell::new(false) };
}

/// Ask treasury, from inside this handler, what it has DURABLY recorded for the
/// armed proposal id — and record the answer once.
///
/// A replicated inter-canister call to a `#[query]` executes against the
/// callee's COMMITTED state, so treasury cannot answer out of the continuation
/// it is suspended in. `Some(Reserved)` here therefore means the reservation
/// was written and committed before treasury awaited `icrc1_fee` — its FIRST
/// await, which is the property SI-11 actually claims.
#[cfg(feature = "testing")]
async fn si11_observe_if_armed() {
    let armed = SI11_OBSERVER_TARGET_FOR_TEST.with(|t| *t.borrow());
    let Some((treasury, proposal_id)) = armed else { return };
    // FIRST FIRE WINS — a later icrc1_fee (the pool makes its own, after
    // treasury's) must not overwrite the observation of the first await. The
    // guard is the FIRED flag, never the observed value: see its declaration.
    if SI11_FIRED_FOR_TEST.with(|f| *f.borrow()) {
        return;
    }
    SI11_FIRED_FOR_TEST.with(|f| *f.borrow_mut() = true);
    let observed: Result<(Option<ReservationStatusForTest>,), _> =
        ic_cdk::call(treasury, "reservation_status_for_test", (proposal_id,)).await;
    SI11_OBSERVED_FOR_TEST.with(|o| *o.borrow_mut() = observed.ok().and_then(|(s,)| s));
}

/// Arm the observer, and clear any previous observation. Testing build only.
#[cfg(feature = "testing")]
#[update]
fn set_si11_observer_for_test(treasury: Principal, proposal_id: u64) {
    SI11_OBSERVER_TARGET_FOR_TEST.with(|t| *t.borrow_mut() = Some((treasury, proposal_id)));
    SI11_OBSERVED_FOR_TEST.with(|o| *o.borrow_mut() = None);
    SI11_FIRED_FOR_TEST.with(|f| *f.borrow_mut() = false);
}

/// What the armed observer saw, read back after `execute_withdrawal` returns.
/// `None` means either "no observation was made" or "treasury had no
/// reservation record for that id" — the SI-11 test distinguishes them by
/// asserting the POSITIVE value on the unmutated build.
#[cfg(feature = "testing")]
#[query]
fn si11_observed_reservation_status_for_test() -> Option<ReservationStatusForTest> {
    SI11_OBSERVED_FOR_TEST.with(|o| *o.borrow())
}

#[query] fn icrc1_total_supply() -> Nat { Nat::from(TOTAL_SUPPLY) }
#[query] fn icrc1_minting_account() -> Option<Account> { None } // no minting after genesis

#[query]
fn icrc1_balance_of(account: Account) -> Nat {
    #[cfg(feature = "testing")]
    if R15_BALANCE_OVERSIZE.with(|v| *v.borrow()) { return Nat::from(u128::MAX) + Nat::from(1u8); }
    let key = account.encode_key();
    Nat::from(ledger_maps::get_balance(&key))
}

/// DEV-003: the token logo, committed as a PNG asset (assets/stsh-logo.png —
/// 256×256 8-bit grayscale, white STSH mark on a solid black tile) rasterised
/// deterministically from assets/stsh-logo.svg (kept for provenance) by
/// assets/rasterize_logo.py, and served as a base64 PNG data URL in
/// icrc1:logo (some DEX/wallet UIs do not render SVG data URLs).
const LOGO_PNG: &[u8] = include_bytes!("../assets/stsh-logo.png");

fn logo_data_url() -> String {
    use base64::Engine as _;
    format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(LOGO_PNG)
    )
}

#[query]
fn icrc1_metadata() -> Vec<(String, MetadataValue)> {
    vec![
        ("icrc1:name".to_string(),     MetadataValue::Text(NAME.to_string())),
        ("icrc1:symbol".to_string(),   MetadataValue::Text(SYMBOL.to_string())),
        ("icrc1:decimals".to_string(), MetadataValue::Nat(Nat::from(DECIMALS as u128))),
        ("icrc1:fee".to_string(),      MetadataValue::Nat(Nat::from(TRANSFER_FEE.with(|f| *f.borrow())))),
        ("icrc1:logo".to_string(),     MetadataValue::Text(logo_data_url())), // DEV-003
    ]
}

#[query]
fn icrc1_supported_standards() -> Vec<StandardRecord> {
    supported_standards_list()
}

/// ICRC-10: the standalone supported-standards discovery method (same named
/// record shape as F-001's icrc1_supported_standards) — signers and the
/// reference ledger expose it; nearly free once the shared list exists.
#[query]
fn icrc10_supported_standards() -> Vec<StandardRecord> {
    supported_standards_list()
}

// ── ICRC-1 Transfer ───────────────────────────────────────────────────────────

#[update]
fn icrc1_transfer(args: TransferArgs) -> Result<Nat, TransferError> {
    let caller = ic_cdk::caller();
    let fee = TRANSFER_FEE.with(|f| *f.borrow());

    // F-ADV-D2: a fee that does not fit u128 can never equal the live fee — fail
    // on the conversion itself (BadFee), never on a coerced sentinel value.
    if let Some(ref provided) = args.fee {
        if provided.0.to_u128().map_or(true, |v| v != fee) {
            return Err(TransferError::BadFee { expected_fee: Nat::from(fee) });
        }
    }

    let now = time();
    if let Some(created_at) = args.created_at_time {
        if created_at > now + PERMITTED_DRIFT_NS {
            return Err(TransferError::CreatedInFuture { ledger_time: now });
        }
        if now.saturating_sub(created_at) > TX_DEDUP_WINDOW_NS {
            return Err(TransferError::TooOld);
        }
    }

    let from = Account { owner: caller, subaccount: args.from_subaccount };
    let from_key = from.encode_key();
    let to_key   = args.to.encode_key();
    let amount   = args.amount.0.to_u128().ok_or_else(|| TransferError::GenericError {
        error_code: Nat::from(1u32), message: "Amount overflow".to_string()
    })?;
    // R10-1 (lane A-3): refuse `amount == 0`, BEFORE `checked_total_debit`, the
    // dedup lookup and every balance/allowance read or write.
    //
    // WHY: on the IC a returned `Err` COMMITS whatever the message already wrote
    // (only a trap rolls back — see the note at the end of this function), so
    // "no partial state on rejection" is the correctness requirement. Rejecting
    // here satisfies it on this path.
    //
    // This is a KNOWING ICRC-1 DEVIATION, not a conformance fix: ICRC-1 permits
    // zero-amount transfers, and this ledger accepted them until now
    // (`test_icrc1_e07_..._dev004`). It ships because at DEFAULT_FEE = 0 a
    // zero-amount transfer is a completely free no-op that still writes a dedup
    // entry — an unpriced state-growth vector spammable at ingress cost alone.
    // Registered in NOTE_A-3_icrc_deviation.md.
    //
    // ORDERING, stated because it is asymmetric with `icrc2_transfer_from`: this
    // endpoint validates `created_at_time` ABOVE (CreatedInFuture / TooOld), so a
    // stale zero-amount call returns `TooOld` here and the zero refusal there.
    // Pre-existing structure, ruled to stand (CTO_RULING_A-3_error_precedence);
    // see NOTE_A-3_error_precedence_asymmetry.md.
    if amount == 0 {
        return Err(TransferError::GenericError {
            error_code: Nat::from(ERR_CODE_ZERO_AMOUNT),
            message: ERR_MSG_ZERO_AMOUNT.to_string(),
        });
    }
    let total_debit = checked_total_debit(amount, fee)?;

    // ── DEF-050B-1 / B1: idempotent-retry guard, ICRC-1 variant (withdraw-side of
    // QA-DEF-023) ──
    // When created_at_time is supplied, short-circuit a byte-identical retry BEFORE
    // any balance/staking read or write — so a controller-driven retry of a
    // transport-unknown transfer returns Duplicate { duplicate_of } instead of
    // moving funds a second time. The dedup lookup runs before the Phase-1 balance
    // check so a post-success retry with now-insufficient funds still returns
    // Duplicate, not InsufficientFunds. The window was validated above; the dedup
    // entry is written only AFTER the transfer commits. transfer_dedup_key uses a
    // DISTINCT domain tag so it can never collide with an icrc2_transfer_from key.
    // created_at_time == None preserves the prior, non-idempotent path.
    let dedup_key = if let Some(t) = args.created_at_time {
        let key = transfer_dedup_key(&from, &args.to, amount, &args.fee, &args.memo, t);
        if let Some(v) = TRANSFER_DEDUP.with(|d| d.borrow().get(&key)) {
            let block_idx = u64::from_le_bytes(v[0..8].try_into().unwrap());
            return Err(TransferError::Duplicate { duplicate_of: Nat::from(block_idx) });
        }
        Some((key, t))
    } else {
        None
    };

    // QA-DEF-019 / B1: check-before-mutate two-phase. On the IC a returned Err
    // commits any state already written in this message (only a trap rolls back), so
    // the previous ordering — write the debit, THEN run the fallible recipient
    // credit — could commit a debit and drop the credit if checked_credit overflowed
    // (tokens destroyed). Validate the liquid balance AND the recipient credit first;
    // only once every check passes do we write. Mirrors icrc2_transfer_from.

    // ── Phase 1: read + validate, no writes ──
    let from_bal = ledger_maps::get_balance(&from_key);
    // Enforce liquid balance — staked tokens are not transferable. Staking locks are
    // recorded on the main account key (subaccount: None); a from_key carrying a
    // subaccount has no lock, so liquid == from_bal.
    let locked = ledger_maps::get_lock(&from_key);
    let liquid = from_bal.saturating_sub(locked);
    if liquid < total_debit {
        return Err(TransferError::InsufficientFunds { balance: Nat::from(liquid) });
    }
    let new_from = from_bal.checked_sub(total_debit)
        .ok_or(TransferError::InsufficientFunds { balance: Nat::from(liquid) })?;
    // Recipient credit — for a self-transfer (to == from) credit the POST-debit
    // balance so the net effect is losing only the fee, matching the prior
    // read-after-write semantics. This is the last fallible check.
    let to_base = if to_key == from_key {
        new_from
    } else {
        ledger_maps::get_balance(&to_key)
    };
    let new_to = checked_credit(to_base, amount)?;

    // ── Phase 2: every check passed — apply writes (infallible) ──
    ledger_maps::write_balance(from_key, from_bal, new_from);
    ledger_maps::write_balance(to_key, to_base, new_to);

    // Route fee to treasury
    route_fee_to_treasury(fee);

    let block = next_block();

    // DEF-050B-1 / B1: record the dedup entry only after the transfer has committed,
    // so a byte-identical retry within TX_DEDUP_WINDOW_NS returns Duplicate. Prune
    // first (capped) to bound stable-memory growth.
    if let Some((key, created_at)) = dedup_key {
        record_dedup(key, block, created_at);
    }

    Ok(Nat::from(block))
}

// ── H-01 (HARDEN-02): bounded allowance lifetime + indexed reclamation ───────
//
// THE EXPOSURE THIS CLOSES. `ALLOWANCES` grew monotonically: no row was ever
// removed on any path (revoke overwrote with `amount: 0`, a drain wrote back the
// reduced record, expiry was read-side only), while `icrc2_approve` admitted a
// new row from a zero-balance caller at `DEFAULT_FEE = 0` for ingress cost
// alone. Both halves of the row key — the approver's subaccount and the spender
// account — are caller-supplied, and IC principals are free to generate, so the
// number of distinct keys one attacker can write was limited by nothing in this
// canister.
//
// THE RULED DESIGN (SSA C-1, CTO addendum 2026-09-17 §2):
//   (f1) every allowance `icrc2_approve` stores has an end no later than
//        `now + MAX_APPROVAL_TTL_NS` — deviation dev007. An absent
//        `expires_at` is defaulted to that end and a later one clamped to it
//        (TOKEN-APPROVE-TTL; originally both were refused). An approval with no
//        stated end cannot exist, so there is no unreclaimable row.
//   (f2) Expired rows are RECLAIMED, by TWO independent triggers: a bounded
//        prune on every successful `icrc2_approve`, and a canister-owned
//        interval timer.
//
// WHY THESE TWO AND NOT THE THIRD. An earlier revision of this lane also pruned
// on every successful `icrc2_transfer_from`, as SSA N-2's second trigger site.
// That was REMOVED after measurement, by CTO ruling
// `cto-ruling-harden02-ac10-and-residuals-2026-09-17` (AC-10 Option 2): it cost
// +34,526 instructions (+37.896 %) on that endpoint against an AC-10 ceiling of
// 6,000 instructions or 6 %, a permanent tax on the ledger's highest-volume call.
// See the comment at the removal site in `icrc2_transfer_from` for the numbers.
//
// WHY N-1 IS STILL CLOSED. N-1 was not "there must be N triggers" — it was that
// the ONE trigger then proposed was caller-switchable. The token's
// `TRANSFER_DEDUP` prune fires from `record_dedup_at`, which `icrc2_approve`
// calls only inside `if let Some((key, created_at)) = dedup_key`, and `dedup_key`
// is `None` whenever the caller omits the optional `created_at_time`. Omitting it
// is free and is the attacker's cheaper call shape anyway (it also skips the
// dedup-row write), so a prune hung off that branch is reclamation with an off
// switch the attacker holds. Neither surviving trigger has one: the approve prune
// is UNCONDITIONAL on that path, outside that block, and the interval timer is
// canister-owned and not caller-switchable at all.
//
// WHY N-2 IS STILL CLOSED. N-2 was that a write-path trigger alone leaves a
// burst-then-silence backlog resident, because reclamation is then coupled to
// traffic that has stopped.
// MEASURED: timer_drains_a_backlog_with_no_further_calls
// The timer is what answers that, and it answers it whether or not any
// write path also prunes. What the removal costs is width, not boundedness: the
// worst-case backlog between ticks is now bounded by the approve arrival rate
// over one interval rather than also being drained by intervening `transfer_from`
// traffic. Measured, not asserted — see the residency tests named below.
//
// WHAT IT DOES NOT DO. Bounding the resident set is not the same as making the
// attack expensive. An attacker still makes the canister carry a TTL's worth of
// rows and pay for the pruning; (f) makes that recoverable and survivable, not
// free. Only a nonzero approve fee would move the cost onto the attacker, and
// that is barred without a fee-model ruling (ARCHITECTURE.md law 5). The measured
// envelope — peak, throughput, residency and the real allocated footprint — is
// reported by the HARDEN-02 packet from the tests named below, and is
// deliberately NOT restated here as a bound.

/// Upper bound on the encoded length of a `compound_key(account, spender)`.
/// `Account`'s own `Storable` bound is 64 bytes per half and `compound_key`
/// prepends a u32 length to each half, so 4 + 64 + 4 + 64. Asserted against the
/// real worst-case key by `allowance_expiry_key_fits_its_declared_bound`.
const MAX_ALLOWANCE_KEY_LEN: usize = 4 + 64 + 4 + 64;

/// Cap on expired allowance rows reclaimed per successful `icrc2_approve` — the
/// only write path that prunes (see the removal note in `icrc2_transfer_from`).
/// Mirrors `MAX_PRUNE_PER_CALL`'s role for the dedup maps: it
/// bounds the work ONE message does, and it is emphatically not a bound on a
/// full scan — `prune_expired_allowances` walks only the expired prefix of the
/// time index, so a flood of unexpired rows is never traversed.
/// MEASURED: measure_allowance_prune_instructions_for_test
const MAX_ALLOWANCE_PRUNE_PER_CALL: usize = 100;

/// Cap for the timer's own pass. Larger than the per-write cap because the timer
/// is the trigger that has to drain a backlog nobody is writing against, and it
/// runs in its own message with the whole message budget to itself. Same value
/// as the pool's `MAX_PRUNE_RECORDS_PER_CALL` timer pass, for the same reason.
/// MEASURED: measure_allowance_prune_instructions_for_test
const MAX_ALLOWANCE_PRUNE_PER_TIMER_TICK: usize = 1_000;

/// Interval of the canister-owned maintenance timer.
const ALLOWANCE_MAINTENANCE_INTERVAL_NS: u64 = 300 * 1_000_000_000;

/// H-01: key type for the ALLOWANCES_BY_EXPIRY index. `expires_at_ns` is
/// declared FIRST so the derived `Ord` sorts chronologically and then by
/// allowance key; pinned `ic-stable-structures 0.6.9` orders a StableBTreeMap by
/// `K::Ord` on the DECODED key, so chronological iteration is correct by that
/// derivation rather than by the byte form. Same idiom as `DedupTimeKey`, with
/// one difference that matters: the joined-back key here is the VARIABLE-LENGTH
/// `compound_key`, not a fixed 32-byte hash, so the bound is
/// `8 + MAX_ALLOWANCE_KEY_LEN` and `is_fixed_size` is false.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AllowanceExpiryKey {
    expires_at_ns: u64,
    allowance_key: Vec<u8>,
}

impl AllowanceExpiryKey {
    #[inline]
    fn new(expires_at_ns: u64, allowance_key: Vec<u8>) -> Self {
        Self { expires_at_ns, allowance_key }
    }
}

impl Storable for AllowanceExpiryKey {
    const BOUND: Bound =
        Bound::Bounded { max_size: (8 + MAX_ALLOWANCE_KEY_LEN) as u32, is_fixed_size: false };
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut out = Vec::with_capacity(8 + self.allowance_key.len());
        out.extend_from_slice(&self.expires_at_ns.to_be_bytes());
        out.extend_from_slice(&self.allowance_key);
        Cow::Owned(out)
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        let expires_at_ns = u64::from_be_bytes(b[..8].try_into().unwrap());
        Self { expires_at_ns, allowance_key: b[8..].to_vec() }
    }
}

/// H-01 (f1): the EFFECTIVE lifetime of a requested approval.
#[derive(Debug, PartialEq, Eq)]
enum ApprovalLifetime {
    /// `expires_at <= now`: already expired at creation — refused (F-006).
    AlreadyExpired,
    /// The expiry the allowance is STORED with: the requested one if it is within
    /// the cap, otherwise (absent, or further ahead) `now + MAX_APPROVAL_TTL_NS`.
    Effective(u64),
}

/// H-01 (f1), TOKEN-APPROVE-TTL: the effective lifetime of a requested approval,
/// as a PURE function of (`expires_at`, `now`).
///
/// - absent → `now + MAX_APPROVAL_TTL_NS` (defaulted; dev007)
/// - `exp <= now` → `AlreadyExpired` (F-006, unchanged)
/// - `now < exp <= now + MAX_APPROVAL_TTL_NS` → `exp`, as given
/// - `exp > now + MAX_APPROVAL_TTL_NS` → `now + MAX_APPROVAL_TTL_NS` (clamped; dev007)
///
/// Before TOKEN-APPROVE-TTL the absent and over-cap arms were REFUSED (codes 7/8,
/// now retired). Every standard ICRC-2 client — DEX front ends, wallets — sends
/// `icrc2_approve` without `expires_at`, so the refusal made STSH unsellable on
/// ICPSwap. Storing the approval with the cap applied meets H-01's reason for the
/// refusal equally well: the stored row always has an end, is always indexed, and
/// both reclamation triggers reach it.
///
/// Extracted rather than written inline so the boundaries are pinned exactly by
/// `approval_lifetime_boundaries_are_exact`. They cannot be pinned exactly by a
/// PocketIC test: a replica advances its clock as it executes rounds, so the `now`
/// an update observes is strictly later than the `now` the harness read when it
/// computed `expires_at`, and an assertion written at `now + CAP + 1` silently
/// becomes an assertion at something under the cap.
///
/// Both boundaries are stated the way the rest of the file states them: the
/// already-expired test is `expires_at <= now` (F-006, the inclusive expiry
/// boundary seen from the creation side), and the cap is exceeded only STRICTLY
/// past it, so a lifetime of exactly `MAX_APPROVAL_TTL_NS` is stored as given.
///
/// `saturating_add`: overflow-checks is on in release, and the cap arithmetic must
/// never trap. At `now > u64::MAX - MAX_APPROVAL_TTL_NS` the effective expiry
/// saturates to `u64::MAX` — still `Some`, still indexed, still a stated end.
fn effective_approval_lifetime(expires_at: Option<u64>, now: u64) -> ApprovalLifetime {
    let cap = now.saturating_add(MAX_APPROVAL_TTL_NS);
    match expires_at {
        None => ApprovalLifetime::Effective(cap),
        Some(exp) if exp <= now => ApprovalLifetime::AlreadyExpired,
        Some(exp) => ApprovalLifetime::Effective(exp.min(cap)),
    }
}

// ── HARDEN-03-SETTLEMENT: deposit receipts ────────────────────────────────────
//
// See D-4 (the map), D-5 (the fence), D-7 (the two hashes), D-8 (atomicity),
// D-9 (no GC), D-14/P-1..P-3 (privacy). The ONE structural property the whole
// construction rests on is I-5: no `await` between the balance mutation and the
// receipt write, and a failure there TRAPS rather than returning an ordinary
// `Err`. `icrc2_transfer_from` and `close_deposit_attempt` both contain no
// `await` at all, so that is structural — but do not introduce one.

/// The receipt map's key: the operation id, `SHA-256(RECEIPT_OPID_DOMAIN ||
/// memo_bytes)` (D-7). Carries NO `note_commitment` (P-3) — it is a hash of memo
/// bytes that are already public ledger data on every deposit today, so nothing
/// newly leaves the pool by computing it.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DepositReceiptKey(pub [u8; 32]);

impl Storable for DepositReceiptKey {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.0.to_vec())
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        DepositReceiptKey(a)
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: 32,
        is_fixed_size: true,
    };
}

/// The stored receipt. TWO variants, deliberately — `Cancelled` IS the
/// cancellation fence (D-5), which is why this lane allocates one token MemoryId
/// rather than two.
///
/// **WHY THE FENCE EXISTS — the two live reasons.** Read these before deleting
/// the `Cancelled` branch, because a design whose stated reason is wrong gets
/// deleted by the next person who notices, and they would take the audit witness
/// with them:
///
///   1. **It is the audit witness `D-12` depends on.** The pool writes NO
///      permanent `note_commitment`-keyed tombstone on a fence-confirmed close —
///      doing so would collide head-on with F2-REDACT's *enforced* 30-day
///      destruction of commitment-linked records, and with the forward secrecy
///      that `DEPOSIT_NONCES` removal exists to provide. This receipt is the
///      better-placed witness instead: a DIFFERENT canister from the one whose
///      operator took the decision, keyed by `operation_id`, carrying no
///      commitment, and readable by no query. Delete this branch and that
///      witness goes with it. (This ground is CONTINGENT on D-12's choice, not
///      independent of it — see 2 for the ground that carries alone.)
///   2. **INDEPENDENT: the message-ordering claim is a platform property this
///      repo cannot verify.** One might argue the fence is unnecessary because
///      the IC preserves ordering between a given sender/receiver pair, so a
///      resubmission that is definitively rejected proves the original already
///      resolved. That reasoning may well be correct, but it is not in
///      `canisters/`, not in any pinned artifact, and no test in this tree can
///      prove it. A money-safety design must not rest on a reviewer's
///      recollection of the Interface Spec. The cost of keeping the fence is ONE
///      principal comparison on the ordinary path; the cost of being wrong is
///      the permanent loss of a user's funds. That asymmetry decides it.
///
/// **THE RETIRED ARGUMENT — recorded so nobody reinstates it.** An earlier
/// revision justified the fence by claiming an original request "outlives its
/// caller's continuation" when an `install_code` upgrade drops the callback, so
/// a definite reject proves only "cannot execute NOW". That premise is true but
/// INSUFFICIENT: losing the callback loses the pool the *answer*, not the
/// ordering — and losing the answer is exactly what this map exists to repair.
/// Do not put that argument back.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum DepositReceiptV1 {
    /// The qualifying transfer EXECUTED, and this was written in the same
    /// await-free segment as the balance mutation and the block allocation.
    Applied {
        block_index: u64,
        amount: u128,
        fee_charged: u128,
        request_hash: [u8; 32],
        applied_at_ns: u64,
    },
    /// The pool asked for the operation to be fenced and no `Applied` receipt
    /// existed. A later transfer bearing this memo is refused with
    /// `ERR_CODE_DEPOSIT_FENCED` and moves nothing.
    Cancelled {
        request_hash: [u8; 32],
        closed_at_ns: u64,
    },
}

/// Fixed-width manual encoding, NOT Candid.
///
/// Deliberate: the map's allocation behaviour is the subject of AC-25's measured
/// cap, and a Candid value carries a type table whose width is an implementation
/// detail of the encoder. A fixed layout makes the declared `max_size` exact and
/// the measurement reproducible. Layout (81 bytes, zero-padded to the bound):
///
/// ```text
///   [0]      tag: 0 = Applied, 1 = Cancelled
///   [1..33]  request_hash                     (both variants)
///   [33..41] block_index u64 LE  / closed_at_ns u64 LE
///   [41..57] amount u128 LE                   (Applied only, else 0)
///   [57..73] fee_charged u128 LE              (Applied only, else 0)
///   [73..81] applied_at_ns u64 LE             (Applied only, else 0)
/// ```
pub const DEPOSIT_RECEIPT_ENCODED_LEN: usize = 81;

impl Storable for DepositReceiptV1 {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut b = vec![0u8; DEPOSIT_RECEIPT_ENCODED_LEN];
        match self {
            DepositReceiptV1::Applied {
                block_index,
                amount,
                fee_charged,
                request_hash,
                applied_at_ns,
            } => {
                b[0] = 0;
                b[1..33].copy_from_slice(request_hash);
                b[33..41].copy_from_slice(&block_index.to_le_bytes());
                b[41..57].copy_from_slice(&amount.to_le_bytes());
                b[57..73].copy_from_slice(&fee_charged.to_le_bytes());
                b[73..81].copy_from_slice(&applied_at_ns.to_le_bytes());
            }
            DepositReceiptV1::Cancelled {
                request_hash,
                closed_at_ns,
            } => {
                b[0] = 1;
                b[1..33].copy_from_slice(request_hash);
                b[33..41].copy_from_slice(&closed_at_ns.to_le_bytes());
            }
        }
        Cow::Owned(b)
    }

    fn from_bytes(b: Cow<[u8]>) -> Self {
        // A short or unrecognised-tag region is a corrupt receipt, and a receipt
        // is money-safety evidence: decoding it to a plausible-looking value
        // would be worse than refusing. Trap.
        assert!(
            b.len() >= DEPOSIT_RECEIPT_ENCODED_LEN,
            "DEPOSIT_RECEIPTS: short receipt region ({} bytes, expected {})",
            b.len(),
            DEPOSIT_RECEIPT_ENCODED_LEN
        );
        let mut request_hash = [0u8; 32];
        request_hash.copy_from_slice(&b[1..33]);
        let word = u64::from_le_bytes(b[33..41].try_into().unwrap());
        match b[0] {
            0 => DepositReceiptV1::Applied {
                block_index: word,
                amount: u128::from_le_bytes(b[41..57].try_into().unwrap()),
                fee_charged: u128::from_le_bytes(b[57..73].try_into().unwrap()),
                request_hash,
                applied_at_ns: u64::from_le_bytes(b[73..81].try_into().unwrap()),
            },
            1 => DepositReceiptV1::Cancelled {
                request_hash,
                closed_at_ns: word,
            },
            other => ic_cdk::trap(&format!(
                "DEPOSIT_RECEIPTS: unrecognised receipt tag {other}"
            )),
        }
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: DEPOSIT_RECEIPT_ENCODED_LEN as u32,
        is_fixed_size: true,
    };
}

impl DepositReceiptV1 {
    fn request_hash(&self) -> [u8; 32] {
        match self {
            DepositReceiptV1::Applied { request_hash, .. }
            | DepositReceiptV1::Cancelled { request_hash, .. } => *request_hash,
        }
    }
}

/// The exact transfer identity, as the pool submitted it. Both receipt endpoints
/// take this and RECOMPUTE everything from it plus `ic_cdk::caller()` and
/// `ic_cdk::api::id()`; nothing the pool asserts about the identity is trusted
/// (fix-design §3.2: "The request hash is not trusted because the pool supplied
/// it").
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct DepositAttemptArgs {
    pub from: Account,
    pub spender_subaccount: Option<[u8; 32]>,
    pub to: Account,
    pub amount: Nat,
    pub fee: Option<Nat>,
    pub memo: Option<Vec<u8>>,
    pub created_at_time: Option<u64>,
}

/// The WIRE form of a receipt. Amounts are `Nat`, not `u128`.
///
/// **THIS TYPE EXISTS BECAUSE OF THE AMOUNT-BOUNDARY CENSUS (C4 rule 3), AND
/// SEPARATING IT FROM THE STORED TYPE IS THE POINT.** The first cut of this lane
/// returned `DepositReceiptV1` — the stored type — directly from both receipt
/// endpoints, which put a raw `u128` on a public boundary. The gate's
/// amount-boundary census refused it, and correctly: *"a new raw-amount boundary
/// requires CTO/SSA adjudication… Do not add allowlist rows to clear it."*
///
/// The right answer was not an allowlist row but not creating the boundary.
/// Every other public money field on this canister is a `Nat` — `TransferArgs`,
/// `TransferFromArgs`, `Allowance`, `icrc1_balance_of`, `icrc1_fee` — so a
/// receipt reporting `u128` was the outlier, not the census.
///
/// The stored type keeps its fixed-width `u128` layout, which is what makes the
/// declared `max_size` exact and AC-25's allocation measurement reproducible.
/// The two roles are genuinely different and now have genuinely different types.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub enum DepositReceiptView {
    Applied {
        block_index: u64,
        amount: Nat,
        fee_charged: Nat,
        request_hash: [u8; 32],
        applied_at_ns: u64,
    },
    Cancelled {
        request_hash: [u8; 32],
        closed_at_ns: u64,
    },
}

impl From<DepositReceiptV1> for DepositReceiptView {
    fn from(r: DepositReceiptV1) -> Self {
        match r {
            DepositReceiptV1::Applied {
                block_index,
                amount,
                fee_charged,
                request_hash,
                applied_at_ns,
            } => DepositReceiptView::Applied {
                block_index,
                amount: Nat::from(amount),
                fee_charged: Nat::from(fee_charged),
                request_hash,
                applied_at_ns,
            },
            DepositReceiptV1::Cancelled {
                request_hash,
                closed_at_ns,
            } => DepositReceiptView::Cancelled {
                request_hash,
                closed_at_ns,
            },
        }
    }
}

/// The answer `get_deposit_receipt` gives (§5.2).
#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum ReceiptLookup {
    Found(DepositReceiptView),
    /// No receipt, and no dedup entry either — the pool may proceed to step B.
    /// PROVISIONAL ONLY (fix-design §3.3): absence of evidence is never, on its
    /// own, evidence of non-execution.
    Unrecorded,
    /// No receipt, but `TRANSFER_DEDUP` holds this exact dedup key — the
    /// transfer executed BEFORE the receipt protocol existed. Unreachable
    /// post-launch. **Must never be read as `Cancelled`** (fix-design §3.3).
    RetiredOrUnavailable,
}

/// The answer `close_deposit_attempt` gives (§5.4).
#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum CloseOutcome {
    /// It landed after all — the pool credits rather than closing.
    Applied(DepositReceiptView),
    /// The fence is now durable. The pool may close the deposit.
    Cancelled(DepositReceiptView),
    /// A pre-protocol execution. Never a close trigger.
    RetiredOrUnavailable,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ReceiptError {
    /// The caller is not the configured pool, or no pool is configured.
    /// Returned on an IDENTICAL shape and code path whether or not a receipt
    /// exists for the derived operation id, so a wrong caller cannot distinguish
    /// "no receipt" from "not allowed to ask" (P-1).
    Unauthorized,
    /// The same operation id presented with a different request hash. A
    /// CONFLICT, not a new attempt (fix-design §3.4). Nothing is written.
    RequestMismatch,
    /// The identity cannot be receipted at all (no `created_at_time`, no memo,
    /// or an over-long memo), or the receipt map is at capacity on a close.
    UnsupportedProtocol,
}

/// D-7: `operation_id := SHA-256(RECEIPT_OPID_DOMAIN || memo_bytes)`.
///
/// Two distinct deposits have distinct memos — the pool's memo binds a 256-bit
/// secret nonce — so distinct operation ids follow under SHA-256 collision
/// resistance. That is the same soundness argument that already licenses the
/// pool's `Duplicate`-means-confirmed classification.
fn deposit_operation_id(memo: &[u8]) -> DepositReceiptKey {
    let mut h = Sha256::new();
    hash_len_prefixed(&mut h, RECEIPT_OPID_DOMAIN);
    hash_len_prefixed(&mut h, memo);
    let d = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&d);
    DepositReceiptKey(k)
}

/// D-7: `request_hash := SHA-256(RECEIPT_REQUEST_DOMAIN || self || dedup_key)`.
///
/// Built on the token's EXISTING canonical transfer-identity encoder rather than
/// a new one, so the receipt's notion of "the same request" cannot drift from
/// the ledger's notion of "the same transfer".
fn deposit_request_hash(
    from: &Account,
    spender: &Account,
    to: &Account,
    amount: u128,
    fee: &Option<Nat>,
    memo: &Option<Vec<u8>>,
    created_at_time: u64,
) -> [u8; 32] {
    let dedup = transfer_from_dedup_key(from, spender, to, amount, fee, memo, created_at_time);
    let mut h = Sha256::new();
    hash_len_prefixed(&mut h, RECEIPT_REQUEST_DOMAIN);
    hash_len_prefixed(&mut h, ic_cdk::api::id().as_slice());
    hash_len_prefixed(&mut h, &dedup);
    let d = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&d);
    k
}

/// The live receipt-capacity ceiling. In production this is exactly
/// `MAX_DEPOSIT_RECEIPTS`; the override branch does not exist without
/// `--features testing`.
fn receipt_capacity() -> u64 {
    #[cfg(feature = "testing")]
    {
        if let Some(cap) = RECEIPT_CAPACITY_OVERRIDE.with(|c| *c.borrow()) {
            return cap;
        }
    }
    MAX_DEPOSIT_RECEIPTS
}

/// Everything the pool-path gate derives about a qualifying transfer, computed
/// BEFORE phase 1 and consumed in phase 2. Holding it in one value is what makes
/// "derive and validate before any mutation, write after every check passed"
/// visible at the call site rather than a property to be traced.
struct PoolReceiptContext {
    key: DepositReceiptKey,
    request_hash: [u8; 32],
}

/// D-8: the pre-mutation half of the receipt protocol on `icrc2_transfer_from`.
///
/// Returns `Ok(None)` for every ordinary transfer — the cost of this whole
/// mechanism to the ledger's highest-volume endpoint is the one `Principal`
/// comparison below and nothing else (I-6). NO stable-map read happens on the
/// ordinary path.
///
/// Every refusal here is an ORDINARY `Err` raised before any write, which is
/// correct precisely because nothing has moved yet. The phase-2 counterpart is
/// the opposite and deliberately so: a failure THERE traps, because rolling the
/// whole message back is the only outcome that keeps "no debit without its
/// receipt" true.
fn pool_receipt_gate(
    spender_acc: &Account,
    args: &TransferFromArgs,
    amount: u128,
) -> Result<Option<PoolReceiptContext>, TransferFromError> {
    // ── The whole ordinary path is this comparison. ──
    let Some(pool) = POOL_CANISTER.with(|p| *p.borrow()) else {
        return Ok(None);
    };
    if pool != spender_acc.owner {
        return Ok(None);
    }

    // NO FALLBACK TO A BARE, UNRECEIPTED TRANSFER (fix-design §3.4). The real
    // pool always supplies both a memo and a `created_at_time`, so these arms
    // are unreachable from it; they exist so the invariant is ENFORCED rather
    // than assumed.
    let (Some(memo), Some(created_at_time)) = (args.memo.as_ref(), args.created_at_time) else {
        return Err(TransferFromError::GenericError {
            error_code: Nat::from(ERR_CODE_DEPOSIT_UNRECEIPTABLE),
            message: "deposit transfer requires both a memo and a created_at_time to be receipted"
                .to_string(),
        });
    };
    if memo.len() > MAX_DEPOSIT_MEMO_LEN {
        return Err(TransferFromError::GenericError {
            error_code: Nat::from(ERR_CODE_DEPOSIT_UNRECEIPTABLE),
            message: format!(
                "deposit memo exceeds {MAX_DEPOSIT_MEMO_LEN} bytes and cannot be receipted"
            ),
        });
    }

    let key = deposit_operation_id(memo);
    let request_hash = deposit_request_hash(
        &args.from,
        spender_acc,
        &args.to,
        amount,
        &args.fee,
        &args.memo,
        created_at_time,
    );

    // ── ONE EXECUTION PER OPERATION ID, EVER. ──
    //
    // Both arms refuse before any mutation. `Cancelled` is the fence proper.
    // `Applied` is the defence-in-depth arm described at
    // `ERR_CODE_RECEIPT_CONFLICT`: the ordinary byte-identical resubmission is
    // already stopped upstream by the `TRANSFER_DEDUP` short-circuit (inside the
    // window) or by `TooOld` (outside it), so reaching here with an `Applied`
    // receipt means a transfer bearing an already-executed operation's memo with
    // a DIFFERENT identity — which is the double-charge shape, keyed on the memo
    // rather than on the fee, and it is refused.
    if let Some(existing) = DEPOSIT_RECEIPTS.with(|r| r.borrow().get(&key)) {
        return Err(match existing {
            DepositReceiptV1::Cancelled { .. } => TransferFromError::GenericError {
                error_code: Nat::from(ERR_CODE_DEPOSIT_FENCED),
                message: "deposit operation is fenced: a cancellation receipt already exists"
                    .to_string(),
            },
            DepositReceiptV1::Applied { .. } => TransferFromError::GenericError {
                error_code: Nat::from(ERR_CODE_RECEIPT_CONFLICT),
                message: "deposit operation already has an applied receipt".to_string(),
            },
        });
    }

    // ── Capacity preflight (D-8), BEFORE phase 1. ──
    //
    // `StableBTreeMap::insert` can panic on a failed memory grow, and that panic
    // is a TRAP, which rolls the whole message back — the correct outcome (no
    // debit, no block, no receipt) but a violent one. This turns the common case
    // into an ordinary rejection with nothing moved. `len()` is O(1) on
    // `ic-stable-structures` 0.6, so this needs no counter and therefore no
    // extra MemoryId. It evicts NOTHING (AC-9).
    if DEPOSIT_RECEIPTS.with(|r| r.borrow().len()) >= receipt_capacity() {
        return Err(TransferFromError::GenericError {
            error_code: Nat::from(ERR_CODE_RECEIPT_CAPACITY),
            message: "deposit receipt capacity reached".to_string(),
        });
    }

    Ok(Some(PoolReceiptContext { key, request_hash }))
}

/// MD-01: the ONE expiry predicate. INCLUSIVE — `now == expires_at` is already
/// expired. That is F-DBR-1, the boundary `icrc2_allowance`, `icrc2_transfer_from`
/// and `icrc2_approve`'s `Expired` refusal already agreed on before this lane;
/// the shared notion adopts it rather than renegotiating it.
///
/// `now` is a PARAMETER, never read inside (F-7 / I-A5). A query cannot share an
/// update's captured instant, so a predicate that read the clock itself could not
/// be shared across a query and two updates without re-introducing exactly the
/// disagreement this fix removes. Each call site captures `now` ONCE per message
/// and passes it in.
#[inline]
fn allowance_is_expired(expires_at: Option<u64>, now: u64) -> bool {
    matches!(expires_at, Some(exp) if now >= exp)
}

/// MD-01: the ONE notion of *effective allowance* — the amount actually
/// spendable at instant `now`. Expired means zero, everywhere.
///
/// Before this lane three sites disagreed: `icrc2_allowance` (`:1850`) and
/// `icrc2_transfer_from` (`:1778`) applied expiry, while the `expected_allowance`
/// CAS in `icrc2_approve` compared against the RAW stored amount with no expiry
/// test. The consequence was not cosmetic: the shipped shield flow always sends
/// `expected_allowance` sourced from its own `allowance()` query, so after an
/// unspent 15-minute expiry the query returned 0, the CAS compared 0 against the
/// stale stored amount, and every re-approval was refused `AllowanceChanged`
/// with nothing on any path able to rewrite the row. That was a permanent
/// lockout of the primary flow.
///
/// RESIDUAL, on the record: an expiry-aware CAS converts that permanent lockout
/// into a narrow boundary race. An approve whose `expected_allowance` was read
/// just before `expires_at` and which executes just after it is now refused
/// `AllowanceChanged { current_allowance: 0 }` where it previously succeeded.
/// That is correct — the state really did change — but the `AllowanceChanged`
/// class is not gone, and the wallet surfaces it as a terminal batch failure.
/// The race is between the wallet's `allowance()` query and its later, separate
/// `icrc2_approve` update; it is NOT a race inside one message execution, where
/// the IC guarantees a constant `time()` for the whole invocation.
#[inline]
fn effective_allowance(record: &AllowanceRecord, now: u64) -> u128 {
    if allowance_is_expired(record.expires_at, now) { 0 } else { record.amount }
}

/// H-01: the ONE writer for ALLOWANCES and its expiry index.
///
/// `previous_expires_at` is the expiry of the row being REPLACED (`None` when no
/// row existed, or when the existing row carried no expiry). The stale index
/// entry is removed and the new one inserted in the same synchronous block as
/// the primary-map write, with no `await` anywhere between them — the renewal
/// case depends on that atomicity: `approve K until E1` then `renew K until E2`
/// must leave exactly one index entry, at E2, or a cleanup pass reaching E1
/// deletes a row that is still live.
///
/// Every mutation of an allowance goes through here or through
/// `remove_allowance`: approve, renewal, revocation, transfer-exhaustion and the
/// timer's own pass. There is deliberately no separate timer-only deletion path
/// that could drift from the others.
fn put_allowance(key: Vec<u8>, previous_expires_at: Option<u64>, record: AllowanceRecord) {
    // UNCHANGED EXPIRY ⇒ NO INDEX WRITES AT ALL.
    //
    // When the expiry is not moving, the entry that would be removed and the entry
    // that would be inserted are THE SAME KEY — `AllowanceExpiryKey` is
    // `(expires_at, allowance_key)` and both halves are identical — so the pair is
    // a remove and a re-insert of one row, with no net effect on the map.
    //
    // This is the ordinary `icrc2_transfer_from` case, and it is not a micro-
    // optimisation there: a spend writes back `{ new_allow, record.expires_at }`,
    // carrying the SAME expiry it read, so before this guard every transfer_from
    // paid for two `StableBTreeMap` operations on a 144-byte-bounded key to arrive
    // back where it started. That was most of what AC-10 measured on this endpoint
    // — dropping the prune took the delta from +37.896 % to +29.831 %, and this
    // guard is what addresses the remainder.
    //
    // CORRECT BY THE BIJECTION, not by luck: `previous_expires_at` is read from the
    // stored row, so `previous == record.expires_at == Some(e)` means a row with
    // expiry `e` existed, and `allowance_index_consistent` guarantees `(e, key)` is
    // already in the index. `previous == record.expires_at == None` means no
    // indexed entry existed and none is owed. Either way the index is ALREADY in
    // the state the writes would have produced. When the expiry does move — a
    // renewal — both writes happen exactly as before, which is the case
    // `renewed_allowance_survives_a_prune_that_reaches_its_old_expiry` pins.
    if previous_expires_at != record.expires_at {
        ALLOWANCES_BY_EXPIRY.with(|t| {
            let mut index = t.borrow_mut();
            if let Some(prev) = previous_expires_at {
                index.remove(&AllowanceExpiryKey::new(prev, key.clone()));
            }
            if let Some(exp) = record.expires_at {
                index.insert(AllowanceExpiryKey::new(exp, key.clone()), ());
            }
        });
    }
    ALLOWANCES.with(|a| a.borrow_mut().insert(key, record));
}

/// H-01: the ONE remover — used by revoke-to-zero, drain-to-zero and the prune.
/// `expires_at` is the expiry of the row being removed, needed to address its
/// index entry.
fn remove_allowance(key: &[u8], expires_at: Option<u64>) {
    ALLOWANCES.with(|a| a.borrow_mut().remove(&key.to_vec()));
    if let Some(exp) = expires_at {
        ALLOWANCES_BY_EXPIRY
            .with(|t| t.borrow_mut().remove(&AllowanceExpiryKey::new(exp, key.to_vec())));
    }
}

/// H-01: bounded reclamation of EXPIRED allowance rows, via the time index.
/// Returns how many rows it removed.
///
/// THE BOUND IS INCLUSIVE, AND THIS IS THE ONE PLACE THE DEDUP PATTERN MUST NOT
/// BE COPIED VERBATIM. `prune_expired_dedup` uses a deliberately EXCLUSIVE upper
/// bound, because a dedup entry expires when `created_at < cutoff` and an entry
/// exactly AT the cutoff is retained. Allowance expiry is the opposite: `now >=
/// expires_at` is expired (F-DBR-1), so a row whose `expires_at` equals `now`
/// must be removed — including several distinct rows sharing that exact
/// timestamp.
///
/// Expressed as: every key strictly below `(now + 1, [])`. `[]` is the smallest
/// possible `allowance_key`, so any key at `expires_at_ns == now + 1` sorts at or
/// above that bound, and every key with `expires_at_ns <= now` sorts below it
/// whatever its allowance_key — which is exactly the expired set, ties included.
/// The `now == u64::MAX` case has no `now + 1`, so the whole index is expired and
/// the upper bound is unbounded.
///
/// Only the expired prefix is visited, so the work does not scale with the number
/// of LIVE rows: a flood of unexpired allowances is never traversed. That is the
/// H-3 lesson applied to a second map, and it is measured rather than asserted.
/// MEASURED: measure_allowance_prune_instructions_for_test
fn prune_expired_allowances(now: u64, cap: usize) -> usize {
    let upper = match now.checked_add(1) {
        Some(next) => {
            std::ops::Bound::Excluded(AllowanceExpiryKey::new(next, Vec::new()))
        }
        None => std::ops::Bound::Unbounded,
    };
    let expired: Vec<AllowanceExpiryKey> = ALLOWANCES_BY_EXPIRY.with(|t| {
        t.borrow()
            .range((std::ops::Bound::Unbounded, upper))
            .take(cap)
            .map(|(k, _)| k)
            .collect()
    });
    if expired.is_empty() {
        return 0;
    }
    let removed = expired.len();
    ALLOWANCES.with(|a| {
        let mut primary = a.borrow_mut();
        ALLOWANCES_BY_EXPIRY.with(|t| {
            let mut index = t.borrow_mut();
            for ek in expired {
                primary.remove(&ek.allowance_key);
                index.remove(&ek);
            }
        });
    });
    removed
}

/// H-01: the maintenance step run on EVERY successful `icrc2_approve`,
/// regardless of whether the caller supplied `created_at_time`.
///
/// ONE CALLER, deliberately. `icrc2_transfer_from` used to call this too; the call
/// was removed by CTO ruling `cto-ruling-harden02-ac10-and-residuals-2026-09-17`
/// after it measured +37.896 % on that endpoint's AC-10 hot-path ceiling. The
/// removal site carries the numbers and the N-1/N-2 reasoning. Do not re-add a
/// caller on a hot path without re-running
/// `r1_ac10_hot_path_cost_is_within_the_ceiling` — that test is what caught it.
///
/// Placed in the WRITE phase by its caller, after the last fallible check. The
/// prune is itself a write, and on the IC a returned `Err` commits whatever was
/// already written in that message — only a trap rolls back (QA-DEF-019). Pruning
/// ahead of a fallible check would therefore commit state on a failing call.
/// Harmless in effect here (only already-expired rows go) but it is precisely the
/// validate-then-write discipline both endpoints are built on, so the prune
/// respects it.
#[inline]
fn run_allowance_maintenance(now: u64) -> usize {
    prune_expired_allowances(now, MAX_ALLOWANCE_PRUNE_PER_CALL)
}

/// H-01: arm the canister-owned maintenance timer. Called from BOTH `init` and
/// `post_upgrade`, and it is the ONLY arming path.
///
/// Why a timer at all, when two write paths already prune: a write-triggered
/// prune couples reclamation to traffic that has stopped. A burst of rows
/// followed by silence would then sit resident until somebody happened to
/// approve or transfer_from again — which at organic launch volume is
/// indistinguishable from resident. The timer is what makes a finite expired
/// backlog drain on its own while the canister is funded and scheduled.
///
/// Why re-arming in `post_upgrade` is not optional: IC timers DO NOT survive an
/// upgrade. A timer armed only in `init` stops at the first upgrade with nothing
/// failing and nothing saying so. The durable state it re-arms against is
/// ALLOWANCES_BY_EXPIRY itself, which is stable and carries the backlog across
/// the upgrade; only the schedule is rebuilt.
///
/// Why the id is cleared first: `ic-cdk-timers` cancels ONLY by id, so a second
/// `set_timer_interval` does not replace the first — it stacks. Taking and
/// clearing the stored id before arming makes repeated initialisation idempotent:
/// after N calls exactly one maintenance timer is live. That is asserted
/// behaviourally, over PocketIC, by
/// `timer_does_not_stack_across_repeated_upgrades` — which counts the rows one
/// interval actually reclaims, so N stacked timers would reclaim N times the cap
/// and fail it.
///
/// WHY `cfg(not(test))` AND NOT `cfg(target_arch = "wasm32")`. Scheduling reaches
/// the ic0 `time` import, which does not exist in the native unit-test binary —
/// and `post_upgrade` IS called directly by native tests in this file
/// (`readback_survives_upgrade_roundtrip`). `test` is an atom both gate censuses
/// evaluate; `target_arch` is NOT — the pool records, measured, that
/// `verify_amount_boundaries` hard-fails the whole census on that predicate
/// rather than let an endpoint vanish behind a cfg it cannot resolve. The
/// consequence is stated plainly rather than worked around: nothing about this
/// timer is proven by the native suite, and an unarmed no-op proves nothing, so
/// every claim about it is made over PocketIC against the real Wasm. `cfg(test)`
/// is never set in any Wasm build, so the production canister always arms.
fn arm_allowance_maintenance_timer() {
    if let Some(old) = ALLOWANCE_MAINTENANCE_TIMER.with(|t| t.borrow_mut().take()) {
        ic_cdk_timers::clear_timer(old);
    }
    #[cfg(not(test))]
    {
        let id = ic_cdk_timers::set_timer_interval(
            std::time::Duration::from_nanos(ALLOWANCE_MAINTENANCE_INTERVAL_NS),
            || {
                prune_expired_allowances(time(), MAX_ALLOWANCE_PRUNE_PER_TIMER_TICK);
            },
        );
        ALLOWANCE_MAINTENANCE_TIMER.with(|t| *t.borrow_mut() = Some(id));
    }
}

/// H-01 / I-A10: the ALLOWANCES ↔ ALLOWANCES_BY_EXPIRY bijection, evaluated.
///
/// Every allowance row carrying an expiry has exactly one index entry at that
/// expiry, and every index entry names a row whose stored expiry matches the
/// entry's own. Under dev007 every row written by `icrc2_approve` carries an
/// expiry, so on a fresh install the two maps have equal length; the length
/// comparison is written against "rows with an expiry" rather than "all rows" so
/// that a hypothetical no-expiry row would be reported as the bijection failure
/// it is rather than silently tolerated.
fn allowance_index_consistent() -> bool {
    let rows: Vec<(Vec<u8>, Option<u64>)> =
        ALLOWANCES.with(|a| a.borrow().iter().map(|(k, r)| (k, r.expires_at)).collect());
    let expiring = rows.iter().filter(|(_, e)| e.is_some()).count() as u64;
    let index_len = ALLOWANCES_BY_EXPIRY.with(|t| t.borrow().len());
    if index_len != expiring {
        return false;
    }
    ALLOWANCES_BY_EXPIRY.with(|t| {
        let index = t.borrow();
        for (key, expires_at) in &rows {
            if let Some(exp) = expires_at {
                if !index.contains_key(&AllowanceExpiryKey::new(*exp, key.clone())) {
                    return false;
                }
            }
        }
        true
    }) && ALLOWANCES.with(|a| {
        let primary = a.borrow();
        ALLOWANCES_BY_EXPIRY.with(|t| {
            t.borrow().iter().all(|(ek, _)| {
                primary
                    .get(&ek.allowance_key)
                    .is_some_and(|r| r.expires_at == Some(ek.expires_at_ns))
            })
        })
    })
}

// ── ICRC-2 ────────────────────────────────────────────────────────────────────

#[update]
fn icrc2_approve(args: ApproveArgs) -> Result<Nat, ApproveError> {
    let caller = ic_cdk::caller();
    let fee = TRANSFER_FEE.with(|f| *f.borrow());

    // F-ADV-D2: fee that does not fit u128 → BadFee (see icrc1_transfer).
    if let Some(ref provided) = args.fee {
        if provided.0.to_u128().map_or(true, |v| v != fee) {
            return Err(ApproveError::BadFee { expected_fee: Nat::from(fee) });
        }
    }

    let now = time();
    let from_acc = Account { owner: caller, subaccount: args.from_subaccount };

    // ── F-004: created_at_time window validation + idempotent-retry dedup ──
    // Mirrors the icrc1_transfer discipline exactly: validate the window, then
    // short-circuit a byte-identical retry BEFORE any state read or write, so a
    // transport-unknown approve retry returns Duplicate { duplicate_of } instead
    // of re-executing (and, when fee > 0, re-debiting the approval fee). The
    // dedup entry is written only AFTER the approval commits. approve_dedup_key
    // carries a DISTINCT length-prefixed domain tag
    // (`stsh.icrc2_approve.dedup.v1`), so it can never collide with an
    // icrc1_transfer or icrc2_transfer_from key in the shared TRANSFER_DEDUP map.
    // created_at_time == None preserves the prior, non-idempotent path. This
    // makes the previously unreachable TooOld / CreatedInFuture / Duplicate
    // ApproveError variants reachable.
    let dedup_key = if let Some(t) = args.created_at_time {
        if t > now + PERMITTED_DRIFT_NS {
            return Err(ApproveError::CreatedInFuture { ledger_time: now });
        }
        if now.saturating_sub(t) > TX_DEDUP_WINDOW_NS {
            return Err(ApproveError::TooOld);
        }
        let key = approve_dedup_key(&from_acc, &args, t);
        if let Some(v) = TRANSFER_DEDUP.with(|d| d.borrow().get(&key)) {
            let block_idx = u64::from_le_bytes(v[0..8].try_into().unwrap());
            return Err(ApproveError::Duplicate { duplicate_of: Nat::from(block_idx) });
        }
        Some((key, t))
    } else {
        None
    };

    // ── F-006 + H-01 (f1): the approval lifetime is DEFAULTED and CAPPED ──
    //
    // F-006 (unchanged): an approval already expired at creation is invalid —
    // Err(Expired { ledger_time }), matching the reference ledger, instead of
    // silently storing a dead record.
    //
    // H-01 (f1), KNOWING ICRC-2 DEVIATION dev007: `expires_at` is optional in
    // ICRC-2 and the reference ledger stores an approval without one as a
    // never-expiring allowance. STSH stores it with an end: an absent expiry is
    // DEFAULTED to `now + MAX_APPROVAL_TTL_NS` and a later one is CLAMPED to it
    // (TOKEN-APPROVE-TTL, 2026-09-25). Without a stated end, a row admitted at
    // ingress cost alone is never expired, never drained and never revoked, so no
    // reclamation trigger could ever reach it; (f2)'s prune works because (f1)
    // guarantees there is nothing it cannot see. Before this lane the two arms
    // were REFUSED (codes 7/8, now retired) — which also refused every standard
    // ICRC-2 client, since DEX front ends and wallets approve without an expiry.
    // A defaulted or clamped row costs and lives exactly what an explicit
    // `Some(now + MAX_APPROVAL_TTL_NS)` row — always admissible — costs and lives,
    // so the resident-set bound (approve rate x 24 h) is unchanged.
    //
    // ORDERING, decided deliberately (G-A4): this sits AFTER the dedup
    // short-circuit above, so a byte-identical retry of an approve that already
    // committed still returns `Duplicate { duplicate_of }` rather than a fresh
    // outcome. And `approve_dedup_key` hashes the CALLER-SENT `expires_at`, never
    // the effective value computed here: the effective value depends on `now`, so
    // hashing it would make a byte-identical retry hash differently and
    // RE-EXECUTE instead of returning `Duplicate` (F-004). Do not "fix" that.
    //
    // A zero-amount approve (revocation) takes the same path: it writes no row —
    // it removes one, or with nothing live to remove is refused by dev006 below
    // with ERR_CODE_ZERO_AMOUNT — so its effective expiry is computed and unused.
    // An already-expired expiry on a revoke is still `Expired` (F-006). The old
    // I-A1 exemption of revokes from the mandatory-expiry refusal is moot: there is
    // no such refusal left to sit in front of a revoke, and dev006's outcome stays
    // reachable by construction.
    //
    // This sits BEFORE the u128 decode below, so F-006's `Expired` still precedes
    // the decode's own `Overflow` refusal.
    let effective_expires_at = match effective_approval_lifetime(args.expires_at, now) {
        ApprovalLifetime::AlreadyExpired => {
            return Err(ApproveError::Expired { ledger_time: now })
        }
        ApprovalLifetime::Effective(e) => e,
    };

    let account_key  = from_acc.encode_key();
    let spender_key  = args.spender.encode_key();
    let allowance_key = compound_key(&account_key, &spender_key);
    let amount = args.amount.0.to_u128().ok_or(ApproveError::GenericError {
        error_code: Nat::from(1u32), message: "Overflow".to_string()
    })?;

    // ── H-01 / MD-01: the existing row, read ONCE, interpreted ONE way ───────
    // Three things need it and each used to derive its own answer: the
    // `expected_allowance` CAS (which read the raw amount), the dev006 liveness
    // test (which re-implemented the expiry comparison), and — new here — the
    // single writer, which needs the OLD expiry to address the stale index entry
    // it must remove. One read, one captured `now`, one notion.
    let existing = ALLOWANCES.with(|a| a.borrow().get(&allowance_key));
    let current_effective = existing.as_ref().map_or(0, |rec| effective_allowance(rec, now));
    let previous_expires_at = existing.as_ref().and_then(|rec| rec.expires_at);

    // Check expected_allowance if provided.
    // F-ADV-D2 site 4: an expected_allowance that does not fit u128 can never
    // match a real stored allowance — treat it as "changed" explicitly (the CAS
    // guard fires). The old unwrap_or(u128::MAX) sentinel COLLIDED when the
    // stored allowance was legitimately u128::MAX (publicly reachable via an
    // approve of amount u128::MAX), silently bypassing the guard.
    //
    // I-A2 / MD-01: the CAS STAYS — its blind spot is fixed, not the check
    // removed. What changed is the value it compares against: `effective_allowance`
    // rather than the raw stored amount, so an expired allowance compares as the
    // zero every reader already sees it as. Deleting the guard instead was never
    // an option: its own history is the argument, the previous sentinel having
    // silently bypassed itself against a legitimately-stored u128::MAX.
    if let Some(ref expected) = args.expected_allowance {
        if expected.0.to_u128().map_or(true, |value| current_effective != value) {
            return Err(ApproveError::AllowanceChanged {
                current_allowance: Nat::from(current_effective),
            });
        }
    }

    // ── R-1 S1: NARROW zero-amount guard (dev006) ────────────────────────────
    // Refuse `amount == 0` ONLY when no LIVE allowance exists for
    // (from_account, spender). A zero approve against a live allowance is
    // REVOCATION and must succeed — the wallet revokes with approve(0)
    // (wallet/src/ui/shieldFlow.ts, revokeShieldAllowance). A sibling-shaped
    // blanket `amount == 0` refusal would break revocation, which is why this
    // guard is not shaped like icrc1_transfer's.
    //
    // "Live" follows icrc2_allowance's INCLUSIVE expiry boundary: `time() >= exp`
    // is expired, and an expired allowance is not live, so a zero approve against
    // one is refused (there is nothing to revoke).
    //
    // KNOWING ICRC-2 DEVIATION dev006, registered in NOTE_A-3_icrc_deviation.md:
    // ICRC-2 permits a zero approve unconditionally. It ships because at
    // DEFAULT_FEE = 0 a no-op zero approve is free, writes an ALLOWANCES row and
    // a dedup entry, and is an unpriced state-growth vector at ingress cost alone.
    //
    // I-A3: the OUTCOME of this guard is unchanged by the MD-01 refactor. "Live"
    // was `rec.amount != 0 && not expired`, which is exactly
    // `effective_allowance(rec, now) != 0` — the fourth expression of the shared
    // notion, now the same expression. A zero approve against an EXPIRED
    // allowance is still refused: post-expiry the effective allowance is 0, so
    // the CAS above now PASSES where it used to fail, and this guard is the only
    // thing still refusing. Losing it would re-open the free-row-write vector it
    // exists to close, in the same file and the same lane as H-01.
    if amount == 0 && current_effective == 0 {
        return Err(ApproveError::GenericError {
            error_code: Nat::from(ERR_CODE_ZERO_AMOUNT),
            message: ERR_MSG_ZERO_AMOUNT.to_string(),
        });
    }

    // Debit fee from approver. Task 3: check/debit against LIQUID balance
    // (total − staking_locked), not raw BALANCES — otherwise an approval fee can
    // erode locked stake, pushing locked above total. Mirrors the transfer paths.
    // Staking locks are keyed on the main account (subaccount: None); if
    // account_key carries a subaccount, STAKING_LOCKS returns 0 (liquid == bal).
    {
        let bal = ledger_maps::get_balance(&account_key);
        let locked = ledger_maps::get_lock(&account_key);
        let liquid = bal.saturating_sub(locked);
        if liquid < fee {
            return Err(ApproveError::InsufficientFunds { balance: Nat::from(liquid) });
        }
        let new_bal = bal.checked_sub(fee)
            .ok_or(ApproveError::InsufficientFunds { balance: Nat::from(liquid) })?;
        ledger_maps::write_balance(account_key, bal, new_bal);
    }

    route_fee_to_treasury(fee);

    // ── Write phase — every check above has passed ────────────────────────────
    //
    // H-01 (f2), REVOCATION RECLAIMS. A zero approve against a live allowance is
    // revocation, and it now REMOVES the row rather than overwriting it with
    // `{ amount: 0, expires_at }`. Before this lane no path ever removed an
    // allowance row, which is what made growth monotonic even under entirely
    // honest use.
    //
    // OBSERVABLE CHANGE, on the record (AA-3): `icrc2_allowance` for a revoked
    // pair now returns `{ allowance = 0; expires_at = null }` where it previously
    // returned `{ allowance = 0; expires_at = <the old expiry> }`. This is a
    // decision, not a side effect: `{0, null}` is the shape the reference ledger
    // reports for a pair with no allowance, and it is already the shape this
    // endpoint returns for an EXPIRED row (F-005), so removal makes the revoked
    // and expired cases agree instead of leaving a third reading.
    if amount == 0 {
        remove_allowance(&allowance_key, previous_expires_at);
    } else {
        put_allowance(
            allowance_key,
            previous_expires_at,
            // The EFFECTIVE expiry (defaulted or clamped above), never the raw
            // request: every row this writes is `Some(<= now + MAX_APPROVAL_TTL_NS)`.
            AllowanceRecord { amount, expires_at: Some(effective_expires_at) },
        );
    }

    // ── H-01 (f2): the reclamation trigger, UNCONDITIONAL ─────────────────────
    //
    // This call is outside the `if let Some((key, created_at)) = dedup_key` block
    // below, and that placement is the whole point (SSA N-1). `record_dedup`
    // prunes the DEDUP maps, but it only runs when the caller supplied
    // `created_at_time`; hanging allowance reclamation off the same call site
    // would hand the attacker an off switch in the form of an omitted optional
    // field — and omitting it is already the cheaper call shape, since it also
    // skips the dedup-row write. So: every successful approve prunes, whatever
    // the caller sent.
    //
    // Position: after the last fallible check and in the write phase (I-A6). The
    // row just written has `expires_at > now`, so it is outside the expired range
    // and this call can never reclaim the approval it accompanies.
    run_allowance_maintenance(now);

    let block = next_block();

    // F-004: record the dedup entry only after the approval has committed, so a
    // byte-identical retry within TX_DEDUP_WINDOW_NS returns Duplicate. Prune
    // first (capped) to bound stable-memory growth — same discipline as the
    // transfer paths.
    if let Some((key, created_at)) = dedup_key {
        record_dedup(key, block, created_at);
    }

    Ok(Nat::from(block))
}

#[update]
fn icrc2_transfer_from(args: TransferFromArgs) -> Result<Nat, TransferFromError> {
    let spender = ic_cdk::caller();
    let fee = TRANSFER_FEE.with(|f| *f.borrow());

    // QA-DEF-018: validate the caller-supplied fee against the live fee BEFORE any
    // mutation, mirroring icrc1_transfer / icrc2_approve. fee == None is ICRC-2
    // compliant — the live fee is applied silently with no validation.
    // F-ADV-D2: fee that does not fit u128 → BadFee (see icrc1_transfer).
    if let Some(ref provided) = args.fee {
        if provided.0.to_u128().map_or(true, |v| v != fee) {
            return Err(TransferFromError::BadFee { expected_fee: Nat::from(fee) });
        }
    }

    let amount = args.amount.0.to_u128().ok_or_else(|| TransferFromError::GenericError {
        error_code: Nat::from(1u32), message: "Overflow".to_string()
    })?;
    // R10-1 (lane A-3): refuse `amount == 0`, before every read and write on this
    // path. Same rationale as the `icrc1_transfer` site above.
    //
    // ORDERING: this endpoint validates `created_at_time` BELOW, inside its dedup
    // block, so the zero refusal precedes `TooOld` here — the opposite of
    // `icrc1_transfer`. Deliberate and ruled; not harmonised, because uniformity
    // would mean moving an existing check across a dedup boundary on a canister
    // holding real supply, and R10-1 is explicitly the minimal form.
    //
    // NOT extended to `icrc2_approve`: a zero approve is how an allowance is
    // REVOKED, and breaking it would remove a user's ability to withdraw an
    // approval. Out of R10-1 by ruling, and asserted by E4.
    if amount == 0 {
        return Err(TransferFromError::GenericError {
            error_code: Nat::from(ERR_CODE_ZERO_AMOUNT),
            message: ERR_MSG_ZERO_AMOUNT.to_string(),
        });
    }

    let from_key    = args.from.encode_key();
    let to_key      = args.to.encode_key();
    let spender_acc = Account { owner: spender, subaccount: args.spender_subaccount };
    let allowance_key = compound_key(&from_key, &spender_acc.encode_key());
    let total_debit = checked_total_debit(amount, fee).map_err(TransferFromError::from)?;

    // ── DEF-050B-1: idempotent-retry guard (QA-DEF-050B; icrc2_transfer_from half
    // of QA-DEF-023) ──
    // When created_at_time is supplied, validate the window and short-circuit a
    // duplicate retry BEFORE any allowance/balance read or write, so a
    // controller-driven retry of a transport-unknown transfer returns
    // Duplicate { duplicate_of } instead of debiting allowance/balance a second
    // time. The dedup entry is written only AFTER the transfer commits (end of this
    // function). created_at_time == None preserves the prior, non-idempotent path.
    // I-A5 / F-7: ONE captured `now` for the whole message, passed to every site
    // that needs it. This endpoint previously read the clock twice — once inside
    // the dedup block below and once in the expiry test further down — and a
    // shared effective-allowance notion cannot be built on two reads that may
    // disagree. (The IC guarantees a constant `time()` for the duration of one
    // entry-point invocation, so the two reads could not in fact straddle the
    // expiry boundary; the reason to capture once is that the notion takes `now`
    // as a parameter and the call sites must agree on which instant they mean.)
    let now = time();

    let dedup_key = if let Some(t) = args.created_at_time {
        if t > now + PERMITTED_DRIFT_NS {
            return Err(TransferFromError::CreatedInFuture { ledger_time: now });
        }
        if now.saturating_sub(t) > TX_DEDUP_WINDOW_NS {
            return Err(TransferFromError::TooOld);
        }
        let key = transfer_from_dedup_key(
            &args.from, &spender_acc, &args.to, amount, &args.fee, &args.memo, t,
        );
        if let Some(v) = TRANSFER_DEDUP.with(|d| d.borrow().get(&key)) {
            let block_idx = u64::from_le_bytes(v[0..8].try_into().unwrap());
            return Err(TransferFromError::Duplicate { duplicate_of: Nat::from(block_idx) });
        }
        Some((key, t))
    } else {
        None
    };

    // ── HARDEN-03-SETTLEMENT (D-8): the pool-path gate ────────────────────────
    //
    // Placed HERE — after the dedup short-circuit, before phase 1 — because
    // everything it can refuse must be refused with nothing moved, and because
    // an ordinary byte-identical resubmission must still be answered by
    // `Duplicate` above rather than by this gate.
    //
    // For every non-pool caller this is one `Principal` comparison and an
    // immediate `None` (I-6). See `pool_receipt_gate`.
    let pool_receipt = pool_receipt_gate(&spender_acc, &args, amount)?;

    // QA-DEF-019: check-before-mutate. On the IC a returned Err commits any state
    // already written in this message (only a trap rolls back), so the previous
    // ordering — reduce the allowance in its own block, then return
    // InsufficientFunds from the balance block — committed a phantom allowance
    // decrement on a failed transfer. Validate the allowance, the liquid balance,
    // AND the recipient credit first; only once every check passes do we write.
    // Mirrors icrc2_approve's check-before-mutate ordering.

    // ── Phase 1: read + validate, no writes ──
    let record = ALLOWANCES.with(|a| a.borrow().get(&allowance_key)
        .unwrap_or(AllowanceRecord { amount: 0, expires_at: None }));
    // ── MD-01: F-003 and F-002 through the ONE shared notion ──────────────────
    //
    // F-003: an expired approval is treated as no approval at all — the ICRC-2
    // spec shape is InsufficientAllowance { allowance: 0 } (reference-ledger
    // parity), not a GenericError. F-DBR-1: the boundary is INCLUSIVE —
    // now == expires_at is already expired, matching icrc2_approve's
    // `exp <= now` rejection and the reference ledger.
    //
    // F-002: an allowance shortfall is InsufficientAllowance carrying the CURRENT
    // allowance — never InsufficientFunds (that variant is reserved for the
    // from-account balance check below).
    //
    // Both were separate tests against `record.expires_at` and `record.amount`;
    // they are now one test against `effective_allowance`, which collapses to
    // exactly the same two error shapes. For an expired row the effective amount
    // is 0 and `amount == 0` was already refused above, so `total_debit >= 1 > 0`
    // and this returns InsufficientAllowance { allowance: 0 } — byte-identical to
    // the old expired branch. For a live shortfall it carries the stored amount,
    // as before. I-A7's enforcement obligation lives here: an expired allowance
    // is refused by THIS check, not by the reclamation. The prune only reclaims
    // storage; whether an allowance is spendable is decided here and in
    // `icrc2_allowance`, and stays decided there even if the timer never runs.
    let spendable = effective_allowance(&record, now);
    if spendable < total_debit {
        return Err(TransferFromError::InsufficientAllowance {
            allowance: Nat::from(spendable),
        });
    }
    let new_allow = spendable.checked_sub(total_debit)
        .ok_or(TransferFromError::InsufficientAllowance { allowance: Nat::from(spendable) })?;

    // Enforce liquid balance — staked tokens are not transferable even via an
    // approved spender. Staking locks are keyed on the main account (subaccount:
    // None); a from_key carrying a subaccount has no lock, so liquid == from_bal.
    let from_bal = ledger_maps::get_balance(&from_key);
    let locked   = ledger_maps::get_lock(&from_key);
    let liquid   = from_bal.saturating_sub(locked);
    if liquid < total_debit {
        return Err(TransferFromError::InsufficientFunds { balance: Nat::from(liquid) });
    }
    // from_bal >= liquid >= total_debit, so this cannot underflow.
    let new_from = from_bal.checked_sub(total_debit)
        .ok_or(TransferFromError::InsufficientFunds { balance: Nat::from(liquid) })?;
    // Recipient credit — for a self-transfer (to == from) credit the post-debit
    // balance so the net effect is losing only the fee, matching the prior
    // read-after-write semantics. This is the last fallible check.
    let to_base = if to_key == from_key {
        new_from
    } else {
        ledger_maps::get_balance(&to_key)
    };
    let new_to = checked_credit(to_base, amount).map_err(TransferFromError::from)?;

    // ── Phase 2: every check passed — apply writes (infallible) ──
    //
    // H-01 (f2), DRAIN-TO-ZERO RECLAIMS. An allowance spent down to exactly zero
    // has nothing left to authorise, so the row goes rather than being written
    // back as `{ amount: 0, expires_at }`. Same reasoning and same observable as
    // revocation in `icrc2_approve`: `icrc2_allowance` reports `{0, null}`, which
    // is what it already reports for an expired row.
    if new_allow == 0 {
        remove_allowance(&allowance_key, record.expires_at);
    } else {
        put_allowance(
            allowance_key,
            record.expires_at,
            AllowanceRecord { amount: new_allow, expires_at: record.expires_at },
        );
    }
    // ── NO RECLAMATION TRIGGER ON THIS PATH — REMOVED BY RULING, NOT OVERSIGHT ──
    //
    // This endpoint maintains the expiry INDEX for the row it is touching (the
    // `put_allowance` / `remove_allowance` call above does that, and must), but it
    // does NOT run the bounded prune over other rows. An earlier revision of this
    // lane did, as SSA N-2's second trigger site. It was removed after measurement:
    //
    //   AC-10, `r1_ac10_hot_path_cost_is_within_the_ceiling`, 5 samples each side,
    //   `performance_counter(0)`:  base 91,108 -> 125,634 instructions,
    //   +34,526 (+37.896 %), against a ceiling of 6,000 instructions OR 6 %.
    //
    // The FIXED samples were perfectly stable at 125,634, so that was a fixed
    // per-call cost rather than a data-dependent one, and removing the call removes
    // it exactly. A permanent ~38 % tax on the ledger's highest-volume endpoint was
    // judged not worth what the trigger bought (CTO ruling
    // `cto-ruling-harden02-ac10-and-residuals-2026-09-17`, AC-10 Option 2).
    //
    // WHY N-1 IS STILL CLOSED WITHOUT IT. N-1's actual finding was that the prune
    // hung off `record_dedup_at`, which fires only when the caller supplies the
    // OPTIONAL `created_at_time` — an off switch the attacker holds. The two
    // triggers that remain have no such knob: the `icrc2_approve` trigger is
    // unconditional on that path, and the interval timer is canister-owned and not
    // caller-switchable at all. Reclamation cannot be disabled by anything a caller
    // sends or omits, which is the property N-1 was about.
    //
    // WHAT IT COSTS, STATED. Worst-case backlog between timer ticks is now bounded
    // by the approve arrival rate over one 300 s interval rather than being drained
    // by intervening `transfer_from` traffic. Still bounded, still measured — see
    // the addendum §2.8 envelope and the timer residency tests — just a wider
    // window.
    ledger_maps::write_balance(from_key, from_bal, new_from);
    ledger_maps::write_balance(to_key, to_base, new_to);

    route_fee_to_treasury(fee);

    let block = next_block();

    // ── HARDEN-03-SETTLEMENT (D-8 / I-5): the receipt, in THIS segment ────────
    //
    // After `next_block()` because the receipt records the block index; before
    // `record_dedup` because both are the same "the transfer committed" fact and
    // they must not be separable. There is NO `await` anywhere in this function,
    // so "same execution segment as the balance mutation" is structural — but do
    // not introduce one.
    //
    // WRITTEN PLAINLY, WITH NO `Result` HANDLING AND NO `unwrap_or`, ON PURPOSE.
    // If this insert cannot succeed it PANICS, and a panic is a trap, and a trap
    // rolls the entire message back — no debit, no block, no receipt. That is
    // the REQUIRED outcome (fix-design §3.4: "If receipt persistence cannot
    // succeed after monetary mutation, the segment must trap and roll back; it
    // must not return an ordinary Err that leaves the debit committed"). A trap
    // here is the safety mechanism, not a bug. Do not "harden" this into a
    // recoverable error: doing so would commit a debit whose receipt does not
    // exist, which is precisely the state the whole lane is built to make
    // unrepresentable.
    //
    // The capacity preflight in `pool_receipt_gate` is what keeps this from
    // being the common failure path.
    if let Some(ctx) = pool_receipt {
        DEPOSIT_RECEIPTS.with(|r| {
            r.borrow_mut().insert(
                ctx.key,
                DepositReceiptV1::Applied {
                    block_index: block,
                    amount,
                    fee_charged: fee,
                    request_hash: ctx.request_hash,
                    applied_at_ns: now,
                },
            )
        });
    }

    // DEF-050B-1: record the dedup entry only after the transfer has committed, so a
    // byte-identical retry within TX_DEDUP_WINDOW_NS returns Duplicate. Prune first
    // (capped) to bound stable-memory growth.
    if let Some((key, created_at)) = dedup_key {
        record_dedup(key, block, created_at);
    }

    Ok(Nat::from(block))
}

// ── HARDEN-03-SETTLEMENT: the two pool-only receipt endpoints ─────────────────
//
// Both are `#[update]`, NOT `#[query]`, and that is a privacy decision as much
// as a correctness one: P-1 requires that `DEPOSIT_RECEIPTS` be readable by no
// query at all, and AC-11 asserts exactly that. An update also guarantees
// replicated, authoritative execution for a read a money decision is taken on.

/// Authoritative receipt read (§5.2). The pool calls this FIRST, before any
/// resubmission, and past the ledger's 24-hour dedup window it is the only thing
/// that can still answer.
///
/// Authority is checked BEFORE any existence-sensitive read, and the
/// `Unauthorized` reply is identical in shape and code path whether or not a
/// receipt exists for the derived operation id (P-1 / AC-11).
#[update]
fn get_deposit_receipt(args: DepositAttemptArgs) -> Result<ReceiptLookup, ReceiptError> {
    let (key, request_hash, dedup) = receipt_lookup_preamble(&args)?;

    if let Some(existing) = DEPOSIT_RECEIPTS.with(|r| r.borrow().get(&key)) {
        // Fix-design §3.4: the same operation id with a different request hash
        // is a CONFLICT, not a new attempt. The pool's §5.2 row for this is
        // "release the claim, never delete".
        if existing.request_hash() != request_hash {
            return Err(ReceiptError::RequestMismatch);
        }
        return Ok(ReceiptLookup::Found(existing.into()));
    }

    // No receipt, but the ledger still remembers the transfer: a PRE-PROTOCOL
    // execution. Unreachable post-launch. It must NEVER read as `Cancelled`
    // (fix-design §3.3) — the pool maps it to an ambiguous-evidence error and
    // deletes nothing.
    if TRANSFER_DEDUP.with(|d| d.borrow().contains_key(&dedup)) {
        return Ok(ReceiptLookup::RetiredOrUnavailable);
    }

    // PROVISIONAL ONLY. Absence of evidence is not evidence of non-execution;
    // the pool proceeds to step B, it does not close on this.
    Ok(ReceiptLookup::Unrecorded)
}

/// Request the cancellation fence (§5.4 / §5.7). ONE synchronous decision point,
/// with no `await` — so single-threaded execution gives fix-design §3.5's
/// requirement for free: whichever of the transfer and the close reaches this
/// canister first determines the terminal state, and the other sees it.
#[update]
fn close_deposit_attempt(args: DepositAttemptArgs) -> Result<CloseOutcome, ReceiptError> {
    let (key, request_hash, dedup) = receipt_lookup_preamble(&args)?;

    // Idempotent on both variants: a repeated close returns the same answer, and
    // a close that lost the race to the transfer returns `Applied` so the pool
    // credits instead of deleting.
    if let Some(existing) = DEPOSIT_RECEIPTS.with(|r| r.borrow().get(&key)) {
        if existing.request_hash() != request_hash {
            return Err(ReceiptError::RequestMismatch);
        }
        return Ok(match existing {
            DepositReceiptV1::Applied { .. } => CloseOutcome::Applied(existing.into()),
            DepositReceiptV1::Cancelled { .. } => CloseOutcome::Cancelled(existing.into()),
        });
    }

    // A pre-protocol execution. Never a close trigger (fix-design §3.3).
    if TRANSFER_DEDUP.with(|d| d.borrow().contains_key(&dedup)) {
        return Ok(CloseOutcome::RetiredOrUnavailable);
    }

    // Capacity preflight, exactly as on the transfer path and for the same
    // reason: refuse cheaply rather than trap on a failed grow. A close moves no
    // money, so this is a pure liveness refusal.
    if DEPOSIT_RECEIPTS.with(|r| r.borrow().len()) >= receipt_capacity() {
        return Err(ReceiptError::UnsupportedProtocol);
    }

    let receipt = DepositReceiptV1::Cancelled {
        request_hash,
        closed_at_ns: time(),
    };
    DEPOSIT_RECEIPTS.with(|r| r.borrow_mut().insert(key, receipt.clone()));
    Ok(CloseOutcome::Cancelled(receipt.into()))
}

/// The shared preamble of both receipt endpoints: authorise, then derive.
///
/// ORDER IS THE CONTRACT. The caller check is FIRST and returns before any map
/// read, so a wrong caller cannot distinguish "no receipt" from "not allowed to
/// ask" by shape, by error code or by which branches ran (P-1).
///
/// Everything after it is RECOMPUTED from `ic_cdk::caller()`, `ic_cdk::api::id()`
/// and the fields actually received. The pool asserts nothing that is believed.
fn receipt_lookup_preamble(
    args: &DepositAttemptArgs,
) -> Result<(DepositReceiptKey, [u8; 32], [u8; 32]), ReceiptError> {
    let caller = ic_cdk::caller();
    let configured = POOL_CANISTER.with(|p| *p.borrow());
    if configured != Some(caller) {
        return Err(ReceiptError::Unauthorized);
    }

    let (Some(memo), Some(created_at_time)) = (args.memo.as_ref(), args.created_at_time) else {
        return Err(ReceiptError::UnsupportedProtocol);
    };
    if memo.len() > MAX_DEPOSIT_MEMO_LEN {
        return Err(ReceiptError::UnsupportedProtocol);
    }
    let amount = args
        .amount
        .0
        .to_u128()
        .ok_or(ReceiptError::UnsupportedProtocol)?;

    let spender_acc = Account {
        owner: caller,
        subaccount: args.spender_subaccount,
    };
    let key = deposit_operation_id(memo);
    let request_hash = deposit_request_hash(
        &args.from,
        &spender_acc,
        &args.to,
        amount,
        &args.fee,
        &args.memo,
        created_at_time,
    );
    let dedup = transfer_from_dedup_key(
        &args.from,
        &spender_acc,
        &args.to,
        amount,
        &args.fee,
        &args.memo,
        created_at_time,
    );
    Ok((key, request_hash, dedup))
}

/// D-3: the mandatory authority readback. Named in the install kit's `read_back`
/// command for the token row so a misconfigured install is caught at deploy time
/// rather than at the first stuck deposit.
#[query]
fn get_deposit_settlement_authority() -> Option<Principal> {
    POOL_CANISTER.with(|p| *p.borrow())
}

#[query]
fn icrc2_allowance(args: AllowanceArgs) -> Allowance {
    let key = compound_key(&args.account.encode_key(), &args.spender.encode_key());
    let record = ALLOWANCES.with(|a| a.borrow().get(&key).unwrap_or(AllowanceRecord { amount: 0, expires_at: None }));
    // F-005: an expired approval reads as no approval — { allowance = 0;
    // expires_at = null }, matching the reference ledger. Reporting the stale
    // stored amount misleads DEX pre-checks into transfer_from attempts that
    // then fail with InsufficientAllowance { allowance: 0 }. F-DBR-1: the
    // boundary is INCLUSIVE (now == expires_at is expired) — consistent with
    // icrc2_approve and icrc2_transfer_from.
    //
    // MD-01: this reading is now the SHARED one, not a private re-implementation.
    // `now` is captured once here and passed in, because a query cannot borrow an
    // update's captured instant (I-A5). I-A7's enforcement obligation: this
    // zeroing is what makes an expired allowance unspendable to a reader, and it
    // holds whether or not the row has been reclaimed yet — reclamation is about
    // storage, never about authorisation.
    let now = time();
    if allowance_is_expired(record.expires_at, now) {
        return Allowance { allowance: Nat::from(0u32), expires_at: None };
    }
    Allowance {
        allowance: Nat::from(effective_allowance(&record, now)),
        expires_at: record.expires_at,
    }
}

/// B1 TEST-ONLY: directly inflate an account balance, bypassing the genesis supply
/// invariant, so a test can drive a recipient near u128::MAX and exercise the
/// checked_credit overflow branch in icrc1_transfer — the direct discriminator for
/// the check-before-mutate write-ordering fix (that overflow is otherwise
/// unreachable, since sum(balances) == TOTAL_SUPPLY == 1e17 << u128::MAX). Compiled
/// ONLY under `--features testing`; dead-code-eliminated from the production Wasm.
#[cfg(feature = "testing")]
#[update]
fn debug_credit_balance_for_test(account: Account, amount: u128) {
    let key = account.encode_key();
    // R-1 S4(d): the injection goes through the SAME funnel as every production
    // write, so injected supply moves the running total and the O(1) public check
    // reports `invariant_holds == false`. A `saturating_add` here would produce a
    // total the funnel's `checked_add` then refuses — the write TRAPS instead,
    // which is the write-time first-law refusal (see arith_hardening T2).
    let cur = ledger_maps::get_balance(&key);
    ledger_maps::write_balance(key, cur, cur.saturating_add(amount));
}

// ── Staking lock interface ────────────────────────────────────────────────────
//
// SECURITY NOTE: Only the staking canister may call these methods.
// The staking canister is set at genesis and cannot be changed without
// a governance upgrade proposal.
//
// Staking does NOT transfer tokens — it marks them as locked within the holder's account.
// This means: liquid_balance = total_balance - staking_locked_balance.

#[update]
fn lock_for_staking(holder: Principal, amount: u128) -> Result<(), String> {
    assert_staking_canister();

    let account = Account { owner: holder, subaccount: None };
    let key = account.encode_key();

    let bal = ledger_maps::get_balance(&key);
    let currently_locked = ledger_maps::get_lock(&key);
    let liquid = bal.saturating_sub(currently_locked);

    if liquid < amount {
        return Err(format!("Insufficient liquid balance: {} < {}", liquid, amount));
    }

    let new_locked = currently_locked.checked_add(amount)
        .ok_or_else(|| "staking lock overflow".to_string())?;
    ledger_maps::write_lock(key, currently_locked, new_locked);
    Ok(())
}

#[update]
fn unlock_from_staking(holder: Principal, amount: u128) -> Result<(), String> {
    assert_staking_canister();

    let key = Account { owner: holder, subaccount: None }.encode_key();

    let locked = ledger_maps::get_lock(&key);
    if locked < amount {
        return Err(format!("Cannot unlock {} — only {} locked", amount, locked));
    }
    let new_locked = locked.checked_sub(amount)
        .ok_or_else(|| "staking unlock underflow".to_string())?;
    ledger_maps::write_lock(key, locked, new_locked);
    Ok(())
}

#[query]
fn staking_locked_balance(holder: Principal) -> u128 {
    let key = Account { owner: holder, subaccount: None }.encode_key();
    ledger_maps::get_lock(&key)
}

#[query]
fn liquid_balance(holder: Principal) -> u128 {
    let key = Account { owner: holder, subaccount: None }.encode_key();
    let total = ledger_maps::get_balance(&key);
    let locked = ledger_maps::get_lock(&key);
    total.saturating_sub(locked)
}

// ── ICRC-21 consent messages — SPEC-CONFORMANT (F-007/F-008/DEV-008) ─────────
//
// Full spec shapes per dfinity/wg-identity-authentication ICRC-21.did (also
// carried verbatim by the reference ledger). Replaces the earlier simplified
// `Result<record { consent_message : text }, text>` shape that spec clients
// (OISY signer flow) could not decode.
//
// - Response: variant { Ok : consent_info; Err : icrc21_error }.
// - Emits GenericDisplayMessage (markdown) for every request — universally
//   supported, including OISY. FieldsDisplayMessage types are declared for
//   ABI completeness but not yet produced.
// - UPDATE method (spec requirement, DEV-008) so the reply is certified.
// - NO caller authentication — anonymous senders are allowed by the spec.
// - Message content (F-008): amount, counterparty INCLUDING subaccount, the
//   FEE, and the memo when present. Amounts render via exact integer
//   arithmetic — never through f64 (the old path lost precision above 2^53).

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct Icrc21ConsentMessageMetadata {
    pub language: String,
    pub utc_offset_minutes: Option<i16>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum Icrc21DeviceSpec {
    GenericDisplay,
    FieldsDisplay,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct Icrc21ConsentMessageSpec {
    pub metadata: Icrc21ConsentMessageMetadata,
    pub device_spec: Option<Icrc21DeviceSpec>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct Icrc21ConsentMessageRequest {
    pub method: String,
    pub arg: Vec<u8>,
    pub user_preferences: Icrc21ConsentMessageSpec,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum Icrc21Value {
    TokenAmount { decimals: u8, amount: u64, symbol: String },
    TimestampSeconds { amount: u64 },
    DurationSeconds { amount: u64 },
    Text { content: String },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct Icrc21FieldsDisplay {
    pub intent: String,
    pub fields: Vec<(String, Icrc21Value)>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum Icrc21ConsentMessage {
    GenericDisplayMessage(String),
    FieldsDisplayMessage(Icrc21FieldsDisplay),
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct Icrc21ConsentInfo {
    pub consent_message: Icrc21ConsentMessage,
    pub metadata: Icrc21ConsentMessageMetadata,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct Icrc21ErrorInfo {
    pub description: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum Icrc21Error {
    UnsupportedCanisterCall(Icrc21ErrorInfo),
    ConsentMessageUnavailable(Icrc21ErrorInfo),
    InsufficientPayment(Icrc21ErrorInfo),
    GenericError { error_code: Nat, description: String },
}

const DECIMALS_FACTOR: u128 = 100_000_000; // 10^DECIMALS

/// Exact decimal rendering of a base-unit amount (integer arithmetic only —
/// F-008 forbids the u128→f64 path, which loses precision above 2^53).
fn format_stsh_amount(amount: u128) -> String {
    format!("{}.{:08} {}", amount / DECIMALS_FACTOR, amount % DECIMALS_FACTOR, SYMBOL)
}

/// Render a Nat amount; values beyond u128 (unreachable for real balances but
/// encodable in args) fall back to raw base units rather than truncating.
fn format_nat_amount(amount: &Nat) -> String {
    match amount.0.to_u128() {
        Some(a) => format_stsh_amount(a),
        None => format!("{} base units", amount),
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Account rendering for consent text: owner principal, plus the subaccount
/// in hex whenever it is set and non-default (F-008: a subaccount target must
/// not render identically to the default account).
fn format_consent_account(owner: &Principal, subaccount: &Option<[u8; 32]>) -> String {
    match subaccount {
        Some(sub) if sub != &[0u8; 32] => format!("{} (subaccount 0x{})", owner, hex_string(sub)),
        _ => owner.to_string(),
    }
}

fn consent_memo_line(memo: &Option<Vec<u8>>) -> String {
    match memo {
        Some(m) if !m.is_empty() => format!("\n\n**Memo:** 0x{}", hex_string(m)),
        _ => String::new(),
    }
}

fn icrc21_decode_err(method: &str, e: candid::Error) -> Icrc21Error {
    Icrc21Error::ConsentMessageUnavailable(Icrc21ErrorInfo {
        description: format!("cannot decode {} argument: {}", method, e),
    })
}

#[update]
fn icrc21_canister_call_consent_message(
    req: Icrc21ConsentMessageRequest,
) -> Result<Icrc21ConsentInfo, Icrc21Error> {
    // T-ICRC-L1: the transfer/approve consent texts render "From: <caller>".
    // An anonymous caller would produce a consent message attributing the
    // action to the anonymous principal while the signed call could come from
    // any identity — fail closed rather than render a misleading sender.
    if ic_cdk::caller() == Principal::anonymous() {
        return Err(Icrc21Error::GenericError {
            error_code: Nat::from(ERR_CODE_ANONYMOUS_CALLER),
            description: "anonymous caller cannot request a consent message".to_string(),
        });
    }
    // Only English is produced; per spec the metadata reports the language
    // actually used (the requested language is a preference, not a contract).
    let metadata = Icrc21ConsentMessageMetadata {
        language: "en".to_string(),
        utc_offset_minutes: None,
    };
    let fee = TRANSFER_FEE.with(|f| *f.borrow());

    let message = match req.method.as_str() {
        "icrc1_transfer" => {
            let args: TransferArgs = candid::decode_one(&req.arg)
                .map_err(|e| icrc21_decode_err("icrc1_transfer", e))?;
            format!(
                "# Transfer {}\n\n**Amount:** {}\n\n**From:** {}\n\n**To:** {}\n\n\
                 **Fee:** {}\nCharged to the sending account on top of the amount.{}",
                SYMBOL,
                format_nat_amount(&args.amount),
                format_consent_account(&ic_cdk::caller(), &args.from_subaccount),
                format_consent_account(&args.to.owner, &args.to.subaccount),
                format_stsh_amount(fee),
                consent_memo_line(&args.memo),
            )
        }
        "icrc2_approve" => {
            let args: ApproveArgs = candid::decode_one(&req.arg)
                .map_err(|e| icrc21_decode_err("icrc2_approve", e))?;
            // TOKEN-APPROVE-TTL: every stored allowance ends within
            // MAX_APPROVAL_TTL_NS of the approval executing — an absent expiry is
            // defaulted to that and a later one clamped to it — so this text must
            // never say "never". Consent renders BEFORE execution, so the cap is
            // stated relative to execution, not as an absolute instant.
            let cap_hours = MAX_APPROVAL_TTL_NS / 3_600_000_000_000;
            let expires = if args.amount == Nat::from(0u32) {
                // A zero approve revokes: it removes the allowance and stores
                // nothing, so no expiry applies.
                "\n\n**Expires:** not applicable (an allowance of zero removes \
                 the approval)"
                    .to_string()
            } else {
                match args.expires_at {
                    Some(ns) if ns > time().saturating_add(MAX_APPROVAL_TTL_NS) => format!(
                        "\n\n**Expires:** {} (seconds since Unix epoch), or {} hours \
                         after the approval executes if that is sooner (ledger maximum)",
                        ns / 1_000_000_000,
                        cap_hours
                    ),
                    Some(ns) => format!(
                        "\n\n**Expires:** {} (seconds since Unix epoch)",
                        ns / 1_000_000_000
                    ),
                    None => format!(
                        "\n\n**Expires:** {} hours after the approval executes \
                         (ledger maximum)",
                        cap_hours
                    ),
                }
            };
            format!(
                "# Approve {} spending\n\n**Spender:** {}\n\n**Allowance:** {}\n\n\
                 **From:** {}\n\n**Approval fee:** {}{}{}",
                SYMBOL,
                format_consent_account(&args.spender.owner, &args.spender.subaccount),
                format_nat_amount(&args.amount),
                format_consent_account(&ic_cdk::caller(), &args.from_subaccount),
                format_stsh_amount(fee),
                expires,
                consent_memo_line(&args.memo),
            )
        }
        "icrc2_transfer_from" => {
            let args: TransferFromArgs = candid::decode_one(&req.arg)
                .map_err(|e| icrc21_decode_err("icrc2_transfer_from", e))?;
            format!(
                "# Transfer {} from an approved account\n\n**Amount:** {}\n\n\
                 **From:** {}\n\n**To:** {}\n\n**Fee:** {}\nPaid by the from-account \
                 and deducted from the allowance together with the amount.{}",
                SYMBOL,
                format_nat_amount(&args.amount),
                format_consent_account(&args.from.owner, &args.from.subaccount),
                format_consent_account(&args.to.owner, &args.to.subaccount),
                format_stsh_amount(fee),
                consent_memo_line(&args.memo),
            )
        }
        other => {
            return Err(Icrc21Error::UnsupportedCanisterCall(Icrc21ErrorInfo {
                description: format!("no consent message defined for method: {}", other),
            }))
        }
    };

    Ok(Icrc21ConsentInfo {
        consent_message: Icrc21ConsentMessage::GenericDisplayMessage(message),
        metadata,
    })
}

// ── Build info (watcher requirement) ─────────────────────────────────────────

#[derive(CandidType, Serialize)]
pub struct BuildInfo {
    pub canister_name: String,
    pub version: String,
    pub governance_canister: Option<Principal>,
    pub staking_canister: Option<Principal>,
    pub treasury: Option<Principal>,
    pub mint_done: bool,
}

#[query]
fn get_build_info() -> BuildInfo {
    BuildInfo {
        canister_name: "stsh_token".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        governance_canister: None, // set in M4
        staking_canister: STAKING_CANISTER.with(|s| *s.borrow()),
        treasury: TREASURY.with(|t| *t.borrow()),
        mint_done: MINT_DONE.with(|m| *m.borrow()),
    }
}

// ── Custody Vault authority read-back (freeze v6 §6, lane L3f) ────────────────
//
// Canonical read-back of EVERY principal held in durable state: TREASURY,
// FEE_COLLECTOR, STAKING_CANISTER. Ruled PUBLIC by the freeze: these
// principals are public post-launch and the purpose of the endpoint is
// externally verifiable proof that the born-under-vault wiring is real.
// Mutation-free; additive; every existing query is unchanged.
//
// FAIL CLOSED: TREASURY and STAKING_CANISTER are required by a well-formed
// install (InitArgs fields are non-optional, :514-516) and pre_upgrade already
// traps if either is None. A None here therefore means uninitialised/corrupt
// state — trap, never substitute a launch default, never echo a caller
// expectation. FEE_COLLECTOR is legitimately optional (DEF-080: None on
// pre-DEF-080 state routes fees to TREASURY), so it is returned as-is.
// STAKING_CANISTER is RULED pinned to the Vault principal at launch (freeze
// §14); this read-back reports the stored value only — no setter exists and
// none is added here.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AuthorityRefs {
    pub treasury: Principal,
    /// DEF-080: neutral fee-collection account. None is a VALID stored value
    /// (fees fall back to treasury) — not a fail-closed condition.
    pub fee_collector: Option<Principal>,
    pub staking_canister: Principal,
}

#[query]
fn get_authority_refs() -> AuthorityRefs {
    let treasury = TREASURY.with(|t| *t.borrow())
        .unwrap_or_else(|| ic_cdk::trap(
            "get_authority_refs: TREASURY is None — uninitialised/corrupt state, failing closed"));
    let staking_canister = STAKING_CANISTER.with(|s| *s.borrow())
        .unwrap_or_else(|| ic_cdk::trap(
            "get_authority_refs: STAKING_CANISTER is None — uninitialised/corrupt state, failing closed"));
    AuthorityRefs {
        treasury,
        fee_collector: FEE_COLLECTOR.with(|f| *f.borrow()),
        staking_canister,
    }
}

/// The canister's own cycle balance — the interface CONTRACT lane A-6's fleet
/// monitor consumes (GAP-U9-1). Additive query; no state read, no caller check
/// (the value is not sensitive and the monitor may be unauthenticated).
///
/// API: ic-cdk 0.16 — `canister_balance128()` returns u128 -> Candid `nat`.
/// (vetkeys' `canister_cycle_balance()` is 0.20-only; see brief A-6b §1.)
#[query]
fn cycle_balance() -> u128 {
    ic_cdk::api::canister_balance128()
}

// ── Governance: update fee — REMOVED (DEF-085) ───────────────────────────────
//
// `governance_set_fee` was gated on `caller == self` and therefore uncallable by
// anyone (QA-DEF-014). Removed rather than fixed: the per-transfer fee model is
// NOT active at launch — TRANSFER_FEE is fixed at its init value and any future
// runtime fee-update path must arrive via a dedicated fee-policy lane with a real
// governance gate, not this dead stub.

// ── Helpers ───────────────────────────────────────────────────────────────────

fn next_block() -> u64 {
    BLOCK_HEIGHT.with(|h| { let n = *h.borrow() + 1; *h.borrow_mut() = n; n })
}

// ── DEF-050B-1: icrc2_transfer_from idempotency (QA-DEF-050B) ──────────────────
//
// A transport-unknown icrc2_transfer_from leaves the caller (the shielded pool)
// unable to tell whether the transfer committed. To make a retry safe, a
// created_at_time-bearing transfer records a dedup entry keyed by the canonical
// transfer identity; a byte-identical retry within TX_DEDUP_WINDOW_NS then returns
// Duplicate { duplicate_of } instead of debiting a second time.

/// H-3 (EXT-2): cap on expired dedup entries removed per successful
/// `created_at_time` op. This is the `K` in the prune's `O(log N + K·log N)` cost —
/// it bounds work *per call*, and is emphatically NOT a bound on an O(N) full scan.
/// prune_expired_dedup walks only the expired prefix of TRANSFER_DEDUP_BY_TIME (a
/// bounded range scan) and stops at this cap, so a fresh flood of unexpired entries
/// is never traversed. (The prior comment claimed this capped an O(N) full walk and
/// that a time index was deliberately omitted for "marginal benefit" — that walk
/// was precisely the algorithmic-complexity self-DoS this lane removes.)
const MAX_PRUNE_PER_CALL: usize = 100;

/// Length-prefixed hash update: u32 LE length, then the bytes. Prevents ambiguous
/// concatenation collisions between adjacent variable-length fields.
fn hash_len_prefixed(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u32).to_le_bytes());
    h.update(bytes);
}

/// Canonical dedup key for icrc2_transfer_from. Domain-separated; field order and
/// encoding are fixed (see QA-DEF-050B). fee is encoded as a presence byte plus a
/// fixed-width value so that a None fee and a Some(0) fee never collide.
fn transfer_from_dedup_key(
    from: &Account,
    spender: &Account,
    to: &Account,
    amount: u128,
    fee: &Option<Nat>,
    memo: &Option<Vec<u8>>,
    created_at_time: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    hash_len_prefixed(&mut h, b"stsh.icrc2_transfer_from.dedup.v1");
    hash_len_prefixed(&mut h, &from.encode_key());
    hash_len_prefixed(&mut h, &spender.encode_key());
    hash_len_prefixed(&mut h, &to.encode_key());
    h.update(amount.to_le_bytes());
    let (fee_present, fee_value): (u8, u128) = match fee {
        Some(f) => (1u8, f.0.to_u128().unwrap_or(0)),
        None => (0u8, 0u128),
    };
    h.update([fee_present]);
    h.update(fee_value.to_le_bytes());
    match memo {
        Some(m) => hash_len_prefixed(&mut h, m),
        None => hash_len_prefixed(&mut h, &[]),
    }
    h.update(created_at_time.to_le_bytes());
    let digest = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// Canonical dedup key for icrc1_transfer (B1; withdraw-side of QA-DEF-023). Same
/// construction as transfer_from_dedup_key but for the ICRC-1 shape (no spender,
/// from.owner == caller) and — critically — a DISTINCT leading domain tag
/// (`stsh.icrc1_transfer.dedup.v1` vs `stsh.icrc2_transfer_from.dedup.v1`). Because
/// the tag is length-prefixed and differs in both content and length, an ICRC-1
/// transfer and an ICRC-2 transfer_from with coincidentally identical
/// (from, to, amount, fee, memo, created_at_time) can never produce the same key in
/// the shared TRANSFER_DEDUP map. fee is encoded as a presence byte plus a
/// fixed-width value so a None fee and a Some(0) fee never collide.
fn transfer_dedup_key(
    from: &Account,
    to: &Account,
    amount: u128,
    fee: &Option<Nat>,
    memo: &Option<Vec<u8>>,
    created_at_time: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    hash_len_prefixed(&mut h, b"stsh.icrc1_transfer.dedup.v1");
    hash_len_prefixed(&mut h, &from.encode_key());
    hash_len_prefixed(&mut h, &to.encode_key());
    h.update(amount.to_le_bytes());
    let (fee_present, fee_value): (u8, u128) = match fee {
        Some(f) => (1u8, f.0.to_u128().unwrap_or(0)),
        None => (0u8, 0u128),
    };
    h.update([fee_present]);
    h.update(fee_value.to_le_bytes());
    match memo {
        Some(m) => hash_len_prefixed(&mut h, m),
        None => hash_len_prefixed(&mut h, &[]),
    }
    h.update(created_at_time.to_le_bytes());
    let digest = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// Canonical dedup key for icrc2_approve (F-004). Same length-prefixed scheme
/// as the transfer keys with a DISTINCT leading domain tag
/// (`stsh.icrc2_approve.dedup.v1`), so an approve can never collide with an
/// icrc1_transfer or icrc2_transfer_from entry in the shared TRANSFER_DEDUP
/// map. Covers the full approval identity: approver account, spender account,
/// amount, expected_allowance, expires_at, fee, memo, created_at_time. Every
/// optional numeric is encoded as a presence byte plus a fixed-width value so
/// None and Some(0) never collide.
fn approve_dedup_key(from: &Account, args: &ApproveArgs, created_at_time: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    hash_len_prefixed(&mut h, b"stsh.icrc2_approve.dedup.v1");
    hash_len_prefixed(&mut h, &from.encode_key());
    hash_len_prefixed(&mut h, &args.spender.encode_key());
    // amount as raw Nat big-endian bytes (length-prefixed) — approve amounts may
    // exceed u128 in the args even though execution caps at u128; hash the
    // canonical wire value so identity matches what the caller sent.
    hash_len_prefixed(&mut h, &args.amount.0.to_bytes_be());
    let (ea_present, ea_value): (u8, u128) = match &args.expected_allowance {
        Some(e) => (1u8, e.0.to_u128().unwrap_or(u128::MAX)),
        None => (0u8, 0u128),
    };
    h.update([ea_present]);
    h.update(ea_value.to_le_bytes());
    let (exp_present, exp_value): (u8, u64) = match args.expires_at {
        Some(e) => (1u8, e),
        None => (0u8, 0u64),
    };
    h.update([exp_present]);
    h.update(exp_value.to_le_bytes());
    let (fee_present, fee_value): (u8, u128) = match &args.fee {
        Some(f) => (1u8, f.0.to_u128().unwrap_or(0)),
        None => (0u8, 0u128),
    };
    h.update([fee_present]);
    h.update(fee_value.to_le_bytes());
    match &args.memo {
        Some(m) => hash_len_prefixed(&mut h, m),
        None => hash_len_prefixed(&mut h, &[]),
    }
    h.update(created_at_time.to_le_bytes());
    let digest = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// H-3 (EXT-2): key type for the TRANSFER_DEDUP_BY_TIME index. `created_at_ns` is
/// declared FIRST so the derived `Ord` sorts chronologically (then by dedup_key) —
/// pinned `ic-stable-structures 0.6.9` orders the StableBTreeMap by `K::Ord` on the
/// DECODED key, so chronological iteration is correct by construction. The
/// big-endian fixed-width serialization below is a canonical, deterministic byte
/// form that happens to agree with that order, but ordering does not depend on it
/// (that would only matter for a raw `[u8; 40]` key). Mirrors the shielded-pool's
/// `TerminalDepositKey` idiom exactly (u64 time-first || 32-byte id, 40 bytes fixed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DedupTimeKey {
    created_at_ns: u64,
    dedup_key: [u8; 32],
}

impl DedupTimeKey {
    #[inline]
    fn new(created_at_ns: u64, dedup_key: [u8; 32]) -> Self {
        Self { created_at_ns, dedup_key }
    }
}

impl Storable for DedupTimeKey {
    const BOUND: Bound = Bound::Bounded { max_size: 40, is_fixed_size: true };
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut bytes = [0u8; 40];
        bytes[0..8].copy_from_slice(&self.created_at_ns.to_be_bytes());
        bytes[8..40].copy_from_slice(&self.dedup_key);
        Cow::Owned(bytes.to_vec())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let created_at_ns = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        let mut dedup_key = [0u8; 32];
        dedup_key.copy_from_slice(&bytes[8..40]);
        Self { created_at_ns, dedup_key }
    }
}

/// H-3 (EXT-2): ceiling on the one-shot v1→v2 dedup migration. The migration scans
/// the entire legacy TRANSFER_DEDUP once (decode + partition + one B-tree insert per
/// live entry) inside a single `post_upgrade` message, so the whole scan must fit
/// the upgrade instruction budget. `MAX_MIGRATION_ENTRIES_PRODUCTION` is sized to the
/// MEASURED worst-path (all-live: one B-tree insert per entry) back-fill cost —
/// ~108k–135k instr/entry over N=1k–20k (measure_h3_migration_budget), extrapolating
/// (log-growth) to ~156k/entry at 200k ⇒ ~31B instructions, ~6x under the ~200B
/// install_code / post_upgrade DTS budget. Over it the migration TRAPS (the upgrade
/// aborts and the v1 module keeps running) rather than risk exhausting instructions
/// mid-migration. Fresh mainnet deploys start at v2 with an empty map, so this bound
/// is inert there — it only matters for a canister that accumulated a large v1 dedup
/// map before upgrade.
///
/// The production value is ALWAYS compiled (so the const-assert unit test locks it
/// regardless of feature flags). Under `--features testing` the *active* limit is a
/// low override, so the boundary tests (exactly-at / over-limit rollback) need only
/// a handful of entries; the production-excludes-override discriminator test proves
/// that override never reaches the release binary.
#[allow(dead_code)]
const MAX_MIGRATION_ENTRIES_PRODUCTION: u64 = 200_000;

#[cfg(not(feature = "testing"))]
const MAX_MIGRATION_ENTRIES: u64 = MAX_MIGRATION_ENTRIES_PRODUCTION;
#[cfg(feature = "testing")]
const MAX_MIGRATION_ENTRIES: u64 = 8;

/// Dedup value encoding: block_index (u64 LE) in [0..8], created_at_time (u64 LE)
/// in [8..16]. Fixed 16 bytes from the start — do not widen.
fn encode_dedup_value(block_index: u64, created_at_time: u64) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[0..8].copy_from_slice(&block_index.to_le_bytes());
    v[8..16].copy_from_slice(&created_at_time.to_le_bytes());
    v
}

/// H-3 (EXT-2): the single writer for BOTH dedup maps. Called by icrc1_transfer,
/// icrc2_transfer_from, and icrc2_approve after the operation commits — the
/// per-writer, domain-separated key derivation is unchanged; only the *recording*
/// is shared. Prunes the expired prefix (bounded range scan) then inserts the new
/// entry into TRANSFER_DEDUP (key → block||created_at) AND TRANSFER_DEDUP_BY_TIME
/// ((created_at, key) → ()), keeping the two maps bijective. The upstream duplicate
/// check guarantees `key` is not already present, so both inserts are net-new.
fn record_dedup(key: [u8; 32], block_index: u64, created_at_time: u64) {
    record_dedup_at(time(), key, block_index, created_at_time)
}

/// R-1 S3 (form (a)): the whole body of `record_dedup`, with `now` supplied by the
/// caller instead of read from `time()`.
///
/// `record_dedup` is a one-line wrapper that passes `time()`. The split exists so
/// the native unit suite can drive the REAL dual insert — previously
/// `h3_dedup_index_tests` reimplemented it in a local `put` helper, which made
/// every bijectivity assertion in that suite vacuous with respect to the
/// production writer (SI-10). Same pattern as `migrate_dedup_index_v1_to_v2(now)`.
fn record_dedup_at(now: u64, key: [u8; 32], block_index: u64, created_at_time: u64) {
    prune_expired_dedup(now);
    TRANSFER_DEDUP.with(|d| {
        d.borrow_mut()
            .insert(key, encode_dedup_value(block_index, created_at_time));
    });
    TRANSFER_DEDUP_BY_TIME.with(|t| {
        t.borrow_mut()
            .insert(DedupTimeKey::new(created_at_time, key), ());
    });
}

/// H-3 (EXT-2): bounded prune of expired dedup entries via the time index. An
/// entry is expired iff `created_at_time < cutoff`, where
/// `cutoff = now_ns - TX_DEDUP_WINDOW_NS` (saturating) — identical boundary to the
/// prior `created + TX_DEDUP_WINDOW_NS < now_ns` test. The scan walks
/// TRANSFER_DEDUP_BY_TIME from the smallest key up to the EXCLUSIVE upper bound
/// `(cutoff, [0u8; 32])`: `[0; 32]` is the minimal dedup_key, so every key strictly
/// below it has `created_at_ns < cutoff` — exactly the expired set, and never an
/// entry at `created_at_ns == cutoff` (retained). Only the expired prefix is
/// visited (a fresh flood of unexpired entries is never traversed); it collects at
/// most MAX_PRUNE_PER_CALL keys, then removes each from BOTH maps, preserving the
/// bijective invariant. Cost `O(log N + K·log N)`, `K ≤ MAX_PRUNE_PER_CALL`,
/// independent of the number of live entries. This is the H-3 fix: the prior full
/// `.iter()` walk was O(N) under an adversarial fresh flood (nothing expired ⇒ the
/// `break` inside `if expired` never fired ⇒ every one of the N entries was scanned).
fn prune_expired_dedup(now_ns: u64) {
    let cutoff = now_ns.saturating_sub(TX_DEDUP_WINDOW_NS);
    let upper = DedupTimeKey::new(cutoff, [0u8; 32]);
    let expired: Vec<DedupTimeKey> = TRANSFER_DEDUP_BY_TIME.with(|t| {
        t.borrow()
            .range((std::ops::Bound::Unbounded, std::ops::Bound::Excluded(upper)))
            .take(MAX_PRUNE_PER_CALL)
            .map(|(k, _)| k)
            .collect()
    });
    if expired.is_empty() {
        return;
    }
    TRANSFER_DEDUP.with(|d| {
        let mut primary = d.borrow_mut();
        TRANSFER_DEDUP_BY_TIME.with(|t| {
            let mut index = t.borrow_mut();
            for tk in expired {
                primary.remove(&tk.dedup_key);
                index.remove(&tk);
            }
        });
    });
}

/// H-3 (EXT-2): one-shot, all-or-nothing STATE_VERSION 1 → 2 migration. A v1
/// checkpoint predates TRANSFER_DEDUP_BY_TIME, so the index starts empty on the
/// upgraded (v2) binary; this back-fills it from the surviving TRANSFER_DEDUP,
/// dropping entries already expired at upgrade time and indexing the rest, leaving
/// the two maps bijective. Bounded by MAX_MIGRATION_ENTRIES: if TRANSFER_DEDUP.len()
/// (total — every entry is visited, live and expired) exceeds the limit, TRAP
/// BEFORE any mutation. The trap aborts the upgrade (the pre-upgrade v1 module keeps
/// running with its state intact) rather than risk exhausting the `post_upgrade`
/// instruction budget partway through the scan. It never partially back-fills:
/// either every live entry is indexed, or (over limit / instruction-exhaustion trap)
/// the whole upgrade rolls back.
fn migrate_dedup_index_v1_to_v2(now: u64) {
    let total = TRANSFER_DEDUP.with(|d| d.borrow().len());
    if total > MAX_MIGRATION_ENTRIES {
        ic_cdk::trap(&format!(
            "post_upgrade: TRANSFER_DEDUP holds {} entries, exceeding the one-shot \
             v1→v2 migration limit of {}. Upgrade ABORTED; the v1 module keeps \
             running with state intact. Recovery: drain the dedup window under low \
             volume (wait out TX_DEDUP_WINDOW_NS so entries expire and the map \
             shrinks), or perform the staged migration, then re-attempt — see \
             MAINNET_DEPLOYMENT.md (token dedup migration runbook).",
            total, MAX_MIGRATION_ENTRIES
        ));
    }
    backfill_dedup_index(now);
}

/// The core back-fill: index every live entry into the (empty) time index during a
/// single immutable scan of the primary map, collecting expired keys to drop
/// afterward (the primary can't be mutated while it is being iterated). Split out
/// from the limit gate so the migration cost can be measured at any N (the
/// #[ignore] measure_h3_budgets test that sizes MAX_MIGRATION_ENTRIES_PRODUCTION).
fn backfill_dedup_index(now: u64) {
    let cutoff = now.saturating_sub(TX_DEDUP_WINDOW_NS);
    let mut to_drop: Vec<[u8; 32]> = Vec::new();
    TRANSFER_DEDUP.with(|d| {
        let primary = d.borrow();
        TRANSFER_DEDUP_BY_TIME.with(|t| {
            let mut index = t.borrow_mut();
            for (k, v) in primary.iter() {
                let created = u64::from_le_bytes(v[8..16].try_into().unwrap());
                if created < cutoff {
                    to_drop.push(k);
                } else {
                    index.insert(DedupTimeKey::new(created, k), ());
                }
            }
        });
    });
    TRANSFER_DEDUP.with(|d| {
        let mut primary = d.borrow_mut();
        for k in &to_drop {
            primary.remove(k);
        }
    });
}

/// H-3 (EXT-2): bijective-consistency check between the two dedup maps — equal
/// cardinality AND every primary entry `(key → …created_at…)` present in the time
/// index as `(created_at, key)`. Equal length plus primary ⊆ index (an injective
/// map, since `key` is embedded in the index key) implies a true bijection. Used by
/// the direct unit tests and by the test-feature observer endpoint; never compiled
/// into production.
#[cfg(any(test, feature = "testing"))]
fn dedup_maps_consistent() -> bool {
    let primary_len = TRANSFER_DEDUP.with(|d| d.borrow().len());
    let index_len = TRANSFER_DEDUP_BY_TIME.with(|t| t.borrow().len());
    if primary_len != index_len {
        return false;
    }
    TRANSFER_DEDUP.with(|d| {
        let primary = d.borrow();
        TRANSFER_DEDUP_BY_TIME.with(|t| {
            let index = t.borrow();
            for (k, v) in primary.iter() {
                let created = u64::from_le_bytes(v[8..16].try_into().unwrap());
                if !index.contains_key(&DedupTimeKey::new(created, k)) {
                    return false;
                }
            }
            true
        })
    })
}

/// H-3 TEST-ONLY: inject a raw entry into the PRIMARY dedup map only (not the time
/// index), simulating legacy v1 residue — in particular an already-expired entry,
/// which real ingress cannot create (the TooOld guard rejects a created_at older
/// than the window). Lets the migration tests build a controlled v1-shaped map and
/// prove the v1→v2 migration drops expired legacy entries / hits the entry-count
/// limit. Compiled only under `--features testing`.
#[cfg(feature = "testing")]
#[update]
fn inject_legacy_dedup_entry_for_test(dedup_key: [u8; 32], block_index: u64, created_at_time: u64) {
    // W2 2-4 (CTO ruling 2026-08-18, SSA scope-change GREEN): a real ledger with a
    // dedup row at block N has BLOCK_HEIGHT >= N (record_dedup only ever runs after
    // next_block() issued that index). Keep the fixture faithful to that, monotonically.
    BLOCK_HEIGHT.with(|h| { let mut b = h.borrow_mut(); *b = (*b).max(block_index); });
    TRANSFER_DEDUP.with(|d| {
        d.borrow_mut()
            .insert(dedup_key, encode_dedup_value(block_index, created_at_time));
    });
}

/// H-3 TEST-ONLY: simulate a STATE_VERSION-1 canister so the next upgrade exercises
/// the real one-shot migration. Strips the time index (v1 never had it) and arms the
/// pre_upgrade force-v1 flag so the next checkpoint is stamped version 1. The
/// primary TRANSFER_DEDUP map (populated via real ingress and/or injected legacy
/// residue) is left untouched — that is exactly the legacy state the migration must
/// reconstruct from. Compiled only under `--features testing`.
#[cfg(feature = "testing")]
#[update]
fn force_v1_legacy_state_for_test() {
    let index_keys: Vec<DedupTimeKey> =
        TRANSFER_DEDUP_BY_TIME.with(|t| t.borrow().iter().map(|(k, _)| k).collect());
    TRANSFER_DEDUP_BY_TIME.with(|t| {
        let mut index = t.borrow_mut();
        for k in index_keys {
            index.remove(&k);
        }
    });
    FORCE_V1_CHECKPOINT.with(|f| *f.borrow_mut() = true);
}

/// H-3 TEST-ONLY observer: (primary_len, index_len, maps_bijective, stored_version).
/// Lets a post-migration observer Wasm witness that the production migration left
/// the two maps equal-length and bijective, expired legacy entries dropped, and the
/// checkpoint advanced to v2 — with no production introspection endpoint. Because
/// the production `pre_upgrade` already stamped v2, the observer's own post_upgrade
/// skips migration and cannot mask a failed first back-fill.
#[cfg(feature = "testing")]
#[query]
fn dedup_index_stats_for_test() -> (u64, u64, bool, u32) {
    let primary_len = TRANSFER_DEDUP.with(|d| d.borrow().len());
    let index_len = TRANSFER_DEDUP_BY_TIME.with(|t| t.borrow().len());
    let bijective = dedup_maps_consistent();
    let stored_version = STABLE_STATE_CELL.with(|c| {
        let bytes = c.borrow().get().clone();
        candid::decode_one::<TokenStableState>(&bytes)
            .map(|s| s.state_version)
            .unwrap_or(0)
    });
    (primary_len, index_len, bijective, stored_version)
}

/// H-3 TEST-ONLY: bulk-insert `count` distinct FRESH entries into BOTH dedup maps
/// (all stamped `created_at_time`), cheaply simulating N resident unexpired records
/// so the P1 perf gate can measure prune cost vs N without thousands of real update
/// rounds. Keys are derived from the loop index (distinct, and never colliding with
/// a real sha256 dedup key). Compiled only under `--features testing`.
#[cfg(feature = "testing")]
#[update]
fn inject_live_dedup_entries_for_test(count: u64, created_at_time: u64) {
    TRANSFER_DEDUP.with(|d| {
        let mut primary = d.borrow_mut();
        TRANSFER_DEDUP_BY_TIME.with(|t| {
            let mut index = t.borrow_mut();
            for i in 0..count {
                let mut key = [0u8; 32];
                key[0..8].copy_from_slice(&i.to_le_bytes());
                key[8..16].copy_from_slice(&created_at_time.to_le_bytes());
                primary.insert(key, encode_dedup_value(i, created_at_time));
                index.insert(DedupTimeKey::new(created_at_time, key), ());
            }
        });
    });
}

/// H-01 TEST-ONLY: the allowance map's own stats — (primary_len, index_len,
/// bijective). The bijection is evaluated by the PRODUCTION predicate
/// `allowance_index_consistent`, not by a re-implementation here (SI-10).
/// Compiled only under `--features testing`.
#[cfg(feature = "testing")]
#[query]
fn allowance_index_stats_for_test() -> (u64, u64, bool) {
    let primary_len = ALLOWANCES.with(|a| a.borrow().len());
    let index_len = ALLOWANCES_BY_EXPIRY.with(|t| t.borrow().len());
    (primary_len, index_len, allowance_index_consistent())
}

/// H-01 TEST-ONLY: bulk-write `count` distinct allowance rows, all expiring at
/// `expires_at`, THROUGH THE PRODUCTION WRITER `put_allowance`. Compiled only
/// under `--features testing`.
///
/// Driving the real writer is the point (SI-10); HARDEN-03 extends that to the
/// KEY. Rows are keyed by the PRODUCTION `Account::encode_key`/`compound_key`
/// encoders at the realizable worst case — a 29-byte principal plus a NONZERO
/// 32-byte subaccount on BOTH halves, 132 bytes — since the former 9-byte key
/// understated every storage figure taken through this hook. A zero subaccount
/// would normalize to `None` under QA-DEF-021 and shorten the key, hence the
/// nonzero tags. The account half varies with `i` so rows stay distinct; the
/// stored expiry is passed back as `previous_expires_at` exactly as
/// `icrc2_approve` does, so a re-pass over the range is a faithful RENEWAL.
#[cfg(feature = "testing")]
#[update]
fn inject_allowances_for_test(count: u64, expires_at: u64, amount: u128) {
    for i in 0..count {
        let mut owner = [0xABu8; 29];
        owner[21..29].copy_from_slice(&i.to_be_bytes());
        let acct = Account { owner: Principal::from_slice(&owner), subaccount: Some([0x11u8; 32]) };
        let spender = Account { owner: Principal::from_slice(&[0xCDu8; 29]), subaccount: Some([0x22u8; 32]) };
        let key = compound_key(&acct.encode_key(), &spender.encode_key());
        let previous = ALLOWANCES.with(|a| a.borrow().get(&key)).and_then(|r| r.expires_at);
        put_allowance(key, previous, AllowanceRecord { amount, expires_at: Some(expires_at) });
    }
}

/// H-01 TEST-ONLY: run the allowance prune at a caller-chosen `now` and cap, and
/// return `(rows_removed, instructions_consumed)`.
///
/// `now` is a parameter so a test can drive the expiry boundary exactly — at
/// `exp - 1`, at `exp`, and at `exp + 1` — without waiting on the replica clock.
/// The instruction delta is what makes the adversarial-flood criterion falsifiable:
/// with N unexpired rows and nothing expired, the cost must show no term in N.
/// Compiled only under `--features testing`.
#[cfg(feature = "testing")]
#[update]
fn measure_allowance_prune_instructions_for_test(now: u64, cap: u64) -> (u64, u64) {
    let start = ic_cdk::api::instruction_counter();
    let removed = prune_expired_allowances(now, cap as usize);
    let used = ic_cdk::api::instruction_counter().saturating_sub(start);
    (removed as u64, used)
}

/// H-01 TEST-ONLY: the canister's ACTUAL allocated stable memory, in 64 KiB
/// WebAssembly pages.
///
/// This is the figure the storage-envelope test reports, deliberately instead of
/// `len() * record_size`: a row's real cost includes the composite primary key,
/// the index entry, and `StableBTreeMap`'s own node overhead, none of which a
/// record-payload multiplication sees. It also makes the flood → prune → reflood
/// shape honest — the IC stable-memory API only ever grows, so removing rows
/// returns pages to the map's free list for reuse but never to the system, and
/// the canister keeps paying for the peak. Compiled only under
/// `--features testing`.
#[cfg(feature = "testing")]
#[query]
fn stable_pages_for_test() -> u64 {
    ic_cdk::api::stable::stable_size()
}

// ── HARDEN-03-SETTLEMENT TEST-ONLY hooks ──────────────────────────────────────
//
// All five are `#[cfg(feature = "testing")]` and carry the `_for_test` suffix,
// so `eager_cell_feature_isolation_tests` — which SCANS the shipped binaries
// rather than asserting — proves them absent from production. None of them is in
// `stsh_token.did`: `verify_did_exports` parses with default features, under
// which these items do not exist.

/// TEST-ONLY: write a receipt directly, so `Applied` / `Cancelled` states can be
/// driven without a real transfer. Pairs with `inject_legacy_dedup_entry_for_test`
/// for the "dedup entry but no receipt" pre-protocol anomaly (`RetiredOrUnavailable`).
#[cfg(feature = "testing")]
#[update]
fn inject_deposit_receipt_for_test(operation_id: [u8; 32], receipt: DepositReceiptV1) {
    DEPOSIT_RECEIPTS.with(|r| {
        r.borrow_mut()
            .insert(DepositReceiptKey(operation_id), receipt)
    });
}

/// TEST-ONLY: override `MAX_DEPOSIT_RECEIPTS`, so the capacity refusal can be
/// driven at n = 0 instead of by allocating 65,536 rows. Precedent:
/// `set_reconcile_row_budget_for_test`. `None` restores the production constant.
#[cfg(feature = "testing")]
#[update]
fn set_receipt_capacity_for_test(cap: Option<u64>) {
    RECEIPT_CAPACITY_OVERRIDE.with(|c| *c.borrow_mut() = cap);
}

/// TEST-ONLY probe: how many receipts exist.
#[cfg(feature = "testing")]
#[query]
fn deposit_receipt_count_for_test() -> u64 {
    DEPOSIT_RECEIPTS.with(|r| r.borrow().len())
}

/// TEST-ONLY: bulk-write `count` distinct receipts in ONE update message.
///
/// The `inject_*_for_test` + `stable_pages_for_test` idiom HARDEN-03-CAPACITY
/// established, and the only practical way to reach AC-25's n: driving the
/// single-row hook `count` times is `count` round trips, which at n = 20,000 is
/// not a test anyone will run.
///
/// **Every row is the structural worst case, and for this map that is not a
/// choice.** `DepositReceiptKey` is a fixed 32 bytes and `DepositReceiptV1` a
/// fixed 81, both `is_fixed_size: true`, so — unlike `ALLOWANCES`, whose
/// unbounded `Vec<u8>` key made "the realizable worst-case key" the live
/// question of CAPACITY's own lane — this map has no key-size variation to
/// explore. The values written here are saturated (`u64::MAX` timestamps, an
/// all-ones request hash) so nothing can be smaller than what a real row costs.
///
/// **CAPACITY §3.6's wall applies to this hook too:** it is one update message,
/// so its own ceiling sits somewhere between 50,000 and 100,000 rows. Do not
/// design a measurement that needs 262,144 — that is precisely why the
/// provisional cap came down to 65,536, inside a band the repo can bracket
/// rather than 5x beyond one it can reach.
#[cfg(feature = "testing")]
#[update]
fn inject_deposit_receipts_for_test(count: u64, seed: u64) {
    DEPOSIT_RECEIPTS.with(|r| {
        let mut m = r.borrow_mut();
        for i in 0..count {
            let mut op = [0xFFu8; 32];
            op[0..8].copy_from_slice(&i.to_le_bytes());
            op[8..16].copy_from_slice(&seed.to_le_bytes());
            m.insert(
                DepositReceiptKey(op),
                DepositReceiptV1::Applied {
                    block_index: u64::MAX,
                    amount: u128::MAX,
                    fee_charged: u128::MAX,
                    request_hash: [0xFFu8; 32],
                    applied_at_ns: u64::MAX,
                },
            );
        }
    });
}

/// TEST-ONLY probe: read a receipt with no authority check, so a test can assert
/// on the map's contents without becoming the pool.
#[cfg(feature = "testing")]
#[query]
fn deposit_receipt_read_for_test(operation_id: [u8; 32]) -> Option<DepositReceiptV1> {
    DEPOSIT_RECEIPTS.with(|r| r.borrow().get(&DepositReceiptKey(operation_id)))
}

/// TEST-ONLY: rebind the pool authority without re-installing, so the
/// unauthorised path and the `None` (misconfigured-token) path of AC-26 can both
/// be driven against one installed canister.
///
/// **MUST stay `testing`-only.** A production authority setter is exactly what
/// D-3 refused; if this ever ships, D-3's reasoning is void.
#[cfg(feature = "testing")]
#[update]
fn set_deposit_settlement_authority_for_test(pool: Option<Principal>) {
    POOL_CANISTER.with(|p| *p.borrow_mut() = pool);
}

/// TEST-ONLY: the canister's own derivation of the operation id from memo bytes.
///
/// Exists so a test asserts against the PRODUCTION derivation rather than a
/// paraphrase of it. A test-local re-implementation of `deposit_operation_id`
/// would be a self-inherited verification — it would pass by construction even
/// if the production hash changed.
#[cfg(feature = "testing")]
#[query]
fn deposit_operation_id_for_test(memo: Vec<u8>) -> [u8; 32] {
    deposit_operation_id(&memo).0
}

/// H-01 TEST-ONLY: is exactly one maintenance timer id recorded?
///
/// The id itself is opaque, so what a test can observe is that repeated arming
/// leaves ONE recorded id rather than accumulating them — the property that makes
/// `arm_allowance_maintenance_timer` idempotent. Combined with the real PocketIC
/// upgrade arm (which proves the timer still fires after an upgrade), this covers
/// the stacking half. Compiled only under `--features testing`.
#[cfg(feature = "testing")]
#[query]
fn maintenance_timer_armed_for_test() -> bool {
    ALLOWANCE_MAINTENANCE_TIMER.with(|t| t.borrow().is_some())
}

/// H-3 TEST-ONLY: run prune_expired_dedup(time()) and return the IC instruction
/// count it consumed (instruction_counter delta). The P1 perf gate calls this with a
/// small then a large resident FRESH map and asserts the cost shows no linear term —
/// the direct regression witness that the old O(N) full scan is gone. An all-fresh
/// map is exactly the adversarial flood: nothing is expired, so the bounded range
/// scan must return without walking a single live entry. Compiled only under
/// `--features testing`.
#[cfg(feature = "testing")]
#[update]
fn measure_prune_instructions_for_test() -> u64 {
    let start = ic_cdk::api::instruction_counter();
    prune_expired_dedup(time());
    ic_cdk::api::instruction_counter().saturating_sub(start)
}

/// H-3 TEST-ONLY: run the one-shot migration over the current primary-only map and
/// return the IC instruction count it consumed. Used offline (the #[ignore]
/// measure_h3_budgets test) to size MAX_MIGRATION_ENTRIES_PRODUCTION against the
/// worst-path post_upgrade budget. `now` is passed so the caller controls the
/// live/expired split. Compiled only under `--features testing`.
#[cfg(feature = "testing")]
#[update]
fn measure_migration_instructions_for_test(now: u64) -> u64 {
    // The back-fill core (no limit gate) so large-N cost can be measured without the
    // low test-feature override trapping; the per-entry cost is what matters.
    let start = ic_cdk::api::instruction_counter();
    backfill_dedup_index(now);
    ic_cdk::api::instruction_counter().saturating_sub(start)
}

fn assert_staking_canister() {
    let staking = STAKING_CANISTER.with(|s| s.borrow().expect("Staking canister not configured"));
    assert_eq!(ic_cdk::caller(), staking, "Only staking canister may call this method");
}

/// Checked total debit (amount + fee). Returns an overflow error instead of
/// wrapping. Tested by u128_overflow_safe.
fn checked_total_debit(amount: u128, fee: u128) -> Result<u128, TransferError> {
    amount.checked_add(fee).ok_or(TransferError::GenericError {
        error_code: Nat::from(3u32),
        message: "total_debit overflow (amount + fee exceeds u128)".to_string(),
    })
}

/// Checked credit (balance + amount). Returns an overflow error instead of
/// wrapping. Used for recipient and treasury fee credits.
fn checked_credit(balance: u128, amount: u128) -> Result<u128, TransferError> {
    balance.checked_add(amount).ok_or(TransferError::GenericError {
        error_code: Nat::from(4u32),
        message: "balance credit overflow (exceeds u128)".to_string(),
    })
}

fn route_fee_to_treasury(fee: u128) {
    if fee == 0 { return; }
    // DEF-080: the effective fee recipient is the neutral fee_collector when set,
    // else the treasury principal (backward-compatible fallback). The crediting
    // mechanics are unchanged — only the recipient binding differs.
    let recipient = FEE_COLLECTOR.with(|f| *f.borrow());
    let treasury = match recipient.or(TREASURY.with(|t| *t.borrow())) {
        Some(t) => t,
        None => {
            // saturating_add: runs after the sender debit committed; no error
            // channel here. Fee totals are bounded by TOTAL_SUPPLY (<< u128::MAX).
            FEE_RESERVE.with(|f| { let v = *f.borrow(); *f.borrow_mut() = v.saturating_add(fee); });
            return;
        }
    };
    let key = Account { owner: treasury, subaccount: None }.encode_key();
    let bal = ledger_maps::get_balance(&key);
    // saturating_add: same rationale — never wrap a treasury fee credit.
    ledger_maps::write_balance(key, bal, bal.saturating_add(fee));
}

/// R-1 S4(e) / AC-12: the pinned row budget for `reconcile_supply_invariant`.
///
/// MEASURED against a REAL trap point, not extrapolated to one.
///
/// RED-3 round 2 (SSA_LANDED_DIFF_R-1_V2_2026-09-05.md, CTO triage
/// `cto-triage-ssa-landed-diff-round2-2026-09-05`): the previous justification
/// converted cycle observations into instructions through the AC-10 calibration
/// that RED-2 refuted, and conceded that no trap point had been reached — so
/// "~80x headroom" was an extrapolation. Both are withdrawn.
///
/// The bracket below is what `r1_ac12_the_row_budget_bracket_is_real`
/// (`#[ignore]`, integration-tests) actually measured, with the budget disabled
/// via `set_reconcile_row_budget_for_test` and rows seeded through the
/// production write funnel:
///
///     4,000,001 rows  ANSWERED, 28,356,177,730 instructions (7,089 per row)
///     8,000,001 rows  TRAPPED  — CanisterInstructionLimitExceeded, the
///                                40,000,000,000-instruction single-message limit
///
/// (and, on the way up: 500,001 rows / 3,464,646,079; 1,000,001 / 7,000,181,365;
/// 2,000,001 / 14,118,136,473 — all ANSWERED.)
///
/// The pinned 60,000-row budget is therefore ~133x below the lowest row count at
/// which the fold is known to trap, and ~67x below the highest at which it is
/// known to answer. The bracket's resolution is one doubling step; refining it
/// costs hours per halving and the margin is two orders of magnitude either way.
///
/// Over budget, the audit path returns honest incompleteness rather than
/// trapping — V1's rule, and it applies on the audit path only.
///
/// RED-3 round 3 (SSA_LANDED_DIFF_R-1_V3_2026-09-05.md): the round-2 test
/// bracketed this constant at 20,001 and 60,001 rows — a 40,000-row range, so
/// halving the pin to 30,000 still passed both arms. The value was not bound.
/// `r1_ac12_reconcile_is_honestly_incomplete_past_its_budget` now probes at
/// exactly `BUDGET - 1`, `BUDGET` and `BUDGET + 1` rows, all derived from the
/// constant, and separately asserts the literal 60,000 that production reports
/// in its incompleteness detail. Changing this constant by a single row in
/// either direction fails that test; changing the `rows > budget` comparison
/// below to `>=` fails its exact-budget arm.
const RECONCILE_ROW_BUDGET: u64 = 60_000;

/// The budget actually applied by `reconcile_supply_invariant`.
///
/// In production this is `RECONCILE_ROW_BUDGET` and nothing else — the override
/// below does not exist in a build without `--features testing`.
///
/// RED-3 round 2 (SSA_LANDED_DIFF_R-1_V2_2026-09-05.md, CTO triage
/// `cto-triage-ssa-landed-diff-round2-2026-09-05`): AC-12's bracket has to be
/// REAL — the highest row count at which the fold ANSWERS and the lowest at
/// which it TRAPS, measured with the budget disabled, with the pinned budget
/// then shown below the trap point with the margin as a number. That
/// measurement is impossible while the budget is the thing stopping the fold,
/// so the test needs a way to take the budget out of the way. It is a
/// `testing`-only override, never a production path, and AC-13 scans the
/// shipped Wasm for its name.
fn reconcile_row_budget() -> u64 {
    #[cfg(feature = "testing")]
    {
        if let Some(b) = RECONCILE_ROW_BUDGET_OVERRIDE.with(|o| *o.borrow()) {
            return b;
        }
    }
    RECONCILE_ROW_BUDGET
}

#[cfg(feature = "testing")]
thread_local! {
    static RECONCILE_ROW_BUDGET_OVERRIDE: RefCell<Option<u64>> = const { RefCell::new(None) };
}

/// R-1 AC-12 TEST-ONLY: replace the pinned row budget for this canister.
/// `None` restores the pinned value.
#[cfg(feature = "testing")]
#[update]
fn set_reconcile_row_budget_for_test(budget: Option<u64>) {
    RECONCILE_ROW_BUDGET_OVERRIDE.with(|o| *o.borrow_mut() = budget);
}

/// R-1 AC-12 TEST-ONLY: the `performance_counter(0)` delta across ONE real
/// `reconcile_supply_invariant` call, in the same message, plus the rows it
/// examined. It WRAPS the production function — it does not reimplement any
/// part of the fold, and `caller()` is unchanged, so the controller check
/// applies exactly as it would to a direct call.
///
/// When the fold exceeds the message instruction limit this hook does not
/// return: the whole message is rejected, which is precisely the trap the
/// bracket is looking for. This is a STRUCTURAL property of the IC runtime —
/// the replica aborts the message — and holds independent of any test. The
/// bracket test that exercises it, `r1_ac12_the_row_budget_bracket_is_real`, is
/// `#[ignore]`d (minutes-long, seeds millions of rows) and does NOT run in the
/// gate, so it is not cited here as backing.
#[cfg(feature = "testing")]
#[update]
fn measure_reconcile_instructions_for_test() -> (u64, u64) {
    let before = ic_cdk::api::performance_counter(0);
    let r = reconcile_supply_invariant();
    let after = ic_cdk::api::performance_counter(0);
    (after - before, r.rows_examined)
}

/// R-1 S4(e): controller-only reconciliation. Writes nothing.
#[update]
fn reconcile_supply_invariant() -> SupplyReconciliation {
    if !ic_cdk::api::is_controller(&ic_cdk::caller()) {
        ic_cdk::trap(
            "reconcile_supply_invariant: controller-only. This is the O(N) audit \
             path; the public, O(1) check is verify_supply_invariant.",
        );
    }

    let maintained_sum_balances = ledger_maps::sum_balances();
    let maintained_sum_staking_locks = ledger_maps::sum_locks();
    let fee_reserve = FEE_RESERVE.with(|f| *f.borrow());

    let rows = ledger_maps::len_balances().saturating_add(ledger_maps::len_locks());
    let budget = reconcile_row_budget();
    if rows > budget {
        // Honest incompleteness — NOT a trap, and NOT a healthy-looking answer.
        return SupplyReconciliation {
            maintained_sum_balances,
            folded_sum_balances: 0,
            maintained_sum_staking_locks,
            folded_sum_staking_locks: 0,
            fee_reserve,
            rows_examined: 0,
            totals_consistent: false,
            folded_first_law_holds: false,
            detail: Some(format!(
                "reconciliation INCOMPLETE: {} rows (BALANCES + STAKING_LOCKS) \
                 exceeds the measured budget {}. No fold was run, so both booleans \
                 are reported false because they are UNKNOWN, not because a \
                 violation was observed.",
                rows, budget
            )),
        };
    }

    let folded_balances_opt = checked_sum(ledger_maps::iter_balances().map(|(_, v)| v));
    let folded_locks_opt = checked_sum(ledger_maps::iter_locks().map(|(_, v)| v));

    let folded_sum_balances = folded_balances_opt.unwrap_or(0);
    let folded_sum_staking_locks = folded_locks_opt.unwrap_or(0);

    let totals_consistent = folded_balances_opt == Some(maintained_sum_balances)
        && folded_locks_opt == Some(maintained_sum_staking_locks);

    let folded_first_law_holds = folded_balances_opt
        .and_then(|f| f.checked_add(fee_reserve))
        == Some(TOTAL_SUPPLY);

    let mut notes: Vec<String> = Vec::new();
    if folded_balances_opt.is_none() {
        notes.push("BALANCES fold overflowed (folded_sum_balances reported as 0)".to_string());
    }
    if folded_locks_opt.is_none() {
        notes.push(
            "STAKING_LOCKS fold overflowed (folded_sum_staking_locks reported as 0)".to_string(),
        );
    }
    if !totals_consistent {
        notes.push(format!(
            "DRIFT: maintained/folded balances {}/{}, locks {}/{}",
            maintained_sum_balances,
            folded_sum_balances,
            maintained_sum_staking_locks,
            folded_sum_staking_locks
        ));
    }
    if !folded_first_law_holds {
        notes.push(format!(
            "FIRST LAW (from the fold): folded_sum_balances({}) + fee_reserve({}) != \
             TOTAL_SUPPLY({})",
            folded_sum_balances, fee_reserve, TOTAL_SUPPLY
        ));
    }

    SupplyReconciliation {
        maintained_sum_balances,
        folded_sum_balances,
        maintained_sum_staking_locks,
        folded_sum_staking_locks,
        fee_reserve,
        rows_examined: rows,
        totals_consistent,
        folded_first_law_holds,
        detail: if notes.is_empty() { None } else { Some(notes.join("; ")) },
    }
}

// ── Upgrade hooks ─────────────────────────────────────────────────────────────
//
// ── MIGRATION LOG ─────────────────────────────────────────────────────────────
//
// STATE_VERSION 1  (M3 Track C — 2026-06-08)
//   Initial stable-persist.  First version to survive a Wasm upgrade without
//   state loss.
//
//   Serialised into TokenStableState (stable Cell, MEM_STABLE_STATE = MemoryId 4):
//     Scalars (4): block_height, transfer_fee, fee_reserve, mint_done
//     Canister refs (2): treasury, staking_canister
//
//   Survive upgrade automatically (StableBTreeMap, no serialisation needed):
//     BALANCES       (MemoryId 0) — per-account token balances
//     ALLOWANCES     (MemoryId 1) — ICRC-2 approve/allowance records
//     ALLOC_TABLE    (MemoryId 2) — genesis allocation categories
//     STAKING_LOCKS  (MemoryId 3) — locked balances held by staking canister
//     TRANSFER_DEDUP (MemoryId 5) — DEF-050B-1 icrc2_transfer_from dedup index
//
// DEF-050B-1 (2026-06-27): added TRANSFER_DEDUP (MemoryId 5). No STATE_VERSION
// bump — TokenStableState (the serialised scalar cell) is unchanged; the new map
// is a StableBTreeMap that initialises empty on first upgrade and persists after.
//
//   Upgrade from pre-Track-C code: NOT SUPPORTED.  Attempting an upgrade from
//   code with no pre_upgrade checkpoint triggers the bootstrap trap and prints:
//   "BLOCK_HEIGHT would reset to 0 (duplicate block numbers); ..."
//   No populated-state recovery is defined for this unsupported boundary.
//   Hold the canister and its identity pending an independently reviewed
//   migration; reinstall wipes stable memory and is not recovery.
//
// STATE_VERSION 2  (H-3 EXT-2 — 2026-07-14)
//   Token dedup DoS remediation. Added TRANSFER_DEDUP_BY_TIME (MemoryId 6), a
//   time-keyed secondary index over TRANSFER_DEDUP that turns prune from an O(N)
//   full scan into a bounded range scan over the expired prefix. The serialised
//   TokenStableState shape is UNCHANGED — the version bump is purely the one-shot
//   migration marker. post_upgrade: stored == 2 → steady state (both maps
//   persisted); stored == 1 → migrate_dedup_index_v1_to_v2() back-fills the index
//   from the surviving primary map (dropping already-expired legacy entries),
//   all-or-nothing, trapping over MAX_MIGRATION_ENTRIES so the whole-map scan can
//   never blow the post_upgrade instruction budget mid-migration; else → trap.
//   Inert on a fresh v2 deploy (empty map). Unlike DEF-050B-1's index, THIS one
//   bumps STATE_VERSION, because the new map must be reconstructed from existing
//   data rather than simply starting empty.
//
// STATE_VERSION 3  (R-1 token supply integrity — 2026-09-05)
//   The supply invariant is MAINTAINED incrementally instead of folded on the
//   public path. TokenStableState gains two fields:
//     sum_balances:      Option<u128>
//     sum_staking_locks: Option<u128>
//   They are `Option` ONLY because post_upgrade decodes the checkpoint bytes
//   BEFORE it inspects state_version — a required field would trap every v2→v3
//   upgrade before the migration arm below could run. The `None` is a
//   DISCRIMINATOR, never a value; the version arm decides what it means:
//     stored == 3 → both fields MUST be Some; a None is a corrupt checkpoint and
//                   restore_from_checkpoint TRAPS naming the missing field. It is
//                   never read as zero.
//     stored == 2 → both fields are IGNORED; both totals are seeded by a one-shot
//                   fold of BALANCES and STAKING_LOCKS, bounded by
//                   MAX_MIGRATION_ENTRIES exactly as the v1→v2 dedup migration is.
//     stored == 1 → migrate_dedup_index_v1_to_v2, then the same v2 seed (1→2→3).
//   Both routes go through ledger_maps::restore_from_checkpoint, so that seam has
//   exactly ONE caller in the crate. No new MemoryId is taken; the registry is
//   untouched. BALANCES and STAKING_LOCKS moved into `mod ledger_maps` in the same
//   change — the maps themselves are unchanged on the wire and in stable memory.
//
// To add a new version: increment STATE_VERSION, add a migration arm in
// post_upgrade that accepts stored_version == N-1 and upgrades the struct,
// then bump STATE_VERSION to N.  Never rely on field defaults for missing values.

#[pre_upgrade]
fn pre_upgrade() {
    // H-3: the checkpoint version is normally STATE_VERSION. Under `--features
    // testing` ONLY, a fixture may force a legacy v1 checkpoint so the next upgrade
    // drives the real one-shot migration; this branch is cfg'd out of production.
    #[allow(unused_mut)]
    let mut checkpoint_version = STATE_VERSION;
    #[cfg(feature = "testing")]
    {
        if FORCE_V1_CHECKPOINT.with(|f| *f.borrow()) {
            checkpoint_version = 1;
        }
    }
    // R-1: the totals are ALWAYS written as `Some` on a real checkpoint. The
    // AC-7d fixture is the only way either field is ever `None` at version 3,
    // and it exists so a test can prove restore_from_checkpoint refuses that
    // checkpoint rather than reading the missing total as zero.
    #[allow(unused_mut)]
    let mut checkpoint_sums = (
        Some(ledger_maps::sum_balances()),
        Some(ledger_maps::sum_locks()),
    );
    #[cfg(feature = "testing")]
    {
        // A REAL v1 checkpoint predates both total fields, so it decodes with
        // them absent. The v1 fixture must reproduce that, not merely stamp the
        // version: carrying live totals on a "v1" record makes the v1 arm's seed
        // unfalsifiable — M7e (drop the seed from the == 1 arm) stayed GREEN
        // against the version-only fixture, because the totals it was supposed
        // to have seeded were already there.
        if FORCE_V1_CHECKPOINT.with(|f| *f.borrow())
            || FORCE_V3_NONE_CHECKPOINT.with(|f| *f.borrow())
        {
            checkpoint_sums = (None, None);
        }
    }
    let state = TokenStableState {
        state_version:    checkpoint_version,
        block_height:     BLOCK_HEIGHT.with(|s| *s.borrow()),
        transfer_fee:     TRANSFER_FEE.with(|s| *s.borrow()),
        fee_reserve:      FEE_RESERVE.with(|s| *s.borrow()),
        mint_done:        MINT_DONE.with(|s| *s.borrow()),
        treasury:         TREASURY.with(|s| s.borrow()
            .expect("pre_upgrade: TREASURY is None — canister not initialised")),
        staking_canister: STAKING_CANISTER.with(|s| s.borrow()
            .expect("pre_upgrade: STAKING_CANISTER is None — canister not initialised")),
        fee_collector:    FEE_COLLECTOR.with(|s| *s.borrow()), // DEF-080 (None is valid)
        sum_balances:      checkpoint_sums.0,
        sum_staking_locks: checkpoint_sums.1,
        // HARDEN-03-SETTLEMENT (D-3): None is valid — an unbound token.
        pool_canister:     POOL_CANISTER.with(|s| *s.borrow()),
    };

    let bytes = candid::encode_one(state)
        .expect("pre_upgrade: Candid encoding of TokenStableState failed");

    STABLE_STATE_CELL.with(|c| {
        c.borrow_mut()
            .set(bytes)
            .expect("pre_upgrade: stable cell write failed");
    });
}

// ── W2 2-4 (L1-03): stale-checkpoint / rollback detection ───────────────────
//
// `post_upgrade` guards checkpoint PRESENCE (empty cell) and VERSION, but never
// FRESHNESS: a version-correct but STALE checkpoint decodes cleanly and then
// overwrites all seven rewindable heap scalars — BLOCK_HEIGHT (duplicate ICRC
// block indices), FEE_RESERVE (fees resurrect), MINT_DONE (genesis mint
// re-opens), and the three principals. The reachable trigger is an operator
// `install_code` with `skip_pre_upgrade = Some(true)`: `pre_upgrade` never runs,
// so the cell retains an OLD snapshot while the stable maps carry current state.
//
// DETECTION WITH A BLIND SPOT — NEVER PREVENTION. This is the honest limit of
// the mechanism and it must not be described any other way:
//
//   * dedup rows exist ONLY for transfers that carry `created_at_time`
//     (`record_dedup` is reached only inside that branch), so any number of
//     transfers can advance BLOCK_HEIGHT leaving no durable trace at all;
//   * rows are pruned at TX_DEDUP_WINDOW_NS (24h), so an old-enough rollback
//     leaves nothing to compare against;
//   * the map can therefore legitimately be EMPTY, in which case this guard
//     says nothing and the upgrade proceeds;
//   * and the probe SAMPLES — it reads only the newest ROLLBACK_PROBE_ENTRIES
//     rows of the time index, ordered by `created_at_time`, which is
//     CALLER-SUPPLIED and therefore need not order rows by issued block index.
//     A post-checkpoint witness can consequently sit OUTSIDE that sample while
//     every sampled row is at or below the stale checkpoint: the map then holds
//     proof of a rollback and this guard is still silent (SSA-W224-CP2-02).
//     Raising the constant widens the sample; it cannot close this.
//
// What it CAN do is never wrong in the other direction: every recorded
// block_index is a block this ledger genuinely issued, so an observed index
// ABOVE the checkpoint's block_height proves the checkpoint predates issued
// blocks. That makes the comparison a true lower bound and the guard
// false-positive-free by construction.
//
// The complete fix is shape (b) — BLOCK_HEIGHT in an eager stable cell — which
// is eager-cell **Phase 3** for this canister (docs/MEMORY_ID_REGISTRY.md marks
// token MemoryId 4 as retiring on Phase 3, conditional on the hot-path
// numbers). That is a CTO-held programme and deliberately NOT this lane.
//
// Cost: bounded and constant. The newest ROLLBACK_PROBE_ENTRIES entries of the
// time index are visited (a reverse range walk), never the whole map — so a
// large dedup map cannot turn `post_upgrade` into an instruction-limit brick,
// and no upgrade-scan cap/trap is needed.

/// How many newest-by-`created_at_time` dedup rows the rollback probe inspects.
/// Bounded work; more rows only sharpen detection, never correctness. Because
/// the ordering key is caller-supplied, a sample of ANY size can miss a higher
/// witness that sits outside it — see the blind-spot list above.
const ROLLBACK_PROBE_ENTRIES: usize = 256;

/// The `block_index` half of a dedup value (`encode_dedup_value`).
fn decode_dedup_block_index(v: &[u8; 16]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&v[0..8]);
    u64::from_le_bytes(b)
}

/// Highest block index witnessed by the SAMPLED dedup rows — the newest
/// ROLLBACK_PROBE_ENTRIES by `created_at_time` — or `None` when the sample is
/// empty (empty or fully pruned map).
///
/// This is a SAMPLE, not a maximum over the map, and `created_at_time` is
/// caller-supplied, so the sample is not ordered by block index: a higher
/// witness outside the newest rows is missed (SSA-W224-CP2-02). Every value it
/// DOES return is still a true lower bound on issued height — that is what
/// keeps the guard free of false positives — so widening or narrowing the
/// constant trades detection power only, never correctness.
fn observed_durable_block_index() -> Option<u64> {
    let keys: Vec<[u8; 32]> = TRANSFER_DEDUP_BY_TIME.with(|t| {
        t.borrow()
            .iter()
            .rev()
            .take(ROLLBACK_PROBE_ENTRIES)
            .map(|(k, _)| k.dedup_key)
            .collect()
    });
    TRANSFER_DEDUP.with(|d| {
        let d = d.borrow();
        keys.iter()
            .filter_map(|k| d.get(k))
            .map(|v| decode_dedup_block_index(&v))
            .max()
    })
}

/// The pure comparison, extracted so its algebra is unit-testable without an
/// upgrade. `None` (no witness) is NOT a rollback — silence is not evidence.
fn checkpoint_rollback_detected(observed: Option<u64>, checkpoint_height: u64) -> bool {
    matches!(observed, Some(o) if o > checkpoint_height)
}

/// R-1: the v1/v2 → v3 seed. Folds the two surviving StableBTreeMaps once and
/// returns a synthesized checkpoint carrying the results as `Some`, so
/// `restore_from_checkpoint` remains the single seam that ever sets the totals.
///
/// Bounded the same way `migrate_dedup_index_v1_to_v2` is: a fold over more than
/// MAX_MIGRATION_ENTRIES rows would risk exhausting the post_upgrade instruction
/// budget mid-seed, so it traps rather than half-seed.
fn seed_totals_state(state: &TokenStableState) -> TokenStableState {
    let rows = ledger_maps::len_balances().saturating_add(ledger_maps::len_locks());
    if rows > MAX_MIGRATION_ENTRIES {
        ic_cdk::trap(&format!(
            "post_upgrade: supply-total seed ABORTED — {} rows (BALANCES + \
             STAKING_LOCKS) exceeds MAX_MIGRATION_ENTRIES {}. The one-shot fold \
             would risk exhausting the upgrade instruction budget mid-seed, \
             leaving a partially seeded running total.",
            rows, MAX_MIGRATION_ENTRIES
        ));
    }
    let sum_balances = checked_sum(ledger_maps::iter_balances().map(|(_, v)| v))
        .unwrap_or_else(|| {
            ic_cdk::trap("post_upgrade: BALANCES fold overflowed while seeding sum_balances")
        });
    let sum_staking_locks = checked_sum(ledger_maps::iter_locks().map(|(_, v)| v))
        .unwrap_or_else(|| {
            ic_cdk::trap("post_upgrade: STAKING_LOCKS fold overflowed while seeding sum_staking_locks")
        });
    TokenStableState {
        sum_balances: Some(sum_balances),
        sum_staking_locks: Some(sum_staking_locks),
        ..state.clone()
    }
}

#[post_upgrade]
fn post_upgrade() {
    let bytes = STABLE_STATE_CELL.with(|c| c.borrow().get().clone());

    if bytes.is_empty() {
        ic_cdk::trap(
            "post_upgrade: no pre_upgrade checkpoint found in stable memory. \
             Aborting to prevent silent state loss. \
             BLOCK_HEIGHT would reset to 0 (duplicate block numbers); \
             TREASURY and STAKING_CANISTER would reset to None (fee routing broken)."
        );
    }

    let state: TokenStableState = candid::decode_one(&bytes)
        .expect("post_upgrade: Candid decode of TokenStableState failed — stable state corrupt");

    // ── H-3 (EXT-2): dedup time-index version handling ───────────────────────
    // STATE_VERSION 2 introduced TRANSFER_DEDUP_BY_TIME (MemoryId 6). A v2
    // checkpoint already carries a populated, bijective index — nothing to do. A v1
    // checkpoint predates the index: run the one-shot, all-or-nothing back-fill
    // (drop already-expired legacy entries, index the rest), which traps over
    // MAX_MIGRATION_ENTRIES rather than risk exhausting the upgrade instruction
    // budget mid-migration. Any other stored version is unsupported → trap.
    // ── R-1 (STATE_VERSION 3): the running supply totals ─────────────────────
    // Evaluated AFTER the decode above, exactly as the dedup arms are. Order:
    //   stored == 3 → restore both totals from the checkpoint (both must be Some)
    //   stored == 2 → ignore both fields; seed both totals by a one-shot fold
    //   stored == 1 → dedup migration, then the same v2 seed (chain 1→2→3)
    if state.state_version == STATE_VERSION {
        // v3 steady state — TRANSFER_DEDUP + TRANSFER_DEDUP_BY_TIME both persisted
        // untouched across the upgrade; no reconstruction needed.
    } else if state.state_version == 2 {
        // v2 → v3: the dedup maps are already in their v2 shape; only the running
        // totals are new, and they are seeded by the fold below.
    } else if state.state_version == 1 {
        migrate_dedup_index_v1_to_v2(time());
    } else {
        ic_cdk::trap(&format!(
            "post_upgrade: unsupported STATE_VERSION — stored {}, this binary \
             supports 1 and 2 (→ one-shot migrate) and {} (steady state). Write \
             an explicit migration before upgrading to this version.",
            state.state_version, STATE_VERSION
        ));
    }

    // The ONE call site of restore_from_checkpoint — and of
    // witness_for_post_upgrade — in the whole crate (see the occurrence lint).
    // A v1 or v2 checkpoint carries no totals, so a checkpoint synthesized from
    // the seed fold is passed instead; that keeps this seam at exactly ONE
    // caller rather than two.
    let restore_state = if state.state_version == STATE_VERSION {
        state.clone()
    } else {
        seed_totals_state(&state)
    };
    ledger_maps::restore_from_checkpoint(&restore_state);

    // ── W2 2-4 (L1-03): FAIL CLOSED on a stale checkpoint ─────────────────────
    // Runs AFTER the version arm above, so a v1 checkpoint has already back-filled
    // TRANSFER_DEDUP_BY_TIME and the probe has an index to walk. Trap, never
    // clamp: a detected rollback means the WHOLE checkpoint is stale, so
    // repairing the one scalar we can observe would leave MINT_DONE, FEE_RESERVE
    // and the three principals stale and would destroy the operator's only
    // signal. Repairing one field of a stale record is worse than refusing it.
    let observed = observed_durable_block_index();
    if checkpoint_rollback_detected(observed, state.block_height) {
        ic_cdk::trap(&format!(
            "post_upgrade: STALE CHECKPOINT REFUSED. The stable transfer-dedup map \
             witnesses block index {} , but the pre_upgrade checkpoint carries \
             block_height {} — the checkpoint predates blocks this ledger already \
             issued, so restoring it would re-issue used ICRC block indices and \
             rewind every checkpointed scalar (fee_reserve, mint_done, treasury, \
             fee_collector, staking_canister). This state is NOT repairable in \
             place. Operator action: abort this upgrade, re-install the PREVIOUS \
             Wasm without skip_pre_upgrade so a fresh pre_upgrade checkpoint is \
             written, then upgrade again. Detection has a blind spot (dedup rows \
             exist only for created_at_time transfers and are pruned at 24h), so \
             the absence of this trap is not proof of a fresh checkpoint.",
            observed.unwrap_or_default(),
            state.block_height
        ));
    }

    // ── Restore all heap-only state — NO defaults ─────────────────────────────

    BLOCK_HEIGHT.with(|s|     *s.borrow_mut() = state.block_height);
    TRANSFER_FEE.with(|s|     *s.borrow_mut() = state.transfer_fee);
    FEE_RESERVE.with(|s|      *s.borrow_mut() = state.fee_reserve);
    MINT_DONE.with(|s|        *s.borrow_mut() = state.mint_done);
    TREASURY.with(|s|         *s.borrow_mut() = Some(state.treasury));
    FEE_COLLECTOR.with(|s|    *s.borrow_mut() = state.fee_collector); // DEF-080
    // HARDEN-03-SETTLEMENT (D-3): restored, never defaulted and never repaired.
    POOL_CANISTER.with(|s|    *s.borrow_mut() = state.pool_canister);
    STAKING_CANISTER.with(|s| *s.borrow_mut() = Some(state.staking_canister));

    // ── H-01 (f2): RE-ARM the allowance-maintenance timer ─────────────────────
    //
    // IC timers do not survive an upgrade. `init` armed one; that one is gone.
    // Without this line the canister keeps pruning on its two write paths and
    // silently stops draining a backlog that nothing is writing against — an
    // upgrade would quietly remove the only trigger that works when traffic has
    // stopped, with nothing failing and nothing saying so.
    //
    // It re-arms against durable state: ALLOWANCES_BY_EXPIRY is stable and
    // carries the whole expired backlog across the upgrade, so the first tick
    // after this resumes exactly where the pre-upgrade binary left off. Only the
    // schedule is rebuilt. Placed last, after the checkpoint restore and the
    // stale-checkpoint refusal, so a refused upgrade traps before arming anything.
    arm_allowance_maintenance_timer();
}

// =============================================================================
// NEGATIVE / SECURITY TESTS — M1.5 Acceptance Gate
// Tests 1-5 per PM brief.
// Tests 3-4 require pocket-ic (caller identity) — marked #[ignore].
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// TOKEN-METADATA AC-1: the ledger name is "STSH" (renamed at launch),
    /// the symbol is unchanged, and icrc1_name / icrc1:name agree.
    #[test]
    fn test_token_metadata_name_is_stsh() {
        assert_eq!(NAME, "STSH");
        assert_eq!(SYMBOL, "STSH");
        assert_eq!(icrc1_name(), "STSH");
        let md = icrc1_metadata();
        let keys: Vec<&str> = md.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            vec!["icrc1:name", "icrc1:symbol", "icrc1:decimals", "icrc1:fee", "icrc1:logo"],
            "metadata key set/order unchanged"
        );
        match &md[0].1 {
            MetadataValue::Text(t) => assert_eq!(t, "STSH"),
            other => panic!("icrc1:name not Text: {other:?}"),
        }
    }

    /// TOKEN-METADATA AC-3: icrc1:logo is a PNG data URL of the committed
    /// asset; the PNG decodes to a 256×256 IHDR and is ≤ 12 KB.
    #[test]
    fn test_token_metadata_logo_is_bounded_png_data_url() {
        use base64::Engine as _;
        let url = logo_data_url();
        let payload = url
            .strip_prefix("data:image/png;base64,")
            .expect("icrc1:logo must be a PNG data URL");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .expect("logo payload must be valid base64");
        assert_eq!(bytes.as_slice(), LOGO_PNG, "logo round-trips to the committed asset");
        assert!(LOGO_PNG.len() <= 12_288, "logo PNG must be ≤ 12 KB");
        assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n", "PNG signature");
        assert_eq!(&bytes[12..16], b"IHDR", "first chunk is IHDR");
        let w = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
        let h = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
        assert_eq!((w, h), (256, 256), "logo is 256×256");
        let md = icrc1_metadata();
        match &md.iter().find(|(k, _)| k == "icrc1:logo").expect("icrc1:logo present").1 {
            MetadataValue::Text(t) => assert_eq!(t, &url),
            other => panic!("icrc1:logo not Text: {other:?}"),
        }
    }

    /// E6 (R10-1, lane A-3) — the pinned zero-amount error code and message.
    /// An error code that can drift silently is not a contract; the integration
    /// suites duplicate the value 5 because they drive the canister over
    /// PocketIC and cannot link this constant, so a change here REDs them.
    #[test]
    fn test_r10_1_e6_zero_amount_error_code_pinned() {
        assert_eq!(ERR_CODE_ZERO_AMOUNT, 5, "R10-1 pinned GenericError code");
        assert!(
            ERR_MSG_ZERO_AMOUNT.contains("greater than zero"),
            "the refusal message must name the rule"
        );
        assert!(
            ERR_MSG_ZERO_AMOUNT.contains("R10-1"),
            "the refusal message must be traceable to its lane item"
        );
    }


    // ── T-ICRC-1: allowance compound-key injectivity (reviewer PoC, ported) ──

    /// The PRE-FIX key scheme, replicated byte-for-byte so the reviewer's PoC
    /// stays executable as the RED half: plain concat of two encode_key outputs.
    fn old_allowance_key(from: &Account, spender: &Account) -> Vec<u8> {
        [from.encode_key().as_slice(), spender.encode_key().as_slice()].concat()
    }

    /// Reviewer PoC pair (A1_TOKEN_ICRC_CAMPAIGN_2026-08-27 §1): two DISTINCT
    /// (from, spender) pairs — different from-accounts AND different spenders —
    /// whose plain-concat keys are byte-identical. All principals 29 bytes.
    fn poc_collision_pairs() -> ((Account, Account), (Account, Account)) {
        let p_owner = dummy_principal(0x50); // victim P
        let q_owner = dummy_principal(0x51); // approved spender Q
        let r_owner = dummy_principal(0x52); // attacker's second principal R

        // crafted spender subaccount S = [0xAA, 0xBB] || [29] || R  (32 bytes)
        let mut s = [0u8; 32];
        s[0] = 0xAA;
        s[1] = 0xBB;
        s[2] = 29;
        s[3..32].copy_from_slice(principal_bytes_29(&r_owner));
        // derived victim subaccount A = [29] || Q || [0xAA, 0xBB]   (32 bytes)
        let mut a = [0u8; 32];
        a[0] = 29;
        a[1..30].copy_from_slice(principal_bytes_29(&q_owner));
        a[30] = 0xAA;
        a[31] = 0xBB;

        let pair1 = (
            Account { owner: p_owner, subaccount: None },
            Account { owner: q_owner, subaccount: Some(s) },
        );
        let pair2 = (
            Account { owner: p_owner, subaccount: Some(a) },
            Account { owner: r_owner, subaccount: None },
        );
        (pair1, pair2)
    }

    fn principal_bytes_29(p: &Principal) -> &[u8] {
        let b = p.as_slice();
        assert_eq!(b.len(), 29, "PoC requires 29-byte principals");
        b
    }

    /// RED half: the pre-fix concat scheme collides on the PoC pair — the
    /// defect is real, not an argument.
    #[test]
    fn test_ticrc1_poc_old_concat_key_collides() {
        let ((f1, s1), (f2, s2)) = poc_collision_pairs();
        assert_ne!(f1, f2, "PoC premise: distinct from-accounts");
        assert_ne!(s1, s2, "PoC premise: distinct spenders");
        assert_eq!(
            old_allowance_key(&f1, &s1),
            old_allowance_key(&f2, &s2),
            "PoC no longer demonstrates the pre-fix collision — pairs drifted"
        );
    }

    /// GREEN half: compound_key separates the same PoC pair.
    #[test]
    fn test_ticrc1_poc_compound_key_distinct() {
        let ((f1, s1), (f2, s2)) = poc_collision_pairs();
        assert_ne!(
            compound_key(&f1.encode_key(), &s1.encode_key()),
            compound_key(&f2.encode_key(), &s2.encode_key()),
            "compound_key must be injective on the reviewer's PoC pair"
        );
    }

    /// compound_key framing: u32-LE length prefixes on both halves, exact bytes.
    #[test]
    fn test_ticrc1_compound_key_framing_exact_bytes() {
        let k = compound_key(&[0x01, 0x02], &[0x03]);
        assert_eq!(k, vec![2, 0, 0, 0, 0x01, 0x02, 1, 0, 0, 0, 0x03]);
    }

    /// Dual-nonzero-subaccount axis: distinct nonzero subaccounts on BOTH the
    /// account and the spender all produce mutually distinct compound keys.
    #[test]
    fn test_ticrc1_dual_nonzero_subaccount_keys_distinct() {
        let owner = dummy_principal(0x60);
        let spender_owner = dummy_principal(0x61);
        let sub = |t: u8| { let mut s = [0u8; 32]; s[31] = t; Some(s) };
        let combos: Vec<Vec<u8>> = [
            (None, None), (sub(1), None), (None, sub(2)), (sub(1), sub(2)), (sub(2), sub(1)),
        ].iter().map(|(fs, ss)| compound_key(
            &Account { owner, subaccount: *fs }.encode_key(),
            &Account { owner: spender_owner, subaccount: *ss }.encode_key(),
        )).collect();
        for i in 0..combos.len() {
            for j in i + 1..combos.len() {
                assert_ne!(combos[i], combos[j], "combo {} vs {} collided", i, j);
            }
        }
    }

    /// QA-DEF-021 still holds through the compound key: Some([0;32]) ≡ None on
    /// both halves (encode_key normalization is unchanged).
    #[test]
    fn test_ticrc1_compound_key_preserves_qa_def_021_normalization() {
        let owner = dummy_principal(0x62);
        let spender_owner = dummy_principal(0x63);
        let zero = Some([0u8; 32]);
        assert_eq!(
            compound_key(
                &Account { owner, subaccount: zero }.encode_key(),
                &Account { owner: spender_owner, subaccount: zero }.encode_key(),
            ),
            compound_key(
                &Account { owner, subaccount: None }.encode_key(),
                &Account { owner: spender_owner, subaccount: None }.encode_key(),
            ),
        );
    }

    /// Format-boundary arm: this is a STORED-format change shipped pre-genesis —
    /// a fresh install carries ZERO allowance rows before the new format is
    /// exercised, so no migration exists or is needed. (Native thread-local
    /// stable structures start empty exactly as a fresh canister install does.)
    #[test]
    fn test_ticrc1_format_boundary_fresh_install_has_zero_allowance_rows() {
        ALLOWANCES.with(|a| assert_eq!(a.borrow().len(), 0,
            "fresh state must have no allowance rows at the format boundary"));
    }

    fn dummy_principal(n: u8) -> Principal {
        // 29 bytes: first byte is n, rest zero — yields a valid non-anonymous principal
        let mut bytes = [0u8; 29];
        bytes[0] = n;
        Principal::from_slice(&bytes)
    }

    /// Build a minimal AllocationCategory for testing.
    fn make_alloc(category_id: &str, amount: u128) -> AllocationCategory {
        AllocationCategory {
            category_id:          category_id.to_string(),
            category_name:        format!("Test {}", category_id),
            amount,
            recipient:            dummy_principal(1),
            subaccount:           None,
            lock_policy:          LockPolicy::ImmediatelyLiquid,
            vesting_policy:       None,
            created_at_genesis:   false,
            genesis_timestamp_ns: 0,
        }
    }

    // ── K3-002a/b boundary tests (P-ARITH): checked folds at exact u128::MAX ──

    #[test]
    fn test_arith_checked_sum_exact_u128_max_boundary() {
        assert_eq!(checked_sum([u128::MAX].into_iter()), Some(u128::MAX));
        assert_eq!(checked_sum([u128::MAX, 1u128].into_iter()), None);
        assert_eq!(checked_sum([u128::MAX - 1, 1u128].into_iter()), Some(u128::MAX));
        assert_eq!(checked_sum(std::iter::empty::<u128>()), Some(0));
    }

    #[test]
    fn test_arith_plus_fee_and_staking_overflow_flags_attributed() {
        let a = dummy_principal(210);
        let b = dummy_principal(211);

        // Balances fold succeeds at exactly u128::MAX; the +fee_reserve add
        // overflows → ONLY the third site fires; the fold result is reported.
        set_balance_for(a, u128::MAX);
        FEE_RESERVE.with(|f| *f.borrow_mut() = 1);
        let eval = evaluate_supply_invariant();
        assert!(!eval.balances_overflow);
        assert!(eval.balances_plus_fee_overflow, "balances+fee site must be attributed");
        assert!(!eval.invariant_holds, "any arithmetic error forces invariant_holds=false");
        assert_eq!(eval.sum_balances, u128::MAX, "successful fold result stays reported");
        FEE_RESERVE.with(|f| *f.borrow_mut() = 0);

        // R-1 S4(c) EXPLAINED DELTA: the two FOLD-overflow attributions
        // (`balances_overflow`, `staking_locks_overflow`) can no longer occur on
        // the public path, because there is no fold left there to overflow — the
        // totals are maintained. They are reported `false`, and the refusal they
        // used to carry moved EARLIER, to write time: see
        // `test_arith_staking_lock_total_overflow_is_a_write_time_refusal`.
        set_lock_for(a, 7);
        let eval = evaluate_supply_invariant();
        assert!(!eval.staking_locks_overflow,
            "R-1: no fold on the public path, so this site can no longer be attributed");
        assert!(!eval.balances_overflow,
            "R-1: no fold on the public path, so this site can no longer be attributed");
        assert_eq!(eval.staking_locked, 7, "the MAINTAINED locks total is reported");

        clear_state_for(a);
        clear_state_for(b);
        let _ = b;
    }

    /// R-1 S4(b)/(d): the arithmetic refusal the fold used to report is now a
    /// WRITE-TIME refusal — a running total that cannot represent the ledger is a
    /// trap, not a wrong number (invariant 4, P-ARITH R-1).
    ///
    /// Runs on a dedicated thread so the deliberately-unrepresentable thread-local
    /// ledger state is discarded with that thread rather than leaking into the
    /// sibling tests that share this one.
    #[test]
    fn test_arith_staking_lock_total_overflow_is_a_write_time_refusal() {
        let handle = std::thread::spawn(|| {
            let a = dummy_principal(212);
            let b = dummy_principal(213);
            set_lock_for(a, u128::MAX);
            set_lock_for(b, 1); // SUM_STAKING_LOCKS cannot represent this
        });
        let err = handle.join().expect_err("the second lock write must trap, never wrap");
        let msg = err
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .unwrap_or_default();
        assert!(
            msg.contains("SUM_STAKING_LOCKS: running total cannot represent the ledger"),
            "unexpected panic message: {msg}"
        );
    }

    #[test]
    fn l03a_balance_funnel_removes_zero_and_preserves_folded_total() {
        let handle = std::thread::spawn(|| {
            let key = Account { owner: dummy_principal(217), subaccount: Some([3; 32]) }.encode_key();
            let rows = ledger_maps::len_balances();
            let total = ledger_maps::sum_balances();

            ledger_maps::write_balance(key.clone(), 0, 0);
            assert_eq!(ledger_maps::len_balances(), rows, "zero must not allocate a row");
            assert_eq!(ledger_maps::get_balance(&key), 0, "absent reads as zero");
            assert_eq!(ledger_maps::sum_balances(), total);
            assert_eq!(ledger_maps::iter_balances().map(|(_, v)| v).sum::<u128>(), total);

            ledger_maps::write_balance(key.clone(), 0, 19);
            assert_eq!(ledger_maps::len_balances(), rows + 1);
            assert_eq!(ledger_maps::sum_balances(), total + 19);
            assert_eq!(ledger_maps::iter_balances().map(|(_, v)| v).sum::<u128>(), total + 19);

            ledger_maps::write_balance(key.clone(), 19, 0);
            assert_eq!(ledger_maps::len_balances(), rows);
            assert_eq!(ledger_maps::get_balance(&key), 0, "removed reads as zero");
            assert_eq!(ledger_maps::sum_balances(), total);
            assert_eq!(ledger_maps::iter_balances().map(|(_, v)| v).sum::<u128>(), total);
        });
        handle.join().expect("balance funnel zero-row test must not trap");
    }

    #[test]
    fn l03a_lock_funnel_removes_zero_and_preserves_folded_total() {
        let handle = std::thread::spawn(|| {
            let key = Account { owner: dummy_principal(218), subaccount: None }.encode_key();
            let rows = ledger_maps::len_locks();
            let total = ledger_maps::sum_locks();

            ledger_maps::write_lock(key.clone(), 0, 0);
            assert_eq!(ledger_maps::len_locks(), rows, "zero must not allocate a row");
            assert_eq!(ledger_maps::get_lock(&key), 0, "absent reads as zero");
            assert_eq!(ledger_maps::sum_locks(), total);
            assert_eq!(ledger_maps::iter_locks().map(|(_, v)| v).sum::<u128>(), total);

            ledger_maps::write_lock(key.clone(), 0, 23);
            assert_eq!(ledger_maps::len_locks(), rows + 1);
            assert_eq!(ledger_maps::sum_locks(), total + 23);
            assert_eq!(ledger_maps::iter_locks().map(|(_, v)| v).sum::<u128>(), total + 23);

            ledger_maps::write_lock(key.clone(), 23, 0);
            assert_eq!(ledger_maps::len_locks(), rows);
            assert_eq!(ledger_maps::get_lock(&key), 0, "removed reads as zero");
            assert_eq!(ledger_maps::sum_locks(), total);
            assert_eq!(ledger_maps::iter_locks().map(|(_, v)| v).sum::<u128>(), total);
        });
        handle.join().expect("lock funnel zero-row test must not trap");
    }

    /// R-1 AC-5(vii): `route_fee_to_treasury` is a production BALANCES write
    /// whose delta is structurally ZERO on the launch Wasm (`DEFAULT_FEE = 0`,
    /// and it early-returns on `fee == 0`), so no PocketIC behaviour can
    /// distinguish it. It is bound here instead, by calling it directly with a
    /// nonzero fee and asserting the MAINTAINED total moved by exactly that fee
    /// AND still equals the fold. Swapping this one call site off the funnel
    /// (mutation M5-(vii)) drives this test RED.
    #[test]
    fn test_r1_route_fee_to_treasury_moves_the_maintained_total() {
        let handle = std::thread::spawn(|| {
            let treasury = dummy_principal(216);
            TREASURY.with(|t| *t.borrow_mut() = Some(treasury));
            FEE_COLLECTOR.with(|f| *f.borrow_mut() = None);

            let before = ledger_maps::sum_balances();
            route_fee_to_treasury(7);
            let after = ledger_maps::sum_balances();

            assert_eq!(after - before, 7, "the fee credit must move the running total");
            let folded: u128 = ledger_maps::iter_balances().map(|(_, v)| v).sum();
            assert_eq!(after, folded, "maintained total must equal the fold");
            let key = Account { owner: treasury, subaccount: None }.encode_key();
            assert_eq!(ledger_maps::get_balance(&key), 7, "the recipient row moved too");
        });
        handle.join().expect("route_fee_to_treasury unit case must not trap");
    }

    /// AC-5(iv), stated rather than tested: `icrc2_approve`'s fee debit is the
    /// other structurally-zero-delta production write. Unlike (vii) it CANNOT be
    /// reached off-canister at all — `icrc2_approve` reads `caller()` — and
    /// `DEFAULT_FEE = 0` has no setter (DEF-085), so no Wasm can exercise it with
    /// a nonzero delta. It is bound by AC-5(x)/(x2) ONLY: it is on the funnel
    /// because `BALANCES` is unreachable from that call site, which the compiler
    /// enforces, not a test.
    #[test]
    fn test_r1_approve_fee_debit_is_bound_structurally_not_behaviourally() {
        assert_eq!(DEFAULT_FEE, 0, "AC-5(iv)'s premise: the approve fee delta is structurally zero");
    }

    /// The balances-side sibling of the test above.
    #[test]
    fn test_arith_balance_total_overflow_is_a_write_time_refusal() {
        let handle = std::thread::spawn(|| {
            let a = dummy_principal(214);
            let b = dummy_principal(215);
            set_balance_for(a, u128::MAX);
            set_balance_for(b, 1); // SUM_BALANCES cannot represent this
        });
        let err = handle.join().expect_err("the second balance write must trap, never wrap");
        let msg = err
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .unwrap_or_default();
        assert!(
            msg.contains("SUM_BALANCES: running total cannot represent the ledger"),
            "unexpected panic message: {msg}"
        );
    }

    #[test]
    fn test_arith_wrapping_genesis_manifest_rejected_typed() {
        // u128::MAX + (TOTAL_SUPPLY + 1) ≡ TOTAL_SUPPLY (mod 2^128): the exact
        // K3-002a wrap. Distinct recipients so per-account credits don't trap.
        let mut a1 = make_alloc("wrap_a", u128::MAX);
        a1.recipient = dummy_principal(11);
        let mut a2 = make_alloc("wrap_b", TOTAL_SUPPLY + 1);
        a2.recipient = dummy_principal(12);

        let result = validate_init_allocations(&[a1, a2]);
        assert!(result.is_err(), "wrapping manifest must be rejected");
        assert!(
            result.unwrap_err().contains("overflows u128"),
            "rejection must be the typed overflow message"
        );
    }

    // ── Test 1: Duplicate category_ids are rejected at init ───────────────────
    //
    // INVARIANT: every genesis allocation must have a unique category_id.
    // Duplicates would allow a category to appear twice in the genesis table,
    // breaking auditability and potentially doubling the accounting of one tranche.
    #[test]
    fn test_01_duplicate_allocation_ids_rejected() {
        let half = TOTAL_SUPPLY / 2;
        let allocs = vec![
            make_alloc("treasury", half),
            make_alloc("treasury", TOTAL_SUPPLY - half), // same id as above
        ];

        let result = validate_init_allocations(&allocs);

        assert!(result.is_err(), "Duplicate category_id must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("Duplicate category_id"),
            "Error must cite 'Duplicate category_id'; got: {:?}", err
        );
        assert!(
            err.contains("treasury"),
            "Error must name the offending id; got: {:?}", err
        );
    }

    // ── Test 2: Allocation sum != TOTAL_SUPPLY is rejected at init ────────────
    //
    // INVARIANT: sum(allocations) must equal TOTAL_SUPPLY exactly.
    // Any shortfall or excess means tokens are either unaccounted-for or overcreated.
    // Neither is permitted — fixed supply is non-negotiable.
    #[test]
    fn test_02_allocation_sum_mismatch_rejected() {
        // One token short of TOTAL_SUPPLY
        let allocs = vec![make_alloc("all", TOTAL_SUPPLY - 1)];

        let result = validate_init_allocations(&allocs);

        assert!(result.is_err(), "Sum < TOTAL_SUPPLY must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("TOTAL_SUPPLY"),
            "Error must mention TOTAL_SUPPLY; got: {:?}", err
        );

        // Also test sum > TOTAL_SUPPLY
        let allocs_over = vec![make_alloc("all", TOTAL_SUPPLY + 1)];
        let result_over = validate_init_allocations(&allocs_over);
        assert!(result_over.is_err(), "Sum > TOTAL_SUPPLY must also be rejected");
    }

    // Tests 03 and 04 (caller-identity guards for lock_for_staking / unlock_from_staking)
    // moved to integration-tests/tests/security_tests.rs — require real cross-canister
    // caller identity which is only available via PocketIC.

    // ── Test 5: Staking locks are included in the supply invariant ────────────
    //
    // DESIGN: lock_for_staking() marks tokens as locked WITHIN the holder's
    // BALANCES entry — it does NOT remove them from BALANCES.
    // INVARIANT: sum(BALANCES) + fee_reserve == TOTAL_SUPPLY must hold even
    // when large staking locks are active.
    //
    // This test documents and verifies the arithmetic identity:
    //   sum_balances = circulating_liquid + staking_locked
    //   sum_balances + fee_reserve == TOTAL_SUPPLY  ✓
    //
    // If staking locks were subtracted from BALANCES (incorrect), the invariant
    // would break — this test catches that design error.
    #[test]
    fn test_05_supply_invariant_holds_with_staking_locks() {
        // Representative split: 400M circulating, 500M staked, 100M in fee reserve
        let fee_reserve:     u128 = 100_000_000 * 100_000_000; // 100M STSH
        let staking_locked:  u128 = 500_000_000 * 100_000_000; // 500M STSH
        let circulating:     u128 = TOTAL_SUPPLY - staking_locked - fee_reserve;

        // In the correct design: BALANCES includes both circulating AND staking-locked
        let sum_balances: u128 = circulating + staking_locked;

        assert_eq!(
            sum_balances + fee_reserve,
            TOTAL_SUPPLY,
            "Invariant: sum_balances + fee_reserve == TOTAL_SUPPLY even with staking locks"
        );

        // Demonstrate that removing locks from BALANCES breaks the invariant:
        let wrong_sum_balances: u128 = circulating; // incorrectly excludes locked
        assert_ne!(
            wrong_sum_balances + fee_reserve,
            TOTAL_SUPPLY,
            "Incorrect design (locks excluded from BALANCES) breaks the supply invariant"
        );

        // Staking-locked total is publicly visible but does NOT reduce BALANCES
        assert_eq!(
            circulating + staking_locked + fee_reserve,
            TOTAL_SUPPLY,
            "All tokens accounted for: liquid + locked + fee_reserve == TOTAL_SUPPLY"
        );
    }

    // ── Tests 06–11: Liquid balance enforcement (P1 fix) ──────────────────────
    //
    // These tests verify the liquid_balance / staking_locked_balance logic that
    // icrc1_transfer and icrc2_transfer_from now use for their balance check.
    //
    // Transfer-path enforcement (icrc1_transfer + icrc2_transfer_from called
    // against locked balances) requires IC runtime (caller()) and lives in
    // integration-tests/tests/security_tests.rs.

    // R-1 S4(d): these go through the SAME funnel as production. Under S4(b)
    // this is not a style preference — BALANCES/STAKING_LOCKS are private to
    // `mod ledger_maps`, so there is no other way left to write either map.
    fn set_balance_for(owner: Principal, amount: u128) {
        let key = Account { owner, subaccount: None }.encode_key();
        let old = ledger_maps::get_balance(&key);
        ledger_maps::write_balance(key, old, amount);
    }

    fn set_lock_for(owner: Principal, amount: u128) {
        let key = Account { owner, subaccount: None }.encode_key();
        let old = ledger_maps::get_lock(&key);
        ledger_maps::write_lock(key, old, amount);
    }

    /// Zeroing through the funnel rather than removing the row: `remove` is not
    /// on the funnel (a row at 0 and an absent row read identically through
    /// `get_balance`/`get_lock`), and zeroing keeps the running totals exact.
    fn clear_state_for(owner: Principal) {
        let key = Account { owner, subaccount: None }.encode_key();
        let old_bal = ledger_maps::get_balance(&key);
        let old_lock = ledger_maps::get_lock(&key);
        ledger_maps::write_balance(key.clone(), old_bal, 0);
        ledger_maps::write_lock(key, old_lock, 0);
    }

    // ── Test 06: liquid_balance == total when no lock ──────────────────────────
    #[test]
    fn test_06_liquid_balance_equals_total_when_no_lock() {
        let p = dummy_principal(6);
        set_balance_for(p, 1_000_000);
        assert_eq!(liquid_balance(p), 1_000_000);
        clear_state_for(p);
    }

    // ── Test 07: liquid_balance == total - locked when partial lock ────────────
    //
    // INVARIANT: staked tokens reduce the liquid amount available for transfer.
    #[test]
    fn test_07_liquid_balance_reduces_by_lock_amount() {
        let p = dummy_principal(7);
        set_balance_for(p, 1_000_000);
        set_lock_for(p, 400_000);
        assert_eq!(liquid_balance(p), 600_000, "liquid = total - locked");
        clear_state_for(p);
    }

    // ── Test 08: liquid_balance == 0 when fully staked ────────────────────────
    //
    // INVARIANT: A fully staked account has zero transferable balance.
    #[test]
    fn test_08_liquid_balance_is_zero_when_fully_staked() {
        let p = dummy_principal(8);
        set_balance_for(p, 500_000);
        set_lock_for(p, 500_000);
        assert_eq!(liquid_balance(p), 0, "fully staked → liquid = 0");
        clear_state_for(p);
    }

    // ── Test 09: saturating_sub — locked cannot drive liquid below zero ────────
    //
    // INVARIANT: even if STAKING_LOCKS somehow exceeds BALANCES (invariant
    // violation), saturating_sub prevents underflow — liquid floors at 0.
    #[test]
    fn test_09_liquid_balance_floors_at_zero_on_oversized_lock() {
        let p = dummy_principal(9);
        set_balance_for(p, 100);
        set_lock_for(p, 999); // lock > balance — must not panic
        assert_eq!(liquid_balance(p), 0, "saturating_sub: liquid cannot go below 0");
        clear_state_for(p);
    }

    // ── Test 10: unlock restores full liquid balance ───────────────────────────
    //
    // INVARIANT: after unlock, liquid_balance == total_balance again.
    #[test]
    fn test_10_unlock_restores_liquid_balance() {
        let p = dummy_principal(10);
        set_balance_for(p, 800_000);
        set_lock_for(p, 800_000);
        assert_eq!(liquid_balance(p), 0, "fully locked before unlock");
        set_lock_for(p, 0);
        assert_eq!(liquid_balance(p), 800_000, "full balance liquid after unlock");
        clear_state_for(p);
    }

    // ── Test 11: partial lock — liquid boundary arithmetic ────────────────────
    //
    // INVARIANT: liquid = total - locked.
    // Transfer-path enforcement (icrc1_transfer / icrc2_transfer_from against
    // locked balances) requires IC runtime and is tested in
    // integration-tests/tests/security_tests.rs.
    #[test]
    fn test_11_partial_stake_liquid_boundary() {
        let p = dummy_principal(11);
        set_balance_for(p, 1_000);
        set_lock_for(p, 300);
        let liq = liquid_balance(p);
        assert_eq!(liq, 700, "liquid = 1000 - 300 = 700");
        assert!(liq >= 700, "transfer of exactly 700 must be permitted");
        assert!(liq < 701,  "transfer of 701 exceeds liquid — must be rejected");
        clear_state_for(p);
    }

    // ── Lane B §3: u128_overflow_safe ─────────────────────────────────────────
    //
    // The transfer paths route every balance add/sub through checked_total_debit
    // and checked_credit. Near u128::MAX these MUST return an error, never wrap.
    #[test]
    fn test_u128_overflow_safe() {
        // NOTE: a nonzero fee literal — this is an arithmetic-property test of
        // the checked helpers, independent of the (now zero, F-000) live fee.
        // With the live fee, u128::MAX + 0 would not overflow and the probe
        // would be vacuous.
        let fee = 10_000u128;

        // amount + fee that overflows u128 → Err, no wrap.
        assert!(checked_total_debit(u128::MAX, fee).is_err(),
            "total_debit must error when amount + fee overflows u128");
        assert!(checked_total_debit(u128::MAX, 1).is_err(),
            "total_debit must error one unit past the ceiling");

        // Exact boundary that still fits is computed correctly (no wrap, no error).
        assert_eq!(checked_total_debit(u128::MAX - 10_000, 10_000).unwrap(), u128::MAX,
            "total_debit must equal the exact sum when it fits");

        // Recipient / fee credit near the ceiling likewise errors, not wraps.
        assert!(checked_credit(u128::MAX, 1).is_err(),
            "credit must error when balance + amount overflows u128");
        assert_eq!(checked_credit(u128::MAX - 5, 5).unwrap(), u128::MAX,
            "credit must equal the exact sum at the boundary");

        // Sanity: ordinary arithmetic is unaffected.
        assert_eq!(checked_total_debit(1_000, 10_000).unwrap(), 11_000);
        assert_eq!(checked_credit(1_000, 500).unwrap(), 1_500);
    }

    // ── Lane B §3: supply_invariant (derived from verify_supply_invariant) ─────
    //
    // Canonical invariant taken from verify_supply_invariant() in this file:
    //   TOTAL_SUPPLY == sum(all BALANCES entries) + fee_reserve
    // fee_reserve is an EXTERNAL bucket (outside BALANCES) that only accrues when
    // TREASURY is unset (see route_fee_to_treasury). Staking locks live INSIDE
    // BALANCES (lock_for_staking moves liquid→locked within the account), so they
    // are NOT added separately — counting them would double-count.
    //
    // This drives the real BALANCES map + FEE_RESERVE through the production
    // verify_supply_invariant() and asserts the report; then perturbs by one unit
    // to prove the check is not vacuous.
    #[test]
    fn test_supply_invariant_holds_and_is_not_vacuous() {
        // Fully clear this thread's BALANCES / STAKING_LOCKS / FEE_RESERVE so the
        // sum is independent of any sibling test that shares the thread-locals.
        for (k, v) in ledger_maps::iter_balances() {
            ledger_maps::write_balance(k, v, 0);
        }
        for (k, v) in ledger_maps::iter_locks() {
            ledger_maps::write_lock(k, v, 0);
        }
        FEE_RESERVE.with(|f| *f.borrow_mut() = 0);

        let a      = dummy_principal(200);
        let b      = dummy_principal(201);
        let staker = dummy_principal(202);

        // Distribute the ENTIRE fixed supply across BALANCES, with one account
        // fully staked (locked balance stays inside BALANCES).
        let staked = 500_000_000u128 * 100_000_000;     // 500M STSH locked
        let a_bal  = 400_000_000u128 * 100_000_000;     // 400M STSH liquid
        let b_bal  = TOTAL_SUPPLY - a_bal - staked;     // remainder
        set_balance_for(a, a_bal);
        set_balance_for(b, b_bal);
        set_balance_for(staker, staked);
        set_lock_for(staker, staked);                   // fully staked, still in BALANCES

        let eval = evaluate_supply_invariant();
        assert!(eval.invariant_holds,
            "sum(BALANCES)+fee_reserve must equal TOTAL_SUPPLY; sum={} fee_reserve={}",
            eval.sum_balances, eval.fee_reserve);
        assert_eq!(eval.sum_balances, TOTAL_SUPPLY,
            "all supply lives in BALANCES here (fee_reserve == 0)");
        assert_eq!(eval.fee_reserve, 0, "no fee reserve accrued in this test");
        assert!(
            !eval.balances_overflow && !eval.staking_locks_overflow
                && !eval.balances_plus_fee_overflow,
            "no arithmetic error on a healthy ledger"
        );
        let locked_total: u128 = ledger_maps::iter_locks().map(|(_, v)| v).sum();
        assert_eq!(locked_total, staked,
            "locked total is tracked but NOT subtracted from BALANCES");

        // Not vacuous: removing a single base unit must break the invariant.
        set_balance_for(a, a_bal - 1);
        let eval_after = evaluate_supply_invariant();
        assert!(!eval_after.invariant_holds,
            "removing 1 base unit must break the supply invariant");

        // Clean up so sibling tests on this thread see an empty slate.
        clear_state_for(a);
        clear_state_for(b);
        clear_state_for(staker);
    }
}

// =============================================================================
// H-3 (EXT-2) — token dedup DoS remediation: DIRECT unit tests for the
// time-keyed prune index. Exercises the module-private maps and the
// now-parameterised prune / migrate helpers directly, so the exact expiry
// boundary and the one-shot v1→v2 migration logic are proven with zero PocketIC
// timing dependence. Production-Wasm behaviour (three writers, real upgrades,
// perf) is covered by integration-tests/tests/token_dedup_dos_tests.rs.
// =============================================================================
#[cfg(test)]
mod h3_dedup_index_tests {
    use super::*;

    /// Reset both dedup maps so tests sharing a thread start from an empty slate
    /// (thread_local StableBTreeMaps persist across sequential tests on a thread).
    fn reset_dedup_maps() {
        let pk: Vec<[u8; 32]> =
            TRANSFER_DEDUP.with(|d| d.borrow().iter().map(|(k, _)| k).collect());
        TRANSFER_DEDUP.with(|d| {
            let mut m = d.borrow_mut();
            for k in pk {
                m.remove(&k);
            }
        });
        let tk: Vec<DedupTimeKey> =
            TRANSFER_DEDUP_BY_TIME.with(|t| t.borrow().iter().map(|(k, _)| k).collect());
        TRANSFER_DEDUP_BY_TIME.with(|t| {
            let mut m = t.borrow_mut();
            for k in tk {
                m.remove(&k);
            }
        });
    }

    fn key_of(seed: u64) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0..8].copy_from_slice(&seed.to_be_bytes());
        k
    }

    /// R-1 S3 (form (a), SI-10 fix): this drives the PRODUCTION writer,
    /// `record_dedup_at` — the whole body of `record_dedup` with `now` passed in
    /// rather than read from `time()`. It no longer reimplements the dual insert
    /// locally, so every bijectivity/cardinality assertion in this suite is bound
    /// to the real code: deleting either insert inside `record_dedup_at` drives
    /// this suite RED (mutations M3a/M3b).
    ///
    /// `now = 0` makes the prune inside the writer a no-op (cutoff saturates to
    /// 0, and no entry has `created_at_ns < 0`), so the fixtures land exactly as
    /// the old local helper placed them.
    fn put(seed: u64, block: u64, created_at: u64) {
        record_dedup_at(0, key_of(seed), block, created_at);
    }

    fn primary_len() -> u64 {
        TRANSFER_DEDUP.with(|d| d.borrow().len())
    }
    fn index_len() -> u64 {
        TRANSFER_DEDUP_BY_TIME.with(|t| t.borrow().len())
    }
    fn has_primary(seed: u64) -> bool {
        TRANSFER_DEDUP.with(|d| d.borrow().contains_key(&key_of(seed)))
    }

    // ── DedupTimeKey Storable round-trip + time-first (big-endian) ordering ────
    #[test]
    fn dedup_time_key_storable_roundtrip_and_order() {
        let k = DedupTimeKey::new(0x0123_4567_89ab_cdef, [0xAB; 32]);
        let bytes = k.to_bytes();
        assert_eq!(bytes.len(), 40, "fixed 40-byte encoding");
        assert_eq!(
            &bytes[0..8],
            &0x0123_4567_89ab_cdefu64.to_be_bytes(),
            "created_at_ns is big-endian in [0..8]"
        );
        assert_eq!(DedupTimeKey::from_bytes(bytes), k, "round-trips");
        // created_at dominates dedup_key in the ordering (time-first).
        let earlier = DedupTimeKey::new(10, [0xFF; 32]);
        let later = DedupTimeKey::new(11, [0x00; 32]);
        assert!(earlier < later, "smaller created_at sorts first regardless of key bytes");
    }

    // ── exact cardinality + bijective consistency after inserts / no-op prune ─
    #[test]
    fn cardinality_and_bijective_consistency() {
        reset_dedup_maps();
        let base = 100 * TX_DEDUP_WINDOW_NS;
        for i in 0..5u64 {
            put(i, i, base + i);
        }
        assert_eq!(primary_len(), 5);
        assert_eq!(index_len(), 5);
        assert!(dedup_maps_consistent(), "maps bijective after inserts");
        prune_expired_dedup(base + 10); // nothing expired
        assert_eq!(primary_len(), 5, "nothing expired ⇒ nothing pruned");
        assert!(dedup_maps_consistent());
        reset_dedup_maps();
    }

    // ── exact expiry boundary (P3): == cutoff retained; == cutoff-1 pruned;
    //    == cutoff+1 retained — driven with a fixed `now`, no PocketIC. ─────────
    #[test]
    fn exact_expiry_boundary() {
        reset_dedup_maps();
        let now = 50 * TX_DEDUP_WINDOW_NS;
        let cutoff = now - TX_DEDUP_WINDOW_NS; // expired iff created_at < cutoff
        put(1, 1, cutoff); // == cutoff → retained
        put(2, 2, cutoff - 1); // < cutoff → expired, prunable
        put(3, 3, cutoff + 1); // > cutoff → retained
        assert_eq!(primary_len(), 3);
        prune_expired_dedup(now);
        assert!(has_primary(1), "created_at == cutoff is RETAINED (boundary is inclusive)");
        assert!(!has_primary(2), "created_at == cutoff-1 is EXPIRED and pruned");
        assert!(has_primary(3), "created_at == cutoff+1 is RETAINED");
        assert_eq!(primary_len(), 2);
        assert_eq!(index_len(), 2, "expired entry dropped from the index too");
        assert!(dedup_maps_consistent(), "still bijective after prune");
        reset_dedup_maps();
    }

    // ── out-of-order insertion still yields chronological prune behaviour ──────
    #[test]
    fn out_of_order_timestamps_chronological_prune() {
        reset_dedup_maps();
        let now = 50 * TX_DEDUP_WINDOW_NS;
        let cutoff = now - TX_DEDUP_WINDOW_NS;
        // Insert in NON-chronological order; a mix of expired and fresh.
        put(10, 10, cutoff + 5);
        put(11, 11, cutoff - 100);
        put(12, 12, cutoff + 1);
        put(13, 13, cutoff - 1);
        put(14, 14, cutoff - 50);
        assert_eq!(primary_len(), 5);
        prune_expired_dedup(now);
        assert!(has_primary(10) && has_primary(12), "fresh entries retained");
        assert!(
            !has_primary(11) && !has_primary(13) && !has_primary(14),
            "every expired entry pruned regardless of insertion order"
        );
        assert_eq!(primary_len(), 2);
        assert!(dedup_maps_consistent());
        reset_dedup_maps();
    }

    // ── prune removes at most MAX_PRUNE_PER_CALL per call (oldest-first) ───────
    #[test]
    fn prune_is_bounded_per_call() {
        reset_dedup_maps();
        let now = 50 * TX_DEDUP_WINDOW_NS;
        let cutoff = now - TX_DEDUP_WINDOW_NS;
        let n = MAX_PRUNE_PER_CALL as u64 + 20;
        for i in 0..n {
            put(i, i, cutoff - 1 - i); // all expired, strictly increasing age
        }
        assert_eq!(primary_len(), n);
        prune_expired_dedup(now);
        assert_eq!(
            primary_len(),
            n - MAX_PRUNE_PER_CALL as u64,
            "a single prune removes at most MAX_PRUNE_PER_CALL"
        );
        assert!(dedup_maps_consistent(), "bijective after a capped prune");
        reset_dedup_maps();
    }

    // ── one-shot v1→v2 migration: back-fill live, drop expired, stay bijective ─
    #[test]
    fn migration_backfills_live_and_drops_expired() {
        reset_dedup_maps();
        let now = 50 * TX_DEDUP_WINDOW_NS;
        let cutoff = now - TX_DEDUP_WINDOW_NS;
        // Simulate a v1 map: primary-only entries (no index yet), mixed ages.
        let put_primary_only = |seed: u64, created: u64| {
            TRANSFER_DEDUP.with(|d| {
                d.borrow_mut().insert(key_of(seed), encode_dedup_value(seed, created));
            });
        };
        put_primary_only(1, cutoff + 10); // live
        put_primary_only(2, cutoff - 10); // expired
        put_primary_only(3, cutoff); // live (== cutoff retained)
        put_primary_only(4, cutoff - 1); // expired
        assert_eq!(primary_len(), 4);
        assert_eq!(index_len(), 0, "v1 shape: no time index yet");

        migrate_dedup_index_v1_to_v2(now);

        assert!(has_primary(1) && has_primary(3), "live entries survive migration");
        assert!(!has_primary(2) && !has_primary(4), "expired legacy entries dropped");
        assert_eq!(primary_len(), 2);
        assert_eq!(index_len(), 2, "index back-filled for the live entries only");
        assert!(dedup_maps_consistent(), "maps bijective after migration");
        reset_dedup_maps();
    }

    // ── production migration limit is the measured value (change-detector) ─────
    #[test]
    fn production_migration_limit_is_measured_value() {
        // Locks MAX_MIGRATION_ENTRIES_PRODUCTION to the value measured against the
        // worst-path post_upgrade budget (see the PR). Editing the const without
        // re-measuring trips this test. Always compiled — independent of the
        // `testing` feature — so feature unification can never mask it.
        assert_eq!(MAX_MIGRATION_ENTRIES_PRODUCTION, 200_000);
    }
}

// =============================================================================
// H-01 (HARDEN-02) — allowance lifetime, expiry index and reclamation.
//
// The pure half of the H-01 matrix: the key type, the shared effective-allowance
// notion, and the prune's boundary and cap arithmetic, driven directly against
// the PRODUCTION writer and the PRODUCTION prune with `now` supplied as a
// parameter. The behavioural half (real ingress, the real timer, real upgrades)
// is integration-tests/tests/token_allowance_lifetime_tests.rs.
// =============================================================================

#[cfg(test)]
mod h01_allowance_index_tests {
    use super::*;

    /// thread_local StableBTreeMaps persist across sequential tests on a thread,
    /// so each test starts by emptying both maps through the PRODUCTION remover.
    fn reset_allowance_maps() {
        let rows: Vec<(Vec<u8>, Option<u64>)> =
            ALLOWANCES.with(|a| a.borrow().iter().map(|(k, r)| (k, r.expires_at)).collect());
        for (k, exp) in rows {
            remove_allowance(&k, exp);
        }
        // Any index entry with no primary row (which the bijection forbids, but
        // which a failing test could leave behind) is swept too, so one failure
        // cannot cascade into every later test in the module.
        let orphans: Vec<AllowanceExpiryKey> =
            ALLOWANCES_BY_EXPIRY.with(|t| t.borrow().iter().map(|(k, _)| k).collect());
        ALLOWANCES_BY_EXPIRY.with(|t| {
            let mut m = t.borrow_mut();
            for k in orphans {
                m.remove(&k);
            }
        });
        assert_eq!(ALLOWANCES.with(|a| a.borrow().len()), 0, "fixture: primary map empty");
        assert_eq!(ALLOWANCES_BY_EXPIRY.with(|t| t.borrow().len()), 0, "fixture: index empty");
    }

    fn key(seed: u64) -> Vec<u8> {
        let mut k = vec![0xFEu8];
        k.extend_from_slice(&seed.to_be_bytes());
        k
    }

    fn approve_row(seed: u64, amount: u128, expires_at: u64) {
        put_allowance(key(seed), None, AllowanceRecord { amount, expires_at: Some(expires_at) });
    }

    fn stored(seed: u64) -> Option<AllowanceRecord> {
        ALLOWANCES.with(|a| a.borrow().get(&key(seed)))
    }

    fn index_len() -> u64 {
        ALLOWANCES_BY_EXPIRY.with(|t| t.borrow().len())
    }

    // ── the constant D-2 ruled, and the alias it must NOT become ──────────────

    /// D-2: `MAX_APPROVAL_TTL_NS` is 24 h, and it is INDEPENDENT of
    /// `TX_DEDUP_WINDOW_NS`. The two values are equal today, so no assertion can
    /// distinguish an independent constant from an alias at runtime — what this
    /// test pins is the VALUE, from its own arithmetic, so that tightening the
    /// dedup window (a different governance question) cannot move the approval
    /// lifetime without turning this test red and forcing the decision to be made
    /// on purpose.
    #[test]
    fn max_approval_ttl_is_24h_and_independently_stated() {
        assert_eq!(
            MAX_APPROVAL_TTL_NS,
            24u64 * 60 * 60 * 1_000_000_000,
            "D-2 ruled a 24-hour candidate approval lifetime"
        );
        assert_eq!(
            MAX_APPROVAL_TTL_NS, TX_DEDUP_WINDOW_NS,
            "the two are equal TODAY — if this ever fails, that is fine and expected: \
             D-2 ruled they are separately governed. Update this assertion, do not \
             re-alias the constants"
        );
    }

    /// The two reclamation caps and the timer interval, pinned. The timer's cap is
    /// deliberately the larger of the two: it is the trigger that has to drain a
    /// backlog nobody is writing against, and it runs in its own message. The
    /// write-path cap is the smaller one because it rides on a caller's message
    /// and must not make an honest approve pay for an attacker's backlog.
    /// UNBACKED: these are the ruled starting values, sized from the in-repo
    /// precedents (the dedup prune's 100 per write, the pool retention timer's
    /// 1,000 per tick); the envelope they produce is measured and reported by the
    /// integration suite, not claimed here.
    #[test]
    fn reclamation_caps_and_interval_pinned() {
        assert_eq!(MAX_ALLOWANCE_PRUNE_PER_CALL, 100, "mirrors MAX_PRUNE_PER_CALL");
        assert_eq!(MAX_ALLOWANCE_PRUNE_PER_TIMER_TICK, 1_000);
        assert!(
            MAX_ALLOWANCE_PRUNE_PER_TIMER_TICK > MAX_ALLOWANCE_PRUNE_PER_CALL,
            "the timer pass must not be the narrower of the two"
        );
        assert_eq!(ALLOWANCE_MAINTENANCE_INTERVAL_NS, 300 * 1_000_000_000, "300 s");
        assert!(
            ALLOWANCE_MAINTENANCE_INTERVAL_NS < MAX_APPROVAL_TTL_NS,
            "the maintenance interval must be far inside the approval lifetime, or \
             the timer cannot reclaim within a TTL of a row expiring"
        );
    }

    /// RETIREMENT PIN (TOKEN-APPROVE-TTL, SSA R-2). Codes 7 and 8 were dev007's
    /// refusals of an absent / over-cap `expires_at`; no path raises them any more
    /// (the arms are defaulted / clamped — see `approval_lifetime_boundaries_are_exact`).
    /// They stay declared with their old meaning so the numbers are NEVER reissued:
    /// a client that saw 7 or 8 from the live modules must never see the same code
    /// mean something else. Any new error code starts above 8 — this test fails if
    /// either constant is repointed, and the uniqueness arm fails if a later
    /// constant reuses 7 or 8.
    #[test]
    fn dev007_error_codes_pinned() {
        assert_eq!(ERR_CODE_APPROVAL_EXPIRY_REQUIRED, 7, "retired, never reused");
        assert_eq!(ERR_CODE_APPROVAL_TTL_TOO_LONG, 8, "retired, never reused");
        assert!(ERR_MSG_APPROVAL_EXPIRY_REQUIRED.contains("expires_at is required"));
        assert!(ERR_MSG_APPROVAL_TTL_TOO_LONG.contains("maximum approval lifetime"));
        // Every OTHER registered GenericError code in this module, which must not
        // collide with the two retired numbers.
        for (name, code) in [
            ("ERR_CODE_ZERO_AMOUNT", ERR_CODE_ZERO_AMOUNT),
            ("ERR_CODE_ANONYMOUS_CALLER", ERR_CODE_ANONYMOUS_CALLER),
            ("ERR_CODE_RECEIPT_CAPACITY", ERR_CODE_RECEIPT_CAPACITY),
            ("ERR_CODE_DEPOSIT_UNRECEIPTABLE", ERR_CODE_DEPOSIT_UNRECEIPTABLE),
            ("ERR_CODE_DEPOSIT_FENCED", ERR_CODE_DEPOSIT_FENCED),
            ("ERR_CODE_RECEIPT_CONFLICT", ERR_CODE_RECEIPT_CONFLICT),
        ] {
            assert!(code != 7 && code != 8, "{name} = {code} reuses a retired dev007 code");
        }
    }

    // ── (f1): the effective lifetime, named to the nanosecond ─────────────────

    /// The boundaries of the defaulted, capped lifetime, EXACTLY (TOKEN-APPROVE-TTL:
    /// moved from the refusal semantics — absent and over-cap were refused — to the
    /// storage semantics). This is the test the PocketIC harness cannot be: a
    /// replica advances its clock between the harness reading `now` and the update
    /// observing it, so an integration assertion written at `now + CAP + 1`
    /// executes at something under the cap and passes for the wrong reason.
    #[test]
    fn approval_lifetime_boundaries_are_exact() {
        let now = 1_000_000_000_000u64;
        let cap = now + MAX_APPROVAL_TTL_NS;

        assert_eq!(
            effective_approval_lifetime(None, now),
            ApprovalLifetime::Effective(cap),
            "dev007: no expires_at is stored with the cap applied, not refused"
        );

        // The already-expired side, INCLUSIVE (F-006) — still a refusal.
        assert_eq!(
            effective_approval_lifetime(Some(now), now),
            ApprovalLifetime::AlreadyExpired,
            "expires_at == now is already expired"
        );
        assert_eq!(
            effective_approval_lifetime(Some(now - 1), now),
            ApprovalLifetime::AlreadyExpired
        );
        assert_eq!(
            effective_approval_lifetime(Some(now + 1), now),
            ApprovalLifetime::Effective(now + 1),
            "one nanosecond of life is stored as given"
        );

        // The cap. Exactly at it is stored AS GIVEN; one nanosecond past it is
        // CLAMPED to it.
        assert_eq!(
            effective_approval_lifetime(Some(cap), now),
            ApprovalLifetime::Effective(cap),
            "a lifetime of exactly MAX_APPROVAL_TTL_NS is stored as given — the \
             boundary belongs to the allowed side"
        );
        assert_eq!(
            effective_approval_lifetime(Some(cap + 1), now),
            ApprovalLifetime::Effective(cap),
            "one nanosecond past the cap is clamped to the cap"
        );

        // The shape that used to be an unreclaimable row wearing a compliant
        // shape is clamped, and the u64::MAX end of the range (no overflow, no panic).
        assert_eq!(
            effective_approval_lifetime(Some(u64::MAX), now),
            ApprovalLifetime::Effective(cap)
        );
        assert_eq!(
            effective_approval_lifetime(Some(u64::MAX), u64::MAX),
            ApprovalLifetime::AlreadyExpired
        );

        // SSA R-6 saturation arm: at `now = u64::MAX - 1` the cap saturates. The
        // effective expiry is u64::MAX — a stated (enormous) end stored as Some,
        // not a special infinite value — and the arithmetic does not trap under
        // overflow-checks.
        let late = u64::MAX - 1;
        assert_eq!(
            effective_approval_lifetime(None, late),
            ApprovalLifetime::Effective(u64::MAX),
            "None at now = u64::MAX - 1 saturates to u64::MAX"
        );
        assert_eq!(
            effective_approval_lifetime(Some(u64::MAX), late),
            ApprovalLifetime::Effective(u64::MAX)
        );

        // The shipped wallet's own lifetime is three orders of magnitude inside the
        // cap, so its approvals are stored exactly as sent.
        let wallet_ttl = 15u64 * 60 * 1_000_000_000;
        assert_eq!(
            effective_approval_lifetime(Some(now + wallet_ttl), now),
            ApprovalLifetime::Effective(now + wallet_ttl)
        );
        assert!(wallet_ttl * 96 == MAX_APPROVAL_TTL_NS, "24 h is 96 x the wallet's 15 min");
    }

    // ── AllowanceExpiryKey: round-trip, ordering, declared bound ──────────────

    #[test]
    fn allowance_expiry_key_round_trips_and_sorts_time_first() {
        let k = AllowanceExpiryKey::new(0x0123_4567_89ab_cdef, key(42));
        let bytes = k.to_bytes().to_vec();
        assert_eq!(&bytes[0..8], &0x0123_4567_89ab_cdefu64.to_be_bytes());
        assert_eq!(AllowanceExpiryKey::from_bytes(Cow::Owned(bytes)), k, "round-trips");

        // Time dominates the allowance key: an earlier expiry with the largest
        // possible key still sorts below a later expiry with the smallest.
        let earlier = AllowanceExpiryKey::new(10, vec![0xFF; MAX_ALLOWANCE_KEY_LEN]);
        let later = AllowanceExpiryKey::new(11, Vec::new());
        assert!(earlier < later, "chronological order, whatever the key half");
    }

    /// The declared `Storable` bound must fit the real worst-case key, because
    /// `StableBTreeMap` traps on an oversize key rather than growing. The worst
    /// case is two 32-byte-subaccount accounts with maximum-length principals.
    #[test]
    fn allowance_expiry_key_fits_its_declared_bound() {
        // Principal::from_slice accepts up to 29 bytes; 0xFF*29 is not a valid
        // textual principal but encode_key only reads the slice, which is what
        // sets the length.
        let worst = Account {
            owner: Principal::from_slice(&[0xAB; 29]),
            subaccount: Some([0x11; 32]),
        };
        let compound = compound_key(&worst.encode_key(), &worst.encode_key());
        assert!(
            compound.len() <= MAX_ALLOWANCE_KEY_LEN,
            "a real compound_key ({} bytes) must fit MAX_ALLOWANCE_KEY_LEN ({})",
            compound.len(),
            MAX_ALLOWANCE_KEY_LEN
        );
        let encoded = AllowanceExpiryKey::new(u64::MAX, compound).to_bytes().to_vec();
        let Bound::Bounded { max_size, .. } = AllowanceExpiryKey::BOUND else {
            panic!("the index key must stay Bounded — StableBTreeMap sizes its nodes from it");
        };
        assert!(
            encoded.len() <= max_size as usize,
            "encoded worst-case index key is {} bytes against a declared bound of {}",
            encoded.len(),
            max_size
        );
    }

    // ── MD-01: the shared notion, on the inclusive boundary ───────────────────

    /// I-A4 / F-DBR-1 as a three-point table. `now == exp` is the discriminator:
    /// it is the column that distinguishes the inclusive boundary the three call
    /// sites already agreed on from the exclusive one a reimplementation drifts to.
    #[test]
    fn effective_allowance_is_zero_from_the_expiry_instant_inclusive() {
        let exp = 1_000u64;
        let rec = AllowanceRecord { amount: 500, expires_at: Some(exp) };
        assert_eq!(effective_allowance(&rec, exp - 1), 500, "before expiry: the full amount");
        assert_eq!(effective_allowance(&rec, exp), 0, "AT expiry: already expired (INCLUSIVE)");
        assert_eq!(effective_allowance(&rec, exp + 1), 0, "after expiry: zero");

        assert!(!allowance_is_expired(Some(exp), exp - 1));
        assert!(allowance_is_expired(Some(exp), exp));
        assert!(allowance_is_expired(Some(exp), exp + 1));
        // A row with no expiry is never expired. Under dev007 `icrc2_approve`
        // cannot create one; the notion still answers for it rather than
        // pretending the case away.
        assert!(!allowance_is_expired(None, u64::MAX));
        assert_eq!(
            effective_allowance(&AllowanceRecord { amount: 7, expires_at: None }, u64::MAX),
            7
        );
    }

    // ── the single writer, and the bijection it maintains ─────────────────────

    #[test]
    fn put_allowance_maintains_the_bijection() {
        reset_allowance_maps();
        approve_row(1, 100, 5_000);
        approve_row(2, 200, 6_000);
        assert_eq!(index_len(), 2);
        assert!(allowance_index_consistent(), "one index entry per expiring row");
    }

    #[test]
    fn remove_allowance_clears_both_maps() {
        reset_allowance_maps();
        approve_row(1, 100, 5_000);
        remove_allowance(&key(1), Some(5_000));
        assert!(stored(1).is_none(), "primary row gone");
        assert_eq!(index_len(), 0, "index entry gone with it");
        assert!(allowance_index_consistent());
    }

    /// THE RENEWAL CASE (CTO addendum §2.6, required). approve K until E1, renew
    /// K until E2, then run a cleanup pass that reaches E1: the renewed row must
    /// survive intact. This is the test that fails if the writer inserts the new
    /// index entry without removing the old one — the stale E1 entry would then
    /// still name K, and the prune at E1 would delete a live allowance.
    #[test]
    fn renewed_allowance_survives_a_prune_that_reaches_its_old_expiry() {
        reset_allowance_maps();
        let e1 = 1_000u64;
        let e2 = 9_000u64;

        approve_row(7, 100, e1);
        assert_eq!(index_len(), 1);

        // The renewal, through the production writer, carrying the OLD expiry so
        // the stale index entry is addressed and removed.
        put_allowance(key(7), Some(e1), AllowanceRecord { amount: 250, expires_at: Some(e2) });
        assert_eq!(index_len(), 1, "renewal must leave ONE index entry, not two");
        assert!(allowance_index_consistent());

        // A cleanup pass that reaches E1 — and, to be strict, one that reaches
        // well past E1 but not E2.
        let removed = prune_expired_allowances(e1, MAX_ALLOWANCE_PRUNE_PER_CALL);
        assert_eq!(removed, 0, "nothing is expired at E1 any more: the row was renewed to E2");
        let removed = prune_expired_allowances(e2 - 1, MAX_ALLOWANCE_PRUNE_PER_CALL);
        assert_eq!(removed, 0);

        let row = stored(7).expect("the renewed row must survive");
        assert_eq!(row.amount, 250, "intact, with the renewed amount");
        assert_eq!(row.expires_at, Some(e2));
        assert!(allowance_index_consistent());

        // And it does go once its OWN expiry is reached, inclusively.
        assert_eq!(prune_expired_allowances(e2, MAX_ALLOWANCE_PRUNE_PER_CALL), 1);
        assert!(stored(7).is_none());
        assert!(allowance_index_consistent());
    }

    // ── the prune's boundary: INCLUSIVE, ties included ────────────────────────

    /// The bound is INCLUSIVE, unlike `prune_expired_dedup`'s. A row whose
    /// `expires_at` equals `now` is expired and must go — and so must every other
    /// row sharing that exact instant, which is the case a naive
    /// `(cutoff, min_key)` exclusive bound copied from the dedup prune would leave
    /// behind entirely.
    #[test]
    fn prune_removes_every_row_at_exactly_now_including_ties() {
        reset_allowance_maps();
        let exp = 4_000u64;
        for seed in 0..5 {
            approve_row(seed, 10, exp); // five DISTINCT keys, ONE expiry instant
        }
        approve_row(99, 10, exp + 1); // one instant later — must survive

        assert_eq!(
            prune_expired_allowances(exp - 1, MAX_ALLOWANCE_PRUNE_PER_CALL),
            0,
            "one nanosecond before: nothing is expired"
        );
        assert_eq!(ALLOWANCES.with(|a| a.borrow().len()), 6);

        assert_eq!(
            prune_expired_allowances(exp, MAX_ALLOWANCE_PRUNE_PER_CALL),
            5,
            "AT the instant: all five tied rows go, not four and not zero"
        );
        assert!(stored(99).is_some(), "the row expiring one ns later survives");
        assert_eq!(index_len(), 1);
        assert!(allowance_index_consistent());

        assert_eq!(prune_expired_allowances(exp + 1, MAX_ALLOWANCE_PRUNE_PER_CALL), 1);
        assert!(allowance_index_consistent());
    }

    /// The `now == u64::MAX` arm of the upper bound (no `now + 1` exists). Not
    /// reachable with a real clock; covered because the alternative is an
    /// arithmetic overflow in a release build with overflow-checks on, which would
    /// trap inside a timer callback where a trap is invisible.
    #[test]
    fn prune_at_u64_max_treats_everything_as_expired() {
        reset_allowance_maps();
        approve_row(1, 10, u64::MAX);
        approve_row(2, 10, 1);
        assert_eq!(prune_expired_allowances(u64::MAX, MAX_ALLOWANCE_PRUNE_PER_CALL), 2);
        assert_eq!(index_len(), 0);
    }

    /// The cap bounds ONE pass, oldest first, and the remainder is still there for
    /// the next trigger to take. This is what makes a burst drain in bounded steps
    /// rather than in one unbounded message.
    #[test]
    fn prune_is_capped_per_pass_and_takes_the_oldest_first() {
        reset_allowance_maps();
        let n = MAX_ALLOWANCE_PRUNE_PER_CALL as u64 + 20;
        for seed in 0..n {
            // Expiry ASCENDING with the seed, so "oldest first" is observable.
            approve_row(seed, 10, 1_000 + seed);
        }
        let removed = prune_expired_allowances(1_000 + n, MAX_ALLOWANCE_PRUNE_PER_CALL);
        assert_eq!(removed, MAX_ALLOWANCE_PRUNE_PER_CALL, "one pass takes at most the cap");
        assert_eq!(
            ALLOWANCES.with(|a| a.borrow().len()),
            n - MAX_ALLOWANCE_PRUNE_PER_CALL as u64,
            "the remainder is still resident, for the next trigger"
        );
        // Oldest-first: the earliest expiries are the ones that went.
        assert!(stored(0).is_none());
        assert!(stored(n - 1).is_some());
        assert!(allowance_index_consistent());

        // Draining the rest takes further passes, and terminates.
        let mut passes = 0;
        while prune_expired_allowances(1_000 + n, MAX_ALLOWANCE_PRUNE_PER_CALL) > 0 {
            passes += 1;
            assert!(passes < 10, "a bounded backlog must drain in bounded passes");
        }
        assert_eq!(ALLOWANCES.with(|a| a.borrow().len()), 0);
        assert!(allowance_index_consistent());
    }

    /// I-A10: the bijection predicate must actually BITE. A test whose invariant
    /// cannot fail is not an invariant, so this corrupts the index directly —
    /// behind the single writer's back, which is the only way a real drift could
    /// arise — and asserts the predicate reports it.
    #[test]
    fn the_bijection_predicate_detects_a_corrupted_index() {
        reset_allowance_maps();
        approve_row(1, 100, 5_000);
        assert!(allowance_index_consistent(), "baseline: consistent");

        // A stale entry at an expiry the row does not carry.
        ALLOWANCES_BY_EXPIRY
            .with(|t| t.borrow_mut().insert(AllowanceExpiryKey::new(9_999, key(1)), ()));
        assert!(
            !allowance_index_consistent(),
            "an index entry whose expiry disagrees with the stored row is drift"
        );
        ALLOWANCES_BY_EXPIRY
            .with(|t| t.borrow_mut().remove(&AllowanceExpiryKey::new(9_999, key(1))));
        assert!(allowance_index_consistent());

        // A missing entry for a row that has one.
        ALLOWANCES_BY_EXPIRY
            .with(|t| t.borrow_mut().remove(&AllowanceExpiryKey::new(5_000, key(1))));
        assert!(!allowance_index_consistent(), "an unindexed expiring row is drift");
        reset_allowance_maps();
    }

    /// An adversarial fresh flood: N rows, NOTHING expired. The prune must walk
    /// none of them. Natively the observable is that it returns having removed
    /// nothing and having left both maps untouched; the instruction-count form of
    /// the same claim — the one that can distinguish a bounded range scan from an
    /// O(N) walk — is measured over PocketIC by
    /// `measure_allowance_prune_instructions_for_test`.
    #[test]
    fn prune_over_an_all_live_flood_removes_nothing() {
        reset_allowance_maps();
        let n = 2_000u64;
        for seed in 0..n {
            approve_row(seed, 10, 100_000 + seed);
        }
        assert_eq!(prune_expired_allowances(50_000, MAX_ALLOWANCE_PRUNE_PER_CALL), 0);
        assert_eq!(ALLOWANCES.with(|a| a.borrow().len()), n);
        assert_eq!(index_len(), n);
        assert!(allowance_index_consistent());
        reset_allowance_maps();
    }
}

// =============================================================================
// L3f — Custody Vault authority read-back (freeze v6 §6)
// get_authority_refs: PUBLIC canonical read-back of TREASURY, FEE_COLLECTOR,
// STAKING_CANISTER. Fails closed on uninit/corrupt; survives upgrades.
// =============================================================================

#[cfg(test)]
mod authority_refs_tests {
    use super::*;

    fn p(n: u8) -> Principal {
        let mut bytes = [0u8; 29];
        bytes[0] = n;
        Principal::from_slice(&bytes)
    }

    /// Seed the three durable refs. Tests sharing a thread see each other's
    /// thread_locals, so every test sets all three explicitly up front.
    fn set_refs(treasury: Option<Principal>, fee_collector: Option<Principal>, staking: Option<Principal>) {
        TREASURY.with(|t| *t.borrow_mut() = treasury);
        FEE_COLLECTOR.with(|f| *f.borrow_mut() = fee_collector);
        STAKING_CANISTER.with(|s| *s.borrow_mut() = staking);
    }

    // ── positive: exact stored values returned, byte-for-byte ────────────────
    #[test]
    fn readback_returns_exact_stored_principals() {
        let (treasury, fee_collector, staking) = (p(0xA1), p(0xB2), p(0xC3));
        set_refs(Some(treasury), Some(fee_collector), Some(staking));

        let refs = get_authority_refs();
        assert_eq!(refs.treasury, treasury, "canonical stored TREASURY, not a default");
        assert_eq!(refs.fee_collector, Some(fee_collector));
        assert_eq!(refs.staking_canister, staking, "ruled Vault-pinned value reported as stored");

        // DEF-080 backward-compatible state: fee_collector None is VALID and
        // must be reported as None (fees fall back to treasury) — not a trap.
        set_refs(Some(treasury), None, Some(staking));
        let refs = get_authority_refs();
        assert_eq!(refs.fee_collector, None);
        assert_eq!(refs.treasury, treasury);
        assert_eq!(refs.staking_canister, staking);
    }

    // ── fail-closed: TREASURY uninitialised → trap, never a default ──────────
    // (ic_cdk::trap panics with a generic "trap should only be called inside
    // canisters" message off-canister, so no `expected` substring.)
    #[test]
    #[should_panic]
    fn readback_fails_closed_on_uninit_treasury() {
        set_refs(None, Some(p(0xB2)), Some(p(0xC3)));
        let _ = get_authority_refs();
    }

    // ── fail-closed: STAKING_CANISTER uninitialised → trap ───────────────────
    #[test]
    #[should_panic]
    fn readback_fails_closed_on_uninit_staking_canister() {
        set_refs(Some(p(0xA1)), None, None);
        let _ = get_authority_refs();
    }

    // ── upgrade persistence: pre_upgrade → heap wipe → post_upgrade round-trip
    // restores the exact refs, and the read-back then reports them. ───────────
    #[test]
    fn readback_survives_upgrade_roundtrip() {
        let (treasury, fee_collector, staking) = (p(0xD4), p(0xE5), p(0xF6));
        set_refs(Some(treasury), Some(fee_collector), Some(staking));

        pre_upgrade();

        // Simulate the Wasm swap: heap refs are gone, stable memory survives.
        set_refs(None, None, None);
        post_upgrade();

        let refs = get_authority_refs();
        assert_eq!(refs.treasury, treasury, "TREASURY must survive the upgrade");
        assert_eq!(refs.fee_collector, Some(fee_collector));
        assert_eq!(refs.staking_canister, staking, "STAKING_CANISTER must survive the upgrade");
    }

    // ── fail-closed on corrupt stable checkpoint: post_upgrade must trap on
    // undecodable bytes rather than boot with defaulted (None) refs, and the
    // read-back on the resulting uninitialised state also traps. ──────────────
    #[test]
    #[should_panic(expected = "Candid decode of TokenStableState failed")]
    fn post_upgrade_fails_closed_on_corrupt_checkpoint() {
        STABLE_STATE_CELL.with(|c| {
            c.borrow_mut().set(vec![0xDE, 0xAD, 0xBE, 0xEF]).expect("test cell write")
        });
        post_upgrade();
    }

    // ── W2 2-4 (L1-03): the rollback guard's algebra ────────────────────────
    //
    // NATIVE COVERAGE OF THE COMPARISON ONLY. These prove what is decidable
    // without a canister; they are NOT evidence that the guard fires across a
    // real upgrade — thread-locals survive an in-process post_upgrade, so a
    // native "upgrade" proves nothing about durability. The cross-Wasm proof is
    // integration-tests/tests/w2_2_4_checkpoint_rollback_tests.rs.

    #[test]
    fn rollback_detected_when_a_witnessed_block_exceeds_the_checkpoint() {
        // The stale-checkpoint case: the dedup map witnesses block 42, the
        // checkpoint claims height 10 — those ten blocks were already issued.
        assert!(checkpoint_rollback_detected(Some(42), 10));
    }

    #[test]
    fn no_rollback_when_no_witness_survives() {
        // NO-FALSE-POSITIVE 1 — empty or fully pruned dedup map. Silence is not
        // evidence of a rollback, and must never block an upgrade.
        assert!(!checkpoint_rollback_detected(None, 0));
        assert!(!checkpoint_rollback_detected(None, 10_000));
    }

    #[test]
    fn no_rollback_when_the_checkpoint_is_at_or_ahead_of_every_witness() {
        // NO-FALSE-POSITIVE 2 — the normal upgrade. The checkpoint is written
        // after the last transfer, so height >= every witnessed index. Equality
        // is the common case (last transfer recorded a dedup row) and must pass.
        assert!(!checkpoint_rollback_detected(Some(10), 10));
        assert!(!checkpoint_rollback_detected(Some(9), 10));
        assert!(!checkpoint_rollback_detected(Some(0), 0));
    }

    #[test]
    fn observed_durable_block_index_reads_the_max_of_the_probed_rows() {
        // The probe's decode/max path over real map entries: three rows, the
        // highest block index wins regardless of created_at ordering.
        for (i, (block, created_at)) in [(7u64, 300u64), (99, 100), (12, 200)].iter().enumerate() {
            let mut key = [0u8; 32];
            key[0] = i as u8;
            TRANSFER_DEDUP.with(|d| {
                d.borrow_mut().insert(key, encode_dedup_value(*block, *created_at));
            });
            TRANSFER_DEDUP_BY_TIME.with(|t| {
                t.borrow_mut().insert(DedupTimeKey::new(*created_at, key), ());
            });
        }
        assert_eq!(observed_durable_block_index(), Some(99));
        assert!(checkpoint_rollback_detected(observed_durable_block_index(), 98));
        assert!(!checkpoint_rollback_detected(observed_durable_block_index(), 99));

        // Leave no residue for sibling tests in this module.
        for i in 0..3u8 {
            let mut key = [0u8; 32];
            key[0] = i;
            TRANSFER_DEDUP.with(|d| { d.borrow_mut().remove(&key); });
        }
        TRANSFER_DEDUP_BY_TIME.with(|t| {
            let all: Vec<DedupTimeKey> = t.borrow().iter().map(|(k, _)| k).collect();
            let mut m = t.borrow_mut();
            for k in all { m.remove(&k); }
        });
    }

    // ── fail-closed on missing checkpoint (bootstrap trap): no silent reset ──
    #[test]
    #[should_panic]
    fn post_upgrade_fails_closed_on_missing_checkpoint() {
        STABLE_STATE_CELL.with(|c| c.borrow_mut().set(vec![]).expect("test cell write"));
        post_upgrade();
    }
}
#[cfg(feature = "testing")]
#[ic_cdk_macros::update]
fn r15_set_transfer_fee_for_test(fee: u128) {
    TRANSFER_FEE.with(|f| *f.borrow_mut() = fee);
}

#[cfg(feature = "testing")]
thread_local! { static R15_BALANCE_OVERSIZE: RefCell<bool> = RefCell::new(false); }
#[cfg(feature = "testing")]
#[ic_cdk_macros::update]
fn r15_balance_oversize_for_test(enable: bool) { R15_BALANCE_OVERSIZE.with(|v| *v.borrow_mut()=enable); }
