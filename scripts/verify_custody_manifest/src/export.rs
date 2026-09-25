//! §P.2 — the authenticated D5 exporter → ceremony verification root.
//!
//! WHAT THIS REPLACES. Without it, D5 provenance reaches the custody manifest
//! by an operator reading `get_creation_receipts` output off a terminal and
//! typing principals into a TOML file. Every property the manifest gate then
//! checks — bijectivity, one-shot purposes, cardinality — is checked against
//! whatever the operator typed. This tool makes the path from the Vault's own
//! typed receipts to the manifest bytes mechanical, and records enough hashes
//! that a reviewer can recompute the whole of it.
//!
//! WHAT IT REFUSES. Every rule below is a hard stop with a committed negative
//! test: an unauthorized read (never mistaken for end-of-pagination), a cursor
//! that fails to advance, a repeated cursor, a walk that ends without
//! `next_cursor = None`, a page that does not decode, a receipt set that is
//! not exactly the nine one-shot governed roles, a non-`Bound` receipt, an
//! output destination that already exists, a dirty or wrong-SHA source clone,
//! and a page whose recorded hash does not reproduce.
//!
//! THE SOURCE PIN IS AN ARGUMENT, NOT A CONSTANT. The ceremony verification
//! root is a clone of the commit that CONTAINS this tool — self-referential at
//! build time, so it cannot be written down here. The caller passes the
//! ceremony-source SHA and the tool verifies it against the clone's own
//! `git rev-parse HEAD`. Hardcoding any commit (including the base this was
//! built on) would pin the root to a tree that cannot contain the exporter.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::{sha256_hex, BORN_UNDER_VAULT_ROLES};

// ── Pinned read parameters ───────────────────────────────────────────────────

/// The pinned initial cursor. `None` starts the audit-event scan at the
/// beginning; the walk never begins mid-history, because a mid-history start
/// silently drops every earlier receipt.
pub const PINNED_INITIAL_CURSOR: Option<u64> = None;

/// The pinned page limit. Must satisfy the Vault's `1 <= limit <=
/// MAX_READ_PAGE_LIMIT` (128) — the tool validates this BEFORE any call, so a
/// `None` response can only ever mean "unauthorized", never "bad limit".
pub const PINNED_PAGE_LIMIT: u32 = 64;

/// The Vault's `MAX_READ_PAGE_LIMIT` (canisters/custody-types/src/lib.rs).
/// Mirrored rather than imported through the vault crate for the same reason
/// the role allowlist is: depending on the vault crate would move the
/// workspace `Cargo.lock`, a production build input, and disarm the release
/// tripwire.
pub const MAX_READ_PAGE_LIMIT: u32 = 128;

// ── Typed failures ───────────────────────────────────────────────────────────

/// Every failure mode is typed and terminal. There is no warning tier: this
/// tool either produces a complete, hash-recorded ceremony root or it produces
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportError {
    /// The pinned page limit is outside the Vault's accepted range. Checked
    /// before any call, so `None` responses are unambiguous.
    InvalidPageLimit { limit: u32 },
    /// `get_creation_receipts` returned `None`. The query gate returns `None`
    /// for a non-signer caller, and the limit is pre-validated, so this is an
    /// UNAUTHORIZED read. It is a STOP — never end-of-pagination.
    Unauthorized { cursor: Option<u64> },
    /// The transport (the `dfx` invocation) failed.
    TransportFailure { detail: String },
    /// A page did not decode as `opt CreationReceiptPage`.
    DecodeFailed { cursor: Option<u64>, detail: String },
    /// `next_cursor` did not strictly advance.
    CursorNonProgress { from: Option<u64>, to: u64 },
    /// A cursor was visited twice — a cycle.
    CursorCycle { cursor: u64 },
    /// The page sequence ended while the last `next_cursor` was still `Some`.
    /// Termination is only ever `next_cursor = None`.
    TruncatedWalk { last_next_cursor: u64 },
    /// Pages arrived in an order inconsistent with the cursors they were
    /// fetched for.
    ReorderedPages { detail: String },
    /// The receipt set is not exactly the nine governed roles.
    ReceiptCardinality { detail: String },
    /// A receipt names a purpose outside the one-shot governed allowlist.
    PurposeNotAllowed { purpose: String },
    /// Two receipts for the same principal, or two for the same purpose.
    DuplicateReceipt { detail: String },
    /// A receipt is not `Bound` — discoverable custody, never a binding.
    ReceiptNotBound { principal: String, status: String },
    /// A recorded page hash did not reproduce.
    HashMismatch { what: String, expected: String, actual: String },
    /// The output destination already exists. The tool only ever writes into a
    /// newly created directory; overwriting an evidence root destroys the
    /// evidence it is supposed to preserve.
    DestinationExists { path: PathBuf },
    /// The source clone is dirty — an immutable root cannot be a working tree
    /// with uncommitted edits.
    DirtySourceClone { detail: String },
    /// The source clone's HEAD is not the ceremony-source SHA the caller
    /// declared.
    SourceShaMismatch { expected: String, actual: String },
    /// The declared ceremony-source SHA is not a full 40-hex commit id.
    MalformedSourceSha { given: String },
    /// The manifest could not be rendered without touching unrelated bytes.
    RenderFailed { detail: String },

    // ── §Q finalize+assemble ────────────────────────────────────────────────
    /// The separately hashed bootstrap-ring ceremony artifact is missing,
    /// unreadable or empty. Fail-closed: an unhashed pointer target is exactly
    /// the gap §P.1's fail-closed pointer exists to make visible.
    RingArtifactUnavailable { detail: String },
    /// The §P export root cannot be read back as an authenticated export:
    /// absent, incomplete, mismatched raw/canonical sets, or a page that is
    /// not in canonical form (i.e. hand-edited).
    ExportRootUnusable { detail: String },
    /// The export root's `mode` line does not equal the mode the operator
    /// DECLARED from the filed §P transcript. The mode is not derivable from
    /// the files — a replay and an authenticated export produce byte-identical
    /// pages — so it is attested, never inferred.
    ExportModeUnattested { declared: String, recorded: String },
    /// The export root's `INVENTORY` does not hash to the root sha256 the
    /// export phase printed and the §P transcript recorded. This is what makes
    /// an edited `mode` line (or an edited entry) detectable at all: the
    /// listing covers the mode, and the recorded hash is held OUTSIDE the root.
    ExportRootUnattested { expected: String, actual: String },
    /// The repository-shaped verification tree could not be assembled.
    TreeAssemblyFailed { detail: String },

    Io { detail: String },
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportError::InvalidPageLimit { limit } => write!(
                f,
                "INVALID PAGE LIMIT: {limit} — must satisfy 1 <= limit <= {MAX_READ_PAGE_LIMIT}. \
                 Validated before any call so that a `None` response is unambiguous."
            ),
            ExportError::Unauthorized { cursor } => write!(
                f,
                "UNAUTHORIZED: get_creation_receipts returned None at cursor {cursor:?}. The \
                 limit was pre-validated, so this is a rejected (non-signer) read — a STOP. It \
                 is NEVER end-of-pagination: pagination ends at next_cursor = None inside a \
                 returned page, not at an absent page."
            ),
            ExportError::TransportFailure { detail } => {
                write!(f, "TRANSPORT FAILURE: {detail}")
            }
            ExportError::DecodeFailed { cursor, detail } => write!(
                f,
                "DECODE FAILED at cursor {cursor:?}: {detail} — a page that does not decode as \
                 the Vault's typed page is not evidence, whatever it looks like."
            ),
            ExportError::CursorNonProgress { from, to } => write!(
                f,
                "CURSOR NON-PROGRESS: next_cursor {to} does not strictly advance past {from:?} — \
                 a non-advancing cursor walks forever or silently repeats a page."
            ),
            ExportError::CursorCycle { cursor } => {
                write!(f, "CURSOR CYCLE: cursor {cursor} was visited twice.")
            }
            ExportError::TruncatedWalk { last_next_cursor } => write!(
                f,
                "TRUNCATED WALK: the page sequence ended while next_cursor was still \
                 Some({last_next_cursor}). A truncated walk under-reports receipts, which is \
                 exactly how a missing governed target would go unnoticed."
            ),
            ExportError::ReorderedPages { detail } => {
                write!(f, "REORDERED PAGES: {detail}")
            }
            ExportError::ReceiptCardinality { detail } => write!(
                f,
                "RECEIPT CARDINALITY: {detail} — the export renders nothing unless it holds \
                 exactly {} unique Bound receipts.",
                BORN_UNDER_VAULT_ROLES.len()
            ),
            ExportError::PurposeNotAllowed { purpose } => write!(
                f,
                "PURPOSE NOT ALLOWED: `{purpose}` is not one of the nine one-shot governed roles."
            ),
            ExportError::DuplicateReceipt { detail } => {
                write!(f, "DUPLICATE RECEIPT: {detail}")
            }
            ExportError::ReceiptNotBound { principal, status } => write!(
                f,
                "RECEIPT NOT BOUND: {principal} has status `{status}` — a non-Bound receipt is \
                 discoverable custody pending governed resolution, never a binding. Resolve it \
                 through governance; do not render around it."
            ),
            ExportError::HashMismatch { what, expected, actual } => write!(
                f,
                "HASH MISMATCH: {what} expected {expected}, got {actual}."
            ),
            ExportError::DestinationExists { path } => write!(
                f,
                "DESTINATION EXISTS: {} — the ceremony root is written into a NEWLY CREATED \
                 directory only. Overwriting an evidence root destroys the evidence.",
                path.display()
            ),
            ExportError::DirtySourceClone { detail } => write!(
                f,
                "DIRTY SOURCE CLONE: {detail} — the verification root must be an immutable clean \
                 clone, not a working tree."
            ),
            ExportError::SourceShaMismatch { expected, actual } => write!(
                f,
                "SOURCE SHA MISMATCH: clone HEAD is {actual}, declared ceremony source is \
                 {expected}."
            ),
            ExportError::MalformedSourceSha { given } => write!(
                f,
                "MALFORMED SOURCE SHA: `{given}` is not a full 40-hex commit id."
            ),
            ExportError::RenderFailed { detail } => write!(f, "RENDER FAILED: {detail}"),
            ExportError::RingArtifactUnavailable { detail } => write!(
                f,
                "RING ARTIFACT UNAVAILABLE: {detail} — the manifest's ring pointer cannot be \
                 populated without the artifact it points at, and an unhashed pointer target is \
                 never an empty pass."
            ),
            ExportError::ExportRootUnusable { detail } => write!(
                f,
                "EXPORT ROOT UNUSABLE: {detail} — the finalize phase consumes an AUTHENTICATED \
                 export and re-proves it from its own files; anything it cannot re-prove is not \
                 an export."
            ),
            ExportError::ExportModeUnattested { declared, recorded } => write!(
                f,
                "EXPORT MODE UNATTESTED: the export root records mode `{recorded}`, the operator \
                 declared `{declared}`. A replay and an authenticated export write byte-identical \
                 pages, so the mode is ATTESTED from the filed §P transcript and never inferred \
                 from the root — otherwise editing one line of text would relabel replay evidence \
                 as an authenticated export."
            ),
            ExportError::ExportRootUnattested { expected, actual } => write!(
                f,
                "EXPORT ROOT UNATTESTED: the export root's INVENTORY hashes to {actual}, the \
                 declared §P ceremony root sha256 is {expected}. The listing covers the mode line \
                 and every artifact entry, and the declared hash is recorded OUTSIDE the root — \
                 so any edit inside the root, including the mode, fails here."
            ),
            ExportError::TreeAssemblyFailed { detail } => {
                write!(f, "TREE ASSEMBLY FAILED: {detail}")
            }
            ExportError::Io { detail } => write!(f, "IO: {detail}"),
        }
    }
}

// ── Vault type mirrors (decode-side only) ────────────────────────────────────

/// Mirror of the Vault's `CreationReceiptStatus`.
#[derive(candid::CandidType, serde::Serialize, serde::Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreationReceiptStatus {
    Bound,
    OrphanedPurposeConflict,
}

impl CreationReceiptStatus {
    /// The manifest's snake_case spelling.
    pub fn manifest_str(self) -> &'static str {
        match self {
            CreationReceiptStatus::Bound => crate::RECEIPT_STATUS_BOUND,
            CreationReceiptStatus::OrphanedPurposeConflict => crate::RECEIPT_STATUS_ORPHANED,
        }
    }
}

/// Mirror of the Vault's `CreationReceipt`.
#[derive(candid::CandidType, serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CreationReceipt {
    pub proposal_id: u64,
    pub principal: candid::Principal,
    pub purpose: String,
    pub disposition: stsh_custody_types::ManifestDisposition,
    pub created_at_ns: u64,
    pub status: CreationReceiptStatus,
}

/// Mirror of the Vault's `CreationReceiptPage`.
#[derive(candid::CandidType, serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CreationReceiptPage {
    pub items: Vec<CreationReceipt>,
    pub next_cursor: Option<u64>,
}

// ── Page acquisition ─────────────────────────────────────────────────────────

/// Where raw pages come from. The walk is written against this trait so the
/// entire rule set — authentication, pagination, canonicalization, hashing —
/// is exercised by committed tests without a network.
pub trait PageSource {
    /// Return the RAW textual Candid response for one call, exactly as the
    /// transport produced it.
    fn fetch(&mut self, cursor: Option<u64>, limit: u32) -> Result<String, ExportError>;
}

/// One acquired page, with its canonical form and hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquiredPage {
    /// The cursor this page was FETCHED for.
    pub cursor: Option<u64>,
    /// The transport's bytes, untouched.
    pub raw: String,
    /// The canonical Candid re-serialization. Hashing this rather than `raw`
    /// makes the page hash independent of transport whitespace while remaining
    /// a function of the decoded value — so a re-run reproduces it, and an
    /// altered value does not.
    pub canonical: String,
    /// sha256 of `canonical` — computed AFTER canonicalization, never over
    /// transport bytes.
    pub sha256: String,
    pub page: CreationReceiptPage,
}

/// Canonicalize a raw Candid response and decode it as `opt
/// CreationReceiptPage`. `Ok(None)` means the Vault returned `None`.
///
/// CANONICALIZATION IS TYPE-DIRECTED, AND IT HAS TO BE. Parsing textual Candid
/// without the expected type produces a value whose types are INFERRED, and
/// inference over a `vec record` takes its element type from the first
/// element. A page mixing `Bound` and `OrphanedPurposeConflict` receipts would
/// then re-serialize with every status coerced to whichever the first receipt
/// carried — silently rewriting the evidence this tool exists to preserve, and
/// rewriting it in the direction that turns an orphan into a binding.
/// Annotating against the mirror type first makes the round trip lossless and
/// makes a wrong-shaped response a decode failure rather than a coercion.
pub fn canonicalize_and_decode(
    raw: &str,
    cursor: Option<u64>,
) -> Result<(String, Option<CreationReceiptPage>), ExportError> {
    let parsed: candid::IDLArgs =
        candid_parser::parse_idl_args(raw.trim()).map_err(|e| ExportError::DecodeFailed {
            cursor,
            detail: format!("not parseable Candid text: {e}"),
        })?;
    let mut container = candid::types::internal::TypeContainer::new();
    let ty = container.add::<Option<CreationReceiptPage>>();
    let env = &container.env;
    let typed = parsed
        .annotate_types(true, env, std::slice::from_ref(&ty))
        .map_err(|e| ExportError::DecodeFailed {
            cursor,
            detail: format!("not an `opt CreationReceiptPage`: {e}"),
        })?;
    // Canonical form of the TYPED value — the hash is over this, not over the
    // transport bytes and not over an inference-flattened value.
    let canonical = typed.to_string();
    let bytes = typed
        .to_bytes_with_types(env, std::slice::from_ref(&ty))
        .map_err(|e| ExportError::DecodeFailed {
            cursor,
            detail: format!("cannot re-encode: {e}"),
        })?;
    let decoded: Option<CreationReceiptPage> =
        candid::decode_one(&bytes).map_err(|e| ExportError::DecodeFailed {
            cursor,
            detail: format!("not an `opt CreationReceiptPage`: {e}"),
        })?;
    Ok((canonical, decoded))
}

/// Walk `get_creation_receipts` to completion under every pagination rule.
pub fn walk<S: PageSource>(src: &mut S, limit: u32) -> Result<Vec<AcquiredPage>, ExportError> {
    if limit == 0 || limit > MAX_READ_PAGE_LIMIT {
        return Err(ExportError::InvalidPageLimit { limit });
    }
    let mut pages: Vec<AcquiredPage> = Vec::new();
    let mut cursor = PINNED_INITIAL_CURSOR;
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    loop {
        let raw = src.fetch(cursor, limit)?;
        let (canonical, decoded) = canonicalize_and_decode(&raw, cursor)?;
        // `None` here is a rejected read. It is NOT end-of-pagination: a
        // finished walk returns a PAGE whose next_cursor is None.
        let page = decoded.ok_or(ExportError::Unauthorized { cursor })?;
        let sha256 = sha256_hex(canonical.as_bytes());
        let next = page.next_cursor;
        pages.push(AcquiredPage {
            cursor,
            raw,
            canonical,
            sha256,
            page,
        });
        match next {
            None => return Ok(pages),
            Some(n) => {
                // STRICT progress: the next cursor must exceed the one we just
                // fetched for. `None` (the pinned start) is before everything.
                let advanced = match cursor {
                    None => true,
                    Some(c) => n > c,
                };
                if !advanced {
                    return Err(ExportError::CursorNonProgress { from: cursor, to: n });
                }
                if !seen.insert(n) {
                    return Err(ExportError::CursorCycle { cursor: n });
                }
                cursor = Some(n);
            }
        }
    }
}

/// Re-verify an acquired sequence: cursor chain, ordering, page hashes, and
/// terminal condition. Run over pages that were read back from a recorded
/// ceremony root, this is what catches a truncated, reordered, duplicated or
/// hand-edited evidence set.
pub fn verify_sequence(pages: &[AcquiredPage]) -> Result<(), ExportError> {
    if pages.is_empty() {
        return Err(ExportError::ReceiptCardinality {
            detail: "no pages at all".into(),
        });
    }
    if pages[0].cursor != PINNED_INITIAL_CURSOR {
        return Err(ExportError::ReorderedPages {
            detail: format!(
                "first page was fetched for cursor {:?}, the pinned initial cursor is {:?}",
                pages[0].cursor, PINNED_INITIAL_CURSOR
            ),
        });
    }
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for (i, p) in pages.iter().enumerate() {
        let actual = sha256_hex(p.canonical.as_bytes());
        if actual != p.sha256 {
            return Err(ExportError::HashMismatch {
                what: format!("page {i}"),
                expected: p.sha256.clone(),
                actual,
            });
        }
        match p.page.next_cursor {
            None => {
                if i + 1 != pages.len() {
                    return Err(ExportError::ReorderedPages {
                        detail: format!(
                            "page {i} terminates the walk (next_cursor = None) but {} more pages \
                             follow",
                            pages.len() - i - 1
                        ),
                    });
                }
            }
            Some(n) => {
                if i + 1 == pages.len() {
                    return Err(ExportError::TruncatedWalk { last_next_cursor: n });
                }
                let advanced = match p.cursor {
                    None => true,
                    Some(c) => n > c,
                };
                if !advanced {
                    return Err(ExportError::CursorNonProgress { from: p.cursor, to: n });
                }
                if !seen.insert(n) {
                    return Err(ExportError::CursorCycle { cursor: n });
                }
                if pages[i + 1].cursor != Some(n) {
                    return Err(ExportError::ReorderedPages {
                        detail: format!(
                            "page {} was fetched for cursor {:?}, but page {i} hands over cursor \
                             {n}",
                            i + 1,
                            pages[i + 1].cursor
                        ),
                    });
                }
            }
        }
    }
    Ok(())
}

// ── Receipt validation ───────────────────────────────────────────────────────

/// The nine validated receipts, in allowlist order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedReceipt {
    pub role: String,
    pub principal: String,
    pub proposal_id: u64,
    pub created_at_ns: u64,
}

/// Validate that the walk holds exactly the nine one-shot governed roles, each
/// once, each `Bound`. NOTHING is rendered before this passes.
pub fn validate_receipts(pages: &[AcquiredPage]) -> Result<Vec<ValidatedReceipt>, ExportError> {
    let all: Vec<&CreationReceipt> = pages.iter().flat_map(|p| p.page.items.iter()).collect();

    let mut by_principal: BTreeSet<String> = BTreeSet::new();
    let mut by_role: std::collections::BTreeMap<String, ValidatedReceipt> = Default::default();

    for r in &all {
        let principal = r.principal.to_text();
        if !by_principal.insert(principal.clone()) {
            return Err(ExportError::DuplicateReceipt {
                detail: format!("principal {principal} appears in more than one receipt"),
            });
        }
        if r.status != CreationReceiptStatus::Bound {
            return Err(ExportError::ReceiptNotBound {
                principal,
                status: r.status.manifest_str().into(),
            });
        }
        if !BORN_UNDER_VAULT_ROLES.contains(&r.purpose.as_str()) {
            return Err(ExportError::PurposeNotAllowed {
                purpose: r.purpose.clone(),
            });
        }
        if r.disposition != stsh_custody_types::ManifestDisposition::BornUnderVault {
            return Err(ExportError::PurposeNotAllowed {
                purpose: format!("{} (disposition {:?})", r.purpose, r.disposition),
            });
        }
        if by_role
            .insert(
                r.purpose.clone(),
                ValidatedReceipt {
                    role: r.purpose.clone(),
                    principal,
                    proposal_id: r.proposal_id,
                    created_at_ns: r.created_at_ns,
                },
            )
            .is_some()
        {
            return Err(ExportError::DuplicateReceipt {
                detail: format!("role `{}` is bound more than once", r.purpose),
            });
        }
    }

    let missing: Vec<&str> = BORN_UNDER_VAULT_ROLES
        .iter()
        .copied()
        .filter(|role| !by_role.contains_key(*role))
        .collect();
    if !missing.is_empty() {
        return Err(ExportError::ReceiptCardinality {
            detail: format!("{} receipts, missing roles {missing:?}", all.len()),
        });
    }
    if by_role.len() != BORN_UNDER_VAULT_ROLES.len() {
        return Err(ExportError::ReceiptCardinality {
            detail: format!(
                "{} bound roles, expected exactly {}",
                by_role.len(),
                BORN_UNDER_VAULT_ROLES.len()
            ),
        });
    }
    // Allowlist order, not map order — the rendering must be deterministic.
    Ok(BORN_UNDER_VAULT_ROLES
        .iter()
        .map(|role| by_role.get(*role).expect("checked complete").clone())
        .collect())
}

// ── Deterministic manifest rendering ─────────────────────────────────────────

/// Render the validated receipts into the custody manifest.
///
/// Three edits, all inside the region they name, all deterministic:
///   1. `[sources.d5]` `status` pending → populated;
///   2. `[sources.d5]` `receipts = []` → the nine receipt tables, in allowlist
///      order;
///   3. each governed `[[canister]]` block gains its `principal`.
///
/// Every other byte of the file is carried through untouched. Rendering twice
/// over the same input produces identical bytes.
pub fn render_manifest(
    source: &str,
    receipts: &[ValidatedReceipt],
) -> Result<String, ExportError> {
    if receipts.len() != BORN_UNDER_VAULT_ROLES.len() {
        return Err(ExportError::RenderFailed {
            detail: format!("{} receipts, expected {}", receipts.len(), BORN_UNDER_VAULT_ROLES.len()),
        });
    }

    // (1)+(2) — the [sources.d5] block only.
    let d5_start = source.find("\n[sources.d5]").ok_or(ExportError::RenderFailed {
        detail: "[sources.d5] not found".into(),
    })? + 1;
    let d5_end = source[d5_start..]
        .find("\n[")
        .map(|i| d5_start + i + 1)
        .unwrap_or(source.len());
    let d5 = &source[d5_start..d5_end];
    if !d5.contains("status = \"pending\"") {
        return Err(ExportError::RenderFailed {
            detail: "[sources.d5] is not `status = \"pending\"` — refusing to render over an \
                     already-populated D5"
                .into(),
        });
    }
    if !d5.contains("receipts = []") {
        return Err(ExportError::RenderFailed {
            detail: "[sources.d5] does not carry an empty `receipts = []` to fill".into(),
        });
    }
    let mut rendered_receipts = String::new();
    for r in receipts {
        rendered_receipts.push_str("\n[[sources.d5.receipts]]\n");
        rendered_receipts.push_str(&format!("principal = \"{}\"\n", r.principal));
        rendered_receipts.push_str(&format!("manifest_purpose = \"{}\"\n", r.role));
        rendered_receipts.push_str(&format!("status = \"{}\"\n", crate::RECEIPT_STATUS_BOUND));
        rendered_receipts.push_str(&format!("proposal_id = {}\n", r.proposal_id));
        rendered_receipts.push_str(&format!("created_at_ns = {}\n", r.created_at_ns));
    }
    let new_d5 = d5
        .replace("status = \"pending\"", "status = \"populated\"")
        .replace("receipts = []\n", &rendered_receipts);
    let mut out = String::with_capacity(source.len() + rendered_receipts.len());
    out.push_str(&source[..d5_start]);
    out.push_str(&new_d5);
    out.push_str(&source[d5_end..]);

    // (3) — one principal line per governed entry.
    for r in receipts {
        let needle = format!("dfx_name = \"{}\"\ndisposition = \"born_under_vault\"\n", r.role);
        let Some(at) = out.find(&needle) else {
            return Err(ExportError::RenderFailed {
                detail: format!("no born_under_vault entry for role `{}` to bind", r.role),
            });
        };
        // IDEMPOTENT BIND (lane A-3 FINALIZE, 2026-09-12). The A-3 re-encode had
        // to bind `ids_name = "shielded_pool"` to this entry, and the D2 binding
        // check then FORCES a `principal` on it — so a governed role can already
        // carry its principal BEFORE the receipts are exported. Re-binding the
        // SAME principal is a no-op and must not fail the render; binding a
        // DIFFERENT one is still a hard refusal, which is the property this
        // guard existed for. The distinction is the point: silently overwriting,
        // or appending a second `principal` line, would let a receipt contradict
        // a recorded custody binding with no signal.
        let already = format!("{needle}principal = ");
        if out[at..].starts_with(&already) {
            let same = format!("{already}\"{}\"\n", r.principal);
            if out[at..].starts_with(&same) {
                continue;
            }
            return Err(ExportError::RenderFailed {
                detail: format!(
                    "role `{}` already carries a DIFFERENT principal than its receipt (receipt: {})",
                    r.role, r.principal
                ),
            });
        }
        let insert_at = at + needle.len();
        out.insert_str(insert_at, &format!("principal = \"{}\"\n", r.principal));
    }
    Ok(out)
}

// ── The ceremony verification root ───────────────────────────────────────────

/// The written evidence root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyRoot {
    pub dir: PathBuf,
    /// `(filename, sha256)`, sorted by filename.
    pub inventory: Vec<(String, String)>,
    /// sha256 of the rendered manifest.
    pub manifest_sha256: String,
    /// sha256 over the canonical inventory listing — one hash that covers the
    /// whole root, so a reviewer compares ONE value and every artifact is
    /// bound by it.
    pub inventory_sha256: String,
}

/// The canonical `INVENTORY` listing of an export root: the mode, the
/// ceremony-source SHA, then one `<sha256>  <name>` line per artifact, sorted
/// by name.
///
/// FACTORED OUT ON PURPOSE. The §Q finalize phase re-derives this listing from
/// the entries it parsed and requires BYTE-EQUALITY with the file on disk, then
/// requires its hash to equal the root sha256 the §P transcript recorded. One
/// canonicalization, used by the writer and by the verifier, is what makes that
/// comparison meaningful — two independent spellings of "the listing" would
/// only ever prove the two spellings agree.
pub fn ceremony_root_listing(
    mode: &str,
    ceremony_source_sha: &str,
    inventory: &[(String, String)],
) -> String {
    let mut listing = format!("mode {mode}\nceremony_source_sha {ceremony_source_sha}\n");
    for (name, hash) in inventory {
        listing.push_str(&format!("{hash}  {name}\n"));
    }
    listing
}

/// Write the ceremony verification root into a NEWLY CREATED directory.
///
/// `mode` is stamped into the inventory listing (and therefore into the root
/// hash) so a REPLAY root — pages re-read from disk, with no live signer
/// authentication behind them — can never be mistaken for, or substituted
/// into, an authenticated export.
pub fn write_ceremony_root(
    dest: &Path,
    mode: &str,
    ceremony_source_sha: &str,
    pages: &[AcquiredPage],
    rendered_manifest: &str,
) -> Result<CeremonyRoot, ExportError> {
    if dest.exists() {
        return Err(ExportError::DestinationExists { path: dest.into() });
    }
    std::fs::create_dir_all(dest).map_err(|e| ExportError::Io {
        detail: format!("cannot create {}: {e}", dest.display()),
    })?;

    let write = |name: &str, body: &str| -> Result<(String, String), ExportError> {
        std::fs::write(dest.join(name), body).map_err(|e| ExportError::Io {
            detail: format!("cannot write {name}: {e}"),
        })?;
        Ok((name.to_string(), sha256_hex(body.as_bytes())))
    };

    let mut inventory: Vec<(String, String)> = Vec::new();
    for (i, p) in pages.iter().enumerate() {
        inventory.push(write(&format!("page-{i:03}.raw.candid"), &p.raw)?);
        let (name, hash) = write(&format!("page-{i:03}.canonical.candid"), &p.canonical)?;
        if hash != p.sha256 {
            return Err(ExportError::HashMismatch {
                what: name,
                expected: p.sha256.clone(),
                actual: hash,
            });
        }
        inventory.push((name, hash));
    }
    let (manifest_name, manifest_sha256) = write("custody_manifest.toml", rendered_manifest)?;
    inventory.push((manifest_name, manifest_sha256.clone()));

    inventory.sort();
    let listing = ceremony_root_listing(mode, ceremony_source_sha, &inventory);
    let inventory_sha256 = sha256_hex(listing.as_bytes());
    std::fs::write(dest.join("INVENTORY"), &listing).map_err(|e| ExportError::Io {
        detail: format!("cannot write INVENTORY: {e}"),
    })?;

    Ok(CeremonyRoot {
        dir: dest.into(),
        inventory,
        manifest_sha256,
        inventory_sha256,
    })
}

// ── The source clone ─────────────────────────────────────────────────────────

/// Verify the ceremony-source clone: a full-SHA argument (never a hardcoded
/// commit), matched against the clone's own HEAD, on a clean tree.
pub fn verify_source_clone(clone: &Path, ceremony_source_sha: &str) -> Result<(), ExportError> {
    let sha = ceremony_source_sha.trim();
    if sha.len() != 40 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ExportError::MalformedSourceSha { given: sha.into() });
    }
    let git = |args: &[&str]| -> Result<String, ExportError> {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(clone)
            .args(args)
            .output()
            .map_err(|e| ExportError::Io {
                detail: format!("git {args:?}: {e}"),
            })?;
        if !out.status.success() {
            return Err(ExportError::Io {
                detail: format!("git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr)),
            });
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let head = git(&["rev-parse", "HEAD"])?;
    if head != sha {
        return Err(ExportError::SourceShaMismatch {
            expected: sha.into(),
            actual: head,
        });
    }
    let status = git(&["status", "--porcelain"])?;
    if !status.is_empty() {
        return Err(ExportError::DirtySourceClone { detail: status });
    }
    Ok(())
}
