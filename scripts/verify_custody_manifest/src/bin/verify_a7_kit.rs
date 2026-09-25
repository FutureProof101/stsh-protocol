// ─────────────────────────────────────────────────────────────────────────────
//  verify_a7_kit — A-7 INSTALL KIT gate (lane A-7)
//
//      cargo run -p verify-custody-manifest --bin verify_a7_kit -- [<repo-root>]
//
//  WHY THIS TOOL EXISTS. Before A-7, NO gate validated a non-genesis init
//  artifact. `verify_genesis_manifest` reads only token_init/vesting_init;
//  `verify_custody_manifest --deploy-time` reads only vault_init (and, since
//  R2.1, upgrader_init). The seven non-genesis canisters installed at A-7 had no
//  committed init artifact at all, so there was nothing to hash, review, or
//  replay — the
//  Owner would have been typing arguments into the operator page by hand, which
//  is the reconstructed-args class Gate-D exists to forbid.
//
//  WHAT IT PROVES, per row of deployment/mainnet/a7_install_kit.toml:
//
//    1. RE-ENCODE. The reviewable Candid text `<canister>_init.did` is parsed
//       and encoded AGAINST THE CANISTER'S OWN INTERFACE (the `service : (…)`
//       init type of canisters/<c>/<c>.did), and the result must be
//       BYTE-IDENTICAL to the committed `<canister>_init.bin`. A .bin that
//       drifted from its .did — in either direction — is a hard failure. This
//       also type-checks the text: a field name, a variant, or a numeric width
//       that the interface does not accept cannot encode at all.
//
//    2. HASHES. sha256(.bin) == `arg_sha256` and sha256(.did) == `arg_text_sha256`.
//       `arg_sha256` is the number the Owner types as `expected_arg_hash`: the
//       operator page uploads the RAW FILE BYTES and performs no encoding
//       (wallet/src/ui/pages/operator.ts:664-667,
//       wallet/src/operator/proposals.ts codePayload), and the Vault recomputes
//       sha256 over exactly those bytes at propose AND at execute. The page
//       shows a local hash for the WASM only (operator.ts:628-636) — never for
//       the arg — so the runbook's `sha256sum` step is the Owner's only
//       independent check, and this row is what it is checked against.
//
//    3. PRINCIPAL PROVENANCE. Every principal literal appearing in the .did
//       text, and every row's `target`, must be one of the nine born under the
//       Vault at J-18 (RECORD_J18_VAULT_BIRTHS_2026-09-12.md), the Vault
//       itself, or a RESOLVED role in deployment/mainnet/genesis_principals.toml
//       — the committed, byte-pinned genesis principal record, read at point of
//       use rather than mirrored here (RR-1b; the genesis install args carry
//       holder principals that are not canisters). An unrecognised principal in
//       an install argument is exactly the
//       attacker-supplied-authority class the Upgrader artifact (R2.1) closed
//       on the custody side; structure is not identity.
//
//    RR-1b (2026-09-13) added the two GENESIS rows — stsh_token and vesting —
//    so all nine J-18 births are now covered. Their arguments are the Gate-D
//    genesis artifacts themselves, which is why check 3's universe had to grow
//    beyond canisters (see the widening note in `main`).
//
//    4. TARGET/ROLE. `target` equals the D5 principal for `canister`, and
//       `role` is one of the nine BORN_UNDER_VAULT_ROLES (the operator page's
//       dropdown), mapped to the `[wasm.*]` section through the documented
//       alias (`verifier` → `stsh-verifier`).
//
//    5. WASM IDENTITY. `wasm_sha256` equals the `[wasm.<row>]` pin in
//       deployment/mainnet/release_hashes.toml. `vetkeys` is the ONE row with
//       no pin, by ruling (D1) — for it the recorded hash is measured from the
//       gate's own `env -i` build of the excluded crate, and this tool hashes
//       that built artifact directly.
//
//    6. THE RR-1 HOLD, BOTH WAYS. shielded_pool carries `hold`. While
//       genesis_manifest `[pool_init]` still names the P0-3 placeholders rather
//       than the D5 principals in shielded_pool_init.did, the hold MUST be
//       declared; once the two agree, the hold MUST be cleared. A hold that
//       outlives its cause is a defect of the same kind as a missing one: both
//       make the record stop describing the tree.
//
//  PUBLIC-EXPORT REDACTED MODE (PUBLIC-MIRROR, CTO Add.5 F-1). The public
//  source export redacts a personal name from two genesis init artifacts. For
//  `stsh_token` the encoded `stsh_token_init.bin` is NOT published (its bytes
//  carry the name) and one `.did` label is redacted; for `vesting` only `.did`
//  comments are redacted, so its `.bin` still re-encodes byte-identically. The
//  kit's recorded `arg_sha256` / `arg_text_sha256` stay AS RECORDED: they are
//  the true hashes of what was installed on-chain. Only the checks that need
//  the unredacted private record are skipped (`PUBLIC_REDACTED_ARGS`), each with
//  one printed `REDACTED (public export)` line. Every other check on those rows
//  (J-18 target, role, init type, `.did` parse and type-check against the
//  interface, principal provenance, Wasm identity) still runs, and every other
//  row is checked in full. `--emit` refuses the redacted rows.
//
//  Exit 0 = clean. Exit 1 = violations (all printed). Exit 2 = usage/IO.
// ─────────────────────────────────────────────────────────────────────────────

use candid::types::internal::TypeInner;
use candid::types::Type;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

// ── the nine principals born under the Vault at J-18, plus the Vault ─────────
//
// Source: office record RECORD_J18_VAULT_BIRTHS_2026-09-12.md (proposals 1-9,
// disposition BornUnderVault, all nine `get_creation_receipts` status Bound).
// Mirrored here because that record is NOT committed in this repository; the
// mirror is load-bearing and is what check 3 resolves against.
const D5_PRINCIPALS: [(&str, &str); 9] = [
    ("shielded_pool", "cxrfg-qaaaa-aaaar-qchfa-cai"),
    ("treasury", "cqqds-5yaaa-aaaar-qchfq-cai"),
    ("vesting", "cfxs7-4qaaa-aaaar-qchga-cai"),
    ("nullifier_registry", "ccwul-riaaa-aaaar-qchgq-cai"),
    ("stsh_token", "clv7x-haaaa-aaaar-qchha-cai"),
    ("merkle_tree", "cmuzd-kyaaa-aaaar-qchhq-cai"),
    ("verifier", "arjxl-zqaaa-aaaar-qchia-cai"),
    ("smoke_alarm_monitor", "awir7-uiaaa-aaaar-qchiq-cai"),
    ("vetkeys", "a7l2d-caaaa-aaaar-qchja-cai"),
];

/// The custody Vault. Ruled value for every `controller` field in the kit, and
/// for the pool's `staking_canister` (D1: staking is not installed at launch).
const VAULT: &str = "cpdab-saaaa-aaaar-qca2q-cai";

// ── public-export redacted mode ──────────────────────────────────────────────

/// Which recorded-hash checks a public-export row cannot reproduce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Redaction {
    /// The `.bin` is not published and the `.did` text is redacted: skip the
    /// re-encode-vs-`.bin` comparison, `arg_sha256` and `arg_text_sha256`.
    BinAndText,
    /// Only `.did` comments are redacted: skip `arg_text_sha256` only. The
    /// `.bin` is published, and the re-encode and `arg_sha256` checks stay ACTIVE.
    TextOnly,
}

/// The kit rows whose install-argument text is redacted in the public export.
const PUBLIC_REDACTED_ARGS: &[(&str, Redaction)] =
    &[("stsh_token", Redaction::BinAndText), ("vesting", Redaction::TextOnly)];

fn redaction_for(canister: &str) -> Option<Redaction> {
    PUBLIC_REDACTED_ARGS.iter().find(|(c, _)| *c == canister).map(|(_, r)| *r)
}

fn redacted_line(canister: &str, check: &str) -> String {
    format!(
        "REDACTED (public export): {canister} {check} not reproducible from the public tree; \
         the recorded kit hash is the true on-chain value and verifying it requires the private record"
    )
}

/// The operator page's dropdown, mirrored from
/// `verify_custody_manifest::BORN_UNDER_VAULT_ROLES`.
fn roles() -> BTreeSet<&'static str> {
    verify_custody_manifest::BORN_UNDER_VAULT_ROLES.iter().copied().collect()
}

// ── kit schema ───────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct Kit {
    schema_version: u32,
    encoder: String,
    #[serde(rename = "entry")]
    entries: Vec<Entry>,
}

#[derive(serde::Deserialize)]
struct Entry {
    canister: String,
    role: String,
    target: String,
    interface: String,
    init_type: String,
    arg_did: String,
    arg_bin: String,
    arg_text_sha256: String,
    arg_sha256: String,
    /// `[wasm.<row>]` section name in release_hashes.toml; EMPTY for vetkeys,
    /// the one role that carries no pin by ruling.
    #[serde(default)]
    wasm_row: String,
    wasm_sha256: String,
    wasm_path: String,
    order: u32,
    /// Non-empty = this install is HELD and must not be performed.
    #[serde(default)]
    hold: String,
    #[serde(default)]
    read_back: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The init argument types of a canister's `service : (…) -> {…}` clause.
///
/// A service with no init arguments yields an empty vector, which is a distinct
/// and legitimate shape — not an error — so it is reported as such rather than
/// silently treated as "one argument".
fn init_types(did: &Path) -> Result<(candid::TypeEnv, Vec<Type>), String> {
    let (env, actor) = candid_parser::pretty_check_file(did)
        .map_err(|e| format!("{}: interface does not type-check: {e}", did.display()))?;
    let actor = actor.ok_or_else(|| format!("{}: no `service` clause", did.display()))?;
    // `pretty_check_file` may return the actor as a reference into the env.
    let resolved = env
        .trace_type(&actor)
        .map_err(|e| format!("{}: cannot resolve the service type: {e}", did.display()))?;
    match resolved.as_ref() {
        TypeInner::Class(args, _) => Ok((env, args.clone())),
        TypeInner::Service(_) => Ok((env, Vec::new())),
        other => Err(format!("{}: `service` is not a service type ({other:?})", did.display())),
    }
}

/// Render an init-type vector the way the interface writes it, for comparison
/// against the kit's DECLARED `init_type`. Declaring it in the record means a
/// silent interface change (an added init field, say) surfaces as a mismatch
/// here and not only as an encoding failure with a deeper message.
fn render_init_type(env: &candid::TypeEnv, args: &[Type]) -> String {
    let _ = env;
    // Collapse every whitespace run to one space: a record type pretty-prints
    // across many lines, and the kit declares this as a single TOML string.
    let inner: Vec<String> = args
        .iter()
        .map(|t| t.to_string().split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    format!("({})", inner.join(", "))
}

/// Every `principal "…"` literal in a Candid text.
/// Every `principal "…"` literal in a Candid TEXT file.
///
/// SCOPE, stated because it bounds check 3 (A-7 SSA F-3). This scans the
/// REVIEWABLE `.did` TEXT, not the encoded `.bin`. That is sound only because
/// check 1 re-encodes the same text and requires byte-identity with the
/// committed `.bin`: the text is therefore a faithful rendering of the bytes,
/// and a principal that is in the bytes but not in the text cannot exist. It
/// also means the scan sees ONLY the `principal "…"` text form — a principal
/// expressed any other way in Candid text (e.g. `blob`-encoded) would be
/// invisible here. No committed kit artifact does that, and the re-encode plus
/// the typed init signature is what keeps it that way; if one ever does, this
/// function is the thing to extend, not the check to relax.
fn principal_literals(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while let Some(rel) = text[i..].find("principal") {
        let start = i + rel;
        let mut j = start + "principal".len();
        while j < bytes.len() && (bytes[j] as char).is_whitespace() {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'"' {
            j += 1;
            if let Some(end_rel) = text[j..].find('"') {
                out.insert(text[j..j + end_rel].to_string());
                i = j + end_rel + 1;
                continue;
            }
        }
        i = start + "principal".len();
    }
    out
}

/// Read `[pool_init]` trust roots out of genesis_manifest.toml.
fn pool_init_roots(manifest: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut in_section = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_section = t.starts_with("[pool_init]");
            continue;
        }
        if !in_section || t.starts_with('#') {
            continue;
        }
        let Some((k, v)) = t.split_once('=') else { continue };
        let k = k.trim();
        if matches!(
            k,
            "token_canister" | "treasury_canister" | "staking_canister" | "controller"
        ) {
            let v = v.trim().trim_matches('"').trim().trim_matches('"');
            out.push((k.to_string(), v.to_string()));
        }
    }
    out
}

/// `[wasm.<row>] sha256` pairs from release_hashes.toml.
fn wasm_pins(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            current = t
                .strip_prefix("[wasm.")
                .and_then(|r| r.strip_suffix(']'))
                .map(|r| r.trim_matches('"').to_string());
            continue;
        }
        if t.starts_with('#') {
            continue;
        }
        if let (Some(row), Some(rest)) = (current.as_ref(), t.strip_prefix("sha256")) {
            if let Some((_, v)) = rest.split_once('=') {
                out.push((row.clone(), v.trim().trim_matches('"').to_string()));
            }
        }
    }
    out
}

/// Every RESOLVED principal in the committed genesis principal record, with
/// `binding = "vault_authorities"` roles resolved through
/// `vault_authorities.toml` the way the record's own grammar defines.
///
/// Deliberately a re-read of the committed record rather than a constant: see
/// the RR-1b widening note in `main`. `PENDING` is a role's fail-closed marker
/// and is dropped, so an unresolved role can never widen the allowed set.
fn record_principals(root: &Path) -> Result<Vec<String>, String> {
    let path = root.join("deployment/mainnet/genesis_principals.toml");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let doc: toml::Value =
        toml::from_str(&text).map_err(|e| format!("{} does not parse: {e}", path.display()))?;
    let roles = match doc.get("role").and_then(|r| r.as_table()) {
        Some(t) => t,
        None => return Err(format!("{} carries no [role.*] entries", path.display())),
    };

    let mut vault_bound: Option<String> = None;
    let mut out: Vec<String> = Vec::new();
    for (name, entry) in roles {
        if let Some(p) = entry.get("principal").and_then(|p| p.as_str()) {
            if p != "PENDING" && !p.trim().is_empty() {
                out.push(p.to_string());
            }
            continue;
        }
        match entry.get("binding").and_then(|b| b.as_str()) {
            Some("vault_authorities") => {
                if vault_bound.is_none() {
                    let vp = root.join("deployment/mainnet/vault_authorities.toml");
                    let vt = std::fs::read_to_string(&vp)
                        .map_err(|e| format!("cannot read {}: {e}", vp.display()))?;
                    let vd: toml::Value = toml::from_str(&vt)
                        .map_err(|e| format!("{} does not parse: {e}", vp.display()))?;
                    vault_bound = vd
                        .get("recovery")
                        .and_then(|r| r.get("vault"))
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string());
                }
                match &vault_bound {
                    Some(x) => out.push(x.clone()),
                    None => {
                        return Err(format!(
                            "[role.{name}] is cross-bound but vault_authorities.toml carries no                              [recovery].vault"
                        ))
                    }
                }
            }
            Some(other) => {
                return Err(format!("[role.{name}] declares unknown binding `{other}`"))
            }
            None => {
                return Err(format!(
                    "[role.{name}] carries neither `principal` nor `binding`"
                ))
            }
        }
    }
    Ok(out)
}

/// Checks 1, 2, 3 and 5 plus `read_back` for ONE kit row. `bin_bytes` is
/// `None` only for a `Redaction::BinAndText` row, whose `.bin` is not published.
/// Skipped checks are recorded in `notes`, never silently.
#[allow(clippy::too_many_arguments)]
fn check_row(
    e: &Entry,
    root: &Path,
    did_text: &str,
    bin_bytes: Option<&[u8]>,
    allowed: &BTreeSet<String>,
    pins: &[(String, String)],
    v: &mut Vec<String>,
    notes: &mut Vec<String>,
) {
    let c = &e.canister;
    let red = redaction_for(c);
    let iface_path = root.join(&e.interface);

    // 1 — re-encode the .did against the canister's own interface
    match init_types(&iface_path) {
        Err(err) => v.push(format!("{c}: {err}")),
        Ok((env, types)) => {
            let rendered = render_init_type(&env, &types);
            if rendered != e.init_type {
                v.push(format!(
                    "{c}: kit declares init_type `{}` but {} declares `{rendered}`",
                    e.init_type,
                    e.interface
                ));
            }
            match candid_parser::parse_idl_args(did_text) {
                Err(err) => v.push(format!(
                    "{c}: {} is not a parseable Candid argument list: {err}",
                    e.arg_did
                )),
                Ok(args) => match args.to_bytes_with_types(&env, &types) {
                    Err(err) => v.push(format!(
                        "{c}: {} does not type-check against {} init type `{rendered}`: {err}",
                        e.arg_did, e.interface
                    )),
                    Ok(encoded) => match bin_bytes {
                        None => notes.push(redacted_line(c, "re-encode-vs-.bin")),
                        Some(bin_bytes) => {
                            if encoded != bin_bytes {
                                v.push(format!(
                                    "{c}: RE-ENCODE MISMATCH — {} re-encodes to {} bytes \
                                     (sha256 {}) but the committed {} is {} bytes (sha256 {}). \
                                     The .did and the .bin have drifted; the Owner would upload \
                                     bytes that no reviewed text produces.",
                                    e.arg_did,
                                    encoded.len(),
                                    sha256_hex(&encoded),
                                    e.arg_bin,
                                    bin_bytes.len(),
                                    sha256_hex(bin_bytes),
                                ));
                            }
                        }
                    },
                },
            }
        }
    }

    // 2 — hashes
    match bin_bytes {
        None => notes.push(redacted_line(c, "arg_sha256")),
        Some(bin_bytes) => {
            let bin_sha = sha256_hex(bin_bytes);
            if bin_sha != e.arg_sha256 {
                v.push(format!(
                    "{c}: arg_sha256 (the Owner's expected_arg_hash) is {} but sha256({}) is {bin_sha}",
                    e.arg_sha256, e.arg_bin
                ));
            }
        }
    }
    if red.is_some() {
        notes.push(redacted_line(c, "arg_text_sha256"));
    } else {
        let text_sha = sha256_hex(did_text.as_bytes());
        if text_sha != e.arg_text_sha256 {
            v.push(format!(
                "{c}: arg_text_sha256 is {} but sha256({}) is {text_sha}",
                e.arg_text_sha256, e.arg_did
            ));
        }
    }

    // 3 — principal provenance
    let mut lits = principal_literals(did_text);
    lits.insert(e.target.clone());
    for p in lits {
        if !allowed.contains(&p) {
            v.push(format!(
                "{c}: principal `{p}` appears in the install argument but is NOT one of the \
                 nine J-18 births, the Vault, or a RESOLVED role in \
                 deployment/mainnet/genesis_principals.toml. An install argument may name \
                 only ruled principals."
            ));
        }
    }

    // 5 — Wasm identity
    if e.wasm_row.is_empty() {
        // vetkeys — unpinned BY RULING (D1). Measure the gate's build.
        let built = root.join(&e.wasm_path);
        match std::fs::read(&built) {
            Ok(b) => {
                let got = sha256_hex(&b);
                if got != e.wasm_sha256 {
                    v.push(format!(
                        "{c}: kit records wasm_sha256 {} but the built {} hashes to {got}",
                        e.wasm_sha256, e.wasm_path
                    ));
                }
            }
            Err(_) => v.push(format!(
                "{c}: the unpinned-by-ruling Wasm {} is absent — it is measured, not pinned, \
                 so there is nothing to compare. Build it exactly as the gate does:\n    \
                 cargo build --manifest-path canisters/vetkeys/Cargo.toml \
                 --target wasm32-unknown-unknown --release --locked",
                e.wasm_path
            )),
        }
    } else {
        match pins.iter().find(|(row, _)| *row == e.wasm_row) {
            Some((_, sha)) if *sha == e.wasm_sha256 => {}
            Some((_, sha)) => v.push(format!(
                "{c}: kit records wasm_sha256 {} but [wasm.{}] pins {sha}",
                e.wasm_sha256, e.wasm_row
            )),
            None => v.push(format!(
                "{c}: release_hashes.toml has no [wasm.{}] row",
                e.wasm_row
            )),
        }
    }

    if e.read_back.trim().is_empty() {
        v.push(format!("{c}: read_back must carry the exact post-install command"));
    }
}

fn main() -> ExitCode {
    // `--emit` REGENERATES each `<canister>_init.bin` from its `.did` using the
    // very encode path the verification uses, then verifies. It exists so the
    // committed binaries are reproducible from the reviewable text by a
    // committed tool rather than by a one-off script that left no trace — the
    // class of "artifact only its author's machine can rebuild". The gate never
    // passes it: a gate that can rewrite the artifact it checks checks nothing.
    let mut emit = false;
    let mut root = PathBuf::from(".");
    for a in std::env::args().skip(1) {
        if a == "--emit" {
            emit = true;
        } else {
            root = PathBuf::from(a);
        }
    }
    let kit_path = root.join("deployment/mainnet/a7_install_kit.toml");

    let kit_text = match std::fs::read_to_string(&kit_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("verify_a7_kit: cannot read {}: {e}", kit_path.display());
            return ExitCode::from(2);
        }
    };
    let kit: Kit = match toml::from_str(&kit_text) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("verify_a7_kit: {} does not parse: {e}", kit_path.display());
            return ExitCode::from(2);
        }
    };

    let mut v: Vec<String> = Vec::new();

    if kit.schema_version != 1 {
        v.push(format!("schema_version must be 1, found {}", kit.schema_version));
    }
    if kit.encoder.trim().is_empty() {
        v.push("`encoder` must name the encoder and its exact version".into());
    }

    // ── the universe of acceptable principals ────────────────────────────────
    //
    // RR-1b WIDENING. Until RR-1b the kit held only INFRASTRUCTURE arguments,
    // whose principals are canisters, so D5 ∪ Vault was the whole universe. The
    // stsh_token and vesting rows added here carry GENESIS HOLDER principals —
    // eleven multisig/identity principals that are not canisters and are not in
    // D5 — so the set must grow, and the only question is what it grows FROM.
    //
    // It grows from `deployment/mainnet/genesis_principals.toml`: the committed,
    // byte-pinned genesis principal record (`GENESIS_PRINCIPAL_RECORD_SHA256`),
    // which `verify_genesis_manifest` already proves every genesis install site
    // against. NOT from a hardcoded holder list pasted in here — a list typed
    // into this file from an office document would be self-inherited evidence:
    // this tool would then be checking the install args against a copy of the
    // same numbers rather than against the record that certifies them.
    //
    // A role carries `principal` OR `binding`; a `binding` is resolved through
    // `vault_authorities.toml` exactly as the record's grammar says. The literal
    // "PENDING" is a role's fail-closed marker and is NEVER admitted, so an
    // install argument naming an unresolved role still fails check 3.
    let mut allowed: BTreeSet<String> =
        D5_PRINCIPALS.iter().map(|(_, p)| p.to_string()).collect();
    allowed.insert(VAULT.to_string());
    match record_principals(&root) {
        Ok(ps) => {
            if ps.is_empty() {
                v.push(
                    "deployment/mainnet/genesis_principals.toml yielded NO resolved principal —                      check 3 would then be answered by absence rather than by the record"
                        .into(),
                );
            }
            allowed.extend(ps);
        }
        Err(e) => v.push(format!("cannot build the allowed principal set: {e}")),
    }
    let role_set = roles();

    let pins_text = std::fs::read_to_string(root.join("deployment/mainnet/release_hashes.toml"))
        .unwrap_or_default();
    let pins = wasm_pins(&pins_text);

    // ── optional regeneration (never on the gate path) ───────────────────────
    if emit {
        for e in &kit.entries {
            if redaction_for(&e.canister).is_some() {
                let m = redacted_line(&e.canister, "--emit (.bin regeneration)");
                eprintln!("  {m}");
                v.push(m);
                continue;
            }
            let iface = root.join(&e.interface);
            let did_path = root.join(&e.arg_did);
            match (init_types(&iface), std::fs::read_to_string(&did_path)) {
                (Ok((env, types)), Ok(text)) => match candid_parser::parse_idl_args(&text)
                    .map_err(|e| e.to_string())
                    .and_then(|a| a.to_bytes_with_types(&env, &types).map_err(|e| e.to_string()))
                {
                    Ok(bytes) => {
                        let out = root.join(&e.arg_bin);
                        if let Err(err) = std::fs::write(&out, &bytes) {
                            v.push(format!("{}: cannot write {}: {err}", e.canister, out.display()));
                        } else {
                            println!(
                                "  emit {} — {} bytes, sha256 {}",
                                e.arg_bin,
                                bytes.len(),
                                sha256_hex(&bytes)
                            );
                        }
                    }
                    Err(err) => v.push(format!("{}: cannot encode: {err}", e.canister)),
                },
                (Err(err), _) => v.push(format!("{}: {err}", e.canister)),
                (_, Err(err)) => v.push(format!("{}: cannot read {}: {err}", e.canister, e.arg_did)),
            }
        }
    }

    // ── per-row checks ───────────────────────────────────────────────────────
    let mut seen_order: BTreeSet<u32> = BTreeSet::new();
    let mut seen_canister: BTreeSet<String> = BTreeSet::new();
    let mut notes: Vec<String> = Vec::new();

    for e in &kit.entries {
        let c = &e.canister;
        if !seen_canister.insert(c.clone()) {
            v.push(format!("{c}: duplicate kit row"));
        }
        if !seen_order.insert(e.order) {
            v.push(format!("{c}: duplicate install order {}", e.order));
        }

        // 4 — role + target
        if !role_set.contains(e.role.as_str()) {
            v.push(format!(
                "{c}: role `{}` is not one of the nine BORN_UNDER_VAULT_ROLES (the operator dropdown)",
                e.role
            ));
        }
        match D5_PRINCIPALS.iter().find(|(n, _)| *n == c.as_str()) {
            Some((_, p)) if *p == e.target => {}
            Some((_, p)) => v.push(format!(
                "{c}: target {} is not the J-18 principal for this canister ({p})",
                e.target
            )),
            None => v.push(format!("{c}: not a canister born under the Vault at J-18")),
        }

        // 1-3, 5 — read the artifacts, then check the row. A BinAndText row's
        // `.bin` is not published, so it is not read (redacted mode).
        let did_path = root.join(&e.arg_did);
        let did_text = match std::fs::read_to_string(&did_path) {
            Ok(t) => t,
            Err(err) => {
                v.push(format!("{c}: cannot read {}: {err}", did_path.display()));
                continue;
            }
        };
        let bin_bytes = if redaction_for(c) == Some(Redaction::BinAndText) {
            None
        } else {
            let bin_path = root.join(&e.arg_bin);
            match std::fs::read(&bin_path) {
                Ok(b) => Some(b),
                Err(err) => {
                    v.push(format!("{c}: cannot read {}: {err}", bin_path.display()));
                    continue;
                }
            }
        };
        check_row(e, &root, &did_text, bin_bytes.as_deref(), &allowed, &pins, &mut v, &mut notes);
    }

    // ── 6 — the RR-1 hold, enforced in BOTH directions ───────────────────────
    let gm = std::fs::read_to_string(root.join("deployment/mainnet/genesis_manifest.toml"))
        .unwrap_or_default();
    let roots = pool_init_roots(&gm);
    if let Some(pool) = kit.entries.iter().find(|e| e.canister == "shielded_pool") {
        let pool_text =
            std::fs::read_to_string(root.join(&pool.arg_did)).unwrap_or_default();
        // The four fields genesis_manifest [pool_init] owns (DPOOL-4..7).
        let want: Vec<(&str, String)> = ["token_canister", "treasury_canister", "staking_canister", "controller"]
            .iter()
            .map(|f| {
                let val = pool_text
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.starts_with("//"))
                    .find(|l| l.starts_with(&format!("{f} ")) || l.starts_with(&format!("{f}=")))
                    .and_then(|l| l.split_once('"').map(|(_, r)| r))
                    .and_then(|r| r.split('"').next())
                    .unwrap_or("")
                    .to_string();
                (*f, val)
            })
            .collect();
        let agree = want.iter().all(|(f, val)| {
            !val.is_empty()
                && roots.iter().any(|(k, mv)| k == f && mv == val)
        });
        if agree && !pool.hold.is_empty() {
            v.push(
                "shielded_pool: genesis_manifest [pool_init] now AGREES with \
                 shielded_pool_init.did, so the RR-1 hold has served its purpose and must be \
                 CLEARED. A hold that outlives its cause stops describing the tree."
                    .into(),
            );
        }
        if !agree && pool.hold.is_empty() {
            v.push(format!(
                "shielded_pool: genesis_manifest [pool_init] still names {} — NOT the D5 \
                 principals in shielded_pool_init.did — so the pool install is HELD on RR-1 and \
                 the kit row MUST declare `hold`.",
                roots
                    .iter()
                    .map(|(k, val)| format!("{k}={val}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    } else {
        v.push("the kit has no shielded_pool row".into());
    }

    for n in &notes {
        println!("  {n}");
    }
    if v.is_empty() {
        println!(
            "verify_a7_kit: OK — {} install rows; every .did re-encodes byte-identically to its \
             .bin, every hash matches, every principal is a J-18 birth, the Vault, or a \
             resolved role in the committed genesis principal record ({} check(s) skipped \
             in public-export redacted mode, listed above).",
            kit.entries.len(),
            notes.len()
        );
        println!("  encoder: {}", kit.encoder);
        ExitCode::SUCCESS
    } else {
        eprintln!("verify_a7_kit: {} violation(s)", v.len());
        for line in &v {
            eprintln!("  - {line}");
        }
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    //! Redacted mode (PUBLIC-MIRROR T-11): it skips EXACTLY the listed checks,
    //! and nothing else on a redacted row is weakened.
    use super::*;

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn fixture() -> (Kit, BTreeSet<String>, Vec<(String, String)>) {
        let root = root();
        let kit: Kit = toml::from_str(
            &std::fs::read_to_string(root.join("deployment/mainnet/a7_install_kit.toml")).unwrap(),
        )
        .unwrap();
        let mut allowed: BTreeSet<String> =
            D5_PRINCIPALS.iter().map(|(_, p)| p.to_string()).collect();
        allowed.insert(VAULT.to_string());
        allowed.extend(record_principals(&root).unwrap());
        let pins = wasm_pins(
            &std::fs::read_to_string(root.join("deployment/mainnet/release_hashes.toml")).unwrap(),
        );
        (kit, allowed, pins)
    }

    fn entry<'a>(kit: &'a Kit, c: &str) -> &'a Entry {
        kit.entries.iter().find(|e| e.canister == c).unwrap()
    }

    fn run(e: &Entry, did: &str, bin: Option<&[u8]>) -> (Vec<String>, Vec<String>) {
        let (_, allowed, pins) = fixture();
        let (mut v, mut notes) = (Vec::new(), Vec::new());
        check_row(e, &root(), did, bin, &allowed, &pins, &mut v, &mut notes);
        (v, notes)
    }

    fn did(e: &Entry) -> String {
        std::fs::read_to_string(root().join(&e.arg_did)).unwrap()
    }

    #[test]
    fn redacted_mode_table_is_exactly_the_two_genesis_rows() {
        assert_eq!(redaction_for("stsh_token"), Some(Redaction::BinAndText));
        assert_eq!(redaction_for("vesting"), Some(Redaction::TextOnly));
        let (kit, _, _) = fixture();
        let others: Vec<&str> = kit
            .entries
            .iter()
            .map(|e| e.canister.as_str())
            .filter(|c| redaction_for(c).is_some())
            .collect();
        assert_eq!(others, vec!["stsh_token", "vesting"]);
    }

    #[test]
    fn stsh_token_skips_exactly_reencode_and_both_hashes() {
        let (kit, _, _) = fixture();
        let e = entry(&kit, "stsh_token");
        let (v, notes) = run(e, &did(e), None);
        assert!(v.is_empty(), "{v:?}");
        assert_eq!(
            notes,
            vec![
                redacted_line("stsh_token", "re-encode-vs-.bin"),
                redacted_line("stsh_token", "arg_sha256"),
                redacted_line("stsh_token", "arg_text_sha256"),
            ]
        );
    }

    #[test]
    fn vesting_skips_only_the_text_hash_and_keeps_the_bin_checks() {
        let (kit, _, _) = fixture();
        let e = entry(&kit, "vesting");
        let bin = std::fs::read(root().join(&e.arg_bin)).unwrap();
        let (v, notes) = run(e, &did(e), Some(&bin));
        assert!(v.is_empty(), "{v:?}");
        assert_eq!(notes, vec![redacted_line("vesting", "arg_text_sha256")]);

        // The .bin checks are still live: one tampered byte must fail BOTH the
        // re-encode comparison and arg_sha256.
        let mut bad = bin.clone();
        bad.push(0);
        let (v, _) = run(e, &did(e), Some(&bad));
        assert!(v.iter().any(|m| m.contains("RE-ENCODE MISMATCH")), "{v:?}");
        assert!(v.iter().any(|m| m.contains("arg_sha256")), "{v:?}");
    }

    #[test]
    fn redacted_row_still_rejects_an_unruled_principal() {
        let (kit, _, _) = fixture();
        let e = entry(&kit, "stsh_token");
        let text = did(e);
        let start = text.find("principal \"").unwrap() + "principal \"".len();
        let end = start + text[start..].find('"').unwrap();
        let rogue = format!("{}aaaaa-aa{}", &text[..start], &text[end..]);
        let (v, _) = run(e, &rogue, None);
        assert!(v.iter().any(|m| m.contains("principal `aaaaa-aa`")), "{v:?}");
    }

    #[test]
    fn unredacted_rows_record_no_skip() {
        let (kit, _, _) = fixture();
        for e in kit
            .entries
            .iter()
            .filter(|e| redaction_for(&e.canister).is_none() && !e.wasm_row.is_empty())
        {
            let bin = std::fs::read(root().join(&e.arg_bin)).unwrap();
            let (v, notes) = run(e, &did(e), Some(&bin));
            assert!(v.is_empty(), "{}: {v:?}", e.canister);
            assert!(notes.is_empty(), "{}: {notes:?}", e.canister);
        }
    }
}
