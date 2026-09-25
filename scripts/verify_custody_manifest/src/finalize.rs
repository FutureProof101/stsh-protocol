//! §Q — the finalize+assemble phase of `export_creation_receipts`.
//!
//! WHAT IT CURES (SSA §4C, P0). The §P export phase writes a MINIMAL ceremony
//! root: raw/canonical pages, a rendered manifest, and an `INVENTORY`. Two
//! things follow, and both are fatal to the runbook step that consumes it:
//!
//!   1. That root is not a repository. `verify_custody_manifest --deploy-time
//!      <root>` needs `deployment/mainnet/custody_manifest.toml`, `dfx.json`,
//!      `canister_ids.json`, canister source, init artifacts, the release
//!      record and built Wasms. The command the runbook gives cannot run.
//!   2. The rendered manifest populates D5 only. The committed template still
//!      carries `bootstrap_ring.status = "pending"` with an empty evidence
//!      hash, so the ring pointer must be populated afterwards — which makes
//!      the already-recorded manifest and root hashes stale, while editing the
//!      immutable clone first is prohibited and fails the clean-clone check.
//!      There was no sequence that both populated the pointer and preserved
//!      the recorded hashes.
//!
//! THE CURE, per the ruling: one deterministic phase that renders the FINAL
//! schema-2 manifest — D5 receipts AND the populated ring pointer — before any
//! hashing, assembles a full repository-shaped scratch tree from the verified
//! pinned clone with only the finalized manifest, the ring evidence artifact
//! and the built Wasms substituted or added, and computes the manifest hash
//! and root inventory LAST. The checker gains no new mode: the cure is
//! entirely on the exporter side.
//!
//! NO POST-HASH MUTATION PATH EXISTS. Hashing is the last thing this module
//! does; after it, the only write is the `INVENTORY` file itself, which is not
//! part of its own inventory. There is no re-render, re-substitute or
//! re-hash entry point, and a committed test re-reads every inventoried file
//! from disk and re-derives the root hash to prove the record still describes
//! the tree.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::export::{
    self, AcquiredPage, ExportError, ValidatedReceipt, PINNED_INITIAL_CURSOR,
};
use crate::sha256_hex;

/// The mode string stamped into the root inventory. Distinct from the export
/// phase's, so a finalize root and an export root can never be confused for
/// one another by hash.
pub const FINALIZE_MODE: &str = "finalize-assemble";

/// Where the tool places the built Wasms inside the assembled tree — the path
/// `measure_payloads` and `check_release_identity` read. Mirrors the checker
/// rather than inventing a location.
pub const TREE_WASM_DIR: &str = "target/wasm32-unknown-unknown/release";

/// Everything the phase consumes.
#[derive(Debug, Clone)]
pub struct FinalizeInputs {
    /// The reviewed ceremony-source commit. An ARGUMENT, verified against the
    /// clone's own HEAD — never a hardcoded commit.
    pub ceremony_source_sha: String,
    /// The clean immutable clone at that commit.
    pub clone: PathBuf,
    /// The §P export phase's output root (raw/canonical pages + INVENTORY).
    pub export_root: PathBuf,
    /// What the operator ATTESTS about that root, from the filed §P transcript:
    /// its mode and the `ceremony root sha256` the export phase printed. Both
    /// are ARGUMENTS held outside the root — see [`ExportAttestation`].
    pub export_attestation: ExportAttestation,
    /// The separately hashed bootstrap-ring ceremony artifact.
    pub ring_artifact: PathBuf,
    /// Directory holding the built production Wasms.
    pub wasm_dir: PathBuf,
    /// The scratch destination. MUST NOT exist.
    pub out: PathBuf,
}

/// Everything the phase records. Every hash here is computed after the tree is
/// complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizeOutcome {
    /// The assembled repository-shaped verification tree.
    pub tree: PathBuf,
    pub ceremony_source_sha: String,
    /// The consumed export root's own mode, carried forward into the root
    /// hash so a replay-derived root is hash-distinct from an authenticated one.
    pub export_mode: String,
    /// Canonical page hashes carried forward from the authenticated export.
    pub page_hashes: Vec<String>,
    pub ring_sha256: String,
    /// The path the manifest's own pointer declares, relative to the tree.
    pub ring_path: String,
    /// sha256 of the FINAL manifest, read back from the assembled tree.
    pub manifest_sha256: String,
    /// `(tree-relative path, sha256)` for every file this tool placed into the
    /// tree, sorted by path.
    pub tree_inventory: Vec<(String, String)>,
    /// sha256 over the canonical root listing. Binds mode, source SHA, page
    /// hashes, ring-artifact hash, manifest hash and tree inventory.
    pub root_sha256: String,
}

// ── Reading back an export root ──────────────────────────────────────────────

/// Reconstruct the authenticated export's page sequence from its written root.
///
/// The cursor each page was fetched for is NOT stored in the root — it is
/// re-derived by chaining: the first page is the pinned initial cursor, each
/// subsequent page the previous page's `next_cursor`. That is deliberate. A
/// stored cursor could be edited to agree with a tampered chain; a derived one
/// makes `verify_sequence` re-prove the chain from the page bytes themselves.
pub fn read_export_root(export_root: &Path) -> Result<Vec<AcquiredPage>, ExportError> {
    let mut raw_by_name: BTreeMap<String, String> = BTreeMap::new();
    let mut canon_by_name: BTreeMap<String, String> = BTreeMap::new();
    let entries = std::fs::read_dir(export_root).map_err(|e| ExportError::ExportRootUnusable {
        detail: format!("cannot read {}: {e}", export_root.display()),
    })?;
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_string()) else {
            continue;
        };
        let body = match std::fs::read_to_string(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if let Some(stem) = name.strip_suffix(".raw.candid") {
            raw_by_name.insert(stem.to_string(), body);
        } else if let Some(stem) = name.strip_suffix(".canonical.candid") {
            canon_by_name.insert(stem.to_string(), body);
        }
    }
    if canon_by_name.is_empty() {
        return Err(ExportError::ExportRootUnusable {
            detail: format!("{} holds no canonical pages", export_root.display()),
        });
    }
    if raw_by_name.keys().ne(canon_by_name.keys()) {
        return Err(ExportError::ExportRootUnusable {
            detail: "raw and canonical page sets do not correspond one-to-one".into(),
        });
    }

    // Names are zero-padded, so BTreeMap order IS page order. The cursor chain
    // is re-derived and then re-verified by `verify_sequence`.
    let mut pages: Vec<AcquiredPage> = Vec::new();
    let mut cursor = PINNED_INITIAL_CURSOR;
    for (stem, canonical) in &canon_by_name {
        let (recanonicalized, decoded) = export::canonicalize_and_decode(canonical, cursor)?;
        // A canonical page must already BE canonical. If re-canonicalizing it
        // changes anything, the file was hand-edited.
        if &recanonicalized != canonical {
            return Err(ExportError::ExportRootUnusable {
                detail: format!("{stem}.canonical.candid is not in canonical form"),
            });
        }
        let page = decoded.ok_or(ExportError::Unauthorized { cursor })?;
        let next = page.next_cursor;
        pages.push(AcquiredPage {
            cursor,
            raw: raw_by_name.get(stem).cloned().unwrap_or_default(),
            canonical: canonical.clone(),
            sha256: sha256_hex(canonical.as_bytes()),
            page,
        });
        match next {
            None => break,
            Some(n) => cursor = Some(n),
        }
    }
    Ok(pages)
}

/// The file name the §P export phase gives its rendered (D5-only) manifest
/// inside the export root. Mirrors `export::write_ceremony_root` rather than
/// being invented here.
pub const EXPORT_MANIFEST_NAME: &str = "custody_manifest.toml";

/// What the operator ATTESTS about the export root, from the filed §P
/// transcript — not from the root itself.
///
/// WHY THIS EXISTS. A replay export and an authenticated export write
/// byte-identical pages; the only thing distinguishing them is the `mode` line
/// the export phase stamped into `INVENTORY`. That line is plain text inside
/// the very directory an attacker would be editing, so nothing inside the root
/// can authenticate it. Two independently recorded values close the gap:
///
///   * `mode` — what the operator declares the §P run was. A recorded mode that
///     differs is a typed STOP, so the tool never simply believes the file.
///   * `root_sha256` — the `ceremony root sha256` the export phase PRINTED and
///     the §P transcript recorded, held OUTSIDE the root. The listing it hashes
///     covers the mode line and every artifact entry, so editing `mode replay`
///     to `mode authenticated-export` changes this hash and is rejected.
///
/// Neither is a constant and neither is read from the root: both are arguments,
/// exactly as the ceremony-source SHA is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportAttestation {
    pub mode: String,
    pub root_sha256: String,
}

/// A strictly parsed export `INVENTORY`.
struct ParsedInventory {
    mode: String,
    ceremony_source_sha: String,
    /// `(name, sha256)` in recorded order.
    entries: Vec<(String, String)>,
}

/// Parse an export root's `INVENTORY` with no tolerance. Every line must be one
/// of the three recognised forms; anything else is malformed, and a malformed
/// evidence listing is not evidence.
fn parse_export_inventory(listing: &str) -> Result<ParsedInventory, ExportError> {
    let unusable = |detail: String| ExportError::ExportRootUnusable { detail };
    let mut mode: Option<String> = None;
    let mut sha: Option<String> = None;
    let mut entries: Vec<(String, String)> = Vec::new();
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();

    for (n, line) in listing.lines().enumerate() {
        let lineno = n + 1;
        if let Some(rest) = line.strip_prefix("mode ") {
            if mode.replace(rest.to_string()).is_some() {
                return Err(unusable(format!("line {lineno}: a second `mode` line")));
            }
            if rest.trim().is_empty() || rest != rest.trim() {
                return Err(unusable(format!("line {lineno}: malformed `mode` value")));
            }
        } else if let Some(rest) = line.strip_prefix("ceremony_source_sha ") {
            if sha.replace(rest.to_string()).is_some() {
                return Err(unusable(format!(
                    "line {lineno}: a second `ceremony_source_sha` line"
                )));
            }
        } else if let Some((hash, name)) = line.split_once("  ") {
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
            {
                return Err(unusable(format!(
                    "line {lineno}: `{hash}` is not a lowercase 64-hex sha256"
                )));
            }
            if name.trim().is_empty() || name != name.trim() || name.contains('/') {
                return Err(unusable(format!("line {lineno}: malformed artifact name `{name}`")));
            }
            if seen.insert(name.to_string(), ()).is_some() {
                return Err(unusable(format!(
                    "line {lineno}: `{name}` is recorded more than once — a duplicate entry lets \
                     one of the two go unchecked"
                )));
            }
            entries.push((name.to_string(), hash.to_string()));
        } else {
            return Err(unusable(format!(
                "line {lineno}: `{line}` is not a recognised INVENTORY line"
            )));
        }
    }

    let mode = mode.ok_or_else(|| unusable("the export INVENTORY records no mode".into()))?;
    let ceremony_source_sha =
        sha.ok_or_else(|| unusable("the export INVENTORY records no ceremony_source_sha".into()))?;
    if entries.is_empty() {
        return Err(unusable("the export INVENTORY records no artifacts".into()));
    }
    Ok(ParsedInventory {
        mode,
        ceremony_source_sha,
        entries,
    })
}

/// Re-prove the COMPLETE §P root from its own files, against two independently
/// recorded values (the ceremony-source SHA and the operator's attestation).
///
/// Each obligation below is separate, and each has its own committed negative:
///
///   1. the recorded ceremony-source SHA equals the finalize argument;
///   2. the listing parses strictly — no malformed line, no duplicate entry;
///   3. the recorded entry set is EXACTLY the expected one — every raw page,
///      every canonical page, the rendered manifest, and nothing else, so a
///      missing entry, an extra entry and a page recorded after the walk's
///      terminal page are all rejected;
///   4. the set of page files actually on disk equals that same set, so a
///      post-terminal page smuggled in beside the listing is rejected too;
///   5. every recorded artifact is re-read from disk and hash-checked — raw
///      pages, canonical pages AND the rendered manifest, not canonical pages
///      alone;
///   6. every raw page CANONICALIZES to its paired canonical page, so the raw
///      evidence and the hashed canonical form cannot disagree;
///   7. the recorded mode equals the mode the operator attested; and
///   8. the listing re-derives byte-for-byte and hashes to the attested §P root
///      sha256 — which is what makes an edited `mode` line detectable, since
///      nothing inside the root could authenticate it.
///
/// Returns the (now attested) export mode. It is carried into the finalize root
/// listing rather than being forced to equal `authenticated-export`: a finalize
/// root built over a REPLAY must remain constructible — the committed synthetic
/// regression is exactly that — but it must never hash the same as one built
/// over an authenticated read, and it must never be able to CLAIM to be one.
pub fn verify_export_inventory(
    export_root: &Path,
    pages: &[AcquiredPage],
    ceremony_source_sha: &str,
    attestation: &ExportAttestation,
) -> Result<String, ExportError> {
    let unusable = |detail: String| ExportError::ExportRootUnusable { detail };
    let raw_listing = std::fs::read_to_string(export_root.join("INVENTORY"))
        .map_err(|e| unusable(format!("cannot read the export root's INVENTORY: {e}")))?;
    let parsed = parse_export_inventory(&raw_listing)?;

    // (1) The root must describe the same ceremony source this phase was given.
    if parsed.ceremony_source_sha != ceremony_source_sha.trim() {
        return Err(ExportError::SourceShaMismatch {
            expected: ceremony_source_sha.trim().to_string(),
            actual: parsed.ceremony_source_sha,
        });
    }

    // (3) The expected entry set, derived from the VERIFIED page walk. Page
    //     indices come from the walk, which terminated at `next_cursor = None`,
    //     so any recorded page beyond it is post-terminal by construction.
    let mut expected: Vec<String> = Vec::new();
    for i in 0..pages.len() {
        expected.push(format!("page-{i:03}.raw.candid"));
        expected.push(format!("page-{i:03}.canonical.candid"));
    }
    expected.push(EXPORT_MANIFEST_NAME.to_string());
    expected.sort();
    let mut recorded_names: Vec<String> = parsed.entries.iter().map(|(n, _)| n.clone()).collect();
    recorded_names.sort();
    if recorded_names != expected {
        let missing: Vec<&String> = expected.iter().filter(|n| !recorded_names.contains(n)).collect();
        let extra: Vec<&String> = recorded_names.iter().filter(|n| !expected.contains(n)).collect();
        return Err(unusable(format!(
            "the export INVENTORY does not record exactly the export's artifacts — missing \
             {missing:?}, extra {extra:?}. An entry recorded for a page beyond the walk's \
             terminal page is `extra` here: the walk ends at next_cursor = None"
        )));
    }

    // (4) …and the pages ON DISK are exactly those pages. An un-inventoried
    //     post-terminal page pair sitting beside the listing is caught here.
    let mut on_disk: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(export_root)
        .map_err(|e| unusable(format!("cannot read {}: {e}", export_root.display())))?
        .filter_map(|e| e.ok())
    {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".raw.candid") || name.ends_with(".canonical.candid") {
            on_disk.push(name);
        }
    }
    on_disk.sort();
    let mut expected_pages: Vec<String> = expected
        .iter()
        .filter(|n| n.as_str() != EXPORT_MANIFEST_NAME)
        .cloned()
        .collect();
    expected_pages.sort();
    if on_disk != expected_pages {
        return Err(unusable(format!(
            "the page files in {} are not exactly the pages the verified walk produced: on disk \
             {on_disk:?}, expected {expected_pages:?}",
            export_root.display()
        )));
    }

    // (5) Re-read and hash-check EVERY recorded artifact from disk — raw pages,
    //     canonical pages and the rendered manifest alike.
    for (name, recorded_hash) in &parsed.entries {
        let bytes = std::fs::read(export_root.join(name))
            .map_err(|e| unusable(format!("cannot re-read {name} from the export root: {e}")))?;
        let actual = sha256_hex(&bytes);
        if &actual != recorded_hash {
            return Err(ExportError::HashMismatch {
                what: name.clone(),
                expected: recorded_hash.clone(),
                actual,
            });
        }
    }

    // (6) Each raw page must canonicalize to its paired canonical page. The
    //     cursor is the one the verified walk derived for that page.
    for (i, p) in pages.iter().enumerate() {
        let (recanonicalized, _) = export::canonicalize_and_decode(&p.raw, p.cursor)?;
        if recanonicalized != p.canonical {
            return Err(unusable(format!(
                "page-{i:03}.raw.candid does not canonicalize to page-{i:03}.canonical.candid — \
                 the raw evidence and the hashed canonical form disagree"
            )));
        }
    }

    // (7) The mode is ATTESTED, never inferred from the root.
    if parsed.mode != attestation.mode {
        return Err(ExportError::ExportModeUnattested {
            declared: attestation.mode.clone(),
            recorded: parsed.mode,
        });
    }

    // (8) The listing re-derives byte-for-byte from the parsed entries and
    //     hashes to the §P root sha256 recorded outside this directory. This is
    //     the clause that makes an edited `mode` line impossible to pass off:
    //     the mode is inside the hashed listing, and the expected hash is not.
    let mut sorted = parsed.entries.clone();
    sorted.sort();
    let rederived =
        export::ceremony_root_listing(&parsed.mode, &parsed.ceremony_source_sha, &sorted);
    if rederived != raw_listing {
        return Err(unusable(
            "the export INVENTORY is not in canonical listing form — entries out of order, \
             reordered lines or stray bytes"
                .into(),
        ));
    }
    let actual = sha256_hex(raw_listing.as_bytes());
    if actual != attestation.root_sha256.trim() {
        return Err(ExportError::ExportRootUnattested {
            expected: attestation.root_sha256.trim().to_string(),
            actual,
        });
    }

    Ok(parsed.mode)
}

// ── The ring pointer ─────────────────────────────────────────────────────────

/// Read the `bootstrap_ring.evidence_path` the template itself declares.
///
/// The artifact is placed at the path the MANIFEST names, never at a path this
/// tool invents: the checker resolves `root.join(evidence_path)`, so any other
/// choice would produce a pointer that does not resolve.
pub fn template_ring_path(template: &str) -> Result<String, ExportError> {
    for line in template.lines() {
        if let Some(rest) = line.trim().strip_prefix("evidence_path") {
            if let Some((_, v)) = rest.split_once('"') {
                let path: String = v.chars().take_while(|c| *c != '"').collect();
                if path.trim().is_empty() {
                    break;
                }
                return Ok(path);
            }
        }
    }
    Err(ExportError::RenderFailed {
        detail: "the template declares no bootstrap_ring.evidence_path".into(),
    })
}

/// Populate the ring pointer: `status` pending → populated, and the artifact's
/// real sha256 into `evidence_sha256`. Refuses a template that is already
/// populated rather than layering a second binding over it.
pub fn render_ring_pointer(manifest: &str, ring_sha256: &str) -> Result<String, ExportError> {
    let start = manifest
        .find("\n[bootstrap_ring]")
        .ok_or(ExportError::RenderFailed {
            detail: "[bootstrap_ring] not found".into(),
        })?
        + 1;
    let end = manifest[start..]
        .find("\n[")
        .map(|i| start + i + 1)
        .unwrap_or(manifest.len());
    let section = &manifest[start..end];
    if !section.contains("status = \"pending\"") {
        return Err(ExportError::RenderFailed {
            detail: "[bootstrap_ring] is not `status = \"pending\"` — refusing to render over an \
                     already-populated ring pointer"
                .into(),
        });
    }
    if !section.contains("evidence_sha256 = \"\"") {
        return Err(ExportError::RenderFailed {
            detail: "[bootstrap_ring].evidence_sha256 is already set — refusing to overwrite a \
                     pinned ring hash"
                .into(),
        });
    }
    let new_section = section
        .replace("status = \"pending\"", "status = \"populated\"")
        .replace(
            "evidence_sha256 = \"\"",
            &format!("evidence_sha256 = \"{ring_sha256}\""),
        );
    let mut out = String::with_capacity(manifest.len() + 64);
    out.push_str(&manifest[..start]);
    out.push_str(&new_section);
    out.push_str(&manifest[end..]);
    Ok(out)
}

// ── Tree assembly ────────────────────────────────────────────────────────────

/// Materialize the repository-shaped tree by CLONING the verified clone and
/// detaching at the same pinned SHA, then re-verifying `rev-parse HEAD`.
///
/// A byte-copy of the working directory would have to be trusted to have been
/// faithful; a clone at a verified SHA PROVES the tree's provenance from git's
/// own object store, and carries the `.git` directory the checker needs for
/// its DID drift lock (`git show HEAD:…`) and release-identity quiescence
/// query (`git log <pin>..HEAD`).
fn materialize_tree(clone: &Path, sha: &str, tree: &Path) -> Result<(), ExportError> {
    let run = |args: Vec<String>| -> Result<(), ExportError> {
        let out = std::process::Command::new("git")
            .args(&args)
            .output()
            .map_err(|e| ExportError::TreeAssemblyFailed {
                detail: format!("git {args:?}: {e}"),
            })?;
        if !out.status.success() {
            return Err(ExportError::TreeAssemblyFailed {
                detail: format!(
                    "git {args:?} failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
            });
        }
        Ok(())
    };
    run(vec![
        "clone".into(),
        "--quiet".into(),
        clone.to_string_lossy().into_owned(),
        tree.to_string_lossy().into_owned(),
    ])?;
    run(vec![
        "-C".into(),
        tree.to_string_lossy().into_owned(),
        "checkout".into(),
        "--quiet".into(),
        "--detach".into(),
        sha.to_string(),
    ])?;
    let head = std::process::Command::new("git")
        .arg("-C")
        .arg(tree)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| ExportError::TreeAssemblyFailed {
            detail: format!("git rev-parse in the assembled tree: {e}"),
        })?;
    let head = String::from_utf8_lossy(&head.stdout).trim().to_string();
    if head != sha {
        return Err(ExportError::SourceShaMismatch {
            expected: sha.to_string(),
            actual: head,
        });
    }
    Ok(())
}

// ── The phase ────────────────────────────────────────────────────────────────

/// Finalize and assemble. Every failure is typed and terminal; on any error
/// nothing downstream is written and no hash is recorded.
pub fn finalize_and_assemble(inputs: &FinalizeInputs) -> Result<FinalizeOutcome, ExportError> {
    // 1. Destination first: refuse to write into anything that already exists,
    //    before doing any work that might tempt a partial result.
    if inputs.out.exists() {
        return Err(ExportError::DestinationExists {
            path: inputs.out.clone(),
        });
    }
    // 2. The clone: clean, and at the declared ceremony-source SHA.
    export::verify_source_clone(&inputs.clone, &inputs.ceremony_source_sha)?;
    let sha = inputs.ceremony_source_sha.trim().to_string();

    // 3. The authenticated export, re-verified end to end from its own files.
    let pages = read_export_root(&inputs.export_root)?;
    export::verify_sequence(&pages)?;
    let export_mode = verify_export_inventory(
        &inputs.export_root,
        &pages,
        &sha,
        &inputs.export_attestation,
    )?;
    let receipts: Vec<ValidatedReceipt> = export::validate_receipts(&pages)?;

    // 4. The ring artifact. Absent or empty is a typed failure, never an
    //    empty pass: an unhashed pointer target is exactly the gap §P.1's
    //    fail-closed pointer exists to make visible.
    let ring_bytes =
        std::fs::read(&inputs.ring_artifact).map_err(|e| ExportError::RingArtifactUnavailable {
            detail: format!("cannot read {}: {e}", inputs.ring_artifact.display()),
        })?;
    if ring_bytes.is_empty() {
        return Err(ExportError::RingArtifactUnavailable {
            detail: format!("{} is empty", inputs.ring_artifact.display()),
        });
    }
    let ring_sha256 = sha256_hex(&ring_bytes);

    // 5. The FINAL manifest — D5 receipts AND the populated ring pointer —
    //    rendered from the immutable clone's template, BEFORE any hashing.
    let template_path = inputs.clone.join("deployment/mainnet/custody_manifest.toml");
    let template =
        std::fs::read_to_string(&template_path).map_err(|e| ExportError::Io {
            detail: format!("cannot read {}: {e}", template_path.display()),
        })?;
    let ring_path = template_ring_path(&template)?;
    let with_d5 = export::render_manifest(&template, &receipts)?;
    let final_manifest = render_ring_pointer(&with_d5, &ring_sha256)?;

    // 6. Assemble the repository-shaped tree.
    std::fs::create_dir_all(&inputs.out).map_err(|e| ExportError::Io {
        detail: format!("cannot create {}: {e}", inputs.out.display()),
    })?;
    let tree = inputs.out.join("tree");
    materialize_tree(&inputs.clone, &sha, &tree)?;

    // Only three classes of file are substituted or added, and each is
    // inventoried below: the finalized manifest, the ring evidence artifact at
    // the path the manifest itself declares, and the built Wasms where the
    // deploy-time checker reads them.
    let mut placed: Vec<(String, String)> = Vec::new();
    let mut place = |rel: &str, bytes: &[u8]| -> Result<(), ExportError> {
        let dest = tree.join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ExportError::TreeAssemblyFailed {
                detail: format!("cannot create {}: {e}", parent.display()),
            })?;
        }
        std::fs::write(&dest, bytes).map_err(|e| ExportError::TreeAssemblyFailed {
            detail: format!("cannot write {}: {e}", dest.display()),
        })?;
        placed.push((rel.to_string(), sha256_hex(bytes)));
        Ok(())
    };

    place(
        "deployment/mainnet/custody_manifest.toml",
        final_manifest.as_bytes(),
    )?;
    place(&ring_path, &ring_bytes)?;

    for (_pkg, wasm) in crate::INLINE_PAYLOAD_ARTIFACTS {
        let src = inputs.wasm_dir.join(wasm);
        let bytes = std::fs::read(&src).map_err(|e| ExportError::TreeAssemblyFailed {
            detail: format!("cannot read built Wasm {}: {e}", src.display()),
        })?;
        place(&format!("{TREE_WASM_DIR}/{wasm}"), &bytes)?;
    }

    // The authenticated export's pages travel BESIDE the tree, not inside it:
    // they are not checker inputs, and adding them to the repository tree would
    // make it something other than the pinned clone for no verification gain.
    // They remain bound to this root through their hashes in the listing below.
    let evidence_dir = inputs.out.join("evidence");
    std::fs::create_dir_all(&evidence_dir).map_err(|e| ExportError::Io {
        detail: format!("cannot create {}: {e}", evidence_dir.display()),
    })?;
    for (i, p) in pages.iter().enumerate() {
        for (name, body) in [
            (format!("page-{i:03}.raw.candid"), &p.raw),
            (format!("page-{i:03}.canonical.candid"), &p.canonical),
        ] {
            std::fs::write(evidence_dir.join(&name), body).map_err(|e| ExportError::Io {
                detail: format!("cannot write {name}: {e}"),
            })?;
        }
    }

    // 7. HASHES LAST. Every inventoried file is re-read from the assembled
    //    tree, so the record describes what is on disk rather than what was
    //    intended to be written.
    let mut tree_inventory: Vec<(String, String)> = Vec::new();
    for (rel, _) in &placed {
        let bytes = std::fs::read(tree.join(rel)).map_err(|e| ExportError::Io {
            detail: format!("cannot re-read {rel} from the assembled tree: {e}"),
        })?;
        tree_inventory.push((rel.clone(), sha256_hex(&bytes)));
    }
    tree_inventory.sort();

    let manifest_sha256 = tree_inventory
        .iter()
        .find(|(rel, _)| rel == "deployment/mainnet/custody_manifest.toml")
        .map(|(_, h)| h.clone())
        .expect("the manifest was just placed and re-read");
    let page_hashes: Vec<String> = pages.iter().map(|p| p.sha256.clone()).collect();

    let listing = root_listing(
        &export_mode,
        &sha,
        &page_hashes,
        &ring_sha256,
        &ring_path,
        &manifest_sha256,
        &tree_inventory,
    );
    let root_sha256 = sha256_hex(listing.as_bytes());
    // The INVENTORY is written after the hash and is deliberately NOT part of
    // its own inventory — the only write that follows hashing, and it cannot
    // change any hash it records.
    std::fs::write(inputs.out.join("INVENTORY"), &listing).map_err(|e| ExportError::Io {
        detail: format!("cannot write INVENTORY: {e}"),
    })?;

    Ok(FinalizeOutcome {
        tree,
        ceremony_source_sha: sha,
        export_mode,
        page_hashes,
        ring_sha256,
        ring_path,
        manifest_sha256,
        tree_inventory,
        root_sha256,
    })
}

/// The canonical root listing. Deterministic and total: mode, ceremony-source
/// SHA, every page hash in walk order, the ring artifact's path and hash, the
/// final manifest hash, and the sorted tree inventory. Recomputable by a
/// reviewer from the tree alone.
pub fn root_listing(
    export_mode: &str,
    ceremony_source_sha: &str,
    page_hashes: &[String],
    ring_sha256: &str,
    ring_path: &str,
    manifest_sha256: &str,
    tree_inventory: &[(String, String)],
) -> String {
    let mut s = format!(
        "mode {FINALIZE_MODE}\nexport_mode {export_mode}\nceremony_source_sha \
         {ceremony_source_sha}\n"
    );
    for (i, h) in page_hashes.iter().enumerate() {
        s.push_str(&format!("page {i:03} {h}\n"));
    }
    s.push_str(&format!("ring_artifact {ring_sha256}  {ring_path}\n"));
    s.push_str(&format!("final_manifest {manifest_sha256}\n"));
    for (rel, h) in tree_inventory {
        s.push_str(&format!("tree {h}  {rel}\n"));
    }
    s
}
