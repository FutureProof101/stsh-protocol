// =============================================================================
// R-10 item 1 — MAINNET_DEPLOYMENT.md's vetkeys reinstall loss-list, drift-locked
// =============================================================================
//
// The reinstall checklist used to name a hardcoded "MemoryIds 3-10" range that
// nothing re-checked; vetkeys had grown to 16 and the prose was six IDs short.
// This test ties the doc's marker-scoped range to the registry the lint crate
// already parses, so the two cannot drift apart silently again.
//
// Pure `std` — no `regex`, no new dependency (brief §3.1, invariant 5).

use std::collections::BTreeSet;
use verify_memory_ids::parse_registry;

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The set of vetkeys-owned (non-KeyManager) active MemoryIds, derived from
/// the registry — the same source scripts/verify_memory_ids already trusts.
fn vetkeys_owned_ids_from_registry(root: &std::path::Path) -> BTreeSet<u8> {
    let md = std::fs::read_to_string(root.join("docs/MEMORY_ID_REGISTRY.md")).unwrap();
    let cfg = parse_registry(&md).expect("registry must parse");
    let vk = cfg
        .canisters
        .iter()
        .find(|c| c.name == "vetkeys")
        .expect("vetkeys row set present");
    // 0-2 are KeyManager's, per docs/MEMORY_ID_REGISTRY.md's own rows/notes.
    vk.active.iter().copied().filter(|id| *id > 2).collect()
}

/// Finds a "MemoryId(s) <N> <sep> <M>" range (ASCII '-' or U+2013 en dash as
/// separator) inside `window`. Pure std char scanning — no regex, no
/// dev-dependency, no Cargo.lock question.
fn find_memoryid_range(window: &str) -> Option<(u8, u8)> {
    let start = window.find("MemoryId")?;
    let after = &window[start + "MemoryId".len()..];
    let after = after.strip_prefix('s').unwrap_or(after);

    // Both numbers must sit CLOSE to the "MemoryId" token: at most a few
    // separator characters before the low number and between the two. Without
    // this bound the scan happily scavenges an unrelated digit from later in
    // the 400-char window (e.g. "Layer 2", "(1) verify..."), so deleting the
    // range outright would still yield a spurious pair and the test would go
    // red for the wrong reason instead of reporting "no range stated".
    const MAX_GAP: usize = 4;

    let mut chars = after.char_indices().peekable();
    let take_number = |chars: &mut std::iter::Peekable<std::str::CharIndices>,
                       max_gap: usize|
     -> Option<u8> {
        let mut skipped = 0usize;
        while let Some(&(_, c)) = chars.peek() {
            if c.is_ascii_digit() {
                break;
            }
            if skipped == max_gap {
                return None;
            }
            skipped += 1;
            chars.next();
        }
        let mut digits = String::new();
        while let Some(&(_, c)) = chars.peek() {
            if !c.is_ascii_digit() {
                break;
            }
            digits.push(c);
            chars.next();
        }
        if digits.is_empty() {
            None
        } else {
            digits.parse().ok()
        }
    };

    let lo = take_number(&mut chars, MAX_GAP)?;
    // A separator must actually exist between the two numbers: if the very next
    // char were a digit the loop above would already have consumed it, so
    // peeking a non-digit here is the separator by construction.
    chars.peek()?;
    let hi = take_number(&mut chars, MAX_GAP)?;
    Some((lo, hi))
}

#[test]
fn test_mainnet_deployment_doc_states_the_full_vetkeys_range_matching_the_registry() {
    let root = repo_root();
    let doc = std::fs::read_to_string(root.join("MAINNET_DEPLOYMENT.md")).unwrap();
    let ids = vetkeys_owned_ids_from_registry(&root);
    let (lo, hi) = (*ids.iter().min().unwrap(), *ids.iter().max().unwrap());
    assert_eq!(
        ids,
        (lo..=hi).collect::<BTreeSet<_>>(),
        "registry's vetkeys ownership is expected contiguous 3..=N; if a gap is ever \
         introduced this test's range-check below is no longer valid and must be redesigned \
         before trusting it"
    );

    let marker = "<!-- MEMORY_ID_RANGE:vetkeys -->";
    let marker_at = doc.find(marker).expect(
        "MAINNET_DEPLOYMENT.md must carry the <!-- MEMORY_ID_RANGE:vetkeys --> marker \
         immediately before the reinstall loss-list parenthetical",
    );
    // Char-boundary-safe window (SSA A-4): never a raw byte slice on UTF-8 prose.
    let window: String = doc[marker_at..].chars().take(400).collect();

    // Form (a) — "no range stated at all" — is NOT accepted. The marker-scoped
    // window MUST state a range, and it must equal the registry's (lo, hi)
    // exactly. A doc that defers to the registry by name but never states a
    // number would otherwise pass this test forever.
    let (doc_lo, doc_hi) = find_memoryid_range(&window).expect(
        "MAINNET_DEPLOYMENT.md's marker-scoped window states no numeric MemoryId range — \
         it must state one, matching the registry's vetkeys ownership, so this test can \
         detect drift instead of passing on an empty claim",
    );
    assert_eq!(
        (doc_lo, doc_hi),
        (lo, hi),
        "MAINNET_DEPLOYMENT.md states vetkeys MemoryIds {doc_lo}-{doc_hi} but the \
         registry's vetkeys ownership (excluding KeyManager's 0-2) is actually \
         {lo}-{hi} — the checklist has drifted from the code/registry."
    );
}
