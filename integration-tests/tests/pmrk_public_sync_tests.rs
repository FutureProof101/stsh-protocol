// =============================================================================
// STSH Campaign B — P-MRK public-sync gate (PocketIC)
//
// The local mirror delegates Poseidon(2) to the repository-pinned circomlibjs
// reference implementation over a long-lived local Node process, not to any
// Rust Merkle implementation or parameter table. Parameter, zero, orientation,
// or depth drift therefore fails the differential gate.
//
// ── Law #7 prerequisites — ALL MANDATORY ─────────────────────────────────────
//
// Every input below is deliberately NOT committed. Each one is asserted at the
// point of use with the exact command that produces it, so a green run can
// never rest on undeclared local state (SSA P1).
//
//   1. Testing Wasm FIRST, then the production rebuild that overwrites it:
//        cargo build --target wasm32-unknown-unknown --release \
//          -p merkle_tree --features testing
//        cp target/wasm32-unknown-unknown/release/merkle_tree.wasm \
//           target/wasm32-unknown-unknown/release/merkle_tree_test.wasm
//        cargo build --target wasm32-unknown-unknown --release \
//          -p merkle_tree -p stsh_verifier
//      (plus the rest of the production set for the wider gate).
//
//   2. Node toolchain for BOTH independent references — the circomlibjs
//      Poseidon oracle and the snarkjs prover. `circuits/node_modules` is
//      untracked; `circuits/package-lock.json` is tracked, so this is exactly
//      reproducible from a clean checkout:
//        npm ci --prefix circuits
//
//   3. Circuit witness generator (untracked build output, regenerable):
//        npm --prefix circuits run compile
//      produces circuits/build/spend_js/spend.wasm.
//
//   4. Proving key circuits/build/spend_1.zkey — the M5 trusted-setup artifact
//      matching the COMMITTED circuits/verification_key.json (the same VK the
//      production verifier canister compiles in via include_str!). It is
//      deliberately NOT regenerable (circuits/package.json: "the production
//      ceremony (M5) is complete — do not regenerate artifacts") and NOT
//      committed; restore it from the ceremony artifact store. Override the
//      location with $SPEND_PROVING_KEY.
//
//   5. Pre-P-MRK BASE Wasm for the real upgrade test (SSA P2). Built from
//      ef635ce — the merged base this lane was cut from — in a throwaway
//      worktree so the active checkout is never disturbed:
//        git worktree add --detach /tmp/stsh-base-ef635ce ef635ce
//        cd /tmp/stsh-base-ef635ce
//        cargo build --target wasm32-unknown-unknown --release -p merkle_tree
//        cp target/wasm32-unknown-unknown/release/merkle_tree.wasm \
//           <workspace>/target/wasm32-unknown-unknown/release/merkle_tree_base_ef635ce.wasm
//      Override the location with $MERKLE_BASE_WASM. The Wasm is NOT committed.
// =============================================================================

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::thread;
use std::time::Duration;

const TREE_DEPTH: usize = 32;
const MAX_SCAN_PAGE_SIZE: u64 = 500;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
struct ScanHead {
    leaf_count: u64,
    root: Vec<u8>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
struct ScanPageEntry {
    index: u64,
    leaf: Vec<u8>,
    encrypted_payload: Vec<u8>,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("integration-tests must be inside the workspace")
        .to_owned()
}

fn read_wasm(path: PathBuf, label: &str) -> Vec<u8> {
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("Cannot read {label} Wasm at {}: {e}", path.display()))
}

fn merkle_prod_wasm() -> Vec<u8> {
    read_wasm(
        workspace_root().join("target/wasm32-unknown-unknown/release/merkle_tree.wasm"),
        "production merkle_tree",
    )
}

fn merkle_test_wasm() -> Vec<u8> {
    read_wasm(
        workspace_root().join("target/wasm32-unknown-unknown/release/merkle_tree_test.wasm"),
        "testing merkle_tree",
    )
}

fn verifier_wasm() -> Vec<u8> {
    read_wasm(
        workspace_root().join("target/wasm32-unknown-unknown/release/stsh_verifier.wasm"),
        "production verifier",
    )
}

fn circuits_dir() -> PathBuf {
    workspace_root().join("circuits")
}

/// Assert a deliberately-uncommitted gate input exists, naming the exact command
/// that produces it.
///
/// SSA P1: every Node, circuit, and ceremony artifact this suite consumes is
/// declared through this one door. A missing prerequisite fails loudly and
/// actionably instead of surfacing as an opaque downstream error — and the suite
/// never silently degrades to a weaker check when one is absent.
fn require_artifact(path: PathBuf, what: &str, how: &str) -> PathBuf {
    assert!(
        path.exists(),
        "Missing {what} at {}.\n\
         This is a MANDATORY P-MRK gate prerequisite (see the file header) — produce it with:\n  {how}",
        path.display()
    );
    path
}

/// Pre-P-MRK production Wasm, built from the `ef635ce` base this lane was cut
/// from. Not committed; see prerequisite 5 in the file header.
fn merkle_base_wasm() -> Vec<u8> {
    let default = workspace_root()
        .join("target/wasm32-unknown-unknown/release/merkle_tree_base_ef635ce.wasm");
    let how = format!(
        "git worktree add --detach /tmp/stsh-base-ef635ce ef635ce && \
         (cd /tmp/stsh-base-ef635ce && \
         cargo build --target wasm32-unknown-unknown --release -p merkle_tree) && \
         cp /tmp/stsh-base-ef635ce/target/wasm32-unknown-unknown/release/merkle_tree.wasm {}",
        default.display()
    );
    let path = require_artifact(
        std::env::var("MERKLE_BASE_WASM")
            .map(PathBuf::from)
            .unwrap_or(default),
        "the pre-P-MRK (ef635ce) base merkle_tree Wasm",
        &how,
    );
    read_wasm(path, "base merkle_tree")
}

/// Resolve `node` the same way for every Node-backed reference in this suite:
/// PATH first, then nvm, otherwise a hard failure.
const NODE_LAUNCHER: &str = "if command -v node >/dev/null 2>&1; then exec node \"$@\"; fi; \
     if [ -s \"$HOME/.nvm/nvm.sh\" ]; then . \"$HOME/.nvm/nvm.sh\"; exec node \"$@\"; fi; \
     echo 'node not found on PATH or via NVM' >&2; exit 127";

fn node_command() -> Command {
    let mut command = Command::new("bash");
    command
        .arg("-lc")
        .arg(NODE_LAUNCHER)
        .arg("node")
        .current_dir(workspace_root());
    command
}

/// `circuits/node_modules/circomlibjs` — the Poseidon reference the mirror is
/// defined against. Untracked, but exactly reproducible from the tracked
/// `circuits/package-lock.json`.
fn require_circomlibjs() {
    require_artifact(
        circuits_dir().join("node_modules/circomlibjs"),
        "the circomlibjs Poseidon reference (circuits/node_modules is not tracked)",
        "npm ci --prefix circuits",
    );
}

/// Convert a 32-byte little-endian field element to the canonical decimal string
/// circom inputs are written in.
fn le_bytes_to_decimal(bytes: &[u8; 32]) -> String {
    let mut digits: Vec<u8> = Vec::with_capacity(78);
    // Most-significant byte first: value = value * 256 + byte.
    for byte in bytes.iter().rev() {
        let mut carry = *byte as u32;
        for digit in digits.iter_mut() {
            let scaled = (*digit as u32) * 256 + carry;
            *digit = (scaled % 10) as u8;
            carry = scaled / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    if digits.is_empty() {
        return "0".to_string();
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

fn p(n: u8) -> Principal {
    let mut bytes = [0u8; 29];
    bytes[0] = n;
    Principal::from_slice(&bytes)
}

fn anon() -> Principal {
    Principal::anonymous()
}

fn fr(n: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&n.to_le_bytes());
    bytes
}

fn as32(label: &str, bytes: &[u8]) -> [u8; 32] {
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("{label} must be exactly 32 bytes, got {}", bytes.len()))
}

fn decode<T, E>(label: &str, call: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = call.unwrap_or_else(|e| panic!("{label}: call rejected: {e:?}"));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{label}: decode failed: {e}"))
}

fn install_merkle(pic: &PocketIc, pool: Principal, wasm: Vec<u8>) -> Principal {
    let canister = pic.create_canister();
    pic.add_cycles(canister, 5_000_000_000_000);
    pic.install_canister(
        canister,
        wasm,
        candid::encode_one(pool).expect("encode merkle init"),
        None,
    );
    canister
}

fn append(
    pic: &PocketIc,
    merkle: Principal,
    pool: Principal,
    leaf: [u8; 32],
    payload: Vec<u8>,
) -> Result<u64, String> {
    decode(
        "append_commitment",
        pic.update_call(
            merkle,
            pool,
            "append_commitment",
            candid::encode_args((leaf.to_vec(), payload)).expect("encode append"),
        ),
    )
}

fn scan_head(pic: &PocketIc, merkle: Principal) -> ScanHead {
    decode(
        "get_scan_head",
        pic.query_call(
            merkle,
            anon(),
            "get_scan_head",
            candid::encode_args(()).expect("encode empty args"),
        ),
    )
}

fn scan_page(
    pic: &PocketIc,
    merkle: Principal,
    from: u64,
    limit: u64,
) -> Result<Vec<ScanPageEntry>, String> {
    decode(
        "get_scan_page",
        pic.query_call(
            merkle,
            anon(),
            "get_scan_page",
            candid::encode_args((from, limit)).expect("encode page args"),
        ),
    )
}

fn get_root(pic: &PocketIc, merkle: Principal) -> Vec<u8> {
    decode(
        "get_root",
        pic.query_call(
            merkle,
            anon(),
            "get_root",
            candid::encode_args(()).expect("encode empty args"),
        ),
    )
}

fn get_leaf(pic: &PocketIc, merkle: Principal, index: u64) -> Option<Vec<u8>> {
    decode(
        "get_leaf",
        pic.query_call(
            merkle,
            anon(),
            "get_leaf",
            candid::encode_one(index).expect("encode leaf index"),
        ),
    )
}

fn remove_pair_member(
    pic: &PocketIc,
    merkle: Principal,
    pool: Principal,
    index: u64,
    remove_leaf: bool,
    remove_payload: bool,
) -> Result<(), String> {
    decode(
        "remove_scan_pair_member_for_test",
        pic.update_call(
            merkle,
            pool,
            "remove_scan_pair_member_for_test",
            candid::encode_args((index, remove_leaf, remove_payload))
                .expect("encode corruption args"),
        ),
    )
}

struct CircomlibPoseidon {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl CircomlibPoseidon {
    fn new() -> Self {
        const SCRIPT: &str = r#"
const readline = require("readline");
const { buildPoseidon } = require("./circuits/node_modules/circomlibjs");
function fromLe(hex) {
  const bytes = Buffer.from(hex, "hex");
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i]);
  return value;
}
function toLe(value) {
  const bytes = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes.toString("hex");
}
buildPoseidon().then((poseidon) => {
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on("line", (line) => {
    const [left, right] = line.trim().split(" ");
    const out = poseidon.F.toObject(poseidon([fromLe(left), fromLe(right)]));
    process.stdout.write(toLe(out) + "\n");
  });
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
"#;

        require_circomlibjs();
        let mut child = node_command()
            .arg("-e")
            .arg(SCRIPT)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn repo-pinned circomlibjs Poseidon oracle");
        let stdin = child.stdin.take().expect("capture Poseidon oracle stdin");
        let stdout = BufReader::new(child.stdout.take().expect("capture Poseidon oracle stdout"));
        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn hash(&mut self, left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        writeln!(self.stdin, "{} {}", hex_le(&left), hex_le(&right))
            .expect("write Poseidon request");
        self.stdin.flush().expect("flush Poseidon request");

        let mut line = String::new();
        self.stdout
            .read_line(&mut line)
            .expect("read Poseidon response");
        assert!(
            !line.is_empty(),
            "Poseidon oracle exited without a response"
        );
        decode_hex_le(line.trim())
    }
}

impl Drop for CircomlibPoseidon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn hex_le(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex_le(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "Poseidon output must be 32-byte hex");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .expect("Poseidon output must be valid hex");
    }
    out
}

struct LocalMirror {
    poseidon: CircomlibPoseidon,
    zero: [[u8; 32]; TREE_DEPTH + 1],
    nodes: BTreeMap<(usize, u64), [u8; 32]>,
    leaf_count: u64,
    root: [u8; 32],
}

impl LocalMirror {
    fn new() -> Self {
        let mut poseidon = CircomlibPoseidon::new();
        let mut zero = [[0u8; 32]; TREE_DEPTH + 1];
        zero[0] = poseidon.hash([0u8; 32], [0u8; 32]);
        for level in 1..=TREE_DEPTH {
            zero[level] = poseidon.hash(zero[level - 1], zero[level - 1]);
        }
        let root = zero[TREE_DEPTH];
        Self {
            poseidon,
            zero,
            nodes: BTreeMap::new(),
            leaf_count: 0,
            root,
        }
    }

    fn append(&mut self, leaf: [u8; 32]) -> u64 {
        let inserted_index = self.leaf_count;
        let mut index = inserted_index;
        let mut current = leaf;

        for level in 0..TREE_DEPTH {
            self.nodes.insert((level, index), current);
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            let sibling = self
                .nodes
                .get(&(level, sibling_index))
                .copied()
                .unwrap_or(self.zero[level]);
            current = if index % 2 == 0 {
                self.poseidon.hash(current, sibling)
            } else {
                self.poseidon.hash(sibling, current)
            };
            index /= 2;
        }

        self.leaf_count += 1;
        self.root = current;
        inserted_index
    }

    fn witness(&self, leaf_index: u64) -> (Vec<[u8; 32]>, Vec<u8>) {
        assert!(leaf_index < self.leaf_count, "witness leaf must exist");
        let mut index = leaf_index;
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut path_indices = Vec::with_capacity(TREE_DEPTH);
        for level in 0..TREE_DEPTH {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            siblings.push(
                self.nodes
                    .get(&(level, sibling_index))
                    .copied()
                    .unwrap_or(self.zero[level]),
            );
            path_indices.push((index % 2) as u8);
            index /= 2;
        }
        (siblings, path_indices)
    }

    fn root_from_witness(
        &mut self,
        leaf: [u8; 32],
        siblings: &[[u8; 32]],
        path_indices: &[u8],
    ) -> [u8; 32] {
        assert_eq!(siblings.len(), TREE_DEPTH);
        assert_eq!(path_indices.len(), TREE_DEPTH);
        siblings
            .iter()
            .zip(path_indices)
            .fold(leaf, |current, (sibling, direction)| match *direction {
                0 => self.poseidon.hash(current, *sibling),
                1 => self.poseidon.hash(*sibling, current),
                other => panic!("path index must be 0 or 1, got {other}"),
            })
    }
}

fn mirror_from_pages(
    pic: &PocketIc,
    merkle: Principal,
    page_size: u64,
) -> (LocalMirror, Vec<ScanPageEntry>) {
    assert!(page_size > 0 && page_size <= MAX_SCAN_PAGE_SIZE);
    let head = scan_head(pic, merkle);
    let mut mirror = LocalMirror::new();
    let mut entries = Vec::new();
    let mut from = 0u64;

    while from < head.leaf_count {
        let page = scan_page(pic, merkle, from, page_size)
            .unwrap_or_else(|e| panic!("scan page at {from} failed: {e}"));
        assert!(
            !page.is_empty(),
            "page before snapshotted tail must not be empty"
        );
        for entry in &page {
            assert_eq!(
                entry.index, from,
                "page stream must be dense across boundaries"
            );
            mirror.append(as32("page leaf", &entry.leaf));
            from += 1;
        }
        entries.extend(page);
    }

    assert_eq!(mirror.leaf_count, head.leaf_count);
    assert_eq!(mirror.root.to_vec(), head.root);
    (mirror, entries)
}

// ── Real proof generation from a mirror-derived witness (SSA P1) ─────────────

/// A Groth16 proof produced in-test from a caller-supplied witness — never a
/// pre-existing fixture.
#[derive(Debug)]
struct GeneratedProof {
    proof_json: String,
    public_json: String,
}

static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

/// Throwaway working directory for one proof, removed on drop.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "stsh-pmrk-{tag}-{}-{}",
            std::process::id(),
            SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create proof scratch dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_node(command: &mut Command, step: &str) -> Result<(), String> {
    let output = command
        .output()
        .unwrap_or_else(|e| panic!("cannot spawn Node for {step}: {e}"));
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{step} failed ({}):\n{}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

/// Build a spend-circuit input from the tracked canonical fixture, replacing the
/// anchor and the Merkle path with values that came exclusively from the public
/// scan mirror. Every other private signal is the fixture's, untouched — so the
/// only thing under test is the mirror-derived witness.
fn circuit_input_from_mirror(
    anchor: [u8; 32],
    siblings: &[[u8; 32]],
    path_indices: &[u8],
) -> String {
    let fixture = std::fs::read_to_string(circuits_dir().join("tests/test_input.json"))
        .expect("tracked canonical circuit fixture must exist");
    let mut input: serde_json::Value =
        serde_json::from_str(&fixture).expect("canonical fixture must be valid JSON");
    let object = input
        .as_object_mut()
        .expect("canonical fixture must be a JSON object");

    object.insert("anchor".into(), le_bytes_to_decimal(&anchor).into());
    object.insert(
        "path_elements".into(),
        siblings
            .iter()
            .map(|s| serde_json::Value::from(le_bytes_to_decimal(s)))
            .collect(),
    );
    object.insert(
        "path_indices".into(),
        path_indices
            .iter()
            .map(|d| serde_json::Value::from(d.to_string()))
            .collect(),
    );
    serde_json::to_string_pretty(&input).expect("serialize circuit input")
}

/// Generate a real Groth16 proof from a caller-supplied circuit input.
///
/// Witness generation is the load-bearing step. `spend.circom` constrains the
/// path to hash — under circomlib Poseidon, independent of any Rust code — to
/// the declared anchor, so a witness whose siblings or path indices are wrong
/// fails HERE and can never reach the prover. That is what binds the paged
/// mirror to the proof, rather than a root comparison made after the fact.
fn try_prove(input_json: &str, tag: &str) -> Result<GeneratedProof, String> {
    let witness_generator = require_artifact(
        circuits_dir().join("build/spend_js/spend.wasm"),
        "the compiled circuit witness generator",
        "npm ci --prefix circuits && npm --prefix circuits run compile",
    );
    let proving_key = require_artifact(
        std::env::var("SPEND_PROVING_KEY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| circuits_dir().join("build/spend_1.zkey")),
        "the M5 proving key matching the committed circuits/verification_key.json",
        "restore circuits/build/spend_1.zkey from the ceremony artifact store — it is NOT \
         regenerable (circuits/package.json pins the completed M5 setup)",
    );
    let snarkjs = require_artifact(
        circuits_dir().join("node_modules/.bin/snarkjs"),
        "the pinned snarkjs prover (circuits/node_modules is not tracked)",
        "npm ci --prefix circuits",
    );

    let scratch = ScratchDir::new(tag);
    let input_path = scratch.path().join("input.json");
    let witness_path = scratch.path().join("witness.wtns");
    let proof_path = scratch.path().join("proof.json");
    let public_path = scratch.path().join("public.json");
    std::fs::write(&input_path, input_json).expect("write circuit input");

    run_node(
        node_command()
            .current_dir(circuits_dir())
            .arg(circuits_dir().join("build/spend_js/generate_witness.js"))
            .arg(&witness_generator)
            .arg(&input_path)
            .arg(&witness_path),
        "witness generation",
    )?;
    run_node(
        node_command()
            .current_dir(circuits_dir())
            .arg(&snarkjs)
            .arg("groth16")
            .arg("prove")
            .arg(&proving_key)
            .arg(&witness_path)
            .arg(&proof_path)
            .arg(&public_path),
        "groth16 prove",
    )?;

    Ok(GeneratedProof {
        proof_json: std::fs::read_to_string(&proof_path).expect("read generated proof"),
        public_json: std::fs::read_to_string(&public_path).expect("read generated public signals"),
    })
}

fn prove(input_json: &str, tag: &str) -> GeneratedProof {
    try_prove(input_json, tag).unwrap_or_else(|e| panic!("proof generation must succeed: {e}"))
}

#[test]
fn page_stream_is_dense_capped_checked_and_leaf_exact() {
    let pic = PocketIc::new();
    let pool = p(0xA1);
    let merkle = install_merkle(&pic, pool, merkle_prod_wasm());

    let leaves: Vec<[u8; 32]> = (1..=9).map(fr).collect();
    let payloads: Vec<Vec<u8>> = (1..=9).map(|n| vec![0xE0, n as u8]).collect();
    for (index, (leaf, payload)) in leaves.iter().zip(&payloads).enumerate() {
        assert_eq!(
            append(&pic, merkle, pool, *leaf, payload.clone()),
            Ok(index as u64)
        );
    }

    let page = scan_page(&pic, merkle, 2, 5).expect("in-cap page must succeed");
    assert_eq!(page.len(), 5);
    for (offset, entry) in page.iter().enumerate() {
        let expected_index = 2 + offset as u64;
        assert_eq!(
            entry.index, expected_index,
            "indices must be dense and unique"
        );
        assert_eq!(entry.leaf, leaves[expected_index as usize]);
        assert_eq!(entry.encrypted_payload, payloads[expected_index as usize]);
        assert_eq!(
            Some(entry.leaf.clone()),
            get_leaf(&pic, merkle, expected_index),
            "page leaf must equal the actual stored commitment"
        );
    }

    let tail = scan_page(&pic, merkle, 7, 5).expect("tail page must succeed");
    assert_eq!(tail.iter().map(|e| e.index).collect::<Vec<_>>(), vec![7, 8]);
    assert!(scan_page(&pic, merkle, 9, 5).unwrap().is_empty());

    let over_cap = scan_page(&pic, merkle, 0, MAX_SCAN_PAGE_SIZE + 1)
        .expect_err("over-cap request must be rejected, never truncated");
    assert!(
        over_cap.contains("PageTooLarge"),
        "unexpected error: {over_cap}"
    );

    let overflow = scan_page(&pic, merkle, u64::MAX, 1)
        .expect_err("from + limit wrap must be rejected before range use");
    assert!(
        overflow.contains("RangeOverflow"),
        "unexpected error: {overflow}"
    );
}

#[test]
fn missing_leaf_or_payload_fails_the_entire_requested_page() {
    let pic = PocketIc::new();
    let pool = p(0xA2);
    let merkle = install_merkle(&pic, pool, merkle_test_wasm());
    for i in 0..3 {
        assert_eq!(append(&pic, merkle, pool, fr(i + 1), vec![i as u8]), Ok(i));
    }

    remove_pair_member(&pic, merkle, pool, 1, false, true).expect("test hook removes payload");
    let missing_payload =
        scan_page(&pic, merkle, 0, 3).expect_err("one missing payload must fail the whole page");
    assert!(
        missing_payload.contains("missing encrypted payload at index 1"),
        "unexpected error: {missing_payload}"
    );
    assert_eq!(
        scan_page(&pic, merkle, 0, 1)
            .expect("unaffected prefix remains readable")
            .len(),
        1
    );

    let pic2 = PocketIc::new();
    let pool2 = p(0xA3);
    let merkle2 = install_merkle(&pic2, pool2, merkle_test_wasm());
    for i in 0..2 {
        assert_eq!(
            append(&pic2, merkle2, pool2, fr(i + 10), vec![i as u8]),
            Ok(i)
        );
    }
    remove_pair_member(&pic2, merkle2, pool2, 0, true, false).expect("test hook removes leaf");
    let missing_leaf =
        scan_page(&pic2, merkle2, 0, 2).expect_err("one missing leaf must fail the whole page");
    assert!(
        missing_leaf.contains("missing commitment at index 0"),
        "unexpected error: {missing_leaf}"
    );

    let prod = install_merkle(&pic2, pool2, merkle_prod_wasm());
    let absent = pic2.update_call(
        prod,
        pool2,
        "remove_scan_pair_member_for_test",
        candid::encode_args((0u64, true, false)).unwrap(),
    );
    assert!(
        absent.is_err(),
        "test-only method must not exist in production Wasm"
    );
}

#[test]
fn scan_head_is_atomic_during_a_real_concurrent_append_race() {
    const APPENDS: u64 = 24;

    let pic = PocketIc::new();
    let pool = p(0xA4);
    let merkle = install_merkle(&pic, pool, merkle_prod_wasm());

    let leaves: Vec<[u8; 32]> = (1..=APPENDS).map(|n| fr(1_000 + n)).collect();
    let mut expected_mirror = LocalMirror::new();
    let mut expected_roots = vec![expected_mirror.root];
    for leaf in &leaves {
        expected_mirror.append(*leaf);
        expected_roots.push(expected_mirror.root);
    }

    let server_url = pic.get_server_url();
    let instance_id = pic.instance_id();
    let append_client = PocketIc::new_from_existing_instance(server_url.clone(), instance_id, None);
    let query_client = PocketIc::new_from_existing_instance(server_url, instance_id, None);
    let start = Arc::new(Barrier::new(2));
    let append_start = Arc::clone(&start);
    let (tx, rx) = mpsc::channel();

    let append_thread = thread::spawn(move || {
        append_start.wait();
        let mut results = Vec::new();
        for (i, leaf) in leaves.into_iter().enumerate() {
            results.push(append(&append_client, merkle, pool, leaf, vec![i as u8]));
            thread::sleep(Duration::from_millis(2));
        }
        tx.send(results).expect("send append results");
    });

    start.wait();
    let mut seen_counts = BTreeSet::new();
    let append_results = loop {
        let head = scan_head(&query_client, merkle);
        assert!(head.leaf_count <= APPENDS);
        assert_eq!(
            head.root, expected_roots[head.leaf_count as usize],
            "TORN HEAD: root does not belong to returned leaf_count {}",
            head.leaf_count
        );
        seen_counts.insert(head.leaf_count);

        match rx.try_recv() {
            Ok(results) => break results,
            Err(mpsc::TryRecvError::Empty) => thread::yield_now(),
            Err(mpsc::TryRecvError::Disconnected) => {
                panic!("append worker disconnected before reporting results")
            }
        }
    };
    append_thread.join().expect("append worker must not panic");

    for (i, result) in append_results.into_iter().enumerate() {
        assert_eq!(result, Ok(i as u64), "append {i} failed");
    }
    let final_head = scan_head(&pic, merkle);
    assert_eq!(final_head.leaf_count, APPENDS);
    assert_eq!(final_head.root, expected_roots[APPENDS as usize]);
    assert!(
        seen_counts.len() >= 2,
        "race must observe at least two coherent snapshots; saw {seen_counts:?}"
    );
}

#[test]
fn independently_paged_poseidon_mirror_matches_empty_and_multi_page_roots() {
    let pic = PocketIc::new();
    let pool = p(0xA5);
    let merkle = install_merkle(&pic, pool, merkle_prod_wasm());

    let empty_mirror = LocalMirror::new();
    let empty_head = scan_head(&pic, merkle);
    assert_eq!(empty_head.leaf_count, 0);
    assert_eq!(empty_head.root, empty_mirror.root);
    assert_eq!(empty_head.root, get_root(&pic, merkle));

    let leaves: Vec<[u8; 32]> = (1..=11).map(|n| fr(20_000 + n)).collect();
    for (i, leaf) in leaves.iter().enumerate() {
        assert_eq!(
            append(&pic, merkle, pool, *leaf, vec![0xB0, i as u8]),
            Ok(i as u64)
        );
    }

    // Page size 4 forces [0..4), [4..8), [8..11): two boundaries.
    let (mut mirror, entries) = mirror_from_pages(&pic, merkle, 4);
    assert_eq!(entries.len(), leaves.len());
    assert_eq!(mirror.root.to_vec(), get_root(&pic, merkle));
    assert_eq!(
        entries.iter().map(|e| e.index).collect::<Vec<_>>(),
        (0..leaves.len() as u64).collect::<Vec<_>>()
    );

    let witness_index = 7u64;
    let (siblings, directions) = mirror.witness(witness_index);
    assert!(directions.contains(&0) && directions.contains(&1));
    assert_eq!(
        mirror.root_from_witness(
            as32("witness leaf", &entries[witness_index as usize].leaf),
            &siblings,
            &directions,
        ),
        mirror.root
    );
}

// =============================================================================
// ef635ce → converted: the upgrade path is now CLOSED BY DESIGN
// =============================================================================
//
// COVERAGE-SHAPE CHANGE (approved by Architect, 2026-07-28). This replaces the
// former `scan_state_survives_the_real_ef635ce_to_p_mrk_upgrade`, whose premise
// was that the real historical ef635ce binary could be upgraded to current and
// its scan state read back through the new surface.
//
// The upgrade-persistence hardening Phase 1 conversion makes that upgrade TRAP:
// merkle-tree's canister ref now lives in an eager cell at MemoryId 5, which
// ef635ce never allocated, so the region is fresh, the sentinel survives
// `Cell::init`, and `post_upgrade` refuses to run. That is intended fail-closed
// behaviour, not a regression — nothing is on mainnet, so there is no legacy
// state to migrate, and silently resetting POOL_CANISTER to None would be far
// worse than a blocked upgrade.
//
// The historical ef635ce→P-MRK DATA MIGRATION is therefore permanently
// unreachable and cannot be tested any more. Rather than delete the coverage,
// it is split in two and both halves are strengthened:
//
//   1. the real ef635ce artifact is still installed and still written to, and
//      we now prove the upgrade fails CLOSED on the sentinel *and* that the
//      trap rolls back atomically — the old binary keeps serving its data;
//   2. the survival property itself ("scan state, including interior tree
//      nodes, survives an upgrade") is re-proved across a genuine cross-Wasm
//      upgrade between two converted modules, with the same decisive
//      independent-mirror root check as before.

#[test]
fn ef635ce_to_converted_upgrade_fails_closed_and_rolls_back_atomically() {
    let pic = PocketIc::new();
    let pool = p(0xA6);

    // The ACTUAL pre-P-MRK, pre-conversion binary — not a same-Wasm stand-in.
    let merkle = install_merkle(&pic, pool, merkle_base_wasm());
    assert!(
        pic.query_call(
            merkle,
            anon(),
            "get_scan_head",
            candid::encode_args(()).expect("encode empty args"),
        )
        .is_err(),
        "base Wasm already exports get_scan_head — that is not the ef635ce artifact, \
         and this test would silently degenerate into a same-Wasm upgrade"
    );

    let leaves: Vec<[u8; 32]> = (0..7u64).map(|i| fr(30_000 + i)).collect();
    let payloads: Vec<Vec<u8>> = (0..7u64).map(|i| vec![0xC0, i as u8]).collect();
    for (i, (leaf, payload)) in leaves.iter().zip(&payloads).enumerate() {
        assert_eq!(
            append(&pic, merkle, pool, *leaf, payload.clone()),
            Ok(i as u64)
        );
    }
    let before_root = get_root(&pic, merkle);

    // Clear the install_code rate limiter. Merkle's init builds 33 Poseidon
    // zero-values, which throttles the NEXT install_code message into a
    // SysTransient `CanisterInstallCodeRateLimited` reject — post_upgrade never
    // runs at all. Without this, the assertion below would "pass" on the wrong
    // error and prove nothing. (This is a real false-green that was observed
    // during Phase 1; it is why the trap MESSAGE is asserted, never just failure.)
    pic.advance_time(std::time::Duration::from_secs(600));
    for _ in 0..2 {
        pic.tick();
    }

    let err = pic
        .upgrade_canister(
            merkle,
            merkle_prod_wasm(),
            candid::encode_args(()).expect("encode upgrade args"),
            None,
        )
        .expect_err(
            "ef635ce -> converted MUST fail closed: the eager cell at MemoryId 5 is absent, \
             so the sentinel survives. A success here means the fail-closed gate is broken.",
        );
    let msg = format!("{err:?}");
    assert!(
        msg.contains("POOL_REF sentinel survived"),
        "must trap on the SENTINEL specifically — a transient reject (e.g. \
         CanisterInstallCodeRateLimited) would mean post_upgrade never ran and this test \
         proved nothing. Got: {msg}"
    );

    // ATOMIC ROLLBACK: a trapping post_upgrade aborts the upgrade, so the OLD
    // module must still be installed and still serving its data intact.
    assert_eq!(
        get_root(&pic, merkle),
        before_root,
        "the failed upgrade must roll back atomically — root changed"
    );
    assert_eq!(
        append(&pic, merkle, pool, fr(39_999), vec![0xEE]),
        Ok(leaves.len() as u64),
        "the old module must still accept appends after the aborted upgrade"
    );
}

#[test]
fn scan_state_survives_a_cross_wasm_upgrade() {
    let pic = PocketIc::new();
    let pool = p(0xA7);

    // Converted production module in, converted TESTING module out. Two
    // genuinely different binaries — a same-Wasm upgrade would not establish
    // that state survives a code change.
    let merkle = install_merkle(&pic, pool, merkle_prod_wasm());

    let leaves: Vec<[u8; 32]> = (0..7u64).map(|i| fr(30_000 + i)).collect();
    let payloads: Vec<Vec<u8>> = (0..7u64).map(|i| vec![0xC0, i as u8]).collect();
    for (i, (leaf, payload)) in leaves.iter().zip(&payloads).enumerate() {
        assert_eq!(
            append(&pic, merkle, pool, *leaf, payload.clone()),
            Ok(i as u64)
        );
    }
    let before_root = get_root(&pic, merkle);

    pic.advance_time(std::time::Duration::from_secs(600));
    for _ in 0..2 {
        pic.tick();
    }

    pic.upgrade_canister(
        merkle,
        merkle_test_wasm(),
        candid::encode_args(()).expect("encode upgrade args"),
        None,
    )
    .expect("legitimate retained state must upgrade cleanly across modules");

    // Everything written before the upgrade must read back through the new module.
    assert_eq!(get_root(&pic, merkle), before_root, "root changed on upgrade");
    let head = scan_head(&pic, merkle);
    assert_eq!(head.leaf_count, leaves.len() as u64);
    assert_eq!(head.root, before_root);

    let page = scan_page(&pic, merkle, 0, MAX_SCAN_PAGE_SIZE).expect("post-upgrade page");
    assert_eq!(
        page.iter().map(|e| e.index).collect::<Vec<_>>(),
        (0..leaves.len() as u64).collect::<Vec<_>>()
    );
    for (i, entry) in page.iter().enumerate() {
        assert_eq!(entry.leaf, leaves[i], "leaf {i} differs after upgrade");
        assert_eq!(entry.encrypted_payload, payloads[i], "payload {i} differs after upgrade");
    }

    // Reconstruct the tree independently from the paged public data.
    let (mut mirror, entries) = mirror_from_pages(&pic, merkle, 4);
    assert_eq!(entries.len(), leaves.len());

    // The decisive check (SSA P2, preserved verbatim): the next append must
    // produce the ROOT the independent mirror predicts, not merely the next
    // index. A TREE_NODES structure that survived only partially — or was
    // remapped — still yields the right index while hashing to the wrong root.
    let next_leaf = fr(40_000);
    let expected_index = mirror.append(next_leaf);
    assert_eq!(
        append(&pic, merkle, pool, next_leaf, vec![0xDD]),
        Ok(expected_index)
    );
    assert_eq!(
        get_root(&pic, merkle),
        mirror.root.to_vec(),
        "post-upgrade append root diverged from the independent Poseidon mirror — \
         interior tree state did not survive the upgrade intact"
    );
    assert_eq!(
        scan_head(&pic, merkle),
        ScanHead {
            leaf_count: mirror.leaf_count,
            root: mirror.root.to_vec(),
        }
    );
}

/// Canonical input commitment for `circuits/tests/test_input.json`. Every other
/// private signal is taken from that tracked fixture untouched; only the anchor
/// and the Merkle path are supplied by the mirror.
/// A-3 FINALIZE regen (2026-09-12): the DOMAIN_POOL_CANISTER_ID re-encode to
/// cxrfg-qaaaa-aaaar-qchfa-cai moved domain_sep and therefore this commitment.
/// Regenerate via `node circuits/tests/gen_test_input.js`.
const INPUT_COMMITMENT: [u8; 32] = [
    0xd2, 0x6f, 0x9b, 0xb7, 0x36, 0x0a, 0xed, 0x7f, 0x09, 0x18, 0xe7, 0x27, 0x12, 0x3c, 0x86, 0x90,
    0xe2, 0x71, 0xb0, 0x5b, 0x6c, 0xb4, 0x52, 0xfc, 0x6f, 0x05, 0x3a, 0xd4, 0xa1, 0x18, 0xdc, 0x0b,
];

/// Deposit the canonical note and return the mirror rebuilt purely from the
/// public scan pages.
fn mirror_with_canonical_note(pic: &PocketIc, pool: Principal) -> LocalMirror {
    let merkle = install_merkle(pic, pool, merkle_prod_wasm());
    let input_leaf = stsh_field_utils::merkle_leaf(100_000_000_000, &INPUT_COMMITMENT);
    assert_eq!(
        append(pic, merkle, pool, input_leaf, vec![0x02, 0xCA, 0xFE]),
        Ok(0)
    );

    // Leaf, siblings and path indices come exclusively from the public scan API.
    let (mirror, entries) = mirror_from_pages(pic, merkle, 1);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        as32("scanned leaf", &entries[0].leaf),
        input_leaf,
        "the scanned leaf must be the commitment that was deposited"
    );
    assert_eq!(mirror.root.to_vec(), get_root(pic, merkle));
    mirror
}

#[test]
fn proof_generated_from_the_mirror_witness_verifies_in_the_production_verifier() {
    let pic = PocketIc::new();
    let pool = p(0xA7);
    let mirror = mirror_with_canonical_note(&pic, pool);
    let (siblings, directions) = mirror.witness(0);
    assert_eq!(siblings.len(), TREE_DEPTH);

    // SSA P1: GENERATE the proof from the mirror-produced siblings and path
    // indices. spend.circom constrains the path to hash to the declared anchor,
    // so a mirror that drifted in parameters, zeros, orientation or depth fails
    // at witness generation and never yields a proof at all.
    let generated = prove(
        &circuit_input_from_mirror(mirror.root, &siblings, &directions),
        "mirror-witness",
    );

    let proof_bytes = stsh_verifier::proof_json_to_bytes(&generated.proof_json)
        .expect("encode generated proof");
    let signals = stsh_verifier::public_json_to_signals(&generated.public_json)
        .expect("parse generated public signals");
    assert_eq!(
        signals[0], mirror.root,
        "the generated proof must be anchored at the mirror root"
    );

    // The mirror-derived witness must also reproduce the tracked canonical
    // signals bit-for-bit — public.json is deterministic even though the proof
    // itself is randomised.
    let canonical_public = std::fs::read_to_string(circuits_dir().join("public.json"))
        .expect("tracked canonical public-signal fixture must exist");
    let canonical = stsh_verifier::public_json_to_signals(&canonical_public)
        .expect("parse canonical public signals");
    assert_eq!(
        signals, canonical,
        "mirror-derived witness produced different public signals than the canonical fixture"
    );

    // Verify through the real production verifier Wasm, never a host stub.
    let verifier = pic.create_canister();
    pic.add_cycles(verifier, 100_000_000_000_000);
    pic.install_canister(
        verifier,
        verifier_wasm(),
        candid::encode_one(pool).expect("encode verifier init"),
        None,
    );
    let signal_vecs = signals.iter().map(|s| s.to_vec()).collect::<Vec<_>>();
    let verified: Result<(), String> = decode(
        "verify_spend_canister",
        pic.update_call(
            verifier,
            pool,
            "verify_spend_canister",
            candid::encode_args((proof_bytes, signal_vecs)).expect("encode verifier call"),
        ),
    );
    assert_eq!(
        verified,
        Ok(()),
        "proof built from the paged mirror witness must verify"
    );
}

#[test]
fn a_witness_that_drifts_from_the_mirror_cannot_produce_a_proof() {
    // Guards the gate above: if a wrong path could still produce a verifying
    // proof, the positive test would prove nothing about the mirror.
    let pic = PocketIc::new();
    let pool = p(0xA8);
    let mirror = mirror_with_canonical_note(&pic, pool);
    let (siblings, directions) = mirror.witness(0);

    let mut corrupted = siblings.clone();
    corrupted[5][0] ^= 0x01;
    let error = try_prove(
        &circuit_input_from_mirror(mirror.root, &corrupted, &directions),
        "drifted-sibling",
    )
    .expect_err("a sibling inconsistent with the anchor must not yield a proof");
    assert!(
        error.contains("witness generation"),
        "expected the circuit's anchor constraint to reject the witness, got: {error}"
    );

    // Same for a flipped path index: orientation drift must be caught too.
    let mut flipped = directions.clone();
    flipped[0] ^= 1;
    let error = try_prove(
        &circuit_input_from_mirror(mirror.root, &siblings, &flipped),
        "drifted-orientation",
    )
    .expect_err("a flipped path index must not yield a proof");
    assert!(
        error.contains("witness generation"),
        "expected the circuit's anchor constraint to reject the witness, got: {error}"
    );
}
