// §P.2 — the authenticated D5 exporter.
//
//   export_creation_receipts \
//       --ceremony-source-sha <40-hex>   \  # the reviewed post-§P commit
//       --clone <path>                   \  # clean immutable clone at that SHA
//       --out <new scratch dir>          \  # MUST NOT already exist
//       [--vault <principal> --network <net> --identity <signer>]  # live mode
//       [--replay <dir>]                    # re-verify recorded raw pages
//
// LIVE MODE reads `get_creation_receipts` from the Vault through `dfx`, under
// a SIGNER identity. REPLAY MODE re-runs every rule over raw pages recorded by
// an earlier run; the mode is stamped into the inventory (and so into the root
// hash), because a replay carries no live authentication and must never be
// substituted for an export.
//
// The exporter is deliberately NOT a canister client library: the transport is
// `dfx`, so this tool adds no dependency to the workspace and therefore cannot
// move `Cargo.lock` — a production build input whose modification would disarm
// the release tripwire.
//
// Exit 0 = a complete ceremony root was written. Exit 1 = a typed STOP; NOTHING
// is rendered and no partial manifest is emitted. Exit 2 = usage.

use std::path::PathBuf;
use std::process::ExitCode;
use verify_custody_manifest::finalize;
use verify_custody_manifest::export::{
    self, AcquiredPage, ExportError, PageSource, PINNED_PAGE_LIMIT,
};

/// Live transport: one `dfx canister call` per page, under the signer identity.
struct DfxPageSource {
    vault: String,
    network: String,
    identity: String,
}

impl PageSource for DfxPageSource {
    fn fetch(&mut self, cursor: Option<u64>, limit: u32) -> Result<String, ExportError> {
        let arg = match cursor {
            None => format!("(null, {limit} : nat32)"),
            Some(c) => format!("(opt ({c} : nat64), {limit} : nat32)"),
        };
        let out = std::process::Command::new("dfx")
            .args([
                "canister",
                "call",
                "--query",
                "--network",
                &self.network,
                "--identity",
                &self.identity,
                &self.vault,
                "get_creation_receipts",
                &arg,
            ])
            // The signer identity is an ENCRYPTED pem: dfx prompts for the
            // passphrase on the controlling terminal. `.output()` would hand
            // the child a null stdin and a captured stderr, and dfx then fails
            // with "not a terminal" (J-18, 2026-09-12). Inherit both; only
            // stdout — the Candid page — is captured.
            .stdin(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::piped())
            .output()
            .map_err(|e| ExportError::TransportFailure {
                detail: format!("cannot run dfx: {e}"),
            })?;
        if !out.status.success() {
            return Err(ExportError::TransportFailure {
                detail: format!(
                    "dfx canister call failed at cursor {cursor:?} (exit {}); dfx's own \
                     diagnostic was written to stderr above",
                    out.status
                ),
            });
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }
}

/// Replay transport: raw pages recorded by an earlier run, in cursor order.
struct FilePageSource {
    pages: Vec<String>,
    at: usize,
}

impl PageSource for FilePageSource {
    fn fetch(&mut self, cursor: Option<u64>, _limit: u32) -> Result<String, ExportError> {
        let p = self.pages.get(self.at).cloned().ok_or(ExportError::TruncatedWalk {
            // The recorded set ran out while the walk still wanted a page: the
            // recording is short. Reported as truncation, never as completion.
            last_next_cursor: cursor.unwrap_or_default(),
        })?;
        self.at += 1;
        Ok(p)
    }
}

fn usage(msg: &str) -> ExitCode {
    eprintln!("export_creation_receipts: {msg}\n\n{}", USAGE);
    ExitCode::from(2)
}

const USAGE: &str = "\
usage: export_creation_receipts --ceremony-source-sha <40-hex> --clone <path> --out <new dir>
                               ( --vault <principal> --network <net> --identity <signer>
                               | --replay <dir> )

       export_creation_receipts --finalize-assemble
                               --ceremony-source-sha <40-hex> --clone <path>
                               --export-root <dir>
                               --export-mode <mode> --export-root-sha256 <64-hex>
                               --ring-artifact <file>
                               --wasm-dir <dir> --out <new dir>

       --export-mode and --export-root-sha256 are the `mode` and the
       `ceremony root sha256` the export phase PRINTED, taken from the filed §P
       transcript. They are attested from outside the export root because
       nothing inside it can authenticate its own mode line.";

fn main() -> ExitCode {
    let mut sha = String::new();
    let mut clone = PathBuf::new();
    let mut out = PathBuf::new();
    let mut vault = String::new();
    let mut network = String::new();
    let mut identity = String::new();
    let mut replay: Option<PathBuf> = None;
    // §Q. A FLAG, not a subcommand: the export phase's command line is already
    // reviewed and appears verbatim in the filed §P evidence transcript, and a
    // subcommand would change every existing invocation — including the ones
    // that transcript attests. The flag leaves the export phase byte-identical
    // and adds the new phase beside it.
    let mut finalize_assemble = false;
    let mut export_root = PathBuf::new();
    let mut export_mode = String::new();
    let mut export_root_sha256 = String::new();
    let mut ring_artifact = PathBuf::new();
    let mut wasm_dir = PathBuf::new();

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().unwrap_or_default();
        match a.as_str() {
            "--ceremony-source-sha" => sha = val(),
            "--clone" => clone = PathBuf::from(val()),
            "--out" => out = PathBuf::from(val()),
            "--vault" => vault = val(),
            "--network" => network = val(),
            "--identity" => identity = val(),
            "--replay" => replay = Some(PathBuf::from(val())),
            "--finalize-assemble" => finalize_assemble = true,
            "--export-root" => export_root = PathBuf::from(val()),
            "--export-mode" => export_mode = val(),
            "--export-root-sha256" => export_root_sha256 = val(),
            "--ring-artifact" => ring_artifact = PathBuf::from(val()),
            "--wasm-dir" => wasm_dir = PathBuf::from(val()),
            other => return usage(&format!("unknown argument `{other}`")),
        }
    }
    if sha.is_empty() || clone.as_os_str().is_empty() || out.as_os_str().is_empty() {
        return usage("--ceremony-source-sha, --clone and --out are all required");
    }

    // ── §Q: finalize + assemble ──────────────────────────────────────────────
    if finalize_assemble {
        if !vault.is_empty()
            || !network.is_empty()
            || !identity.is_empty()
            || replay.is_some()
        {
            return usage("--finalize-assemble takes neither the live flags nor --replay");
        }
        for (name, p) in [
            ("--export-root", &export_root),
            ("--ring-artifact", &ring_artifact),
            ("--wasm-dir", &wasm_dir),
        ] {
            if p.as_os_str().is_empty() {
                return usage(&format!("--finalize-assemble requires {name}"));
            }
        }
        // The §P attestation is REQUIRED, not defaulted. A default would mean
        // the tool believing the export root's own account of itself, which is
        // exactly the relabelling path this closes.
        if export_mode.trim().is_empty() {
            return usage("--finalize-assemble requires --export-mode (from the §P transcript)");
        }
        if export_root_sha256.trim().len() != 64
            || !export_root_sha256.trim().chars().all(|c| c.is_ascii_hexdigit())
        {
            return usage(
                "--finalize-assemble requires --export-root-sha256 as a 64-hex sha256 (the \
                 `ceremony root sha256` the export phase printed)",
            );
        }
        let inputs = finalize::FinalizeInputs {
            ceremony_source_sha: sha.clone(),
            clone: clone.clone(),
            export_root,
            export_attestation: finalize::ExportAttestation {
                mode: export_mode.trim().to_string(),
                root_sha256: export_root_sha256.trim().to_string(),
            },
            ring_artifact,
            wasm_dir,
            out: out.clone(),
        };
        return match finalize::finalize_and_assemble(&inputs) {
            Ok(o) => {
                println!("mode                   {}", finalize::FINALIZE_MODE);
                println!("export_mode (attested) {}", o.export_mode);
                println!("ceremony_source_sha    {}", o.ceremony_source_sha);
                println!("verification tree      {}", o.tree.display());
                for (i, h) in o.page_hashes.iter().enumerate() {
                    println!("page {i:03}               {h}");
                }
                println!("ring artifact          {}  {}", o.ring_sha256, o.ring_path);
                for (rel, h) in &o.tree_inventory {
                    println!("tree artifact          {h}  {rel}");
                }
                println!("final manifest sha256  {}", o.manifest_sha256);
                println!("ceremony root sha256   {}", o.root_sha256);
                println!();
                println!(
                    "next: verify_custody_manifest --deploy-time {}",
                    o.tree.display()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("export_creation_receipts: {e}");
                ExitCode::from(1)
            }
        };
    }
    // The §Q-only flags belong to the §Q phase. Accepting them silently in the
    // export phase would let an operator believe an attestation was checked
    // when nothing read it.
    if !export_root.as_os_str().is_empty()
        || !export_mode.is_empty()
        || !export_root_sha256.is_empty()
        || !ring_artifact.as_os_str().is_empty()
        || !wasm_dir.as_os_str().is_empty()
    {
        return usage("--export-root/--export-mode/--export-root-sha256/--ring-artifact/--wasm-dir require --finalize-assemble");
    }
    let live = !vault.is_empty() || !network.is_empty() || !identity.is_empty();
    if live && replay.is_some() {
        return usage("--replay and the live flags are mutually exclusive");
    }
    if live && (vault.is_empty() || network.is_empty() || identity.is_empty()) {
        return usage("live mode requires --vault, --network AND --identity together");
    }
    if !live && replay.is_none() {
        return usage("choose live mode (--vault/--network/--identity) or --replay <dir>");
    }

    // The clone is verified BEFORE any read: a root that is not the declared
    // reviewed commit, or is not clean, invalidates everything downstream.
    if let Err(e) = export::verify_source_clone(&clone, &sha) {
        eprintln!("export_creation_receipts: {e}");
        return ExitCode::from(1);
    }

    let (mode, pages): (&str, Result<Vec<AcquiredPage>, ExportError>) = match &replay {
        Some(dir) => {
            let mut raw: Vec<(String, String)> = match std::fs::read_dir(dir) {
                Ok(rd) => rd
                    .filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| p.to_string_lossy().ends_with(".raw.candid"))
                    .filter_map(|p| {
                        let name = p.file_name()?.to_string_lossy().to_string();
                        Some((name, std::fs::read_to_string(&p).ok()?))
                    })
                    .collect(),
                Err(e) => {
                    eprintln!("export_creation_receipts: cannot read {}: {e}", dir.display());
                    return ExitCode::from(1);
                }
            };
            // Names are zero-padded, so lexical order IS cursor order — and
            // verify_sequence re-checks the cursor chain regardless.
            raw.sort();
            let mut src = FilePageSource {
                pages: raw.into_iter().map(|(_, body)| body).collect(),
                at: 0,
            };
            ("replay", export::walk(&mut src, PINNED_PAGE_LIMIT))
        }
        None => {
            let mut src = DfxPageSource {
                vault,
                network,
                identity,
            };
            ("authenticated-export", export::walk(&mut src, PINNED_PAGE_LIMIT))
        }
    };

    let pages = match pages {
        Ok(p) => p,
        Err(e) => {
            eprintln!("export_creation_receipts: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = export::verify_sequence(&pages) {
        eprintln!("export_creation_receipts: {e}");
        return ExitCode::from(1);
    }
    let receipts = match export::validate_receipts(&pages) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("export_creation_receipts: {e}");
            return ExitCode::from(1);
        }
    };

    // The manifest template comes from the IMMUTABLE CLONE, never from the
    // working tree the operator happens to be standing in.
    let template_path = clone.join("deployment/mainnet/custody_manifest.toml");
    let template = match std::fs::read_to_string(&template_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "export_creation_receipts: cannot read {}: {e}",
                template_path.display()
            );
            return ExitCode::from(1);
        }
    };
    let rendered = match export::render_manifest(&template, &receipts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("export_creation_receipts: {e}");
            return ExitCode::from(1);
        }
    };

    match export::write_ceremony_root(&out, mode, &sha, &pages, &rendered) {
        Ok(root) => {
            println!("mode                   {mode}");
            println!("ceremony_source_sha    {sha}");
            println!("pages                  {}", pages.len());
            println!("bound receipts         {}", receipts.len());
            for (name, hash) in &root.inventory {
                println!("artifact               {hash}  {name}");
            }
            println!("output manifest sha256 {}", root.manifest_sha256);
            println!("ceremony root sha256   {}", root.inventory_sha256);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("export_creation_receipts: {e}");
            ExitCode::from(1)
        }
    }
}
