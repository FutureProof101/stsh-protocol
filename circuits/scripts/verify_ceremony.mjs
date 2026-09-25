#!/usr/bin/env node
/**
 * verify_ceremony.mjs — A-3 PREP: the ceremony acceptance-evidence checker.
 *
 * This is the executable form of the SSA/A1 acceptance-evidence list. It is the
 * check that decides whether F6-1 is CLOSED — not "a ceremony ran again".
 *
 * Checks (each independently reported; any FAIL fails the run):
 *   C1  ptau is production-grade: EITHER its sha256 AND its blake2b-512 BOTH match
 *       one pinned, authoritative public-ceremony entry, OR the self-run path is
 *       fully evidenced — >=
 *       MIN_PTAU_CONTRIBUTIONS contributions AND a STRUCTURAL beacon (snarkjs
 *       contribution type == 1, not a contribution merely NAMED "beacon") AND a
 *       fully-populated self_run_evidence record (contributor identities,
 *       contribution hashes, beacon source/value/hashes, recorded manual
 *       independence approval) that AGREES with what the file actually contains.
 *   C2  ptau power — read from the ptau BINARY HEADER, not the manifest — is large
 *       enough for the circuit's constraint count; a misdeclared manifest power is
 *       itself a failure.
 *   C3  final zkey verifies against BOTH the final R1CS AND the chosen ptau.
 *   C4  zkey phase-2 contributions: count AND every contributor name must be
 *       recorded in the manifest and match what is observed in the zkey. An absent
 *       record is a FAIL, not an implicit agreement.
 *   C5  exported VK sha256 matches the manifest pin.
 *   C6  the production zkey hashes to its manifest pin, the two manifest path fields
 *       naming it agree, no artifact tagged STALE_* shares its hash, and a
 *       declared-stale artifact that is MISSING fails unless explicitly marked
 *       ALLOW_ABSENT (a silent skip would let a rename erase the evidence).
 *
 * Usage:
 *   node circuits/scripts/verify_ceremony.mjs --generation m5    # baseline; C1 FAILS by design (F6-1 open)
 *   node circuits/scripts/verify_ceremony.mjs --generation next  # A6.7 runs this; must be all-GREEN
 *   node circuits/scripts/verify_ceremony.mjs --generation m5 --transcript out.txt
 *
 * Exit codes: 0 all checks pass · 1 a check failed · 2 usage/prerequisite error.
 *
 * NOTE ON PINNED PUBLIC-CEREMONY HASHES. A hash for a public powers-of-tau file
 * must be taken from the authoritative PUBLISHER at the time the file is fetched,
 * and pinned here in the same change that fetches it. Populating the allowlist
 * from memory or from an untrusted mirror would defeat the entire purpose of the
 * check, so the tool fails closed on anything it cannot match.
 *
 * TWO HASHES, BOTH BINDING. The publisher of the Hermez `powersOfTau28_hez_final_*`
 * series (the snarkjs/iden3 README powers-of-tau table) attests **blake2b-512**,
 * not sha256 — so an allowlist keyed on sha256 alone can only ever carry a
 * LOCALLY COMPUTED digest, which is provenance for nothing. Each entry therefore
 * carries BOTH `sha256` and `blake2b`, and C1 requires BOTH to match the file on
 * disk. `blake2b` is the publisher-attested value and is what actually binds the
 * file to the ceremony; `sha256` is the second, independent digest.
 *
 * A file matching one field but not the other is a HARD FAIL with its own message
 * — it is never allowed to fall through to the self-run branch, because a
 * half-match means the pin and the file disagree and one of them is wrong.
 *
 * `source` is the URL the bytes were DOWNLOADED from. It is a mirror, NOT an
 * attestation: the canonical Hermez/zkevm buckets stopped serving anonymous reads
 * (403) in 2026-09, so the bytes and the attestation now come from different
 * places on purpose. `attestation` is the published hash list; that is the only
 * field that establishes provenance.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const CIRCUITS = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST = resolve(CIRCUITS, "ceremony/domain_manifest.json");

/** Minimum independent contributions for a self-run multi-party ptau (path (b)). */
const MIN_PTAU_CONTRIBUTIONS = 3;

/**
 * Authoritative public powers-of-tau files. See the "TWO HASHES, BOTH BINDING"
 * note in the header: `blake2b` is the publisher-attested digest and `sha256` is
 * the independent second digest; C1 requires BOTH.
 *
 * Add an entry ONLY in the same change that fetches the file, with `blake2b`
 * transcribed from the publisher's own hash list and `attestation` /
 * `attestation_retrieved` recording where and when it was read.
 */
const PUBLIC_PTAU_ALLOWLIST = [
  {
    name: "powersOfTau28_hez_final_15",
    power: 15,
    // PUBLISHER-ATTESTED. snarkjs (iden3) README powers-of-tau table, row power=15,
    // header "Prepared (phase2) Ptau files for bn128 with 54 contributions and a beacon".
    blake2b:
      "982372c867d229c236091f767e703253249a9b432c1710b4f326306bfa2428a1" +
      "7b06240359606cfe4d580b10a5a1f63fbed499527069c18ae17060472969ae6e",
    // Second, independent digest. Computed locally from the downloaded bytes AND
    // independently published by GitHub LFS as this object's oid (git-lfs oids are
    // sha256), so it is confirmed by a party other than iden3.
    sha256: "3ef2ecc5b75d687048cf2d59195119b42fb07c5af639c5f283d84bfa69829e7f",
    size_bytes: 37831832,
    attestation: "https://raw.githubusercontent.com/iden3/snarkjs/master/README.md",
    attestation_kind:
      "blake2b-512 published by the snarkjs (iden3) README powers-of-tau table (the publisher)",
    attestation_retrieved: "2026-09-09",
    // DOWNLOAD SOURCE (MIRROR), NOT ATTESTATION. Both canonical hosts
    // (hermez.s3-eu-west-1.amazonaws.com and storage.googleapis.com/zkevm/ptau/)
    // return 403 AccessDenied to anonymous callers as of 2026-09-09; the bytes were
    // recovered from a GitHub LFS copy. Which host served the bytes is irrelevant
    // once both hashes match — that is the whole point of pinning hashes.
    source:
      "https://media.githubusercontent.com/media/hswopeams/composite-number-game/main/circuit/powersOfTau28_hez_final_15.ptau",
    source_note: "download source (mirror), not attestation",
    pinned_by: "A-4 PREP wave 2 (CTO ruling: RULING_RECORD_LAUNCH_WEEK_2026-09-09.md Addendum F)",
    pinned_on: "2026-09-09",
  },
];

// ── plumbing ──────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const flag = (n, d) => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : d;
};
const generation = flag("--generation", "m5");
const transcriptPath = flag("--transcript", null);

if (!["m5", "next"].includes(generation)) {
  console.error("usage: verify_ceremony.mjs --generation <m5|next> [--transcript <file>]");
  process.exit(2);
}

const transcript = [];
const results = [];
const say = (s) => {
  transcript.push(s);
  console.log(s);
};
const check = (id, title, status, detail) => {
  results.push({ id, title, status, detail });
  say(`[${status.padEnd(4)}] ${id}  ${title}`);
  for (const line of String(detail).split("\n")) if (line.trim()) say(`         ${line}`);
};

const sha256 = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
/**
 * blake2b-512 — the digest the Hermez ptau publisher actually attests. Node's
 * OpenSSL binding exposes it as "blake2b512"; it is byte-identical to what
 * coreutils `b2sum` prints (b2sum's default IS blake2b-512), so the value pinned
 * in PUBLIC_PTAU_ALLOWLIST can be cross-checked by hand with `b2sum <file>`.
 */
const blake2b512 = (p) => createHash("blake2b512").update(readFileSync(p)).digest("hex");

function snarkjs(argv) {
  try {
    return execFileSync("npx", ["snarkjs", ...argv], {
      cwd: CIRCUITS,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch (e) {
    return `${e.stdout ?? ""}${e.stderr ?? ""}__SNARKJS_FAILED__`;
  }
}
const stripAnsi = (s) => s.replace(/\[[0-9;]*m/g, "");

const manifest = JSON.parse(readFileSync(MANIFEST, "utf8"));
const gen = manifest.ceremony_material[generation];
if (!gen) {
  console.error(`manifest has no ceremony_material.${generation}`);
  process.exit(2);
}

say(`STSH ceremony acceptance evidence — generation: ${generation}`);
say(`manifest: ${MANIFEST}`);
say(`min contributions for a self-run ptau: ${MIN_PTAU_CONTRIBUTIONS}`);
say("");

// ── superseded generations ────────────────────────────────────────────────────
// A-4 LANDING (2026-09-12). A generation whose artifacts have been overwritten in
// place by a later generation cannot be measured: every file-reading check would
// hash the SUCCESSOR's bytes against the PREDECESSOR's pins and fail for the wrong
// reason, reporting "ceremony evidence incomplete" when the truth is "this evidence
// was deliberately replaced". Relabelling to a fresh path is not available (.gitignore
// admits no new tracked dev-key path), so the manifest records the fact instead.
//
// Contract, asserted by tests/ceremony_supersede.test.js:
//   - every check C0-C6 is reported SKIP with the reason;
//   - NO file is read and NO snarkjs subprocess is spawned;
//   - the run emits zero PASS lines and zero FAIL lines;
//   - exit status is 0, and the one-line summary NAMES the superseding generation.
// The live generation must never carry this key; that is asserted separately.
const SKIPPABLE_CHECKS = [
  ["C0", "prerequisites present"],
  ["C1", "ptau is production-grade"],
  ["C2", "ptau power covers the circuit"],
  ["C3", "final zkey verifies against the R1CS and the ptau"],
  ["C4", "phase-2 contributions recorded and observed"],
  ["C5", "exported VK sha256 matches the manifest pin"],
  ["C6", "production zkey pinned; stale keys not confusable"],
];

if (gen.superseded) {
  const sup = gen.superseded;
  const by = sup.by ?? "(unnamed)";
  const reason = `generation '${generation}' is SUPERSEDED by '${by}'` +
    (sup.at ? ` at ${sup.at}` : "") +
    `.\n${sup.reason ?? "(no reason recorded)"}\n` +
    `No artifact file is read for a superseded generation: its pins describe bytes that no longer exist at those paths.`;
  for (const [id, title] of SKIPPABLE_CHECKS) check(id, title, "SKIP", reason);
  say("");
  say(`── summary ──  all ${SKIPPABLE_CHECKS.length} checks SKIPPED; generation '${generation}' is superseded by '${by}'. Verify '${by}' instead.`);
  if (transcriptPath) {
    writeFileSync(transcriptPath, transcript.join("\n") + "\n");
    console.log(`\ntranscript written to ${transcriptPath}`);
  }
  process.exit(0);
}

// ── prerequisites ─────────────────────────────────────────────────────────────
const ptauPath = gen.ptau?.path ? resolve(CIRCUITS, "..", gen.ptau.path) : null;
const zkeyPath = gen.zkey?.path ? resolve(CIRCUITS, "..", gen.zkey.path) : null;
const vkPath = gen.vk?.path ? resolve(CIRCUITS, "..", gen.vk.path) : null;
const r1csEntry = manifest.artifact_matrix.atomic_set.find((a) => a.path.endsWith("spend.r1cs"));
const r1csPath = resolve(CIRCUITS, "..", r1csEntry.path);

if (generation === "next" && (!ptauPath || !zkeyPath || !vkPath)) {
  check(
    "C0",
    "generation 'next' artifacts are populated in the manifest",
    "FAIL",
    "ceremony_material.next still has null paths — A6.7 has not run, or the manifest was not updated.\n" +
      "This is expected during A-3 PREP; it is a hard failure at A6.7 acceptance.",
  );
  finish();
}

for (const [label, p] of [["ptau", ptauPath], ["zkey", zkeyPath], ["r1cs", r1csPath], ["vk", vkPath]]) {
  if (!p || !existsSync(p)) {
    check("C0", `prerequisite present: ${label}`, "FAIL", `missing: ${p ?? "(null in manifest)"}`);
    finish();
  }
}

// ── C1/C2 — ptau provenance ───────────────────────────────────────────────────
const ptauHash = sha256(ptauPath);
const ptauBlake2b = blake2b512(ptauPath);

// BOTH digests must match ONE allowlist entry. Look the entry up by EITHER field
// first, so that a file matching one and not the other is reported as the
// contradiction it is instead of silently missing the allowlist and falling
// through to the self-run branch — a fall-through would report "not pinned" for
// what is really "the pin and the file disagree", which sends the reader to the
// wrong problem under ceremony-week time pressure.
const ptauCandidate = PUBLIC_PTAU_ALLOWLIST.find(
  (e) => e.sha256 === ptauHash || e.blake2b === ptauBlake2b,
);
const ptauHashesAgree =
  Boolean(ptauCandidate) && ptauCandidate.sha256 === ptauHash && ptauCandidate.blake2b === ptauBlake2b;
const allowed = ptauHashesAgree ? ptauCandidate : null;
const allowlistHalfMatch = ptauCandidate && !ptauHashesAgree ? ptauCandidate : null;

const ptauOut = stripAnsi(snarkjs(["powersoftau", "verify", ptauPath]));
const ptauVerifies = ptauOut.includes("Powers of Tau Ok!");

/**
 * Parse the per-contribution blocks snarkjs emits. Each block opens with
 * `Contribution #N: <name>` and, for a REAL beacon (contribution type == 1 in
 * the ptau binary), additionally carries `Beacon generator: <hex>` and
 * `Beacon iterations Exp: <n>` — snarkjs prints those two lines only for
 * type == 1 (snarkjs cli.cjs, processSectionContributions).
 *
 * This is why we do NOT text-match /beacon/ over the whole output: a
 * contribution merely NAMED "beacon" would satisfy that, and a self-run
 * ceremony could be waved through by naming a contribution well. The generator
 * line is structural — it comes from the file format, not from a label.
 *
 * snarkjs lists contributions newest-first (the final contribution is #N).
 */
function parsePtauContributions(out) {
  const blocks = [];
  // `[^\S\r\n]*` — HORIZONTAL whitespace only. It must NOT be `\s*`: snarkjs prints an
  // UNNAMED contribution as `Contribution #55: ` (label, trailing space, newline), and `\s*`
  // matches newlines, so it swallowed the line break and `(.*)` then captured the NEXT
  // output line as the contributor name. Measured on the real Hermez pot15, whose beacon is
  // unnamed: the beacon block parsed as a contributor literally called
  // "[INFO]  snarkJS: Next Challenge:". That silently defeated the very check meant to catch
  // unnamed contributions — `observedContributors.length !== contribCount` can never fire if
  // every block is credited with a bogus name — and would have forced the self-run manifest
  // to declare that garbage string to satisfy bidirectional set-equality. Path (a) does not
  // run this parser, so no ceremony result was affected; path (b) would have been.
  const re = /Contribution #(\d+):[^\S\r\n]*(.*)/g;
  const starts = [...out.matchAll(re)];
  for (let i = 0; i < starts.length; i++) {
    const from = starts[i].index;
    const to = i + 1 < starts.length ? starts[i + 1].index : out.length;
    const body = out.slice(from, to);
    const gen = body.match(/Beacon generator:\s*([0-9a-fA-F]+)/);
    blocks.push({
      index: Number(starts[i][1]),
      contributor: starts[i][2].trim(),
      // The FIRST "Response Hash:" in the block is this contribution's response
      // hash. snarkjs prints a SECOND "Response Hash:" immediately after, which
      // is actually prevContr.nextChallenge under a copy-pasted label (cli.cjs
      // processSectionContributions) — do not record that one as the
      // contribution hash. `nextChallenge` below is the block's own
      // "Next Challenge:" value, kept for the record.
      responseHash: readLabelledHash(body, "Response Hash:"),
      nextChallenge: readLabelledHash(body, "Next Challenge:"),
      isBeacon: Boolean(gen),
      generatorHash: gen ? gen[1].toLowerCase() : null,
      iterationsExp: (body.match(/Beacon iterations Exp:\s*(\d+)/) ?? [])[1] ?? null,
    });
  }
  return blocks;
}

/**
 * snarkjs `formatHash` prints a 64-byte blake2b digest as a title line followed
 * by 4 rows of 4 space-separated 8-hex-digit words. Collect the rows that
 * immediately follow the title and concatenate them into one 128-char hex
 * string. Returns null if the block is absent or malformed — callers treat null
 * as "unobserved", never as "matches".
 */
function readLabelledHash(body, label) {
  const at = body.indexOf(label);
  if (at < 0) return null;
  const words = [];
  for (const line of body.slice(at + label.length).split("\n").slice(1)) {
    const row = line.trim();
    if (/^[0-9a-fA-F]{8}(\s+[0-9a-fA-F]{8})*$/.test(row)) words.push(...row.split(/\s+/));
    else if (words.length) break;
    else if (row !== "") break;
  }
  const hex = words.join("").toLowerCase();
  return hex.length === 128 ? hex : null;
}

const contribs = parsePtauContributions(ptauOut);
const contribCount = contribs.length;
const observedContributors = contribs.map((c) => c.contributor).filter(Boolean);
const beaconContrib = contribs.find((c) => c.isBeacon) ?? null;

const nonEmpty = (v) => typeof v === "string" && v.trim().length > 0;
/** Normalise a declared hash for comparison: lowercase, no whitespace (snarkjs prints hashes in spaced word groups). */
const normHash = (v) => (typeof v === "string" ? v.toLowerCase().replace(/\s+/g, "") : null);

/**
 * The self-run fallback path. Structural observation alone is NOT sufficient:
 * a script can count contributions but cannot establish that N names are N
 * independent people. So this path requires the manifest to carry the full
 * transcript AND a recorded human independence approval, and requires the
 * declared transcript to agree with what was actually observed in the file.
 */
function evaluateSelfRunEvidence(ev) {
  const missing = [];
  if (!ev || typeof ev !== "object") return { ok: false, missing: ["self_run_evidence block absent"] };

  // `contributor` is the ONE canonical identity field. There is deliberately no
  // `name` alternative: two accepted spellings meant the required-fields loop and
  // the agreement loop could read different keys, so a declaration carrying an
  // unobserved `contributor` and no `name` satisfied the first and was skipped by
  // the second. One field, checked by both.
  const declared = Array.isArray(ev.contributions) ? ev.contributions : null;
  if (!declared) missing.push("self_run_evidence.contributions (array)");
  else {
    if (declared.length < MIN_PTAU_CONTRIBUTIONS)
      missing.push(`only ${declared.length} declared contribution(s), need >= ${MIN_PTAU_CONTRIBUTIONS}`);
    declared.forEach((c, i) => {
      if (!nonEmpty(c?.contributor)) missing.push(`contributions[${i}].contributor is absent or empty`);
      if (!nonEmpty(c?.contribution_hash)) missing.push(`contributions[${i}].contribution_hash is absent or empty`);
      if (c?.name !== undefined)
        missing.push(
          `contributions[${i}].name is not a recognised field — use "contributor" (one canonical identity field)`,
        );
    });
  }

  const b = ev.beacon;
  for (const f of ["source", "value", "contribution_hash", "generator_hash"]) {
    if (!nonEmpty(b?.[f])) missing.push(`beacon.${f}`);
  }

  const a = ev.manual_independence_approval;
  if (a?.approved !== true) missing.push("manual_independence_approval.approved !== true");
  for (const f of ["approved_by", "approved_at", "record"]) {
    if (!nonEmpty(a?.[f])) missing.push(`manual_independence_approval.${f}`);
  }

  // Declared transcript must match the file we actually verified.
  if (contribCount < MIN_PTAU_CONTRIBUTIONS)
    missing.push(`observed only ${contribCount} contribution(s) in the ptau, need >= ${MIN_PTAU_CONTRIBUTIONS}`);
  if (!beaconContrib) missing.push("no structural beacon contribution (type==1) observed in the ptau");
  if (beaconContrib && nonEmpty(b?.generator_hash) && beaconContrib.generatorHash !== normHash(b.generator_hash))
    missing.push(
      `beacon generator mismatch: observed ${beaconContrib.generatorHash}, manifest ${normHash(b.generator_hash)}`,
    );
  // The beacon block is an observed contribution with a parsed response hash, so
  // beacon.contribution_hash binds by EQUALITY like every other declared hash.
  // Non-emptiness alone left this field decorative: a run could carry correct
  // contributor identities, a real structural beacon and a correct generator
  // hash, yet an arbitrary beacon.contribution_hash, and still pass.
  if (beaconContrib && nonEmpty(b?.contribution_hash)) {
    if (beaconContrib.responseHash === null)
      missing.push(`could not parse a response hash for the observed beacon contribution "${beaconContrib.contributor}"`);
    else if (beaconContrib.responseHash !== normHash(b.contribution_hash))
      missing.push(
        `beacon contribution_hash mismatch: manifest ${normHash(b.contribution_hash)}, ` +
          `ptau beacon response hash ${beaconContrib.responseHash}`,
      );
  }
  // Bidirectional set-equality against the observed ptau contributors — same
  // shape as C4. One direction alone is not enough: declared-not-observed lets a
  // fabricated participant be listed, observed-not-declared lets a real
  // participant go unrecorded.
  if (declared) {
    const observedSet = new Set(observedContributors);
    const declaredSet = new Set(declared.filter((c) => nonEmpty(c?.contributor)).map((c) => c.contributor.trim()));
    for (const name of declaredSet) {
      if (!observedSet.has(name)) missing.push(`declared contributor "${name}" not observed in the ptau`);
    }
    for (const name of observedSet) {
      if (!declaredSet.has(name)) missing.push(`observed contributor "${name}" is not declared in the manifest`);
    }
    if (observedContributors.length !== contribCount)
      missing.push(`${contribCount - observedContributors.length} observed contribution(s) are unnamed in the ptau itself`);

    // Bind each declared contribution_hash to the response hash actually parsed
    // out of that contributor's verified block — equality, not non-emptiness.
    // Non-emptiness let any placeholder string satisfy the "contribution hashes
    // recorded" evidence requirement.
    const byContributor = new Map(contribs.filter((c) => c.contributor).map((c) => [c.contributor, c]));
    for (const c of declared) {
      if (!nonEmpty(c?.contributor) || !nonEmpty(c?.contribution_hash)) continue; // already reported
      const obs = byContributor.get(c.contributor.trim());
      if (!obs) continue; // already reported as not-observed
      const want = normHash(c.contribution_hash);
      if (obs.responseHash === null)
        missing.push(`could not parse a response hash for observed contributor "${c.contributor}"`);
      else if (obs.responseHash !== want)
        missing.push(
          `contribution_hash mismatch for "${c.contributor}": manifest ${want}, ptau response hash ${obs.responseHash}`,
        );
    }
  }
  return { ok: missing.length === 0, missing };
}

if (!ptauVerifies) {
  check("C1", "ptau is production-grade", "FAIL", `snarkjs powersoftau verify did not report OK for ${gen.ptau.path}`);
} else if (allowlistHalfMatch) {
  check(
    "C1",
    "ptau is production-grade",
    "FAIL",
    `ALLOWLIST HALF-MATCH against pinned entry "${allowlistHalfMatch.name}" — the pin and the file DISAGREE.\n` +
      `This is NOT "the ptau is unpinned"; exactly one of the two digests matched, so either the file on\n` +
      `disk is not the attested one, or the pin was transcribed wrongly. Resolve it; do not re-pin to make\n` +
      `it green.\n` +
      `  blake2b  observed ${ptauBlake2b}\n` +
      `           pinned   ${allowlistHalfMatch.blake2b ?? "(absent from the entry)"}` +
      `${allowlistHalfMatch.blake2b === ptauBlake2b ? "  (agrees)" : "  — MISMATCH"}\n` +
      `  sha256   observed ${ptauHash}\n` +
      `           pinned   ${allowlistHalfMatch.sha256 ?? "(absent from the entry)"}` +
      `${allowlistHalfMatch.sha256 === ptauHash ? "  (agrees)" : "  — MISMATCH"}\n` +
      `blake2b is the publisher-attested digest (${allowlistHalfMatch.attestation ?? "attestation URL unrecorded"}); ` +
      `it is the one that binds the file to the ceremony.`,
  );
} else if (allowed) {
  check(
    "C1",
    "ptau is production-grade",
    "PASS",
    `PUBLIC-CEREMONY PATH: matches pinned entry "${allowed.name}" on BOTH digests\n` +
      `blake2b ${ptauBlake2b}  (publisher-attested)\n` +
      `sha256  ${ptauHash}  (independent second digest)\n` +
      `attestation ${allowed.attestation ?? "(unrecorded)"}` +
      `${allowed.attestation_kind ? ` — ${allowed.attestation_kind}` : ""}` +
      `${allowed.attestation_retrieved ? `, retrieved ${allowed.attestation_retrieved}` : ""}\n` +
      `download source ${allowed.source} — ${allowed.source_note ?? "download source (mirror), not attestation"}\n` +
      `pinned by ${allowed.pinned_by ?? "(unrecorded)"} on ${allowed.pinned_on ?? "(unrecorded)"}\n` +
      `NOTE: C1 taking this branch does NOT exercise the structural beacon parser — see the ` +
      `phase-1/self-run branch below. The ptau-layer beacon rests on the publisher's attestation ` +
      `(the README table's own header states the series carries 54 contributions and a beacon), ` +
      `not on a check this tool ran.`,
  );
} else {
  const ev = evaluateSelfRunEvidence(gen.ptau?.self_run_evidence);
  if (ev.ok) {
    check(
      "C1",
      "ptau is production-grade",
      "PASS",
      `SELF-RUN MULTI-PARTY PATH: ${contribCount} contributions + structural beacon\n` +
        `contributors: ${observedContributors.join(", ")}\n` +
        `beacon generator ${beaconContrib.generatorHash} (iterationsExp ${beaconContrib.iterationsExp})\n` +
        `independence approved by ${gen.ptau.self_run_evidence.manual_independence_approval.approved_by}\n` +
        `sha256 ${ptauHash}`,
    );
  } else {
    check(
      "C1",
      "ptau is production-grade",
      "FAIL",
      `F6-1 NOT CLOSED.\n` +
        `Neither digest of this file is in the pinned public-ceremony allowlist (allowlist size: ${PUBLIC_PTAU_ALLOWLIST.length}).\n` +
        `  blake2b ${ptauBlake2b}\n  sha256  ${ptauHash}\n` +
        `Observed in the file: ${contribCount} contribution(s) [${observedContributors.join(", ") || "unnamed"}], ` +
        `structural beacon: ${beaconContrib ? "yes" : "NO"}.\n` +
        `Self-run fallback evidence is incomplete:\n  - ${ev.missing.join("\n  - ")}\n` +
        `Re-running the zkey/phase-2 contribution on this same ptau does NOT close F6-1 — the ptau layer itself must change.`,
    );
  }
}

// C2 — power is read from the ptau BINARY HEADER, not from the manifest. A
// manifest that misdeclares the power must not be able to green this check;
// the file is the authority. Layout (snarkjs readPTauHeader): section 1 =
// { n8:u32le, q:n8 bytes, power:u32le, ceremonyPower:u32le }.
function readPtauPower(path) {
  const buf = readFileSync(path);
  if (buf.toString("latin1", 0, 4) !== "ptau") throw new Error("not a .ptau file (bad magic)");
  const nSections = buf.readUInt32LE(8);
  let pos = 12;
  for (let i = 0; i < nSections; i++) {
    const id = buf.readUInt32LE(pos);
    const size = Number(buf.readBigUInt64LE(pos + 4));
    const data = pos + 12;
    if (id === 1) {
      const n8 = buf.readUInt32LE(data);
      return {
        power: buf.readUInt32LE(data + 4 + n8),
        ceremonyPower: buf.readUInt32LE(data + 4 + n8 + 4),
      };
    }
    pos = data + size;
  }
  throw new Error("ptau has no header section (id 1)");
}

const r1csOut = stripAnsi(snarkjs(["r1cs", "info", r1csPath]));
const constraints = Number((r1csOut.match(/# of Constraints:\s*(\d+)/) ?? [])[1] ?? NaN);

let derivedPower = null;
let powerErr = null;
try {
  derivedPower = readPtauPower(ptauPath).power;
} catch (e) {
  powerErr = e.message;
}
const declaredPower = gen.ptau?.power;
const powerAgrees = declaredPower === undefined || declaredPower === null || declaredPower === derivedPower;
const capacity = derivedPower === null ? NaN : 2 ** derivedPower;
const c2Ok = derivedPower !== null && Number.isFinite(constraints) && constraints <= capacity && powerAgrees;

check(
  "C2",
  "ptau power covers the circuit",
  c2Ok ? "PASS" : "FAIL",
  derivedPower === null
    ? `could not read power from the ptau header: ${powerErr}`
    : `derived power (from ptau header) 2^${derivedPower} = ${capacity}\n` +
      `constraints ${constraints}` +
      (Number.isFinite(constraints) && constraints <= capacity
        ? `  (headroom ${capacity - constraints})`
        : `  — TOO SMALL, recompile against a larger ptau`) +
      `\nmanifest declares power ${declaredPower ?? "(unset)"}` +
      (powerAgrees ? "  (agrees)" : `  — MISMATCH; the file is authoritative, fix the manifest`),
);

// ── C3 — zkey verifies against R1CS AND ptau ──────────────────────────────────
const zkeyOut = stripAnsi(snarkjs(["zkey", "verify", r1csPath, ptauPath, zkeyPath]));
check(
  "C3",
  "final zkey verifies against final R1CS AND chosen ptau",
  zkeyOut.includes("ZKey Ok!") ? "PASS" : "FAIL",
  `r1cs ${r1csEntry.path} (sha256 ${sha256(r1csPath)})\nptau ${gen.ptau.path}\nzkey ${gen.zkey.path} (sha256 ${sha256(zkeyPath)})`,
);

// ── C4 — phase-2 contributions recorded ───────────────────────────────────────
// The header claims "every contributor named". That is only true if an ABSENT
// record fails: a null/undefined declared count previously counted as
// agreement, so a manifest that simply omitted the field passed vacuously.
const z2 = [...zkeyOut.matchAll(/contribution #(\d+)\s*([^:]*):/gi)];
const z2Names = z2.map((m) => m[2].trim()).filter(Boolean);
const declaredCount = gen.zkey?.phase2_contributions;
const declaredNames = gen.zkey?.contribution_names;

const c4Problems = [];
if (z2.length < 1) c4Problems.push("no phase-2 contribution observed in the zkey");
if (typeof declaredCount !== "number")
  c4Problems.push(`zkey.phase2_contributions is ${declaredCount === undefined ? "absent" : String(declaredCount)}; a number is required`);
else if (declaredCount !== z2.length)
  c4Problems.push(`declared ${declaredCount} phase-2 contribution(s), observed ${z2.length}`);

if (!Array.isArray(declaredNames) || declaredNames.length === 0)
  c4Problems.push("zkey.contribution_names is absent or empty; every contributor must be named");
else {
  if (declaredNames.length !== z2.length)
    c4Problems.push(`contribution_names lists ${declaredNames.length} name(s), observed ${z2.length} contribution(s)`);
  const observed = new Set(z2Names);
  for (const n of declaredNames) {
    if (!nonEmpty(n)) c4Problems.push("contribution_names contains an empty entry");
    else if (!observed.has(n.trim())) c4Problems.push(`declared contributor "${n}" not observed in the zkey`);
  }
  const declaredSet = new Set(declaredNames.filter(nonEmpty).map((n) => n.trim()));
  for (const n of z2Names) {
    if (!declaredSet.has(n)) c4Problems.push(`observed contributor "${n}" is not named in the manifest`);
  }
  if (z2Names.length !== z2.length)
    c4Problems.push(`${z2.length - z2Names.length} observed contribution(s) are unnamed in the zkey itself`);
}

check(
  "C4",
  "zkey phase-2 contributions observed and match the record",
  c4Problems.length === 0 ? "PASS" : "FAIL",
  `observed ${z2.length} phase-2 contribution(s): ${z2Names.join(", ") || "(unnamed)"}\n` +
    `manifest declares count ${declaredCount ?? "(absent)"}, names ${
      Array.isArray(declaredNames) ? JSON.stringify(declaredNames) : "(absent)"
    }\n` +
    (c4Problems.length ? `problems:\n  - ${c4Problems.join("\n  - ")}` : "record agrees with the artifact") +
    (z2.length === 1
      ? "\nNOTE: a single phase-2 contributor is a disclosed trust assumption — it must appear in the ceremony record, not be omitted."
      : ""),
);

// ── C5 — VK pin ───────────────────────────────────────────────────────────────
const vkHash = sha256(vkPath);
check(
  "C5",
  "exported VK sha256 matches the manifest pin",
  gen.vk.sha256 ? (vkHash === gen.vk.sha256 ? "PASS" : "FAIL") : "FAIL",
  `computed ${vkHash}\nmanifest ${gen.vk.sha256 ?? "(null)"}\n` +
    `This hash must ALSO be pinned in the pool and verifier artifacts — verified separately by the Rust gate (compiled_vk_sha256).`,
);

// ── C6 — artifact labelling / stale-key confusion ─────────────────────────────
// Three obligations, all of which the header claims and only the third of which
// was previously implemented:
//   (i)  the production zkey is the artifact the manifest PINS — hash it and
//        require equality to ceremony_material[gen].zkey.sha256;
//   (ii) stale_artifacts.production_zkey names the SAME artifact as the
//        generation's zkey (two path fields that can drift apart are a bug);
//   (iii) no PRESENT stale artifact shares the production hash.
// A declared-stale artifact that is MISSING is no longer skipped silently: a
// silent skip lets a rename erase the very collision evidence C6 exists to find.
const problemsC6 = [];

const prodPathDeclared = manifest.stale_artifacts.production_zkey;
const genZkeyPath = gen.zkey.path;
if (resolve(CIRCUITS, "..", prodPathDeclared) !== resolve(CIRCUITS, "..", genZkeyPath)) {
  problemsC6.push(
    `stale_artifacts.production_zkey (${prodPathDeclared}) is not the same artifact as ` +
      `ceremony_material.${generation}.zkey.path (${genZkeyPath})`,
  );
}

const prodHash = sha256(zkeyPath); // hash the GENERATION's zkey, the pinned one
if (!nonEmpty(gen.zkey.sha256)) {
  problemsC6.push(`ceremony_material.${generation}.zkey.sha256 is absent; the production key is unpinned`);
} else if (prodHash !== gen.zkey.sha256) {
  problemsC6.push(
    `production zkey hash mismatch: file ${prodHash}, manifest pin ${gen.zkey.sha256}`,
  );
}

for (const e of manifest.stale_artifacts.entries) {
  const p = resolve(CIRCUITS, "..", e.path);
  const policy = e.missing_policy ?? "FAIL_CLOSED";
  if (!existsSync(p)) {
    if (policy === "ALLOW_ABSENT") continue; // explicit, recorded allowance only
    problemsC6.push(
      `declared-stale ${e.path} (${e.label}) is MISSING and its missing_policy is ${policy} — ` +
        `absence is not evidence; a rename would erase the collision check. Restore it, or set ` +
        `missing_policy to ALLOW_ABSENT with the reason recorded.`,
    );
    continue;
  }
  const h = sha256(p);
  if (h === prodHash) problemsC6.push(`${e.path} (${e.label}) has the SAME hash as the production zkey`);
  if (!nonEmpty(e.sha256)) problemsC6.push(`${e.path} has no recorded sha256; it cannot be validated`);
  else if (h !== e.sha256) problemsC6.push(`${e.path}: recorded ${e.sha256}, found ${h}`);
}

check(
  "C6",
  "production zkey is pinned and stale artifacts cannot be mistaken for it",
  problemsC6.length === 0 ? "PASS" : "FAIL",
  `production zkey ${genZkeyPath}\n  sha256 ${prodHash}\n  manifest pin ${gen.zkey.sha256 ?? "(absent)"}\n` +
    `stale artifacts declared: ${manifest.stale_artifacts.entries.length}\n` +
    (problemsC6.length
      ? `problems:\n  - ${problemsC6.join("\n  - ")}`
      : "production key matches its pin; no stale artifact shares its hash; all declared stale artifacts accounted for") +
    `\nPresence of stale keys on disk is not itself a failure — they are untracked local residue.\n` +
    `Deleting them is local cleanup and is NOT auditable closure evidence.`,
);

finish();

function finish() {
  const failed = results.filter((r) => r.status === "FAIL");
  say("");
  say(`── summary ──  ${results.length - failed.length} pass / ${failed.length} fail`);
  for (const r of results) say(`  ${r.status.padEnd(4)}  ${r.id}  ${r.title}`);
  if (failed.length) {
    say("");
    say(`CEREMONY EVIDENCE INCOMPLETE for generation '${generation}'.`);
  }
  if (transcriptPath) {
    writeFileSync(transcriptPath, transcript.join("\n") + "\n");
    console.log(`\ntranscript written to ${transcriptPath}`);
  }
  process.exit(failed.length ? 1 : 0);
}
