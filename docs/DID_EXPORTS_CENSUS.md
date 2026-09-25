# Canister interface census — did-vs-exports gate and amount-boundary gate

*W3 3-1. Tool: `scripts/verify_did_exports` (standalone crate). Data:
`scripts/did_export_census.toml`, `scripts/amount_boundary_allowlist.toml`.
Wired blocking into `run_gate.sh`.*

## Why this exists

Before this lane there was no candid gate stage at all. `scripts/verify_candid_metadata.sh`
checks that `stsh_token.wasm` carries a non-empty `candid:service` and nothing
else; its sole invocation is `justfile:135`, the mainnet deploy path, and
`run_gate.sh` never called it. Nothing anywhere compared a `.did` against the
endpoints its canister actually exports.

The embed pipeline embeds the *tracked* `.did`, so any embedded-vs-tracked
comparison is circular. The only non-circular check derives the interface from
**source** and compares it with the tracked `.did`. That is D1. D2 is the C4
rule-3 census of raw amount boundaries, which shares the same source parse.

## What the census is

`scripts/did_export_census.toml` is the universe — not a glob. Every directory
under `canisters/` with a `Cargo.toml` appears exactly once, enrolled or
excluded **by name** with a reason. A crate the tool finds on disk and cannot
find in the census is a gate failure, so "we added a canister and forgot the
census" is not a reachable state.

### The 13-vs-12 count, answered

The count is retired and replaced by the named list in the census file:

| | count | names |
|---|---|---|
| in scope (tracked `.did`) | **13** | merkle-tree, nullifier-registry, shielded-pool, smoke-alarm-monitor, staking, stub-verifier, token, treasury, upgrader, vault, verifier, vesting, vetkeys |
| excluded, library crates | 4 | custody-types, eager-cell, fee-policy, field-utils |
| excluded, test-only stub | 1 | stub-bad-fee-token (exposes endpoints, ships no tracked `.did`, never deployed) |
| **total crates under `canisters/`** | **18** | |

The ambiguity was `canisters/vetkeys` — a standalone, non-member crate that a
workspace-derived count misses — together with `stub-bad-fee-token`, which has
endpoints but no interface file to compare against. Both are now named rows.

`src/declarations/*` and `canisters/custody-types/tests/fixtures/did/*` are
generated or fixture copies, not tracked interface sources, and are not
canisters.

## D1 — what equivalence means here

For each in-scope canister:

1. the tracked `.did` exists and is non-empty;
2. it parses with the **real** candid parser (`candid_parser::pretty_check_file`),
   so a balanced-but-invalid file fails — a structural check cannot decide
   syntax;
3. it declares a service actor (the pre-existing no-actor rejection in
   `scripts/verify_genesis_manifest/src/bin/check_candid_did.rs:41-44`, which
   `embed_candid_metadata.sh` already enforces before embedding, is preserved
   and given its own fixture here);
4. the set of service method names in the `.did` equals the set of **effective
   exported names** of the crate's `#[query]`/`#[update]` endpoints, in both
   directions.

**Lifecycle entry points are not service methods.** `init`, `pre_upgrade`,
`post_upgrade`, `heartbeat`, `inspect_message` are excluded from the comparison
and are never demanded of a `.did`.

**Stated limitations of this bar** (deliberate, not omissions):

- Equivalence is over method **names**, not signatures. Type-level drift inside
  a method that exists on both sides is out of scope; catching it would require
  a Rust-type ↔ Candid-type equivalence model, which this lane does not invent.
- Init arguments are not compared against the Candid service constructor.
- **"Both directions" is subject to named, dated waivers.** The
  `[[exception]]` rows in `scripts/did_export_census.toml` suppress specific
  did-vs-exports mismatches — there is at least one live today
  (`canisters/verifier`'s `verify_spend_canister_benchmark`, a deliberate
  omission from the production interface). The bar is therefore "both
  directions, minus the enrolled exceptions", and the exception list is the
  authoritative statement of which those are. Amount-boundary findings are
  never excepted.

## Extraction rules (the D1/D2 source parse)

The export census comes from a real Rust syntax parse (`syn`), never a grep.

**Recognised endpoint attributes** — bare `#[query]`/`#[update]`/`#[init]`, and
the qualified spellings `#[ic_cdk::…]` and `#[ic_cdk_macros::…]`. All forms are
present in-tree; `canisters/verifier` is the crate that uses the qualified form.
The bare/qualified SPLIT is deliberately not restated here — it is a count over
`canisters/` that moves with every endpoint added or removed, and the census
tool re-derives it on every gate run. The figures this paragraph used to quote
were wrong by more than a factor of two by the time anyone recounted them.

**Import aliases are resolved before classification** (SSA landed-diff F1). The
attribute as written is not the attribute's identity:
`use ic_cdk_macros::update as endpoint;` makes `#[endpoint]` an export. The tool
collects every `use` binding in the file — including grouped and renamed forms —
and resolves a single-segment attribute through it before deciding what the
attribute is. Two fail-closed rules go with it: an alias that resolves to an
unrecognised path is a hard failure, and an import that *shadows* the bare name
`query`/`update`/`init` with something unclassifiable is also a hard failure,
never a silent "not an endpoint". Fixture: `alias_endpoint`.

**Bindings are resolved per module scope** (SSA landed-diff F1c). Each module
sees its own `use` items layered over its ancestors', and never a sibling's.
Flattening a file's imports into one map was not a safe over-approximation: two
sibling modules may legally bind the same local name to different things, the
later binding silently overwrote the earlier, and an endpoint alias erased that
way vanished exactly as it did before F1 was fixed — with no illegal code
involved. Fixture: `alias_sibling_scope`.

**Recognised attribute arguments** — `name = "..."` (which *decides* the
exported name), `guard = "..."`, `composite_query`, `manual_reply`, `hidden`,
`decoding_quota`/`skipping_quota`.

**Configuration** — the production configuration is authoritative: `test` is
false, and `feature = "x"` is true only if `x` is in the crate's
`[features] default` list. No canister crate declares default features, so
`testing` and `gate-machinery` items are correctly absent from the interface the
gate demands. `all`/`any`/`not` compose.

**Anything unresolvable is a hard failure.** An attribute whose last segment is
`query`/`update`/`init` under an unrecognised path, an unrecognised attribute
argument, a cfg predicate outside the set above, or a type the boundary
traversal cannot follow all stop the gate with a named reason. Silent omission
is the one outcome the tool will not produce.

**The module graph is walked, not the file list** (SSA landed-diff F1d). The
scan starts at `src/lib.rs` / `src/main.rs` and follows `mod` declarations —
inline, `foo.rs`, `foo/mod.rs`, or an explicit `#[path = "…"]`. A file's meaning
depends on the declaration that pulls it in, in two ways that parsing each `.rs`
as an independent root got wrong:

- **imports are inherited.** `mod foo;` hands `foo.rs` the declaring scope's
  bindings, so an endpoint alias in `lib.rs` still classifies an attribute in
  `foo.rs`. Standalone parsing gave that file an empty map and lost the endpoint.
- **the `#[cfg]` lives on the declaration.** `#[cfg(test)] mod tests;` puts the
  whole file outside the production build; scanning it anyway demanded test-only
  endpoints of a production `.did`. This is live in-tree
  (`canisters/upgrader/src/tests.rs`).

**The roots are the manifest's targets**, not a hardcoded pair: the library and
every binary, from explicit `[lib]`/`[[bin]]` `path` keys where present and
Cargo's autodiscovery (`src/lib.rs`, `src/main.rs`, `src/bin/*.rs`,
`src/bin/*/main.rs`) otherwise. `src/bin/helper.rs` is a target, not an orphan
module of the library.

A **declared** target is a promise, not a guess: if the manifest names a `path`,
that file must exist, and a `[[bin]]` without a path must infer exactly one
source. Absent or ambiguous is a hard failure naming the target — dropping it
would delete a whole module graph from a census still reporting success.

**Identity is physical, not lexical.** Claims, visits, skips and the directory
walk all compare canonicalized paths, so a symlink cannot present one file as
two (which would evade the duplicate-claim rule below), and a symlinked
directory cycle is walked at most once and does not hang the gate. An entry with no
physical identity — a dangling symlink — is matched lexically instead, because
that is exactly how the skip candidate for a **disabled** declaration is
recorded: a `#[cfg(test)] #[path = "…"]` module need not resolve in the
production configuration, and demanding an identity it cannot have turned a
legal tree into a hard failure. A dangling entry no disabled module explains is
still unreachable, and still fails.

Hard failures, all of them cases where the graph is not a graph:

- a `mod` that resolves to no file, or ambiguously to two;
- **one target claiming the same file twice** (`mod foo; mod foo;`, or a
  symlink alias to an already-claimed file) — Rust rejects it, and a traversal
  cache that quietly deduplicates it is not failing closed. The check is per
  target: `lib.rs` and `main.rs` may each legally declare the same module;
- any `.rs` under `src/` that no `mod` declaration claims and no disabled module
  explains — an unreachable file is a place an endpoint can hide.

**What "disabled" covers.** A module the production configuration switches off
takes its whole source subtree with it, whether it is disabled at the
declaration (`#[cfg(test)] mod tests;`) or inside the file (`#![cfg(test)]`), and
whether it lives at the conventional path or an explicit `#[path = "…"]`. Those
files are declared skipped, so they are neither scanned nor mistaken for
unreachable ones.

Fixtures: `external_mod_alias`, `external_mod_cfg`, `orphan_module_file`,
`disabled_path_module`, `file_cfg_subtree`, `bin_target_layout`,
`duplicate_mod_decl`, `symlink_alias_claim`, `missing_declared_bin`,
`missing_declared_lib`, `disabled_dangling_path`.

## D2 — the amount-boundary census (C4 rule 3)

A gate failure for any raw `u128`/`i128` reachable from a public endpoint that
is not on the reviewed allowlist, where *reachable* means: a direct parameter,
or transitively through type aliases, structs, enum variants (named and tuple),
options, vectors, maps, tuples, arrays and references. **Install/init arguments
are inside D2's universe** even though `#[init]` is outside D1's method
universe — the wrapper case is exactly where a raw amount hides.

**Types resolve by identity, not by basename** (SSA landed-diff F2). Three rules,
in order:

1. **Qualification is identity.** A path whose leading segment names another
   crate under `canisters/` resolves in *that* crate. `external::Shared` is not
   the local `Shared`, and a type absent from the crate its path names is a hard
   failure rather than a fallback. Fixture: `amount_qualified_shadow`.
2. **The namespace in force follows the definition site.** Once the traversal
   descends into a `custody-types` struct, a bare field type means
   custody-types' definition — not a same-named type back in the endpoint's
   crate. Without this, a name that is unambiguous where it is *written* would
   read as ambiguous here (`PruneRequest`, defined in both `custody-types` and
   `shielded-pool`, is the live case at this pin).
3. **Ambiguity hard-fails, never guesses.** An unqualified name that the crate
   in force does not define, and that two or more other crates do, stops the
   gate naming the candidates. Fixture: `amount_ambiguous_global`.

Rules 1 and 2 subsume the earlier local-first rule and keep what it was for:
four crates define their own distinct `InitArgs`, and each `init` still sees
only its own.

`scripts/amount_boundary_allowlist.toml` carries the reviewed entries, each
naming the gate that makes the boundary safe, keyed by the exact traversal path
the tool prints. A row that matches nothing at the current pin fails as stale.

Gates are named as `crate::function`, never line numbers: `canisters/` moves
under this allowlist every campaign, and a line number rots into a citation
pointing at unrelated code.

The reviewed boundaries live in `scripts/amount_boundary_allowlist.toml`, and
the count is NOT restated here — the file's own per-class header carries it and
`umc12_allowlist_header_class_counts_match_actual_rows`
(`scripts/verify_gate_lints`) keeps that header honest against the rows. Note
that the allowlist holds **three** adjudication chains, not two: the C4 §4
rule-2 seed entries, the CTO ruling of 2026-08-15 (`8945c2ad…`, A1-concurred) in
the four classes below, and a further R2-1 §2(b) set. A figure quoted here that
counts only the first two — as the "44 reviewed boundaries" line that used to
sit in this paragraph did — understates the file. The four ruling classes:

| class | rows | what makes them safe |
|---|---|---|
| A — inter-canister | 6 | the caller is asserted to be a specific protocol canister; downstream arithmetic is overflow-checked |
| B — controller/operator-gated setters | 10 | controller assert, then explicit bounds/validation before any store |
| C — user-facing | 4 | denomination membership, explicit floors, or conservation checks with `checked_add` — a wrapped magnitude cannot bypass a balance |
| D — vault admission mirrors | 11 | the vault-side value is inert proposal payload; the authoritative gate is the executing canister's own, which the vault reaches as its operator |

That ruling also settled the "deploy-time `init` allocations" reading: it covers
all deploy-time amount parameters in the install argument, allocation-shaped or
not, because the property rule 2 blessed is the channel rather than the field.

**Builders never add allowlist rows.** An unallowlisted hit is a STOP-and-refer:
a new raw-amount boundary requires CTO/SSA adjudication (C4 §4 rule 2). The gate
message says so instead of inviting the operator to clear it.

## Gate wiring

Three stages run with the other blocking lints, before any build:

1. the tool's own fixture suite (the standalone crate is invisible to
   `cargo test --workspace`, so it is run explicitly — a gate whose failure
   modes are unproven proves nothing);
2. D1, did-vs-exports equivalence;
3. D2, the amount-boundary census.

Each failure goes through `verdict_fail`, which prints the canonical
`═══ VERDICT ═══` block: the verdict line is the only truth anyone reads out of
the runner, so a blocking check must state itself there rather than exiting
quietly above it. `justfile:135`'s `VERIFY_ONCHAIN=1` invocation is unchanged.
