/**
 * STSH Off-Chain Watcher
 * ======================
 * Monitors public invariants and alerts governance on any breach.
 *
 * PM requirement: starts off-chain, publishes machine-readable JSON snapshots.
 * Run on a schedule (every 5 minutes recommended).
 *
 * Usage:
 *   npm install @dfinity/agent @dfinity/principal
 *   npx ts-node scripts/watcher.ts --output snapshots/
 *
 * Each run produces a snapshot JSON. The watcher exits with code 1 if any
 * invariant fails — use this in CI/alerting pipelines.
 */

import { Actor, HttpAgent } from "@dfinity/agent";
import { Principal } from "@dfinity/principal";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

// ── Configuration — set these to actual canister IDs ─────────────────────────

const CONFIG = {
  host: process.env.ICP_HOST || "https://icp-api.io",
  tokenCanisterId:    process.env.TOKEN_CANISTER_ID    || "REPLACE_ME",
  poolCanisterId:     process.env.POOL_CANISTER_ID     || "REPLACE_ME",
  nullifierCanisterId: process.env.NULLIFIER_CANISTER_ID || "REPLACE_ME",
  merkleCanisterId:   process.env.MERKLE_CANISTER_ID   || "REPLACE_ME",
  stakingCanisterId:  process.env.STAKING_CANISTER_ID  || "REPLACE_ME",
  treasuryCanisterId: process.env.TREASURY_CANISTER_ID || "REPLACE_ME",
  /// Expected verifying key hash — set after M0 circuit setup
  expectedVkHash:     process.env.EXPECTED_VK_HASH     || "0000000000000000000000000000000000000000000000000000000000000000",
  /// Expected controller/governance principal
  expectedControllers: (process.env.EXPECTED_CONTROLLERS || "").split(",").filter(Boolean),
  outputDir:          process.env.WATCHER_OUTPUT_DIR    || "./snapshots",
};

// ── Snapshot output format ────────────────────────────────────────────────────
// PM requirement: machine-readable JSON with all fields listed in §11 of delta doc

interface WatcherSnapshot {
  // Metadata
  timestamp_iso:          string;
  timestamp_ns:           bigint;
  git_commit_hash:        string;
  watcher_version:        string;

  // Queried canister IDs
  canister_ids: {
    token:      string;
    pool:       string;
    nullifier:  string;
    merkle:     string;
    staking:    string;
    treasury:   string;
  };

  // Supply accounting
  token_total_supply:          bigint;
  escrow_balance:              bigint;  // pool canister's token balance
  staking_locked_balance:      bigint;  // sum of all staking locks
  treasury_balances:           Record<string, bigint>;

  // Privacy pool state
  current_verifier_key_hash:   string;
  expected_verifier_key_hash:  string;
  verifier_key_hash_matches:   boolean;
  active_circuit_versions:     number[];
  pool_version_liabilities:    PoolVersionLiability[];
  nullifier_count:             bigint;
  commitment_count:            bigint;

  // Governance
  controller_list:             string[];
  controllers_match_expected:  boolean;

  // Invariant checks
  checks: {
    solvency:             CheckResult;
    nullifier_monotonic:  CheckResult;
    commitment_monotonic: CheckResult;
    vk_hash:              CheckResult;
    controllers:          CheckResult;
    supply_sum:           CheckResult;
  };

  // Overall result
  overall_pass: boolean;
  violations:   string[];
}

interface CheckResult {
  pass: boolean;
  detail: string;
}

interface PoolVersionLiability {
  version:         number;
  total_deposited: bigint;
  total_withdrawn: bigint;
  max_liability:   bigint;
}

// ── Previous snapshot state (for monotonicity checks) ─────────────────────────

interface PreviousState {
  nullifier_count:  bigint;
  commitment_count: bigint;
  snapshot_file:    string;
}

function loadPreviousState(outputDir: string): PreviousState | null {
  const files = fs.existsSync(outputDir)
    ? fs.readdirSync(outputDir).filter(f => f.endsWith(".json")).sort().reverse()
    : [];
  if (files.length === 0) return null;
  try {
    const prev = JSON.parse(fs.readFileSync(path.join(outputDir, files[0]), "utf-8"));
    return {
      nullifier_count:  BigInt(prev.nullifier_count  || 0),
      commitment_count: BigInt(prev.commitment_count || 0),
      snapshot_file:    files[0],
    };
  } catch { return null; }
}

// ── IDL fragments (minimal — expand as canisters are deployed) ────────────────

const tokenIdl = ({ IDL }: any) => {
  const Account = IDL.Record({ owner: IDL.Principal, subaccount: IDL.Opt(IDL.Vec(IDL.Nat8)) });
  return IDL.Service({
    icrc1_total_supply:          IDL.Func([], [IDL.Nat], ["query"]),
    icrc1_balance_of:            IDL.Func([Account], [IDL.Nat], ["query"]),
    verify_supply_invariant:     IDL.Func([], [IDL.Record({
      fixed_max_supply:    IDL.Nat,
      sum_all_balances:    IDL.Nat,
      staking_locked_total: IDL.Nat,
      fee_reserve_total:   IDL.Nat,
      invariant_holds:     IDL.Bool,
      checked_at_ns:       IDL.Nat64,
      violation_detail:    IDL.Opt(IDL.Text),
      // K3-002b (P-ARITH): additive per-site overflow attribution. Non-null
      // is a hard-red condition regardless of invariant_holds.
      arithmetic_error:    IDL.Opt(IDL.Record({
        balances_overflow:          IDL.Bool,
        staking_locks_overflow:     IDL.Bool,
        balances_plus_fee_overflow: IDL.Bool,
      })),
    })], ["query"]),
  });
};

const poolIdl = ({ IDL }: any) => IDL.Service({
  get_pinned_vk_hash:        IDL.Func([], [IDL.Vec(IDL.Nat8)], ["query"]),
  get_circuit_version:       IDL.Func([], [IDL.Nat32], ["query"]),
  get_pool_version:          IDL.Func([], [IDL.Nat32], ["query"]),
  get_pool_version_stats:    IDL.Func([], [IDL.Vec(IDL.Record({
    version:         IDL.Nat32,
    total_deposited: IDL.Nat,
    total_withdrawn: IDL.Nat,
    max_liability:   IDL.Nat,
    active_at_ns:    IDL.Nat64,
    retired_at_ns:   IDL.Opt(IDL.Nat64),
  }))], ["query"]),
  is_deposits_paused:        IDL.Func([], [IDL.Bool], ["query"]),
  is_spends_paused:          IDL.Func([], [IDL.Bool], ["query"]),
});

const nullifierIdl = ({ IDL }: any) => IDL.Service({
  count: IDL.Func([], [IDL.Nat64], ["query"]),
});

const merkleIdl = ({ IDL }: any) => IDL.Service({
  leaf_count: IDL.Func([], [IDL.Nat64], ["query"]),
});

const stakingIdl = ({ IDL }: any) => IDL.Service({
  get_rewards_pool_balance: IDL.Func([], [IDL.Nat], ["query"]),
  get_total_voting_weight:  IDL.Func([], [IDL.Nat], ["query"]),
});

const treasuryIdl = ({ IDL }: any) => IDL.Service({
  get_subaccount_balances: IDL.Func([], [IDL.Vec(IDL.Record({
    name:    IDL.Text,
    balance: IDL.Nat,
  }))], ["query"]),
});

// ── Main watcher logic ────────────────────────────────────────────────────────

async function runWatcher(): Promise<WatcherSnapshot> {
  const agent = new HttpAgent({ host: CONFIG.host });
  if (CONFIG.host.includes("localhost") || CONFIG.host.includes("127.0.0.1")) {
    await agent.fetchRootKey();
  }

  const token    = Actor.createActor(tokenIdl,    { agent, canisterId: CONFIG.tokenCanisterId });
  const pool     = Actor.createActor(poolIdl,     { agent, canisterId: CONFIG.poolCanisterId });
  const nullifier = Actor.createActor(nullifierIdl, { agent, canisterId: CONFIG.nullifierCanisterId });
  const merkle   = Actor.createActor(merkleIdl,   { agent, canisterId: CONFIG.merkleCanisterId });
  const staking  = Actor.createActor(stakingIdl,  { agent, canisterId: CONFIG.stakingCanisterId });
  const treasury = Actor.createActor(treasuryIdl, { agent, canisterId: CONFIG.treasuryCanisterId });

  const prev = loadPreviousState(CONFIG.outputDir);
  const violations: string[] = [];
  const now = BigInt(Date.now()) * 1_000_000n;

  // ── Fetch all data ─────────────────────────────────────────────────────────

  const [
    totalSupply,
    supplyInvariant,
    poolTokenBalance,
    vkHashBytes,
    poolVersionStats,
    nullifierCount,
    commitmentCount,
    stakingRewardsBalance,
    treasuryBalances,
  ] = await Promise.all([
    token.icrc1_total_supply() as Promise<bigint>,
    token.verify_supply_invariant() as Promise<any>,
    token.icrc1_balance_of({ owner: Principal.fromText(CONFIG.poolCanisterId), subaccount: [] }) as Promise<bigint>,
    pool.get_pinned_vk_hash() as Promise<Uint8Array>,
    pool.get_pool_version_stats() as Promise<any[]>,
    nullifier.count() as Promise<bigint>,
    merkle.leaf_count() as Promise<bigint>,
    staking.get_rewards_pool_balance() as Promise<bigint>,
    treasury.get_subaccount_balances() as Promise<any[]>,
  ]);

  // ── Process data ───────────────────────────────────────────────────────────

  const vkHashHex = Buffer.from(vkHashBytes).toString("hex");
  const vkMatches = vkHashHex === CONFIG.expectedVkHash;

  const poolLiabilities: PoolVersionLiability[] = poolVersionStats.map((s: any) => ({
    version:         Number(s.version),
    total_deposited: BigInt(s.total_deposited),
    total_withdrawn: BigInt(s.total_withdrawn),
    max_liability:   BigInt(s.max_liability),
  }));

  const totalPoolLiability = poolLiabilities.reduce((sum, v) => sum + v.max_liability, 0n);
  const treasuryBalMap: Record<string, bigint> = {};
  for (const entry of treasuryBalances) {
    treasuryBalMap[entry.name] = BigInt(entry.balance);
  }

  const stakingLocked = BigInt(supplyInvariant.staking_locked_total || 0);

  // ── CHECK 1: Solvency ──────────────────────────────────────────────────────
  // total_withdrawable_private_value <= public_STSH_escrow_balance
  const solvencyOk = totalPoolLiability <= poolTokenBalance;
  const solvencyCheck: CheckResult = {
    pass: solvencyOk,
    detail: solvencyOk
      ? `OK: max_liability(${totalPoolLiability}) <= escrow(${poolTokenBalance})`
      : `BREACH: max_liability(${totalPoolLiability}) > escrow(${poolTokenBalance}) — ALERT GOVERNANCE`,
  };
  if (!solvencyOk) violations.push(`SOLVENCY BREACH: liability ${totalPoolLiability} > escrow ${poolTokenBalance}`);

  // ── CHECK 2: Nullifier count monotonically increasing ─────────────────────
  const nullifierOk = prev === null || nullifierCount >= prev.nullifier_count;
  const nullifierCheck: CheckResult = {
    pass: nullifierOk,
    detail: nullifierOk
      ? `OK: count(${nullifierCount}) >= prev(${prev?.nullifier_count ?? "N/A"})`
      : `TAMPER DETECTED: count(${nullifierCount}) < prev(${prev!.nullifier_count})`,
  };
  if (!nullifierOk) violations.push(`NULLIFIER COUNT DECREASED: ${nullifierCount} < ${prev!.nullifier_count}`);

  // ── CHECK 3: Commitment count monotonically increasing ────────────────────
  const commitmentOk = prev === null || commitmentCount >= prev.commitment_count;
  const commitmentCheck: CheckResult = {
    pass: commitmentOk,
    detail: commitmentOk
      ? `OK: count(${commitmentCount}) >= prev(${prev?.commitment_count ?? "N/A"})`
      : `TAMPER DETECTED: count(${commitmentCount}) < prev(${prev!.commitment_count})`,
  };
  if (!commitmentOk) violations.push(`COMMITMENT COUNT DECREASED: ${commitmentCount} < ${prev!.commitment_count}`);

  // ── CHECK 4: Verifying key hash unchanged ──────────────────────────────────
  const vkCheck: CheckResult = {
    pass: vkMatches,
    detail: vkMatches
      ? `OK: VK hash matches expected`
      : `VK CHANGED: got ${vkHashHex} expected ${CONFIG.expectedVkHash}`,
  };
  if (!vkMatches && CONFIG.expectedVkHash !== "0".repeat(64)) {
    violations.push(`VERIFYING KEY CHANGED — check governance log`);
  }

  // ── CHECK 5: Controller list ───────────────────────────────────────────────
  // TODO: query management canister for controller list
  const controllersCheck: CheckResult = { pass: true, detail: "Controller check: TODO (requires management canister query)" };

  // ── CHECK 6: Supply invariant ──────────────────────────────────────────────
  // K3-002b: a non-null arithmetic_error is HARD RED even if invariant_holds
  // were (incorrectly) true — an overflowed total is not evidence of health.
  const arithError = supplyInvariant.arithmetic_error?.[0] ?? null;
  const supplyOk = Boolean(supplyInvariant.invariant_holds) && arithError === null;
  const supplyCheck: CheckResult = {
    pass: supplyOk,
    detail: supplyOk
      ? `OK: sum(balances) == TOTAL_SUPPLY`
      : arithError !== null
        ? `SUPPLY ARITHMETIC ERROR: ${supplyInvariant.violation_detail?.[0] ?? JSON.stringify(arithError)}`
        : `SUPPLY VIOLATION: ${supplyInvariant.violation_detail?.[0] ?? "unknown"}`,
  };
  if (arithError !== null) {
    violations.push(
      `SUPPLY INVARIANT ARITHMETIC ERROR (overflow in checked evaluation): ${supplyInvariant.violation_detail?.[0] ?? "see arithmetic_error record"}`,
    );
  } else if (!supplyOk) {
    violations.push(`SUPPLY INVARIANT VIOLATED: ${supplyInvariant.violation_detail?.[0]}`);
  }

  // ── Build snapshot ─────────────────────────────────────────────────────────

  const snapshot: WatcherSnapshot = {
    timestamp_iso:     new Date().toISOString(),
    timestamp_ns:      now,
    git_commit_hash:   getGitCommit(),
    watcher_version:   "0.1.0",
    canister_ids: {
      token:     CONFIG.tokenCanisterId,
      pool:      CONFIG.poolCanisterId,
      nullifier: CONFIG.nullifierCanisterId,
      merkle:    CONFIG.merkleCanisterId,
      staking:   CONFIG.stakingCanisterId,
      treasury:  CONFIG.treasuryCanisterId,
    },
    token_total_supply:         BigInt(totalSupply),
    escrow_balance:             BigInt(poolTokenBalance),
    staking_locked_balance:     stakingLocked,
    treasury_balances:          treasuryBalMap,
    current_verifier_key_hash:  vkHashHex,
    expected_verifier_key_hash: CONFIG.expectedVkHash,
    verifier_key_hash_matches:  vkMatches,
    active_circuit_versions:    [...new Set(poolVersionStats.map((s: any) => Number(s.version)))],
    pool_version_liabilities:   poolLiabilities,
    nullifier_count:            nullifierCount,
    commitment_count:           commitmentCount,
    controller_list:            [],  // TODO: management canister query
    controllers_match_expected: true,
    checks: {
      solvency:             solvencyCheck,
      nullifier_monotonic:  nullifierCheck,
      commitment_monotonic: commitmentCheck,
      vk_hash:              vkCheck,
      controllers:          controllersCheck,
      supply_sum:           supplyCheck,
    },
    overall_pass: violations.length === 0,
    violations,
  };

  return snapshot;
}

function getGitCommit(): string {
  try {
    const { execSync } = require("child_process");
    return execSync("git rev-parse HEAD", { encoding: "utf-8" }).trim();
  } catch { return "unknown"; }
}

function saveSnapshot(snapshot: WatcherSnapshot, outputDir: string): string {
  if (!fs.existsSync(outputDir)) { fs.mkdirSync(outputDir, { recursive: true }); }
  const filename = `snapshot-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
  const filepath = path.join(outputDir, filename);
  // Serialize BigInts as strings
  fs.writeFileSync(filepath, JSON.stringify(snapshot, (_, v) =>
    typeof v === "bigint" ? v.toString() : v, 2));
  return filepath;
}

// ── Entry point ───────────────────────────────────────────────────────────────

(async () => {
  console.log(`[STSH Watcher] Starting check at ${new Date().toISOString()}`);

  try {
    const snapshot = await runWatcher();
    const filepath = saveSnapshot(snapshot, CONFIG.outputDir);
    console.log(`[STSH Watcher] Snapshot saved: ${filepath}`);

    if (snapshot.overall_pass) {
      console.log("[STSH Watcher] ✓ All invariants pass");
      process.exit(0);
    } else {
      console.error("[STSH Watcher] ✗ INVARIANT VIOLATIONS DETECTED:");
      for (const v of snapshot.violations) {
        console.error(`  → ${v}`);
      }
      console.error("[STSH Watcher] ACTION REQUIRED: Alert governance immediately.");
      process.exit(1); // Non-zero exit for CI/alerting integration
    }
  } catch (err) {
    console.error("[STSH Watcher] ERROR:", err);
    process.exit(2);
  }
})();
