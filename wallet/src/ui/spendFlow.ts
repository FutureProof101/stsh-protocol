/**
 * Spend orchestration (Campaign B / L3c — §10). L0-C + local witness.
 *
 * Scope: self-change + optional PUBLIC payout. No private P2P.
 *
 * Load-bearing ordering (each is a lane non-negotiable, tested):
 *  1. C-VK-3 sandwich + C-DOM-2 deployment binding (same as shield/scan).
 *  2. Manifest attestation check (C-DOM tuple) + artifact verification
 *     (streaming cap, exact hash) — verified Blob URLs ONLY, revoked in
 *     finally; the prover worker never sees a network URL.
 *  3. Fee + payout arithmetic resolved BEFORE journaling (fee =
 *     protocolPrivateSpendFeeStsh; public_amount = recipientNet + live ledger
 *     fee, GROSS — the recipient receives public_amount − ledger_fee).
 *  4. Accepted-root witness (H6-1): get_accepted_root_head → leaf_count <=
 *     mirror head and input.leafIndex < leaf_count; witness from the LOCAL
 *     mirror at that leaf_count; reconstructed root == accepted root, locally
 *     verified BEFORE proof (S-19/S-32). Never the scan head.
 *  5. ONE atomic journal+lock write (beginSpend) BEFORE proof/dispatch.
 *  6. encodeGroth16Proof → 256-byte compact; ALL 9 public signals compared
 *     canonically (bigint equality) against request-derived values.
 *  7. private_spend with exactly 1 nullifier / 2 outer Merkle leaves.
 *  8. Recovery (§10.1/§10.2): advisory queries drive REVERSIBLE actions only;
 *     permanent effects (evict/unlock/change) come ONLY from an authoritative
 *     update Ok.
 */

import { Principal } from "@dfinity/principal";
import { privateSpendFee } from "../crypto/fees";
import type { DerivedPublicKey } from "@dfinity/vetkeys";

import type { PoolCanister, PrivateSpendRequest } from "../actors/pool";
import type { VetkeysCanister } from "../crypto/vetkeys";
import type { FetchKeys } from "../crypto/vetkeys";
import {
  assertCanisterConfig,
  encryptNotePayload,
  fetchUserVetKey,
  masterNoteSecret,
} from "../crypto/vetkeys";
import type { TokenCanister } from "../actors/token";
import type { ScanActors } from "../crypto/scanner";
import { syncMirror, verifyMerkleWitness, downloadSpentSet } from "../crypto/scanner";
import {
  createSpendOutputNote,
  deriveNoteSecretsV2,
  encodeRecipientSignals,
  freshNoteNonce,
  merkleLeaf,
  noteToBytesV2,
  leToBigint,
} from "../crypto/notes";
import { generateSpendProof, type SpendRequest, type PayoutTarget } from "../crypto/prover";
import { encodeGroth16Proof } from "../crypto/encodeProof";
import { assertManifestAttestation, withVerifiedProverAssets } from "../zk/artifacts";
import { PoolCallError } from "../actors/pool";
import {
  SPEND_ALREADY_WENT_THROUGH_COPY,
  masksIdempotentOk,
  parseSpendAdmission,
  spendAdmissionCopy,
  type SpendAdmission,
} from "./spendAdmissionCopy";
import { resolveExpectedVetkdKeyName } from "./shieldFlow";
import { raceSessionTask, throwIfAborted } from "../session/taskOwner";
import type { SpendJournal } from "../storage/spendJournal";
import type { SpendJournalEntryState } from "../storage/noteCache";
import type { ScannedNote } from "../storage/noteCache";
import type { SubmissionDelay } from "./submissionDelay";
import type { OperationLease } from "../actors/authorization";
import type { WalletConfig } from "../session/config";

// ── Types ────────────────────────────────────────────────────────────────────

export interface SpendFlowDeps {
  policyKind: "local" | "production";
  config: WalletConfig;
  principal: Principal;
  vetkeys: VetkeysCanister;
  pool: PoolCanister;
  token: TokenCanister;
  journal: SpendJournal;
  /** Mirror source (anonymous public reads). */
  scan: Pick<ScanActors, "getScanHead" | "getScanPage">;
  /** The session's cached notes (validated by L3b). */
  notes: ScannedNote[];
  /** Expected deployment-config hash (P-DOM, computed by the caller's guard). */
  expectedDeploymentConfigHash: Uint8Array;
  fetchKeys?: FetchKeys;
  /** Prover-asset loader seam — production: withVerifiedProverAssets (verified
   * Blob URLs, revoked in finally); tests inject local file paths so the real
   * snarkjs fullProve runs inline in node. */
  loadAssets?: <T>(
    fn: (assets: { wasmUrl: string; zkeyUrl: string }) => Promise<T>,
    signal?: AbortSignal,
  ) => Promise<T>;
  spawnWorker?: () => Worker;
  signal?: AbortSignal;
  /** Synchronous UI ownership handoff immediately before the durable marker begins. */
  onDispatchBoundary?: () => void;
  now?: () => bigint;
  /**
   * WL-2c, optional: the randomised submission delay, run at the TOP of the
   * operation. Everything this flow reads live — the vetKey config sandwich,
   * the deployment attestation, the governance fee params, the ledger fee, the
   * accepted root head — is read after it. Undefined means no wait.
   */
  submissionDelay?: SubmissionDelay;
  /**
   * WL-2b: the operation lease minted by the gesture that started this spend.
   * One single-use token is drawn from it immediately before `private_spend`.
   */
  lease?: OperationLease;
}

export interface SpendInput {
  inputLeafIndex: bigint;
  /** Public payout: recipient NET (e8s). Omit for a fully private spend. */
  payout?: { destination: Principal; subaccount: Uint8Array | null; recipientNet: bigint };
}

export interface SpendFlowSummary {
  spendId: string;
  changeValue: bigint;
  publicAmount: bigint;
  fee: bigint;
}

export class SpendFlowError extends Error {
  constructor(
    readonly stage:
      | "input"
      | "vetkd-config"
      | "attestation"
      | "fee"
      | "fee-stale"
      | "witness"
      | "journal"
      | "proof"
      | "signals"
      | "submit"
      | "recovery",
    message: string,
    /**
     * WALLET-V12 O-3: set when the pool refused at ADMISSION
     * (`SPEND_ADMISSION;…`) — no pool record was written, the journal entry
     * stays `dispatched`, and the SAME spend_id is retried later (E-2(c)).
     * `message` is then the ruled user copy, rendered advisory (copper).
     */
    readonly admission?: SpendAdmission,
    /**
     * WALLET-V12 E-1 (C-3): a same-id replay was refused at admission while the
     * ADVISORY status query reports the spend finalized. Copy only — no journal
     * state is changed off the query.
     */
    readonly alreadyWentThrough?: boolean,
  ) {
    super(message);
    this.name = "SpendFlowError";
  }
}

/** u64 from 8 CSPRNG bytes — no JS-number conversion anywhere (S-34). */
export function freshSpendId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  return v.toString(10);
}

// ── Logical-intent fingerprint (S-38 — mirrors the pool's comparison exactly) ─
//
// The pool's spend_intent_matches compares: nullifiers, output commitments,
// fee, and public_payout { destination, destination_subaccount, public_amount }.
// This encoder covers EXACTLY that field set, with length-prefixed boundaries
// so no cross-field collision is possible:
//   SHA-256( "stsh.spend-intent.v1"
//            ‖ lp(nullifier) ‖ lp(output_leaf_1) ‖ lp(output_leaf_2)
//            ‖ lp(payout_destination ‖ sub-or-empty ‖ u128be(public_amount)) [empty when no payout]
//            ‖ lp(u128be(fee)) )
// lp(x) = u32_be(len(x)) ‖ x.

function lp(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(4 + len);
  new DataView(out.buffer).setUint32(0, len, false);
  let off = 4;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function u128be(v: bigint): Uint8Array {
  const out = new Uint8Array(16);
  let x = v;
  for (let i = 15; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

export interface IntentFingerprintInput {
  nullifier: Uint8Array;
  outputLeaves: Uint8Array[];
  payout: { destination: Principal; subaccount: Uint8Array | null; publicAmount: bigint } | null;
  fee: bigint;
}

/** The canonical logical-intent fingerprint (hex). */
export async function intentFingerprintHex(input: IntentFingerprintInput): Promise<string> {
  const parts: Uint8Array[] = [new TextEncoder().encode("stsh.spend-intent.v1")];
  parts.push(lp(input.nullifier));
  for (const leaf of input.outputLeaves) parts.push(lp(leaf));
  parts.push(
    input.payout === null
      ? lp()
      : lp(
          input.payout.destination.toUint8Array(),
          input.payout.subaccount ?? new Uint8Array(0),
          u128be(input.payout.publicAmount),
        ),
  );
  parts.push(lp(u128be(input.fee)));
  const total = parts.reduce((n, p) => n + p.length, 0);
  const preImage = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    preImage.set(p, off);
    off += p.length;
  }
  const digest = await crypto.subtle.digest("SHA-256", preImage as BufferSource);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ── Subaccount signal encoding (pool byte-exact, DEF-108) ────────────────────

function subaccountSignals(sub: Uint8Array | null): { lo: Uint8Array; hi: Uint8Array } {
  const full = sub ?? new Uint8Array(32);
  const lo = new Uint8Array(32);
  lo.set(full.slice(0, 16), 0);
  const hi = new Uint8Array(32);
  hi.set(full.slice(16, 32), 0);
  return { lo, hi };
}

// ── The flow ─────────────────────────────────────────────────────────────────

export async function runSpendFlow(deps: SpendFlowDeps, input: SpendInput): Promise<SpendFlowSummary> {
  throwIfAborted(deps.signal);
  const now = deps.now ?? (() => BigInt(Date.now()) * 1_000_000n);

  // WL-2c. The randomised submission delay, in FRONT of the whole operation —
  // the same rule as the shield, for the same reason. The spend's LAST
  // state-changing public call is `private_spend` — step (1)'s `fetchUserVetKey`
  // is also a signed `#[update]` ingress, so `private_spend` is not the only one
  // (AR2-P2-04) — and EVERY live value that
  // guards it (fee params, ledger fee, accepted root head, attestation) is
  // read below this line, so none of them is aged by the wait. Placing the
  // wait later — after proof generation, say — would put a live read on the
  // pre-delay side and recreate exactly the staleness this ordering exists to
  // avoid.
  await raceSessionTask(deps.submissionDelay?.run("spend") ?? Promise.resolve(), deps.signal);

  // (0) Input note must exist, be spendable, and have complete v2 material
  // (the journal's beginSpend re-enforces atomically).
  const note = deps.notes.find((n) => n.leafIndex === input.inputLeafIndex);
  if (note === undefined) {
    throw new SpendFlowError("input", `no note at leaf index ${input.inputLeafIndex}`);
  }
  if (note.state !== "spendable") {
    throw new SpendFlowError("input", `note at leaf ${input.inputLeafIndex} is '${note.state}', not spendable`);
  }
  if (note.nonce === undefined || note.commitment === undefined || note.nullifier === undefined) {
    throw new SpendFlowError("input", "input note has incomplete v2 material");
  }

  // (1) C-VK-3 sandwich (S-43) — identical to the shield flow's ordering.
  const keyName = resolveExpectedVetkdKeyName({ policyKind: deps.policyKind, config: deps.config });
  try {
    await raceSessionTask(assertCanisterConfig(deps.vetkeys, keyName), deps.signal);
  } catch (err) {
    throw new SpendFlowError(
      "vetkd-config",
      err instanceof Error ? err.message : String(err),
    );
  }
  const configBefore = await raceSessionTask(deps.vetkeys.getConfig(), deps.signal);
  const { vetKey, verificationKey } = await raceSessionTask(
    (deps.fetchKeys ?? fetchUserVetKey)(deps.vetkeys, deps.principal),
    deps.signal,
  );
  try {
    await raceSessionTask(assertCanisterConfig(deps.vetkeys, keyName), deps.signal);
  } catch (err) {
    throw new SpendFlowError(
      "vetkd-config",
      `vetkeys canister config changed during key fetch: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  const configAfter = await raceSessionTask(deps.vetkeys.getConfig(), deps.signal);
  if (configBefore[0] !== configAfter[0] || configBefore[1] !== configAfter[1]) {
    throw new SpendFlowError("vetkd-config", "vetkeys canister config drifted during key fetch");
  }
  const master = masterNoteSecret(vetKey);

  // (2) Manifest attestation check (COMPLETE C-DOM tuple — companion guard;
  // the P-DOM update-side hash stays the authority). The tuple is resolved
  // per environment and every principal is mandatory (no optional pins).
  const attRaw = await raceSessionTask(deps.pool.getDeploymentAttestation(), deps.signal);
  assertManifestAttestation(
    {
      pool: attRaw.pool.toText(),
      token: attRaw.token.toText(),
      merkle: attRaw.merkle.toText(),
      nullifier: attRaw.nullifier.toText(),
      verifier: attRaw.verifier.length === 1 ? attRaw.verifier[0].toText() : "",
      vkHash: [...attRaw.vk_hash].map((b) => b.toString(16).padStart(2, "0")).join(""),
      circuitVersion: attRaw.circuit_version,
      poolVersion: attRaw.pool_version,
      proofSystem: attRaw.proof_system,
    },
    {
      pool: deps.config.poolCanisterId,
      token: deps.config.tokenCanisterId,
      merkle: deps.config.merkleCanisterId,
      nullifier: deps.config.nullifierCanisterId,
      verifier: deps.config.verifierCanisterId,
    },
  );

  // (3) Fee basis — resolved BEFORE journaling: spend fee from governance
  // params; the payout GROSS amount from the live ledger fee.
  const feeParams = await raceSessionTask(deps.pool.getGovernanceFeeParams(), deps.signal);
  let publicAmount = 0n;
  let payoutTarget: PayoutTarget | undefined;
  if (input.payout !== undefined) {
    const ledgerFee = await raceSessionTask(deps.token.fee(), deps.signal);
    publicAmount = input.payout.recipientNet + ledgerFee;
    const { lo, hi } = subaccountSignals(input.payout.subaccount);
    payoutTarget = {
      recipientPrincipal: encodeRecipientSignals(input.payout.destination),
      subaccountLo: lo,
      subaccountHi: hi,
    };
  }
  // A-7: an EXIT pays the unshield value fee on the payout gross; a
  // shielded→shielded spend pays the flat protocol spend fee. The fee is bound
  // into the proof as public signal[5], so getting this wrong does not produce a
  // rejected transaction — it produces a proof the pool will not accept, built at
  // the cost of a full proving run.
  const fee = privateSpendFee(input.payout === undefined ? undefined : publicAmount, feeParams);
  const changeValue = note.value - publicAmount - fee;
  if (changeValue < 0n) {
    throw new SpendFlowError(
      "fee",
      `note value ${note.value} cannot cover public_amount ${publicAmount} + fee ${fee}`,
    );
  }

  // (4) Accepted-root witness (H6-1/S-19/S-32).
  // 4a. Sync the local mirror via the ONE authoritative sync (head + validated
  // full sweep — the same page-shape protections as the L3b scan pipeline).
  const { head, mirror } = await syncMirror(deps.scan, { signal: deps.signal });
  throwIfAborted(deps.signal);
  const mirrorRoot = await raceSessionTask(mirror.root(head.leafCount), deps.signal);
  throwIfAborted(deps.signal);
  const hr = head.root;
  if (mirrorRoot.length !== 32 || hr.length !== 32 || !mirrorRoot.every((b, i) => b === hr[i])) {
    throw new SpendFlowError("witness", "local mirror root does not match the scan head");
  }
  // 4b. Anchor to the ACCEPTED head — never the scan head.
  const accepted = await raceSessionTask(deps.pool.getAcceptedRootHead(), deps.signal);
  if (accepted === null) {
    throw new SpendFlowError("witness", "no accepted root head exists yet");
  }
  if (accepted.leafCount > head.leafCount) {
    throw new SpendFlowError(
      "witness",
      `accepted head (${accepted.leafCount}) is ahead of the local mirror (${head.leafCount}) — rescan first`,
    );
  }
  if (input.inputLeafIndex >= accepted.leafCount) {
    throw new SpendFlowError(
      "witness",
      `input leaf ${input.inputLeafIndex} is not under the accepted head (${accepted.leafCount}) — it is not finalized yet`,
    );
  }
  const witness = await raceSessionTask(
    mirror.witness(input.inputLeafIndex, accepted.leafCount),
    deps.signal,
  );
  throwIfAborted(deps.signal);
  const leafAtInput = mirror.leafAt(input.inputLeafIndex);
  if (leafAtInput === null) {
    throw new SpendFlowError("witness", "input leaf missing from the local mirror");
  }
  const witnessOk = await raceSessionTask(
    verifyMerkleWitness(leafAtInput, witness, accepted.root),
    deps.signal,
  );
  throwIfAborted(deps.signal);
  if (!witnessOk) {
    throw new SpendFlowError("witness", "locally reconstructed witness root != accepted root");
  }

  // (5) Outputs: change + zero dummy — each with its own nonce + payload.
  const outNotes = [];
  for (const value of [changeValue, 0n]) {
    const nonce = freshNoteNonce();
    const secrets = await raceSessionTask(deriveNoteSecretsV2(master, nonce), deps.signal);
    const outNote = await raceSessionTask(createSpendOutputNote(value, secrets), deps.signal);
    const leaf = await raceSessionTask(merkleLeaf(value, outNote.commitment), deps.signal);
    const plaintext = noteToBytesV2(outNote, nonce);
    const encrypted = encryptNotePayload(verificationKey, deps.principal, plaintext);
    outNotes.push({ value, nonce, note: outNote, leaf, plaintext, encrypted });
  }

  // (6) The byte-exact request (resubmission-identical, S-38 fingerprint basis).
  const spendId = freshSpendId();
  const att = attRaw;
  const request: PrivateSpendRequest = {
    spendId: BigInt(spendId),
    circuitVersion: att.circuit_version,
    proofSystemId: att.proof_system,
    verifyingKeyHash: new Uint8Array(att.vk_hash),
    rootReference: accepted.root,
    poolVersion: att.pool_version,
    proofBytes: new Uint8Array(0), // filled after proof generation — journal keeps the envelope fields
    nullifiers: [note.nullifier],
    outputCommitments: outNotes.map((o) => o.leaf),
    encryptedOutputs: outNotes.map((o) => o.encrypted),
    fee,
    publicPayout:
      input.payout === undefined
        ? null
        : {
            destination: input.payout.destination,
            destinationSubaccount: input.payout.subaccount,
            publicAmount,
          },
    expectedDeploymentConfigHash: deps.expectedDeploymentConfigHash,
  };

  // (7) ONE atomic journal+lock write BEFORE proof generation or any wire
  // call (Critical contract). The CAS resolution = "persisted and confirmed".
  const fingerprintHex = await raceSessionTask(intentFingerprintHex({
    nullifier: note.nullifier,
    outputLeaves: outNotes.map((o) => o.leaf),
    payout:
      input.payout === undefined
        ? null
        : {
            destination: input.payout.destination,
            subaccount: input.payout.subaccount,
            publicAmount,
          },
    fee,
  }), deps.signal);
  throwIfAborted(deps.signal);
  const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  await deps.journal.beginSpend(input.inputLeafIndex, {
    spendId,
    nullifierHex: hex(note.nullifier),
    inputLeafIndex: input.inputLeafIndex.toString(10),
    outputLeavesHex: outNotes.map((o) => hex(o.leaf)),
    outNoncesHex: outNotes.map((o) => hex(o.nonce)),
    encryptedOutputsHex: outNotes.map((o) => hex(o.encrypted)),
    requestJson: serializeSpendRequest(request),
    intentFingerprintHex: fingerprintHex,
    feeStsh: fee.toString(10),
    ...(input.payout !== undefined
      ? {
          publicPayout: {
            destinationText: input.payout.destination.toText(),
            ...(input.payout.subaccount !== null ? { subaccountHex: hex(input.payout.subaccount) } : {}),
            publicAmount: publicAmount.toString(10),
            recipientNet: input.payout.recipientNet.toString(10),
          },
        }
      : {}),
    acceptedRootHex: hex(accepted.root),
    manifestVersion: 1,
    createdAtNs: now().toString(10),
  });

  // (8) Proof generation over VERIFIED Blob URLs only (revoked in finally) —
  // then the 256-byte compact encoding and the canonical 9-signal compare.
  // The entry stays NEVER-DISPATCHED through all of this: any failure before
  // dispatch archives the intent and restores the note atomically.
  try {
    throwIfAborted(deps.signal);
    const spendReq: SpendRequest = {
      inputNote: {
        value: note.value,
        recipientPk: note.recipientPk,
        rho: note.rho,
        rseed: note.rseed,
        commitment: note.commitment,
        nullifier: note.nullifier,
      },
      spendKey: (await raceSessionTask(deriveNoteSecretsV2(master, note.nonce), deps.signal)).spendKey,
      merklePath: { elements: witness.elements, indices: witness.indices },
      anchor: accepted.root,
      outputNote1: outNotes[0].note,
      outputNote2: outNotes[1].note,
      publicAmount,
      fee,
      ...(payoutTarget !== undefined ? { payout: payoutTarget } : {}),
    };
    const spawnWorker = deps.spawnWorker ?? (() => {
      throw new SpendFlowError("proof", "no prover worker is wired in this build");
    });
    const proof = await raceSessionTask(
      (deps.loadAssets ?? withVerifiedProverAssets)(
        (assets) => generateSpendProof(spendReq, assets, spawnWorker, undefined, deps.signal),
        deps.signal,
      ),
      deps.signal,
    );
    const proofBytes = encodeGroth16Proof(proof.proof);

    // Canonical 9-signal compare (bigint equality) against request-derived values.
    const expected: bigint[] = [
      leToBigint(accepted.root),
      leToBigint(note.nullifier),
      leToBigint(outNotes[0].leaf),
      leToBigint(outNotes[1].leaf),
      publicAmount,
      fee,
      leToBigint(payoutTarget?.recipientPrincipal ?? new Uint8Array(32)),
      leToBigint(payoutTarget?.subaccountLo ?? new Uint8Array(32)),
      leToBigint(payoutTarget?.subaccountHi ?? new Uint8Array(32)),
    ];
    const actual = proof.publicSignals.map((s) => BigInt(s));
    if (actual.length !== 9 || !expected.every((v, i) => v === actual[i])) {
      throw new SpendFlowError(
        "signals",
        "proof public signals do not match the request-derived values (9-signal canonical compare failed)",
      );
    }

    // (8b) Fee-basis revalidation BEFORE the final request is persisted: if
    // the proof-bound fee basis (governance spend fee or the ledger fee under
    // a public payout) drifted since journaling, the proof is stale — archive
    // the never-dispatched intent (note restored) and report drift so the
    // caller rebuilds a fresh intent.
    // A-7: re-derive on the SAME basis as (3). Re-reading only the flat field
    // here would compare the wrong number under a payout — it would miss a
    // governance change to the unshield bps or flat minimum entirely, and would
    // report drift on every payout spend if the two ever differed.
    const feeNow = privateSpendFee(
      input.payout === undefined ? undefined : publicAmount,
      await raceSessionTask(deps.pool.getGovernanceFeeParams(), deps.signal),
    );
    if (feeNow !== fee) {
      await deps.journal.archiveNeverDispatched(spendId, input.inputLeafIndex, "fee basis drifted");
      throw new SpendFlowError(
        "fee-stale",
        `governance spend fee changed mid-flight (${fee} → ${feeNow}) — intent archived; rebuild with fresh parameters`,
      );
    }
    if (input.payout !== undefined) {
      const ledgerFeeNow = await raceSessionTask(deps.token.fee(), deps.signal);
      if (ledgerFeeNow !== publicAmount - input.payout.recipientNet) {
        await deps.journal.archiveNeverDispatched(spendId, input.inputLeafIndex, "ledger fee drifted");
        throw new SpendFlowError(
          "fee-stale",
          "ledger fee changed mid-flight — intent archived; rebuild with fresh parameters",
        );
      }
    }

    // (8c) Persist the COMPLETE final request (with proof bytes) into the
    // journal — the byte-identical replay material for §10.1 recovery.
    const finalRequest: PrivateSpendRequest = { ...request, proofBytes };
    await deps.journal.persistFinalRequest(spendId, serializeSpendRequest(finalRequest));
    throwIfAborted(deps.signal);

    // (9) Dispatch marker (immediately before the wire call), then submit —
    throwIfAborted(deps.signal);
    deps.onDispatchBoundary?.();
    // exactly 1 nullifier / 2 outer Merkle leaves.
    await deps.journal.markDispatched(spendId, now().toString(10));
    await deps.pool.privateSpend(finalRequest, deps.lease?.draw("privateSpend"));
    // Authoritative Ok → input evicted (spent) + the completion transition
    // recorded exactly once (idempotent transitions). The change material
    // (nonces + encrypted outputs) stays in the journal; the L3b validated
    // scanner is the ONLY change-activation path — nothing unvalidated ever
    // reaches balance, and dedup-by-leaf-index makes double-insert impossible.
    await deps.journal.finalizeFromSpendOk(spendId, input.inputLeafIndex);
    return { spendId, changeValue, publicAmount, fee };
  } catch (err) {
    // Any failure BEFORE the dispatch marker (artifact, prover, encoder,
    // signal mismatch, fee drift) archives the NEVER-DISPATCHED intent and
    // restores the note atomically — a genuinely unsubmitted note is never
    // left locked. (The entry is already 'dispatched' only past step 9; those
    // failures route to §10.1/§10.2 recovery instead.)
    const entry = await deps.journal.find(spendId);
    if (entry?.status === "planned") {
      await deps.journal.archiveNeverDispatched(
        spendId,
        input.inputLeafIndex,
        err instanceof Error ? err.message : String(err),
      );
    }
    if (err instanceof SpendFlowError) throw err;
    // WALLET-V12 O-3 / E-2(c): an ADMISSION refusal wrote no pool record. The
    // entry stays `dispatched` (never archived — the ONLY unlock path is a
    // never-dispatched intent), the persisted final request is the retry
    // material, and recovery retries the SAME spend_id after retry_after_ns.
    // A fresh run is never a resubmission (fresh CSPRNG id), so there is no
    // status query here (E-1 lives on the replay path only).
    const admission = parseSpendAdmission(err);
    if (admission !== null) {
      throw new SpendFlowError("submit", spendAdmissionCopy(admission), admission);
    }
    throw new SpendFlowError("submit", err instanceof Error ? err.message : String(err));
  }
}

// ── §10.1/§10.2 recovery (advisory-query-driven, update-validated) ───────────

export type SpendRecoveryAction =
  | { kind: "replay-same-intent" }
  | { kind: "retry-same-id" }
  | { kind: "retry-payout" }
  | {
      kind: "keep-locked";
      /** Set when a same-id retry/replay was refused at admission (E-2(c)). */
      admission?: SpendAdmission;
      /** E-1: the advisory query says finalized — copy only, no journal effect. */
      alreadyWentThrough?: boolean;
    }
  | { kind: "fresh-id" }
  | { kind: "archive-never-dispatched" }
  | { kind: "none-maybe-never-submitted" };

/**
 * The §10.1 table as a pure decision function over the ADVISORY status —
 * every action is update-validated; NO permanent effect comes from the query.
 *
 * WALLET-V12 E-2(c) (Addendum 1a): a `dispatched` entry with NO readable pool
 * record is first retried with the SAME spend_id (`retry-same-id`) — the pool
 * writes no record when it refuses at admission, so None is the expected
 * status after such a refusal and the same id may be resubmitted. Only the
 * outcome of that update classifies further (see `reconcileSpendEntry`):
 * `Ok` → finalized; admission refusal → keep-locked (retry later, same id);
 * `DuplicateSpendId` (the id is genuinely held by a record we cannot read) →
 * the §10.2 fresh-id path; anything else → keep-locked.
 */
export function recoveryActionForAdvisory(
  status: { kind: string } | null,
  journalStatus: string | null,
): SpendRecoveryAction {
  if (status === null) {
    // S-23b: None is indistinguishable (never-submitted vs unauthorized).
    // A never-dispatched local entry may be archived locally (no record exists).
    if (journalStatus === "planned") return { kind: "archive-never-dispatched" };
    // E-2(c): same id first; fresh-id only after the update says DuplicateSpendId.
    if (journalStatus === "dispatched") return { kind: "retry-same-id" };
    return { kind: "fresh-id" }; // settled retry still None + nullifier unspent → collision
  }
  switch (status.kind) {
    case "finalized":
      return { kind: "replay-same-intent" }; // replay's update Ok is the eviction authority
    case "payout-pending":
      return { kind: "retry-payout" }; // SAME spend_id — the update Ok carries authority
    default:
      return { kind: "keep-locked" }; // in-flight / unknown / operator rows: never resubmit blindly
  }
}

// ── Recovery orchestration (implemented, not just classified) ────────────────

export interface SpendRecoveryDeps {
  pool: PoolCanister;
  journal: SpendJournal;
  now?: () => bigint;
  /**
   * WL-2b: recovery's EFFECTFUL arms need an authorising gesture like any other
   * public action. Absent (the automatic classify-only pass), a repair that
   * would reach the wire is refused by the wrapper — which is the point.
   */
  lease?: OperationLease;
}

const hexOf = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (s: string): Uint8Array =>
  Uint8Array.from({ length: s.length / 2 }, (_, i) => parseInt(s.slice(i * 2, i * 2 + 2), 16));

interface SerializedRequest {
  spendId: string;
  circuitVersion: number;
  proofSystemId: string;
  verifyingKeyHash: string;
  rootReference: string;
  poolVersion: number;
  proofBytes: string;
  nullifiers: string[];
  outputCommitments: string[];
  encryptedOutputs: string[];
  fee: string;
  publicPayout: {
    destination: string;
    destinationSubaccount: string | null;
    publicAmount: string;
  } | null;
  expectedDeploymentConfigHash: string;
}

/** Serialize the FINAL request (with proof bytes) for byte-identical replay. */
export function serializeSpendRequest(req: PrivateSpendRequest): string {
  const s: SerializedRequest = {
    spendId: req.spendId.toString(10),
    circuitVersion: req.circuitVersion,
    proofSystemId: req.proofSystemId,
    verifyingKeyHash: hexOf(req.verifyingKeyHash),
    rootReference: hexOf(req.rootReference),
    poolVersion: req.poolVersion,
    proofBytes: hexOf(req.proofBytes),
    nullifiers: req.nullifiers.map(hexOf),
    outputCommitments: req.outputCommitments.map(hexOf),
    encryptedOutputs: req.encryptedOutputs.map(hexOf),
    fee: req.fee.toString(10),
    publicPayout:
      req.publicPayout === null
        ? null
        : {
            destination: req.publicPayout.destination.toText(),
            destinationSubaccount:
              req.publicPayout.destinationSubaccount === null
                ? null
                : hexOf(req.publicPayout.destinationSubaccount),
            publicAmount: req.publicPayout.publicAmount.toString(10),
          },
    expectedDeploymentConfigHash: req.expectedDeploymentConfigHash
      ? hexOf(req.expectedDeploymentConfigHash)
      : "",
  };
  return JSON.stringify(s);
}

/**
 * Deserialize a persisted final request — byte-identical replay material.
 *
 * DECODE-COMPATIBILITY (lane F1-PRIV / R1-F1, decision recorded here):
 * records persisted BEFORE this lane carry `inputAmounts`/`outputAmounts` — the
 * cleartext hidden note values this lane removes from the wire. The choice made
 * is **ignore-on-read**: the keys are absent from `SerializedRequest` and are
 * never read, so a legacy record still deserializes (JSON.parse ignores extra
 * keys) and the rehydrated request carries neither field. Nothing this lane
 * writes ever contains them again.
 *
 * Drop-on-rehydrate (rewriting the stored record on first read) was A1's
 * recommendation and was NOT taken: `SpendJournal.persistFinalRequest`
 * (`storage/spendJournal.ts:175-189`) refuses any write unless the entry is
 * still `planned`, and a recovered record is by definition past that state, so
 * a read-path rewrite would either violate the journal state machine or need a
 * new mutation primitive — a change to the recovery contract, outside this
 * lane. Filed as `NOTE_F1-PRIV_builder3_decode_compat_ignore_on_read.md`.
 *
 * The one path that DOES rewrite the record — §10.2 fresh-id collision retry —
 * re-serializes through `serializeSpendRequest` below and therefore drops the
 * legacy fields for that entry as a side effect of the normal write.
 */
export function deserializeSpendRequest(json: string): PrivateSpendRequest {
  const s = JSON.parse(json) as SerializedRequest;
  return {
    spendId: BigInt(s.spendId),
    circuitVersion: s.circuitVersion,
    proofSystemId: s.proofSystemId,
    verifyingKeyHash: unhex(s.verifyingKeyHash),
    rootReference: unhex(s.rootReference),
    poolVersion: s.poolVersion,
    proofBytes: unhex(s.proofBytes),
    nullifiers: s.nullifiers.map(unhex),
    outputCommitments: s.outputCommitments.map(unhex),
    encryptedOutputs: s.encryptedOutputs.map(unhex),
    fee: BigInt(s.fee),
    publicPayout:
      s.publicPayout === null
        ? null
        : {
            destination: Principal.fromText(s.publicPayout.destination),
            destinationSubaccount:
              s.publicPayout.destinationSubaccount === null
                ? null
                : unhex(s.publicPayout.destinationSubaccount),
            publicAmount: BigInt(s.publicPayout.publicAmount),
          },
    expectedDeploymentConfigHash: unhex(s.expectedDeploymentConfigHash),
  };
}

/** The recovery page cap + bound (fail closed on malformed listings). */
const RECOVERY_PAGE_LIMIT = 100n;
const MAX_RECOVERY_PAGES = 100;

/**
 * Fresh-device recovery (P-REC): page the caller's active spends through the
 * identity-bound index and import each unknown one as a typed
 * `recovery-required` entry — no output material on a fresh device, so NO
 * fabricated change and NO unlocked input; the scanner recovers encrypted
 * outputs from the tree once they land.
 *
 * Fail-closed listing validation (H): page length ≤ cap, spend ids strictly
 * increasing within and across pages, no duplicates, nextCursor strictly
 * ahead of the last id seen, and a hard page-count bound — a malformed or
 * compromised advisory listing can never loop or corrupt recovery state.
 */
export async function recoverSpendsFromPool(deps: SpendRecoveryDeps): Promise<number> {
  let imported = 0;
  let cursor: bigint | null = null;
  let prevCursor: bigint | null = null;
  let lastId = -1n;
  const seen = new Set<string>();
  for (let pageNum = 0; pageNum < MAX_RECOVERY_PAGES; pageNum += 1) {
    const page = await deps.pool.listMyActiveSpends(cursor, RECOVERY_PAGE_LIMIT);
    if (BigInt(page.spends.length) > RECOVERY_PAGE_LIMIT) {
      throw new SpendFlowError(
        "recovery",
        `active-spend page holds ${page.spends.length} records, above the ${RECOVERY_PAGE_LIMIT} cap`,
      );
    }
    for (const record of page.spends) {
      const idStr = record.spendId.toString(10);
      if (seen.has(idStr)) {
        throw new SpendFlowError("recovery", `duplicate spend id ${idStr} across recovery pages`);
      }
      seen.add(idStr);
      if (record.spendId <= lastId) {
        throw new SpendFlowError(
          "recovery",
          `active-spend listing is not strictly increasing (id ${idStr} after ${lastId})`,
        );
      }
      lastId = record.spendId;

      const existing = await deps.journal.find(idStr);
      if (existing === null) {
        const nullifier = record.nullifiers[0];
        const ok = await deps.journal.importRecoveryRequired({
          spendId: idStr,
          nullifierHex: nullifier !== undefined ? hexOf(nullifier) : "",
          inputLeafIndex: "",
          outputLeavesHex: record.outputCommitments.map(hexOf),
          outNoncesHex: ["", ""],
          encryptedOutputsHex: ["", ""],
          requestJson: "",
          intentFingerprintHex: "",
          feeStsh: "0",
          acceptedRootHex: "",
          manifestVersion: 1,
          createdAtNs: record.createdAtNs.toString(10),
        });
        if (ok) imported += 1;
      }
    }
    cursor = page.nextCursor;
    if (cursor === null) return imported;
    if (cursor < lastId || (prevCursor !== null && cursor <= prevCursor)) {
      throw new SpendFlowError(
        "recovery",
        `recovery cursor ${cursor} does not advance (last id ${lastId}, previous cursor ${prevCursor}) — refusing to loop on a malformed listing`,
      );
    }
    prevCursor = cursor;
  }
  throw new SpendFlowError(
    "recovery",
    `active-spend recovery exceeded ${MAX_RECOVERY_PAGES} pages — refusing to trust an unbounded listing`,
  );
}

/** Parse the optional input leaf index: "" (unknown) → null, never 0n. */
function optionalLeafIndex(raw: string): bigint | null {
  return raw === "" ? null : BigInt(raw);
}

/**
 * Same-intent replay (§10.1 advisory Finalized, and the E-2(c) same-id retry
 * after an admission refusal): deserialize the persisted FINAL request (with
 * proof bytes) and replay it BYTE-IDENTICALLY. The pool's Ok is the ONLY
 * eviction authority; the replay performs the completion transition. Never
 * reconstructs outputs/fees/roots/proof.
 *
 * An ADMISSION refusal throws a `SpendFlowError` carrying the parsed
 * admission and mutates NO journal state. E-1 (C-3, SSA F-1): the pool checks
 * FAILED_VERIFY_LIMIT and INFLIGHT_LIMIT BEFORE its idempotency read, so on a
 * replay of an already-finalized id they can mask the idempotent Ok — for
 * those two codes the advisory `get_spend_status` is asked, and a `finalized`
 * answer changes the COPY only ("already went through"); the entry stays
 * `dispatched` until a later replay's authoritative Ok finalizes it.
 */
export async function replaySameIntent(
  deps: SpendRecoveryDeps,
  entry: SpendJournalEntryState,
): Promise<void> {
  if (entry.requestJson === "") {
    throw new SpendFlowError("journal", `entry ${entry.spendId} has no persisted final request`);
  }
  const request = deserializeSpendRequest(entry.requestJson);
  if (request.spendId.toString(10) !== entry.spendId) {
    throw new SpendFlowError("journal", `entry ${entry.spendId} request/id mismatch`);
  }
  try {
    await deps.pool.privateSpend(request, deps.lease?.draw("privateSpend"));
  } catch (err) {
    const admission = parseSpendAdmission(err);
    if (admission === null) throw err;
    let alreadyWentThrough = false;
    if (masksIdempotentOk(admission.code)) {
      try {
        const record = await deps.pool.getSpendStatus(request.spendId);
        alreadyWentThrough = record?.status.kind === "finalized";
      } catch {
        // Advisory only: an unreadable status falls through to the per-code copy.
      }
    }
    throw new SpendFlowError(
      "submit",
      alreadyWentThrough ? SPEND_ALREADY_WENT_THROUGH_COPY : spendAdmissionCopy(admission),
      admission,
      alreadyWentThrough,
    );
  }
  await deps.journal.finalizeFromSpendOk(entry.spendId, optionalLeafIndex(entry.inputLeafIndex));
}

/**
 * §10.2 fresh-id collision recovery (S-23b — IMPLEMENTED end to end):
 * the settled retry returned None (no record we can read) while the nullifier
 * is verifiably UNSPENT (checked against the strictly downloaded FULL spent
 * set — L0-F; the wallet never sends its nullifier to a per-user membership
 * query). Mints a fresh spend_id, retains the original as a collision record,
 * persists the replacement request (same intent, new id — the proof stays
 * valid, spend_id is not proof-bound), marks it dispatched, and SUBMITS it.
 * The authoritative Ok completes normally (input spent via the strict
 * nullifier binding); a transport-uncertain failure leaves the new entry
 * `dispatched` (ambiguous — NEVER archived as never-submitted). A fresh
 * attempt that itself collides can never mint another id (collisionOf).
 * An ADMISSION refusal of the fresh attempt (E-2(c) item 4) also leaves it
 * `dispatched`; recovery then retries THAT id same-id (`retry-same-id`), so
 * it never needs a second fresh id.
 */
export async function recoverSpendFreshId(
  deps: SpendRecoveryDeps & {
    nullifiers: {
      getNullifiersPage(startAfter: Uint8Array | null, limit: bigint): Promise<Uint8Array[]>;
      count(): Promise<bigint>;
    };
  },
  entry: SpendJournalEntryState,
): Promise<string> {
  if (entry.collisionOf !== undefined) {
    throw new SpendFlowError(
      "recovery",
      `entry ${entry.spendId} is already a fresh-id retry of ${entry.collisionOf} — a second fresh id would loop`,
    );
  }
  if (entry.requestJson === "") {
    throw new SpendFlowError("recovery", `entry ${entry.spendId} has no persisted request to retry`);
  }
  const nullifier = unhex(entry.nullifierHex);
  if (nullifier.length !== 32) {
    throw new SpendFlowError("recovery", `entry ${entry.spendId} has no valid input nullifier`);
  }
  // L0-F: download the public spent set (strict walk) and check LOCALLY.
  const spentSet = await downloadSpentSet(deps.nullifiers);
  if (spentSet.has(hexOf(nullifier))) {
    throw new SpendFlowError(
      "recovery",
      "the input nullifier is SPENT — fresh-id recovery does not apply (the spend likely finalized under the unreadable record; reconcile instead of retrying)",
    );
  }
  const newSpendId = freshSpendId();
  const request = deserializeSpendRequest(entry.requestJson);
  request.spendId = BigInt(newSpendId);
  const { spendId: _drop, collisionOf: _drop2, ...rest } = entry;
  await deps.journal.recordCollisionRetry(entry.spendId, {
    ...rest,
    spendId: newSpendId,
    requestJson: serializeSpendRequest(request),
    collisionOf: entry.spendId,
    createdAtNs: (deps.now?.() ?? BigInt(Date.now()) * 1_000_000n).toString(10),
  });
  // Dispatch + submit the replacement (the wire call actually happens here —
  // a journal record alone recovers nothing).
  await deps.journal.markDispatched(
    newSpendId,
    (deps.now?.() ?? BigInt(Date.now()) * 1_000_000n).toString(10),
  );
  try {
    await deps.pool.privateSpend(request, deps.lease?.draw("privateSpend"));
    await deps.journal.finalizeFromSpendOk(
      newSpendId,
      entry.inputLeafIndex === "" ? null : BigInt(entry.inputLeafIndex),
    );
  } catch (err) {
    // E-2(c) item 4: refused at admission — no record written; the entry stays
    // `dispatched` and the next reconcile retries this SAME new id.
    const admission = parseSpendAdmission(err);
    if (admission !== null) {
      throw new SpendFlowError("submit", spendAdmissionCopy(admission), admission);
    }
    // Transport-uncertain: the fresh entry stays `dispatched` (ambiguous) —
    // the §10.1 recovery table owns it from here; it is NEVER archived as
    // never-submitted.
    throw new SpendFlowError(
      "submit",
      `fresh-id retry ${newSpendId} submitted but the outcome is uncertain; it stays locked pending reconciliation: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  return newSpendId;
}

/**
 * §10.1/§10.2 reconciliation for ONE journal entry: the advisory query picks
 * the update-validated action; the UPDATE performs every permanent effect.
 * Returns the action taken (for status display). A replay or same-id retry
 * refused at admission returns `keep-locked` carrying the parsed admission
 * (and E-1's `alreadyWentThrough` copy flag) with NO journal effect; a
 * same-id retry answered `DuplicateSpendId` returns `fresh-id` for the
 * caller's §10.2 path.
 */
export async function reconcileSpendEntry(
  deps: SpendRecoveryDeps,
  entry: SpendJournalEntryState,
): Promise<SpendRecoveryAction> {
  const record = await deps.pool.getSpendStatus(BigInt(entry.spendId));
  const action = recoveryActionForAdvisory(record?.status ?? null, entry.status);
  switch (action.kind) {
    case "replay-same-intent":
      try {
        await replaySameIntent(deps, entry);
      } catch (err) {
        // Refused at admission (E-1): nothing was mutated; keep it locked and
        // replay later. Every other failure propagates exactly as before.
        if (err instanceof SpendFlowError && err.admission !== undefined) {
          return keepLockedForAdmission(err);
        }
        throw err;
      }
      return action;
    case "retry-same-id":
      // E-2(c): the same spend_id first; the UPDATE's answer classifies.
      try {
        await replaySameIntent(deps, entry);
      } catch (err) {
        if (err instanceof SpendFlowError && err.admission !== undefined) {
          return keepLockedForAdmission(err);
        }
        if (err instanceof PoolCallError && "DuplicateSpendId" in err.poolError) {
          // The id is genuinely burned by a record we cannot read — the
          // EXISTING §10.2 fresh-id path (spent-set precheck unchanged).
          return { kind: "fresh-id" };
        }
        // Any other failure: ambiguous — stays locked (no journal effect).
        return { kind: "keep-locked" };
      }
      return action;
    case "retry-payout": {
      await deps.pool.retryPrivateSpendPayout(
        BigInt(entry.spendId),
        deps.lease?.draw("retryPrivateSpendPayout"),
      );
      // The retry's update Ok completes the spend — parent nullifier already
      // spent (registry finality): input → spent (only when the leaf index is
      // KNOWN and nullifier-bound), NEVER unlocked.
      await deps.journal.finalizeFromSpendOk(entry.spendId, optionalLeafIndex(entry.inputLeafIndex));
      return action;
    }
    case "archive-never-dispatched":
      await deps.journal.archiveNeverDispatched(
        entry.spendId,
        optionalLeafIndex(entry.inputLeafIndex),
        "no pool record — never dispatched",
      );
      return action;
    case "fresh-id":
    case "keep-locked":
    case "none-maybe-never-submitted":
      return action;
  }
}

function keepLockedForAdmission(err: SpendFlowError): SpendRecoveryAction {
  return {
    kind: "keep-locked",
    ...(err.admission !== undefined ? { admission: err.admission } : {}),
    ...(err.alreadyWentThrough === true ? { alreadyWentThrough: true } : {}),
  };
}
