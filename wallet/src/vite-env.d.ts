/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_IC_HOST?: string;
  readonly VITE_FETCH_ROOT_KEY?: string;
  readonly VITE_POOL_CANISTER_ID?: string;
  readonly VITE_MERKLE_CANISTER_ID?: string;
  readonly VITE_VETKEYS_CANISTER_ID?: string;
  readonly VITE_TOKEN_CANISTER_ID?: string;
  readonly VITE_STAKING_CANISTER_ID?: string;
  readonly VITE_VESTING_CANISTER_ID?: string;
  readonly VITE_WALLET_SIGNER_URL?: string;
  readonly VITE_II_URL?: string;
  // L3a (C-DOM-2 / C-VK-3):
  readonly VITE_NULLIFIER_CANISTER_ID?: string;
  readonly VITE_FROZEN_POOL_CANISTER_ID?: string;
  readonly VITE_VETKD_KEY_NAME?: string;
  // WT-1 Addendum A (F-2): `config.ts` has read VITE_VERIFIER_CANISTER_ID since
  // L3c, but this interface never declared it and `.env.example` never listed
  // it, so the one knob for the canister the spend path fails closed on was
  // invisible in both places a developer would look. Declared now.
  //
  // For the SHIPPED build every id resolves from the hardcoded `DEFAULT_*`
  // constants in `config.ts`, never from here — the pinned bundle must not
  // depend on build-time env (Addendum A F-1). These remain supported ONLY as
  // local-replica dry-run overrides.
  readonly VITE_VERIFIER_CANISTER_ID?: string;
  readonly VITE_VAULT_CANISTER_ID?: string;
  readonly VITE_UPGRADER_CANISTER_ID?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

/**
 * J-25 (I1): `[build].source_sha` from deployment/mainnet/release_hashes.toml,
 * injected as a compile-time define by vite.config.ts / vitest.config.ts. It is
 * the CANISTER build source, not the commit that produced this UI.
 */
declare const __STSH_CANISTER_BUILD_SOURCE__: string | undefined;
