import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export interface AuthorityRefs { 'pool_canister' : Principal }
export interface ScanHead {
  'root' : Uint8Array | number[],
  'leaf_count' : bigint,
}
export interface ScanPageEntry {
  'encrypted_payload' : Uint8Array | number[],
  'leaf' : Uint8Array | number[],
  'index' : bigint,
}
export interface _SERVICE {
  'append_commitment' : ActorMethod<
    [Uint8Array | number[], Uint8Array | number[]],
    { 'Ok' : bigint } |
      { 'Err' : string }
  >,
  'append_commitments' : ActorMethod<
    [Array<[Uint8Array | number[], Uint8Array | number[]]>],
    { 'Ok' : BigUint64Array | bigint[] } |
      { 'Err' : string }
  >,
  'cycle_balance' : ActorMethod<[], bigint>,
  'get_authority_refs' : ActorMethod<
    [],
    { 'Ok' : AuthorityRefs } |
      { 'Err' : string }
  >,
  'get_leaf' : ActorMethod<[bigint], [] | [Uint8Array | number[]]>,
  'get_payloads' : ActorMethod<
    [bigint, bigint],
    Array<[bigint, Uint8Array | number[]]>
  >,
  'get_root' : ActorMethod<[], Uint8Array | number[]>,
  'get_root_at_index' : ActorMethod<[bigint], [] | [Uint8Array | number[]]>,
  'get_scan_head' : ActorMethod<[], ScanHead>,
  'get_scan_page' : ActorMethod<
    [bigint, bigint],
    { 'Ok' : Array<ScanPageEntry> } |
      { 'Err' : string }
  >,
  'is_valid_anchor' : ActorMethod<[Uint8Array | number[]], boolean>,
  'leaf_count' : ActorMethod<[], bigint>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
