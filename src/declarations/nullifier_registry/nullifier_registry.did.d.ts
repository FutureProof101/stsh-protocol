import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export interface _SERVICE {
  'contains_nullifier' : ActorMethod<[Uint8Array | number[]], boolean>,
  'contains_nullifiers_batch' : ActorMethod<
    [Array<Uint8Array | number[]>],
    Array<boolean>
  >,
  'count' : ActorMethod<[], bigint>,
  'cycle_balance' : ActorMethod<[], bigint>,
  'get_authority_refs' : ActorMethod<[], Principal>,
  'get_nullifiers_page' : ActorMethod<
    [[] | [Uint8Array | number[]], bigint],
    { 'Ok' : Array<Uint8Array | number[]> } |
      { 'Err' : string }
  >,
  'insert_batch' : ActorMethod<
    [Array<Uint8Array | number[]>],
    { 'Ok' : null } |
      { 'Err' : string }
  >,
  'insert_nullifier' : ActorMethod<
    [Uint8Array | number[]],
    { 'Ok' : null } |
      { 'Err' : string }
  >,
  'spent_at' : ActorMethod<[Uint8Array | number[]], [] | [bigint]>,
  'spent_at_for_controller_update' : ActorMethod<
    [Uint8Array | number[]],
    [] | [bigint]
  >,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
