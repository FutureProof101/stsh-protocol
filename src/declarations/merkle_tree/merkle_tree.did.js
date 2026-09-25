export const idlFactory = ({ IDL }) => {
  const AuthorityRefs = IDL.Record({ 'pool_canister' : IDL.Principal });
  const ScanHead = IDL.Record({
    'root' : IDL.Vec(IDL.Nat8),
    'leaf_count' : IDL.Nat64,
  });
  const ScanPageEntry = IDL.Record({
    'encrypted_payload' : IDL.Vec(IDL.Nat8),
    'leaf' : IDL.Vec(IDL.Nat8),
    'index' : IDL.Nat64,
  });
  return IDL.Service({
    'append_commitment' : IDL.Func(
        [IDL.Vec(IDL.Nat8), IDL.Vec(IDL.Nat8)],
        [IDL.Variant({ 'Ok' : IDL.Nat64, 'Err' : IDL.Text })],
        [],
      ),
    'append_commitments' : IDL.Func(
        [IDL.Vec(IDL.Tuple(IDL.Vec(IDL.Nat8), IDL.Vec(IDL.Nat8)))],
        [IDL.Variant({ 'Ok' : IDL.Vec(IDL.Nat64), 'Err' : IDL.Text })],
        [],
      ),
    'cycle_balance' : IDL.Func([], [IDL.Nat], ['query']),
    'get_authority_refs' : IDL.Func(
        [],
        [IDL.Variant({ 'Ok' : AuthorityRefs, 'Err' : IDL.Text })],
        ['query'],
      ),
    'get_leaf' : IDL.Func([IDL.Nat64], [IDL.Opt(IDL.Vec(IDL.Nat8))], ['query']),
    'get_payloads' : IDL.Func(
        [IDL.Nat64, IDL.Nat64],
        [IDL.Vec(IDL.Tuple(IDL.Nat64, IDL.Vec(IDL.Nat8)))],
        ['query'],
      ),
    'get_root' : IDL.Func([], [IDL.Vec(IDL.Nat8)], ['query']),
    'get_root_at_index' : IDL.Func(
        [IDL.Nat64],
        [IDL.Opt(IDL.Vec(IDL.Nat8))],
        ['query'],
      ),
    'get_scan_head' : IDL.Func([], [ScanHead], ['query']),
    'get_scan_page' : IDL.Func(
        [IDL.Nat64, IDL.Nat64],
        [IDL.Variant({ 'Ok' : IDL.Vec(ScanPageEntry), 'Err' : IDL.Text })],
        ['query'],
      ),
    'is_valid_anchor' : IDL.Func([IDL.Vec(IDL.Nat8)], [IDL.Bool], ['query']),
    'leaf_count' : IDL.Func([], [IDL.Nat64], ['query']),
  });
};
export const init = ({ IDL }) => { return [IDL.Principal]; };
