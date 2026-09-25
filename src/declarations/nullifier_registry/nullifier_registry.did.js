export const idlFactory = ({ IDL }) => {
  return IDL.Service({
    'contains_nullifier' : IDL.Func([IDL.Vec(IDL.Nat8)], [IDL.Bool], ['query']),
    'contains_nullifiers_batch' : IDL.Func(
        [IDL.Vec(IDL.Vec(IDL.Nat8))],
        [IDL.Vec(IDL.Bool)],
        ['query'],
      ),
    'count' : IDL.Func([], [IDL.Nat64], ['query']),
    'cycle_balance' : IDL.Func([], [IDL.Nat], ['query']),
    'get_authority_refs' : IDL.Func([], [IDL.Principal], ['query']),
    'get_nullifiers_page' : IDL.Func(
        [IDL.Opt(IDL.Vec(IDL.Nat8)), IDL.Nat64],
        [IDL.Variant({ 'Ok' : IDL.Vec(IDL.Vec(IDL.Nat8)), 'Err' : IDL.Text })],
        ['query'],
      ),
    'insert_batch' : IDL.Func(
        [IDL.Vec(IDL.Vec(IDL.Nat8))],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text })],
        [],
      ),
    'insert_nullifier' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text })],
        [],
      ),
    'spent_at' : IDL.Func([IDL.Vec(IDL.Nat8)], [IDL.Opt(IDL.Nat64)], ['query']),
    'spent_at_for_controller_update' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [IDL.Opt(IDL.Nat64)],
        [],
      ),
  });
};
export const init = ({ IDL }) => { return [IDL.Principal]; };
