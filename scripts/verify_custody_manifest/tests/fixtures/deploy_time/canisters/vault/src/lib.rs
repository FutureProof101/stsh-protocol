// Fixture: minimal vault source carrying the real REQUIRED_CUTOVER const
// format (mirrors canisters/vault/src/lib.rs at integration time). Drives
// the deploy-time artifact check's source scan.

pub const CUTOVER_SOLVENCY_STATUS_PURPOSE: &str = "solvency_status";
pub const CUTOVER_SOLVENCY_STATUS_PRINCIPAL: &str = "pyeop-7yaaa-aaaam-ajfja-cai";
pub const CUTOVER_WALLET_FRONTEND_PURPOSE: &str = "wallet_frontend";
pub const CUTOVER_WALLET_FRONTEND_PRINCIPAL: &str = "s3tyu-aaaaa-aaaab-qhdjq-cai";

/// The required cutover set as (purpose, principal) pairs — exactly these,
/// no more, no fewer.
pub const REQUIRED_CUTOVER: [(&str, &str); 2] = [
    (
        CUTOVER_SOLVENCY_STATUS_PURPOSE,
        CUTOVER_SOLVENCY_STATUS_PRINCIPAL,
    ),
    (
        CUTOVER_WALLET_FRONTEND_PURPOSE,
        CUTOVER_WALLET_FRONTEND_PRINCIPAL,
    ),
];
