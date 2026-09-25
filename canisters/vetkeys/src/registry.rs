// =============================================================================
// W-VETKEYS §C/§E — DEVICE REGISTRY DECISIONS (pure)
// =============================================================================
//
// The parts of `register_device` / `revoke_device` that are decisions rather
// than I/O: the §E registration rate limit and the device cap. Same idiom as
// `admission` and `tickets` — the endpoint is the impure shell.
//
// §H.4 of brief V3 is why these need no reservation machinery: neither endpoint
// contains an await, so each window check and its consumption are ONE atomic
// message. That is stated there as closing the class, not just the instance,
// and it is why the §H′ phase tag has no analogue here.

use crate::pins::{
    MAX_ACTIVE_DEVICES, REGISTRATION_QUOTA, REGISTRATION_WINDOW_NS, REPLACE_QUOTA,
    REPLACE_WINDOW_NS, REVOKE_QUOTA, REVOKE_WINDOW_NS,
};
use crate::state::RegistrationWindow;

/// §E — charge one `register_device` attempt against the caller's rolling 24 h
/// window, or refuse with the exact wait.
///
/// Charged whether the registration goes on to succeed or fail (brief V2 §E:
/// "successful or not"). The uniform rule is the same one lane A-2 adopted for
/// the meter, and for the same reason: if failures were free, the failure path
/// would be an unmetered loop against a caller-writable stable surface.
pub fn charge_registration(now_ns: u64, window: &mut RegistrationWindow) -> Result<(), u64> {
    charge_window(now_ns, window, REGISTRATION_QUOTA, REGISTRATION_WINDOW_NS)
}

/// D-1b v3 §2 — the same mechanism for `replace_envelope`, against its OWN
/// window. Same function, different counter: sharing the counter would couple
/// two unrelated operations' availability.
pub fn charge_replacement(now_ns: u64, window: &mut RegistrationWindow) -> Result<(), u64> {
    charge_window(now_ns, window, REPLACE_QUOTA, REPLACE_WINDOW_NS)
}

/// Opus-round RED-2 — the same mechanism for `revoke_device`, against its OWN
/// window. Revocation was the only update endpoint reaching P-256 verification
/// with no meter; charged whether the revocation succeeds or fails, so the
/// failure path is not an unmetered loop.
pub fn charge_revocation(now_ns: u64, window: &mut RegistrationWindow) -> Result<(), u64> {
    charge_window(now_ns, window, REVOKE_QUOTA, REVOKE_WINDOW_NS)
}

/// The shared sliding-window charge. Written once so the two limits cannot
/// drift apart in behaviour while claiming to be the same mechanism class.
fn charge_window(
    now_ns: u64,
    window: &mut RegistrationWindow,
    quota: u32,
    window_ns: u64,
) -> Result<(), u64> {
    window.attempts.retain(|t| now_ns.saturating_sub(*t) < window_ns);
    if window.attempts.len() >= quota as usize {
        let oldest = window.attempts.iter().min().copied().unwrap_or(now_ns);
        return Err(oldest.saturating_add(window_ns).saturating_sub(now_ns));
    }
    window.attempts.push(now_ns);
    Ok(())
}

/// Is a transcript still live at `now_ns`?
///
/// HALF-OPEN, the same convention as the §B ticket and the §H′ window: live
/// while `now < expiry`, DEAD at `expiry`. Pulled out as a function so the
/// nanosecond boundary is provable — from the client side of PocketIC it is
/// not, because the canister's clock advances between building a call and
/// executing it, so a `now + 1` expiry constructed by a test is already in the
/// past when the endpoint reads the time. The boundary arms therefore live
/// here; the endpoint arm proves past-is-refused / future-is-accepted.
pub fn approval_is_live(now_ns: u64, expiry_ns: u64) -> bool {
    now_ns < expiry_ns
}

/// The device cap counts ACTIVE devices only (brief V2 §E: "device cap stays 10
/// Active"). Revoked records are retained as evidence and must not consume the
/// cap — otherwise a user who rotated devices ten times could never register
/// another one, and the only way out would be deleting the evidence.
pub fn active_cap_reached(active_devices: usize) -> bool {
    active_devices >= MAX_ACTIVE_DEVICES
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_700_000_000_000_000_000;

    #[test]
    fn the_registration_window_admits_exactly_the_quota() {
        let mut w = RegistrationWindow::default();
        for i in 0..REGISTRATION_QUOTA {
            assert_eq!(charge_registration(T0, &mut w), Ok(()), "attempt {i}");
        }
        assert!(charge_registration(T0, &mut w).is_err(), "the sixth attempt in 24 h refuses");
    }

    /// The refusal's wait is EXACT on both sides, like §H′'s.
    #[test]
    fn the_registration_window_wait_is_exact() {
        let mut w = RegistrationWindow::default();
        for _ in 0..REGISTRATION_QUOTA {
            charge_registration(T0, &mut w).expect("budget");
        }
        let wait = charge_registration(T0, &mut w).expect_err("refused");
        // Regenerated at point of use: 24 hours after the oldest attempt.
        assert_eq!(wait, 24 * 60 * 60 * 1_000_000_000);
        assert!(charge_registration(T0 + wait - 1, &mut w).is_err(), "one ns early");
        assert!(charge_registration(T0 + wait, &mut w).is_ok(), "admitted exactly at the wait");
    }

    /// RED-2 — the revocation window admits exactly its quota, and its wait is
    /// exact on both sides (±1 ns): one ns early refuses, at the boundary the
    /// window has slid.
    #[test]
    fn the_revocation_window_admits_exactly_the_quota_with_exact_wait() {
        let mut w = RegistrationWindow::default();
        for i in 0..REVOKE_QUOTA {
            assert_eq!(charge_revocation(T0, &mut w), Ok(()), "attempt {i}");
        }
        let wait = charge_revocation(T0, &mut w).expect_err("the sixth revoke in 24 h refuses");
        // Regenerated at point of use: 24 hours after the oldest attempt.
        assert_eq!(wait, 24 * 60 * 60 * 1_000_000_000);
        assert!(charge_revocation(T0 + wait - 1, &mut w).is_err(), "one ns early");
        assert!(charge_revocation(T0 + wait, &mut w).is_ok(), "admitted exactly at the wait");
    }

    /// Refused attempts still count — the window is charged, so a caller
    /// cannot spin on the failure path.
    #[test]
    fn refused_attempts_are_charged_too() {
        let mut w = RegistrationWindow::default();
        for _ in 0..REGISTRATION_QUOTA {
            charge_registration(T0, &mut w).expect("budget");
        }
        assert_eq!(w.attempts.len(), REGISTRATION_QUOTA as usize);
        // A refusal does not grow the list further (nothing to charge — the
        // budget is already spent), and it certainly does not shrink it.
        let _ = charge_registration(T0, &mut w);
        assert_eq!(w.attempts.len(), REGISTRATION_QUOTA as usize, "no refund on refusal");
    }

    #[test]
    fn the_window_slides() {
        let mut w = RegistrationWindow::default();
        for _ in 0..REGISTRATION_QUOTA {
            charge_registration(T0, &mut w).expect("budget");
        }
        assert!(charge_registration(T0 + REGISTRATION_WINDOW_NS, &mut w).is_ok());
        assert_eq!(w.attempts.len(), 1, "the old attempts aged out, only the new one stands");
    }

    /// The expiry boundary, ±1 ns, on both sides.
    #[test]
    fn the_approval_expiry_boundary_is_half_open() {
        let expiry = T0 + 60 * 1_000_000_000;
        assert!(approval_is_live(expiry - 1, expiry), "one ns before expiry: live");
        assert!(!approval_is_live(expiry, expiry), "AT expiry: dead");
        assert!(!approval_is_live(expiry + 1, expiry), "after expiry: dead");
    }

    /// An expiry of zero (or any past instant) is never live — there is no
    /// "unset means forever" reading of this field.
    #[test]
    fn a_zero_expiry_is_never_live() {
        assert!(!approval_is_live(T0, 0));
    }

    /// The replacement window is its own counter with the same shape, and
    /// spending one does NOT spend the other.
    #[test]
    fn replacement_and_registration_windows_are_independent() {
        let mut registrations = RegistrationWindow::default();
        let mut replacements = RegistrationWindow::default();
        for _ in 0..REPLACE_QUOTA {
            charge_replacement(T0, &mut replacements).expect("replacement budget");
        }
        assert!(charge_replacement(T0, &mut replacements).is_err(), "replacements exhausted");
        assert!(
            charge_registration(T0, &mut registrations).is_ok(),
            "exhausting replacements must not consume the registration allowance"
        );
    }

    #[test]
    fn the_cap_counts_active_devices_only() {
        assert!(!active_cap_reached(MAX_ACTIVE_DEVICES - 1));
        assert!(active_cap_reached(MAX_ACTIVE_DEVICES));
        assert!(active_cap_reached(MAX_ACTIVE_DEVICES + 1));
        // Regenerated at point of use.
        assert!(!active_cap_reached(9));
        assert!(active_cap_reached(10));
    }
}
