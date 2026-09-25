// =============================================================================
// W-VETKEYS §B — THE BOOTSTRAP TICKET (brief V2)
// =============================================================================
//
// WHAT THIS REPLACES. V1 §2 said the first device's registration "must ride a
// successful Layer 2 derive in the same session". SSA's RED-2 was that this is
// an ASSERTION, not something a canister can verify: "the same session" is not
// a thing the canister can see. The ticket makes it verifiable — the canister
// MINTS a capability at the end of the ruled ceremony and later CONSUMES it,
// so "this registration rode a real derive" becomes a state check rather than
// a claim about the client.
//
// MINT is strictly after: quota admission (§H′), eligibility admission (§D),
// and a SUCCESSFUL management derive. So a ticket cannot exist unless the full
// ceremony happened, for that principal, and was paid for.
//
// CONSUME is atomic with the registration it authorizes (§C): one message, one
// caller, the ticket's principal. That is what closes the substitution window —
// there is no interval in which a ticket exists "unbound" and could be paired
// with different registration fields.
//
// Pure decisions here; the endpoint is the shell. Same idiom as `admission`.

use crate::pins::BOOTSTRAP_TICKET_TTL_NS;
use crate::state::BootstrapTicket;

/// Why a bootstrap registration is not authorized (brief V2 §B: typed
/// `BootstrapNotAuthorized { reason }`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketRejection {
    /// No ticket for this principal: no derive was performed, or it was
    /// performed by someone else.
    NoTicket,
    /// Minted, but its 10-minute lifetime has elapsed.
    Expired,
    /// Already consumed. The row is RETAINED after consumption precisely so
    /// this case is distinguishable from `NoTicket` — a deleted row would read
    /// as "never minted", which is what a replay wants it to read as.
    AlreadyUsed,
}

impl TicketRejection {
    /// The `reason` string carried by `BootstrapNotAuthorized`.
    pub fn reason(&self) -> &'static str {
        match self {
            TicketRejection::NoTicket => {
                "no bootstrap ticket for this principal — a first device may only be \
                 registered immediately after a successful vetKey derivation"
            }
            TicketRejection::Expired => {
                "the bootstrap ticket has expired — re-derive (quota permitting) and \
                 register within the ticket lifetime"
            }
            TicketRejection::AlreadyUsed => {
                "the bootstrap ticket has already been consumed — a ticket authorizes \
                 exactly one device registration"
            }
        }
    }
}

/// Mint a fresh ticket. One live ticket per principal: the caller overwrites
/// any existing row, so a re-derive REPLACES rather than accumulates. That is
/// deliberate — two live tickets would authorize two registrations from one
/// ceremony.
pub fn mint(now_ns: u64) -> BootstrapTicket {
    BootstrapTicket {
        minted_at_ns: now_ns,
        expires_at_ns: now_ns.saturating_add(BOOTSTRAP_TICKET_TTL_NS),
        used: false,
    }
}

/// May this ticket authorize a registration right now?
///
/// EXPIRY BOUNDARY, pinned: consumable while `now < expires_at`, refused AT
/// `expires_at`. The half-open interval is the same convention the §H′ window
/// uses, and both sides of it are tested to the nanosecond.
pub fn check_consumable(
    ticket: Option<BootstrapTicket>,
    now_ns: u64,
) -> Result<BootstrapTicket, TicketRejection> {
    let ticket = ticket.ok_or(TicketRejection::NoTicket)?;
    // Ordered used-before-expired so a replayed CONSUMED ticket is reported as
    // a replay even after it would also have expired. The two reasons are not
    // interchangeable: one is a client that waited, the other is an attacker.
    if ticket.used {
        return Err(TicketRejection::AlreadyUsed);
    }
    if now_ns >= ticket.expires_at_ns {
        return Err(TicketRejection::Expired);
    }
    Ok(ticket)
}

/// Mark a ticket consumed. The row is RETAINED (never deleted) — it is the
/// replay evidence, and it must survive an upgrade in this state.
pub fn consume(ticket: BootstrapTicket) -> BootstrapTicket {
    BootstrapTicket { used: true, ..ticket }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_700_000_000_000_000_000;

    #[test]
    fn a_minted_ticket_expires_exactly_one_ttl_later() {
        let t = mint(T0);
        // Regenerated at point of use: ten minutes in nanoseconds.
        assert_eq!(t.expires_at_ns - t.minted_at_ns, 10 * 60 * 1_000_000_000);
        assert!(!t.used, "a fresh ticket is unconsumed");
    }

    #[test]
    fn absent_ticket_is_not_authorization() {
        assert_eq!(check_consumable(None, T0), Err(TicketRejection::NoTicket));
    }

    /// The expiry edge, ±1 ns (brief V2 §B acceptance).
    #[test]
    fn the_expiry_boundary_is_exact() {
        let t = mint(T0);
        assert!(check_consumable(Some(t), t.expires_at_ns - 1).is_ok(), "one ns before expiry");
        assert_eq!(
            check_consumable(Some(t), t.expires_at_ns),
            Err(TicketRejection::Expired),
            "AT the expiry instant the ticket is dead — half-open, like the §H′ window"
        );
        assert_eq!(
            check_consumable(Some(t), t.expires_at_ns + 1),
            Err(TicketRejection::Expired)
        );
    }

    #[test]
    fn a_consumed_ticket_can_never_be_consumed_again() {
        let t = consume(mint(T0));
        assert!(t.used);
        assert_eq!(
            check_consumable(Some(t), T0 + 1),
            Err(TicketRejection::AlreadyUsed),
            "the second consume of one ticket must be refused"
        );
    }

    /// A consumed ticket that ALSO expired still reports the replay, not the
    /// expiry. The distinction is operational: one is a slow client, the other
    /// is a replay attempt, and collapsing them hides the latter.
    #[test]
    fn replay_is_reported_as_replay_even_after_expiry() {
        let t = consume(mint(T0));
        assert_eq!(
            check_consumable(Some(t), t.expires_at_ns + 1_000),
            Err(TicketRejection::AlreadyUsed)
        );
    }

    /// Minting again REPLACES: one live ticket per principal, so one ceremony
    /// can never authorize two registrations.
    #[test]
    fn a_re_derive_replaces_rather_than_accumulates() {
        let first = mint(T0);
        let second = mint(T0 + 1_000);
        assert_ne!(first.minted_at_ns, second.minted_at_ns);
        // The caller writes `second` over `first` at the same key; what this
        // arm pins is that a fresh mint is UNUSED and fully-lived, so a
        // replacement can never resurrect a consumed one's authorization.
        assert!(!second.used);
        assert!(check_consumable(Some(second), T0 + 1_000).is_ok());
    }

    /// Every rejection carries a distinct, actionable reason — the wallet shows
    /// it and the three cases need different user actions.
    #[test]
    fn the_three_rejections_are_distinguishable() {
        let reasons = [
            TicketRejection::NoTicket.reason(),
            TicketRejection::Expired.reason(),
            TicketRejection::AlreadyUsed.reason(),
        ];
        for (i, a) in reasons.iter().enumerate() {
            for b in reasons.iter().skip(i + 1) {
                assert_ne!(a, b, "each rejection reason must be its own text");
            }
        }
    }
}
