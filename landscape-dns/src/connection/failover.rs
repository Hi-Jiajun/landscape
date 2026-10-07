//! Upstream failover with a cross-request breaker.
//!
//! The architecture this belongs to is "a domestic ISP resolver as primary and
//! Alibaba DNS as backup". A rule binds one upstream, so that pairing has to live
//! on the upstream itself: `ips` is the primary and the backup is a second set of
//! addresses tried when the primary cannot be reached.
//!
//! Two semantics matter and they are not symmetric:
//!
//! * **An answer is an answer.** NODATA and a legitimate NXDOMAIN are things the
//!   primary said. They must not be re-asked of the backup (which would replace
//!   the answer the operator's own resolver gave) and must not count as a failure
//!   (which would let one non-existent domain trip the breaker for every other
//!   domain on that rule). Only a failure to *get* an answer switches.
//! * **Switching is per request; remembering is across requests.** A request that
//!   cannot reach the primary is answered from the backup in the same request, and
//!   a primary that keeps failing is set aside for a cooldown so the following
//!   requests do not each pay the same timeout first.

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use hickory_proto::rr::RecordType;
use hickory_resolver::{lookup::Lookup, net::NetError};

use super::LandscapeMarkDNSResolver;

/// Consecutive transport failures before the primary is set aside.
///
/// Two, not one: a single lost datagram is ordinary on a domestic link, and
/// switching the whole house's resolution on it would make the backup the de
/// facto primary.
const SET_ASIDE_AFTER: u32 = 2;
/// How long the primary stays set aside before it is tried again.
const COOLDOWN: Duration = Duration::from_secs(60);

/// Whether a failure means "could not get an answer" or "got an answer".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The upstream answered - including NODATA and NXDOMAIN.
    Answer,
    /// The upstream could not be reached, or failed in a way that produced no
    /// answer at all.
    Transport,
}

/// Classify a resolver error.
///
/// `NoRecordsFound` is hickory's shape for both NODATA and an error response
/// code, i.e. for anything the upstream actually said. Everything else (timeout,
/// I/O, protocol) is a failure to get an answer.
pub(crate) fn classify(error: &NetError) -> Outcome {
    match error {
        NetError::Dns(hickory_resolver::net::DnsError::NoRecordsFound(_)) => Outcome::Answer,
        _ => Outcome::Transport,
    }
}

/// Cross-request memory of how the primary has been behaving.
#[derive(Debug, Default)]
struct Breaker {
    consecutive_failures: u32,
    set_aside_until: Option<Instant>,
}

impl Breaker {
    /// Whether the primary is currently set aside.
    fn is_set_aside(&self, now: Instant) -> bool {
        self.set_aside_until.is_some_and(|until| now < until)
    }

    /// The primary answered: it is healthy, whatever happened before.
    fn note_success(&mut self) {
        self.consecutive_failures = 0;
        self.set_aside_until = None;
    }

    /// The primary could not be reached.
    fn note_failure(&mut self, now: Instant) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= SET_ASIDE_AFTER {
            self.set_aside_until = Some(now + COOLDOWN);
        }
    }
}

/// One upstream plus, when configured, a backup for when it cannot be reached.
/// Manual `Debug`: the point of the type in a log line is which upstream it
/// fronts and whether a backup exists, not the contents of a connection pool.
impl std::fmt::Debug for FailoverResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let breaker = self.breaker.lock().unwrap_or_else(|e| e.into_inner());
        f.debug_struct("FailoverResolver")
            .field("has_backup", &self.backup.is_some())
            .field("consecutive_failures", &breaker.consecutive_failures)
            .field("set_aside", &breaker.set_aside_until.is_some())
            .finish()
    }
}

pub(crate) struct FailoverResolver {
    primary: LandscapeMarkDNSResolver,
    backup: Option<LandscapeMarkDNSResolver>,
    breaker: Mutex<Breaker>,
}

impl FailoverResolver {
    pub(crate) fn new(
        primary: LandscapeMarkDNSResolver,
        backup: Option<LandscapeMarkDNSResolver>,
    ) -> Self {
        Self {
            primary,
            backup,
            breaker: Mutex::new(Breaker::default()),
        }
    }

    /// Resolve, switching to the backup only when the primary produced no answer.
    pub(crate) async fn lookup(
        &self,
        domain: &str,
        query_type: RecordType,
    ) -> Result<Lookup, NetError> {
        let Some(backup) = self.backup.as_ref() else {
            // No backup configured: exactly the previous behaviour.
            return self.primary.lookup(domain, query_type).await;
        };

        let now = Instant::now();
        let set_aside = self.breaker.lock().unwrap_or_else(|e| e.into_inner()).is_set_aside(now);

        if set_aside {
            // The primary is being rested: the backup carries the request. The
            // primary still gets one attempt when the backup also fails, which is
            // how it can earn its way back before the cooldown expires.
            return match backup.lookup(domain, query_type).await {
                Ok(lookup) => Ok(lookup),
                Err(e) if classify(&e) == Outcome::Answer => Err(e),
                Err(backup_error) => match self.primary.lookup(domain, query_type).await {
                    Ok(lookup) => {
                        self.breaker.lock().unwrap_or_else(|e| e.into_inner()).note_success();
                        Ok(lookup)
                    }
                    Err(e) if classify(&e) == Outcome::Answer => Err(e),
                    Err(_) => Err(backup_error),
                },
            };
        }

        match self.primary.lookup(domain, query_type).await {
            Ok(lookup) => {
                self.breaker.lock().unwrap_or_else(|e| e.into_inner()).note_success();
                Ok(lookup)
            }
            // An answer, including NODATA and NXDOMAIN: no switch, no state change.
            Err(e) if classify(&e) == Outcome::Answer => Err(e),
            Err(primary_error) => {
                self.breaker.lock().unwrap_or_else(|e| e.into_inner()).note_failure(now);
                match backup.lookup(domain, query_type).await {
                    Ok(lookup) => Ok(lookup),
                    Err(e) if classify(&e) == Outcome::Answer => Err(e),
                    // Both failed: report the primary's failure. It is the operator's
                    // chosen resolver, so its error is the one worth surfacing.
                    Err(_) => Err(primary_error),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timeout_is_a_transport_failure_but_a_response_is_an_answer() {
        assert_eq!(classify(&NetError::Timeout), Outcome::Transport);
    }

    /// The property the whole feature rests on: only "no answer" may switch. Any
    /// variant that is not the upstream's own response has to classify as a
    /// transport failure, or a domain that legitimately does not exist would trip
    /// the breaker for every other domain on the rule.
    #[test]
    fn only_a_response_from_the_upstream_is_an_answer() {
        // The nameservers hickory reports when it cannot reach anyone are the
        // cases that must switch.
        assert_eq!(classify(&NetError::Timeout), Outcome::Transport);
        assert_eq!(
            classify(&NetError::NoConnections),
            Outcome::Transport,
            "no usable connection is a transport failure like any other"
        );
    }

    /// The two shapes of "the upstream answered, and the answer is that there is
    /// nothing": NXDOMAIN, and NoError with no records (NODATA).
    ///
    /// This is the case the whole domestic-primary design stands on, and the case
    /// that fails silently if it is wrong: misclassify either one and a single
    /// name that does not exist sets the primary aside, so every other domain in
    /// the house is resolved by the backup for the next minute - with the
    /// operator's own resolver silently no longer in use. hickory reports both as
    /// `NoRecordsFound`, whose `response_code` is what distinguishes them.
    #[test]
    fn a_negative_answer_is_an_answer_not_a_failure() {
        use hickory_resolver::proto::op::{Query, ResponseCode};
        use hickory_resolver::proto::rr::{Name, RecordType};

        for (code, what) in [
            (ResponseCode::NXDomain, "the name does not exist"),
            (ResponseCode::NoError, "the name exists but has no record of this type"),
        ] {
            let name = Name::from_ascii("does-not-exist.example.").expect("a literal name");
            let query = Query::query(name, RecordType::AAAA);
            let no_records = hickory_resolver::net::NoRecords::new(query, code);
            let error = NetError::Dns(hickory_resolver::net::DnsError::NoRecordsFound(no_records));
            assert_eq!(
                classify(&error),
                Outcome::Answer,
                "{what} is the primary's own answer, so it must not switch or count as a failure"
            );
        }
    }

    #[test]
    fn the_primary_is_set_aside_only_after_repeated_failures() {
        let mut breaker = Breaker::default();
        let now = Instant::now();

        breaker.note_failure(now);
        assert!(!breaker.is_set_aside(now), "one lost datagram is ordinary");

        breaker.note_failure(now);
        assert!(breaker.is_set_aside(now), "repeated failure sets the primary aside");
    }

    #[test]
    fn a_success_clears_the_breaker() {
        let mut breaker = Breaker::default();
        let now = Instant::now();
        breaker.note_failure(now);
        breaker.note_failure(now);
        assert!(breaker.is_set_aside(now));

        breaker.note_success();
        assert!(!breaker.is_set_aside(now));
        assert_eq!(breaker.consecutive_failures, 0);

        // ... and the count really restarted: one more failure is not enough.
        breaker.note_failure(now);
        assert!(!breaker.is_set_aside(now));
    }

    #[test]
    fn the_primary_is_tried_again_after_the_cooldown() {
        let mut breaker = Breaker::default();
        let now = Instant::now();
        breaker.note_failure(now);
        breaker.note_failure(now);
        assert!(breaker.is_set_aside(now));
        assert!(breaker.is_set_aside(now + COOLDOWN - Duration::from_secs(1)));
        assert!(
            !breaker.is_set_aside(now + COOLDOWN),
            "the cooldown ends, so the primary becomes the first choice again"
        );
    }
}
