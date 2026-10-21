//! Per-monitor alerting state machine, free of I/O.
//!
//! * A monitor goes `down` after `failure_threshold` consecutive failures and
//!   is `pending` in between; it recovers after `recovery_threshold`
//!   consecutive successes.
//! * Notifications compare the current status with the last *notified*
//!   status, rather than reacting to transitions only. A suppressed
//!   notification (dependency down, flapping) is therefore sent later if the
//!   condition persists after the suppression ends, and recoveries are only
//!   announced for outages that were announced.
//! * An acknowledged outage gets no reminders; the acknowledgement ends when
//!   the monitor is up again. A silenced monitor notifies nothing until the
//!   silence ends; the suppression is recorded on its transitions.

use std::collections::VecDeque;

use crate::config::{EventKind, FlapConfig};
use crate::model::{Outcome, Status};
use crate::store::{Acknowledgement, PersistedState, Silence};

#[derive(Clone, Debug)]
pub struct Policy {
    pub failure_threshold: u32,
    pub recovery_threshold: u32,
    pub renotify_every_ms: i64,
    pub notify_degraded: bool,
    pub flapping: Option<FlapConfig>,
}

#[derive(Clone, Debug)]
pub struct MonitorState {
    pub status: Status,
    pub since: i64,
    pub fails: u32,
    pub oks: u32,
    pub notified_status: Option<Status>,
    pub last_notified_at: Option<i64>,
    pub paused: bool,
    pub flapping: bool,
    pub ack: Option<Acknowledgement>,
    pub silence: Option<Silence>,
    flips: VecDeque<i64>,
}

/// Why a monitor cannot be acknowledged.
#[derive(Debug, PartialEq, Eq)]
pub struct NotAcknowledgeable(pub Status);

#[derive(Debug, Default, PartialEq)]
pub struct Effects {
    /// Status change as `(from, to)`.
    pub transition: Option<(Status, Status)>,
    pub notify: Option<EventKind>,
    /// Why a notification that was due has not been sent.
    pub suppressed: Option<String>,
    /// The persisted part of the state changed.
    pub persist: bool,
}

/// External conditions at the time of a result.
#[derive(Debug, Default)]
pub struct Context<'a> {
    pub maintenance: Option<&'a str>,
    /// A dependency of this monitor that is currently down.
    pub dependency_down: Option<&'a str>,
}

impl MonitorState {
    pub fn new(now: i64) -> Self {
        Self {
            status: Status::Unknown,
            since: now,
            fails: 0,
            oks: 0,
            notified_status: None,
            last_notified_at: None,
            paused: false,
            flapping: false,
            ack: None,
            silence: None,
            flips: VecDeque::new(),
        }
    }

    pub fn restore(p: &PersistedState) -> Self {
        Self {
            status: if p.paused { Status::Paused } else { p.status },
            since: p.since,
            fails: 0,
            oks: 0,
            notified_status: p.notified_status,
            last_notified_at: p.last_notified_at,
            paused: p.paused,
            flapping: false,
            ack: p.ack.clone(),
            silence: p.silence.clone(),
            flips: VecDeque::new(),
        }
    }

    pub fn persisted(&self) -> PersistedState {
        PersistedState {
            status: self.status,
            since: self.since,
            notified_status: self.notified_status,
            last_notified_at: self.last_notified_at,
            paused: self.paused,
            ack: self.ack.clone(),
            silence: self.silence.clone(),
        }
    }

    fn set_status(&mut self, to: Status, now: i64, fx: &mut Effects) {
        if self.status != to {
            fx.transition = Some((self.status, to));
            fx.persist = true;
            self.status = to;
            self.since = now;
            // The acknowledged problem is over.
            if to == Status::Up {
                self.ack = None;
            }
        }
    }

    /// Acknowledge the current problem (down, pending or degraded).
    pub fn acknowledge(&mut self, ack: Acknowledgement) -> Result<Effects, NotAcknowledgeable> {
        if !matches!(self.status, Status::Down | Status::Pending | Status::Degraded) {
            return Err(NotAcknowledgeable(self.status));
        }
        self.ack = Some(ack);
        Ok(Effects {
            persist: true,
            ..Effects::default()
        })
    }

    pub fn unacknowledge(&mut self) -> Effects {
        Effects {
            persist: self.ack.take().is_some(),
            ..Effects::default()
        }
    }

    /// Set (or with `None`, lift) a silence.
    pub fn set_silence(&mut self, silence: Option<Silence>) -> Effects {
        let persist = self.silence != silence;
        self.silence = silence;
        Effects {
            persist,
            ..Effects::default()
        }
    }

    /// The silence in force at `now`, if any.
    pub fn silenced(&self, now: i64) -> Option<&Silence> {
        self.silence.as_ref().filter(|s| s.until > now)
    }

    pub fn set_paused(&mut self, paused: bool, now: i64) -> Effects {
        let mut fx = Effects::default();
        if self.paused == paused {
            return fx;
        }
        self.paused = paused;
        self.fails = 0;
        self.oks = 0;
        fx.persist = true;
        self.set_status(if paused { Status::Paused } else { Status::Unknown }, now, &mut fx);
        fx
    }

    pub fn apply(&mut self, outcome: Outcome, ctx: &Context<'_>, now: i64, policy: &Policy) -> Effects {
        let mut fx = Effects::default();
        if self.paused {
            return fx;
        }
        if self.silence.as_ref().is_some_and(|s| s.until <= now) {
            self.silence = None;
            fx.persist = true;
        }
        if ctx.maintenance.is_some() {
            self.fails = 0;
            self.oks = 0;
            self.set_status(Status::Maintenance, now, &mut fx);
            return fx;
        }

        let target = match outcome {
            Outcome::Down => {
                self.fails = self.fails.saturating_add(1);
                self.oks = 0;
                if self.fails >= policy.failure_threshold.max(1) || self.status == Status::Down {
                    Status::Down
                } else {
                    Status::Pending
                }
            }
            Outcome::Up | Outcome::Degraded => {
                self.oks = self.oks.saturating_add(1);
                self.fails = 0;
                if self.status == Status::Down && self.oks < policy.recovery_threshold.max(1) {
                    Status::Down
                } else {
                    outcome.status()
                }
            }
        };
        let from = self.status;
        self.set_status(target, now, &mut fx);
        if from != target && is_flip(from, target) {
            self.flips.push_back(now);
        }
        let flap_started = self.update_flapping(now, policy);

        if !matches!(self.status, Status::Up | Status::Degraded | Status::Down) {
            return fx;
        }

        let Some(notified) = self.notified_status else {
            // First result ever: only an outage is worth a notification.
            if self.status == Status::Down {
                self.decide(EventKind::Down, ctx, now, &mut fx);
            } else {
                self.notified_status = Some(self.status);
                fx.persist = true;
            }
            return fx;
        };

        if flap_started {
            match self.silenced(now) {
                Some(s) => fx.suppressed = Some(silence_reason(s)),
                None => self.notify(EventKind::Flapping, now, &mut fx),
            }
            return fx;
        }

        if self.status != notified {
            let kind = match (notified, self.status) {
                (_, Status::Down) => Some(EventKind::Down),
                (Status::Down, Status::Up) => Some(EventKind::Up),
                (Status::Down, Status::Degraded) => Some(EventKind::Degraded),
                (Status::Degraded, Status::Up) if policy.notify_degraded => Some(EventKind::Up),
                (Status::Up, Status::Degraded) if policy.notify_degraded => Some(EventKind::Degraded),
                _ => None,
            };
            match kind {
                Some(kind) => self.decide(kind, ctx, now, &mut fx),
                None => {
                    self.notified_status = Some(self.status);
                    fx.persist = true;
                }
            }
        } else if self.status == Status::Down
            && self.ack.is_none()
            && policy.renotify_every_ms > 0
            && self
                .last_notified_at
                .is_some_and(|t| now - t >= policy.renotify_every_ms)
        {
            self.decide(EventKind::Reminder, ctx, now, &mut fx);
        }
        fx
    }

    /// Send `kind` unless a suppression applies.
    fn decide(&mut self, kind: EventKind, ctx: &Context<'_>, now: i64, fx: &mut Effects) {
        if let Some(s) = self.silenced(now) {
            fx.suppressed = Some(silence_reason(s));
            return;
        }
        let outage = matches!(kind, EventKind::Down | EventKind::Reminder);
        if outage && let Some(dep) = ctx.dependency_down {
            fx.suppressed = Some(format!("dependency {dep} is down"));
            return;
        }
        if self.flapping {
            fx.suppressed = Some("flapping".into());
            return;
        }
        self.notify(kind, now, fx);
    }

    fn notify(&mut self, kind: EventKind, now: i64, fx: &mut Effects) {
        fx.notify = Some(kind);
        fx.persist = true;
        self.notified_status = Some(self.status);
        self.last_notified_at = Some(now);
    }

    /// Returns true when flapping just started.
    fn update_flapping(&mut self, now: i64, policy: &Policy) -> bool {
        let Some(f) = policy.flapping else {
            self.flapping = false;
            self.flips.clear();
            return false;
        };
        let horizon = now - f.window.as_millis_i64();
        while self.flips.front().is_some_and(|t| *t < horizon) {
            self.flips.pop_front();
        }
        let count = self.flips.len() as u32;
        if !self.flapping && count > f.max_transitions {
            self.flapping = true;
            return true;
        }
        if self.flapping && count <= f.max_transitions / 2 {
            self.flapping = false;
        }
        false
    }
}

fn silence_reason(s: &Silence) -> String {
    let until = jiff::Timestamp::from_second(s.until.div_euclid(1000))
        .map(|t| t.to_string())
        .unwrap_or_else(|_| s.until.to_string());
    format!("silenced by {} until {until}", s.by)
}

/// An availability flip: into or out of `down`.
fn is_flip(from: Status, to: Status) -> bool {
    (to == Status::Down && from.is_available()) || (from == Status::Down && to.is_available())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Dur;

    fn policy() -> Policy {
        Policy {
            failure_threshold: 3,
            recovery_threshold: 1,
            renotify_every_ms: 0,
            notify_degraded: true,
            flapping: None,
        }
    }

    fn run(s: &mut MonitorState, outcomes: &[Outcome], p: &Policy, t0: i64) -> Vec<Effects> {
        let ctx = Context::default();
        outcomes
            .iter()
            .enumerate()
            .map(|(i, o)| s.apply(*o, &ctx, t0 + i as i64 * 1000, p))
            .collect()
    }

    use Outcome::{Degraded as G, Down as D, Up as U};

    #[test]
    fn first_up_is_silent_and_down_needs_threshold() {
        let mut s = MonitorState::new(0);
        let fx = run(&mut s, &[U], &policy(), 0);
        assert_eq!(fx[0].notify, None);
        assert_eq!(fx[0].transition, Some((Status::Unknown, Status::Up)));
        assert_eq!(s.notified_status, Some(Status::Up));

        let fx = run(&mut s, &[D, D], &policy(), 1000);
        assert_eq!(s.status, Status::Pending);
        assert!(fx.iter().all(|f| f.notify.is_none()));
        let fx = run(&mut s, &[D], &policy(), 5000);
        assert_eq!(s.status, Status::Down);
        assert_eq!(fx[0].notify, Some(EventKind::Down));

        // Further failures do not notify again.
        let fx = run(&mut s, &[D, D], &policy(), 6000);
        assert!(fx.iter().all(|f| f.notify.is_none() && f.transition.is_none()));

        let fx = run(&mut s, &[U], &policy(), 9000);
        assert_eq!(fx[0].notify, Some(EventKind::Up));
        assert_eq!(s.status, Status::Up);
    }

    #[test]
    fn pending_then_recovery_is_silent() {
        let mut s = MonitorState::new(0);
        let fx = run(&mut s, &[U, D, D, U], &policy(), 0);
        assert!(fx.iter().all(|f| f.notify.is_none()));
        assert_eq!(fx[3].transition, Some((Status::Pending, Status::Up)));
    }

    #[test]
    fn recovery_threshold() {
        let mut p = policy();
        p.failure_threshold = 1;
        p.recovery_threshold = 2;
        let mut s = MonitorState::new(0);
        let fx = run(&mut s, &[U, D, U, U], &p, 0);
        assert_eq!(fx[1].notify, Some(EventKind::Down));
        assert_eq!(fx[2].notify, None);
        assert_eq!(s.status, Status::Up);
        assert_eq!(fx[3].notify, Some(EventKind::Up));
    }

    #[test]
    fn first_result_down_notifies() {
        let mut p = policy();
        p.failure_threshold = 1;
        let mut s = MonitorState::new(0);
        let fx = run(&mut s, &[D], &p, 0);
        assert_eq!(fx[0].notify, Some(EventKind::Down));
    }

    #[test]
    fn degraded_notifications_follow_policy() {
        let mut s = MonitorState::new(0);
        let fx = run(&mut s, &[U, G, U], &policy(), 0);
        assert_eq!(fx[1].notify, Some(EventKind::Degraded));
        assert_eq!(fx[2].notify, Some(EventKind::Up));

        let mut p = policy();
        p.notify_degraded = false;
        let mut s = MonitorState::new(0);
        let fx = run(&mut s, &[U, G, U], &p, 0);
        assert!(fx.iter().all(|f| f.notify.is_none()));
    }

    #[test]
    fn reminders() {
        let mut p = policy();
        p.failure_threshold = 1;
        p.renotify_every_ms = 2500;
        let mut s = MonitorState::new(0);
        let fx = run(&mut s, &[U, D, D, D, D], &p, 0);
        assert_eq!(fx[1].notify, Some(EventKind::Down));
        assert_eq!(fx[2].notify, None);
        assert_eq!(fx[3].notify, None);
        assert_eq!(fx[4].notify, Some(EventKind::Reminder));
    }

    #[test]
    fn dependency_suppression_is_deferred_not_lost() {
        let mut p = policy();
        p.failure_threshold = 1;
        let mut s = MonitorState::new(0);
        run(&mut s, &[U], &p, 0);
        let dep = Context {
            dependency_down: Some("router"),
            ..Context::default()
        };
        let fx = s.apply(D, &dep, 1000, &p);
        assert_eq!(fx.notify, None);
        assert_eq!(fx.suppressed.as_deref(), Some("dependency router is down"));
        assert_eq!(s.status, Status::Down);
        // The dependency recovered but this monitor did not: notify now.
        let fx = s.apply(D, &Context::default(), 2000, &p);
        assert_eq!(fx.notify, Some(EventKind::Down));

        // A suppressed outage that recovers yields no recovery message.
        let mut s = MonitorState::new(0);
        run(&mut s, &[U], &p, 0);
        s.apply(D, &dep, 1000, &p);
        let fx = s.apply(U, &Context::default(), 2000, &p);
        assert_eq!(fx.notify, None);
    }

    #[test]
    fn maintenance_hides_outages() {
        let mut p = policy();
        p.failure_threshold = 1;
        let mut s = MonitorState::new(0);
        run(&mut s, &[U], &p, 0);
        let m = Context {
            maintenance: Some("w"),
            ..Context::default()
        };
        let fx = s.apply(D, &m, 1000, &p);
        assert_eq!(fx.transition, Some((Status::Up, Status::Maintenance)));
        assert_eq!(fx.notify, None);
        // Still down after maintenance: notified.
        let fx = s.apply(D, &Context::default(), 2000, &p);
        assert_eq!(fx.notify, Some(EventKind::Down));
    }

    #[test]
    fn flapping_suppresses_and_resumes() {
        let mut p = policy();
        p.failure_threshold = 1;
        p.flapping = Some(FlapConfig {
            window: Dur::secs(60),
            max_transitions: 3,
        });
        let mut s = MonitorState::new(0);
        let fx = run(&mut s, &[U, D, U, D, U], &p, 0);
        // flips: D(1) U(2) D(3) U(4) -> flapping on the 4th flip
        assert_eq!(fx[1].notify, Some(EventKind::Down));
        assert_eq!(fx[2].notify, Some(EventKind::Up));
        assert_eq!(fx[3].notify, Some(EventKind::Down));
        assert_eq!(fx[4].notify, Some(EventKind::Flapping));
        assert!(s.flapping);
        let fx = run(&mut s, &[D], &p, 5000);
        assert_eq!(fx[0].suppressed.as_deref(), Some("flapping"));
        // Long after the window, the state settles and the outage is reported.
        let fx = run(&mut s, &[D], &p, 200_000);
        assert!(!s.flapping);
        assert_eq!(fx[0].notify, Some(EventKind::Down));
    }

    #[test]
    fn pause_and_restore() {
        let mut s = MonitorState::new(0);
        run(&mut s, &[U], &policy(), 0);
        let fx = s.set_paused(true, 10);
        assert_eq!(fx.transition, Some((Status::Up, Status::Paused)));
        assert!(
            run(&mut s, &[D, D, D], &policy(), 20)
                .iter()
                .all(|f| *f == Effects::default())
        );
        let p = s.persisted();
        let mut r = MonitorState::restore(&p);
        assert_eq!(r.status, Status::Paused);
        r.set_paused(false, 100);
        assert_eq!(r.status, Status::Unknown);
        let fx = run(&mut r, &[U], &policy(), 200);
        assert_eq!(fx[0].notify, None);
    }
}
