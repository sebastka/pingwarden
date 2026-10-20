//! Maintenance windows: one-off or weekly-recurring periods during which
//! checks still run but results are recorded as `maintenance` and no
//! notification is sent.

use std::collections::HashSet;

use jiff::civil::{Date, Weekday as JWeekday};
use jiff::tz::TimeZone;
use jiff::{Span, Timestamp};

use crate::config::{MaintenanceConfig, MonitorConfig, Weekday};

#[derive(Clone, Debug)]
pub struct Window {
    pub id: String,
    pub description: Option<String>,
    all: bool,
    monitors: HashSet<String>,
    tags: HashSet<String>,
    groups: HashSet<String>,
    schedule: Schedule,
}

#[derive(Clone, Debug)]
enum Schedule {
    OneOff {
        start_ms: i64,
        end_ms: i64,
    },
    Recurring {
        days: Vec<JWeekday>,
        hour: i8,
        minute: i8,
        duration_ms: i64,
        tz: TimeZone,
    },
}

const MAX_RECURRING_DURATION_MS: i64 = 7 * 86_400_000;

impl Window {
    pub fn parse(cfg: &MaintenanceConfig) -> Result<Self, String> {
        let schedule = match (&cfg.start, &cfg.end, &cfg.recurring) {
            (Some(start), Some(end), None) => {
                let start_ms = parse_ts(start)?;
                let end_ms = parse_ts(end)?;
                if end_ms <= start_ms {
                    return Err("`end` must be after `start`".into());
                }
                Schedule::OneOff { start_ms, end_ms }
            }
            (None, None, Some(r)) => {
                let (h, m) = r
                    .start
                    .split_once(':')
                    .ok_or_else(|| format!("invalid start time {:?}, expected HH:MM", r.start))?;
                let hour: i8 = h.parse().map_err(|_| format!("invalid hour in {:?}", r.start))?;
                let minute: i8 = m.parse().map_err(|_| format!("invalid minute in {:?}", r.start))?;
                if !(0..24).contains(&hour) || !(0..60).contains(&minute) {
                    return Err(format!("invalid start time {:?}", r.start));
                }
                let duration_ms = r.duration.as_millis_i64();
                if duration_ms <= 0 || duration_ms > MAX_RECURRING_DURATION_MS {
                    return Err("recurring `duration` must be between 1s and 7d".into());
                }
                let tz = TimeZone::get(&r.timezone).map_err(|e| format!("unknown timezone {:?}: {e}", r.timezone))?;
                Schedule::Recurring {
                    days: r.days.iter().map(|d| to_jiff(*d)).collect(),
                    hour,
                    minute,
                    duration_ms,
                    tz,
                }
            }
            _ => {
                return Err("set either `start` and `end`, or `recurring`".into());
            }
        };
        if !cfg.all && cfg.monitors.is_empty() && cfg.tags.is_empty() && cfg.groups.is_empty() {
            return Err("select monitors with `monitors`, `groups`, `tags` or `all: true`".into());
        }
        Ok(Self {
            id: cfg.id.clone(),
            description: cfg.description.clone(),
            all: cfg.all,
            monitors: cfg.monitors.iter().cloned().collect(),
            tags: cfg.tags.iter().cloned().collect(),
            groups: cfg.groups.iter().cloned().collect(),
            schedule,
        })
    }

    pub fn monitor_ids(&self) -> impl Iterator<Item = &str> {
        self.monitors.iter().map(String::as_str)
    }

    pub fn group_ids(&self) -> impl Iterator<Item = &str> {
        self.groups.iter().map(String::as_str)
    }

    pub fn applies_to(&self, monitor: &MonitorConfig) -> bool {
        self.all
            || self.monitors.contains(&monitor.id)
            || monitor.effective_tags.iter().any(|t| self.tags.contains(t))
            || monitor.group_path.iter().any(|g| self.groups.contains(g))
    }

    /// End of the window containing `now_ms`, if any.
    pub fn active_until(&self, now_ms: i64) -> Option<i64> {
        match &self.schedule {
            Schedule::OneOff { start_ms, end_ms } => (*start_ms <= now_ms && now_ms < *end_ms).then_some(*end_ms),
            Schedule::Recurring {
                days,
                hour,
                minute,
                duration_ms,
                tz,
            } => {
                let now = Timestamp::from_millisecond(now_ms).ok()?;
                let today = now.to_zoned(tz.clone()).date();
                // A window that started up to 7 days ago may still be open.
                let mut best: Option<i64> = None;
                for back in 0..=7i64 {
                    let Some(day) = sub_days(today, back) else { continue };
                    if !days.is_empty() && !days.contains(&day.weekday()) {
                        continue;
                    }
                    let Ok(start) = day.at(*hour, *minute, 0, 0).to_zoned(tz.clone()) else {
                        continue;
                    };
                    let start_ms = start.timestamp().as_millisecond();
                    let end_ms = start_ms.saturating_add(*duration_ms);
                    if start_ms <= now_ms && now_ms < end_ms {
                        best = Some(best.map_or(end_ms, |b| b.max(end_ms)));
                    }
                }
                best
            }
        }
    }
}

fn sub_days(date: Date, days: i64) -> Option<Date> {
    date.checked_sub(Span::new().days(days)).ok()
}

fn parse_ts(s: &str) -> Result<i64, String> {
    s.parse::<Timestamp>()
        .map(|t| t.as_millisecond())
        .map_err(|e| format!("invalid RFC 3339 timestamp {s:?}: {e}"))
}

fn to_jiff(d: Weekday) -> JWeekday {
    match d {
        Weekday::Mon => JWeekday::Monday,
        Weekday::Tue => JWeekday::Tuesday,
        Weekday::Wed => JWeekday::Wednesday,
        Weekday::Thu => JWeekday::Thursday,
        Weekday::Fri => JWeekday::Friday,
        Weekday::Sat => JWeekday::Saturday,
        Weekday::Sun => JWeekday::Sunday,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Dur, RecurringWindow};

    fn cfg() -> MaintenanceConfig {
        MaintenanceConfig {
            id: "w".into(),
            description: None,
            all: true,
            monitors: vec![],
            tags: vec![],
            groups: vec![],
            start: None,
            end: None,
            recurring: None,
        }
    }

    fn ms(s: &str) -> i64 {
        s.parse::<Timestamp>().unwrap().as_millisecond()
    }

    #[test]
    fn one_off() {
        let mut c = cfg();
        c.start = Some("2026-11-01T22:00:00Z".into());
        c.end = Some("2026-11-02T02:00:00Z".into());
        let w = Window::parse(&c).unwrap();
        assert_eq!(w.active_until(ms("2026-11-01T21:59:59Z")), None);
        assert_eq!(
            w.active_until(ms("2026-11-01T23:00:00Z")),
            Some(ms("2026-11-02T02:00:00Z"))
        );
        assert_eq!(w.active_until(ms("2026-11-02T02:00:00Z")), None);
    }

    #[test]
    fn recurring_across_midnight_and_dst() {
        let mut c = cfg();
        c.recurring = Some(RecurringWindow {
            days: vec![Weekday::Sat],
            start: "23:30".into(),
            duration: Dur::secs(3600),
            timezone: "Europe/Oslo".into(),
        });
        let w = Window::parse(&c).unwrap();
        // Saturday 2026-10-24 23:30 CEST (+02:00) = 21:30Z
        assert!(w.active_until(ms("2026-10-24T21:45:00Z")).is_some());
        // Sunday 00:15 local still inside the window.
        assert!(w.active_until(ms("2026-10-24T22:15:00Z")).is_some());
        assert!(w.active_until(ms("2026-10-24T22:31:00Z")).is_none());
        // A Friday is not selected.
        assert!(w.active_until(ms("2026-10-23T21:45:00Z")).is_none());
        // Saturday 2026-10-31 23:30 CET (+01:00) = 22:30Z after DST ended.
        assert!(w.active_until(ms("2026-10-31T21:45:00Z")).is_none());
        assert!(w.active_until(ms("2026-10-31T22:45:00Z")).is_some());
    }

    #[test]
    fn rejects_bad_windows() {
        let mut c = cfg();
        assert!(Window::parse(&c).is_err());
        c.start = Some("2026-11-02T00:00:00Z".into());
        c.end = Some("2026-11-01T00:00:00Z".into());
        assert!(Window::parse(&c).is_err());
        let mut c = cfg();
        c.all = false;
        c.recurring = Some(RecurringWindow {
            days: vec![],
            start: "02:00".into(),
            duration: Dur::secs(60),
            timezone: "UTC".into(),
        });
        assert!(Window::parse(&c).is_err());
    }
}
