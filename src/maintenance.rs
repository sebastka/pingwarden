//! Maintenance windows: one-off or weekly-recurring periods during which
//! checks still run but results are recorded as `maintenance` and no
//! notification is sent. Windows come from the configuration, or are created
//! at runtime through the API (one-off only, at most 30 days).

use std::collections::HashSet;

use serde::Deserialize;

use jiff::civil::{Date, Weekday as JWeekday};
use jiff::tz::TimeZone;
use jiff::{Span, Timestamp};

use crate::config::{Config, Dur, MaintenanceConfig, MonitorConfig, Weekday, valid_id};
use crate::store::{RuntimeWindow, WindowSelection};

#[derive(Clone, Debug)]
pub struct Window {
    pub id: String,
    pub description: Option<String>,
    all: bool,
    monitors: HashSet<String>,
    tags: HashSet<String>,
    groups: HashSet<String>,
    schedule: Schedule,
    /// Who created the window through the API; `None` for configured windows.
    pub created_by: Option<String>,
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
/// Longest runtime window, and how far ahead one may start.
pub const MAX_RUNTIME_SPAN_MS: i64 = 30 * 86_400_000;

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
            created_by: None,
        })
    }

    /// A window created through the API.
    pub fn from_runtime(w: &RuntimeWindow) -> Self {
        Self {
            id: w.id.clone(),
            description: w.description.clone(),
            all: w.selection.all,
            monitors: w.selection.monitors.iter().cloned().collect(),
            tags: w.selection.tags.iter().cloned().collect(),
            groups: w.selection.groups.iter().cloned().collect(),
            schedule: Schedule::OneOff {
                start_ms: w.start_ms,
                end_ms: w.end_ms,
            },
            created_by: Some(w.created_by.clone()),
        }
    }

    /// Start and end of a one-off window; `None` for recurring ones.
    pub fn bounds(&self) -> Option<(i64, i64)> {
        match self.schedule {
            Schedule::OneOff { start_ms, end_ms } => Some((start_ms, end_ms)),
            Schedule::Recurring { .. } => None,
        }
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

/// Body of `POST /api/v1/maintenance`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowRequest {
    pub id: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub monitors: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub all: bool,
    /// Milliseconds since the epoch; now when unset.
    pub start: Option<i64>,
    /// Milliseconds since the epoch; or set `duration`.
    pub end: Option<i64>,
    /// E.g. `"1h"`; or set `end`.
    pub duration: Option<String>,
}

/// Validate a runtime window request against the configuration. The caller
/// still checks that the id is not taken by a stored runtime window.
pub fn runtime_window(req: WindowRequest, by: &str, now: i64, config: &Config) -> Result<RuntimeWindow, String> {
    let id = match req.id {
        Some(id) if !valid_id(&id) => {
            return Err(format!(
                "invalid id {id:?} (letters, digits, `_`, `-`, `.`; at most 128 characters)"
            ));
        }
        Some(id) => id,
        None => format!("api-{now}"),
    };
    if let Some(d) = &req.description
        && d.chars().count() > 1024
    {
        return Err("description is longer than 1024 characters".into());
    }
    if !req.all && req.monitors.is_empty() && req.groups.is_empty() && req.tags.is_empty() {
        return Err("select monitors with `monitors`, `groups`, `tags` or `all: true`".into());
    }
    for m in &req.monitors {
        if !config.monitors.iter().any(|c| &c.id == m) {
            return Err(format!("unknown monitor `{m}`"));
        }
    }
    for g in &req.groups {
        if !config.groups.iter().any(|c| &c.id == g) {
            return Err(format!("unknown group `{g}`"));
        }
    }
    let start = req.start.unwrap_or(now);
    if start > now + MAX_RUNTIME_SPAN_MS {
        return Err("`start` may be at most 30 days ahead".into());
    }
    let end = match (req.end, req.duration.as_deref()) {
        (Some(_), Some(_)) => return Err("set `end` or `duration`, not both".into()),
        (None, None) => return Err("set `end` or `duration`".into()),
        (Some(end), None) => end,
        (None, Some(d)) => {
            let d: Dur = d.parse().map_err(|e| format!("{e}"))?;
            start.saturating_add(d.as_millis_i64())
        }
    };
    if end <= start {
        return Err("the window must end after it starts".into());
    }
    if end <= now {
        return Err("the window must end in the future".into());
    }
    if end - start > MAX_RUNTIME_SPAN_MS {
        return Err("a window may last at most 30 days".into());
    }
    Ok(RuntimeWindow {
        id,
        description: req.description,
        selection: WindowSelection {
            all: req.all,
            monitors: req.monitors,
            groups: req.groups,
            tags: req.tags,
        },
        start_ms: start,
        end_ms: end,
        created_by: by.to_owned(),
        created_at: now,
    })
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
    fn validates_runtime_requests() {
        let config = crate::config::from_str(
            r#"
database: { url: "postgres://x@db/x" }
groups: [{ id: web }]
monitors:
  - { id: site, type: tcp, host: example.com, port: 443, group: web }
"#,
        )
        .unwrap();
        let now = 1_000_000_000_000;
        let req = |f: fn(&mut WindowRequest)| {
            let mut r = WindowRequest {
                monitors: vec!["site".into()],
                duration: Some("1h".into()),
                ..WindowRequest::default()
            };
            f(&mut r);
            runtime_window(r, "oidc:alice", now, &config)
        };
        let ok = req(|_| {}).unwrap();
        assert_eq!((ok.start_ms, ok.end_ms), (now, now + 3_600_000));
        assert_eq!(ok.id, format!("api-{now}"));
        assert_eq!(ok.created_by, "oidc:alice");
        let w = Window::from_runtime(&ok);
        assert_eq!(w.active_until(now + 1), Some(now + 3_600_000));
        assert_eq!(w.bounds(), Some((now, now + 3_600_000)));

        let err = |f: fn(&mut WindowRequest)| req(f).unwrap_err();
        assert!(err(|r| r.monitors.clear()).contains("select monitors"));
        assert!(err(|r| r.monitors = vec!["nope".into()]).contains("unknown monitor"));
        assert!(err(|r| r.groups = vec!["nope".into()]).contains("unknown group"));
        assert!(err(|r| r.id = Some("no spaces".into())).contains("invalid id"));
        assert!(err(|r| r.end = Some(1)).contains("not both"));
        assert!(err(|r| r.duration = None).contains("set `end` or `duration`"));
        assert!(err(|r| r.duration = Some("31d".into())).contains("at most 30 days"));
        assert!(err(|r| r.duration = Some("soon".into())).contains("invalid duration"));
        assert!(err(|r| r.start = Some(1_000_000_000_000 + 31 * 86_400_000)).contains("30 days ahead"));
        assert!(err(|r| r.start = Some(1)).contains("end in the future"));
        assert!(
            err(|r| {
                r.duration = None;
                r.start = Some(1_000_000_000_000 + 10);
                r.end = Some(1_000_000_000_000 + 5);
            })
            .contains("end after it starts")
        );
        assert!(
            req(|r| {
                r.monitors.clear();
                r.groups = vec!["web".into()];
                r.tags = vec!["any".into()];
            })
            .is_ok()
        );
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
