//! Human-friendly durations such as `500ms`, `30s`, `1h30m` or `14d`.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dur(pub Duration);

impl Dur {
    pub const ZERO: Dur = Dur(Duration::ZERO);

    pub const fn secs(s: u64) -> Self {
        Dur(Duration::from_secs(s))
    }

    pub const fn millis(ms: u64) -> Self {
        Dur(Duration::from_millis(ms))
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub fn as_millis_i64(&self) -> i64 {
        i64::try_from(self.0.as_millis()).unwrap_or(i64::MAX)
    }
}

impl From<Dur> for Duration {
    fn from(d: Dur) -> Self {
        d.0
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid duration {0:?}: expected e.g. \"500ms\", \"30s\", \"5m\", \"1h30m\", \"7d\"")]
pub struct ParseDurationError(String);

impl FromStr for Dur {
    type Err = ParseDurationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseDurationError(s.to_owned());
        let input = s.trim();
        if input.is_empty() {
            return Err(err());
        }
        if input == "0" {
            return Ok(Dur::ZERO);
        }
        let mut total = Duration::ZERO;
        let mut rest = input;
        while !rest.is_empty() {
            rest = rest.trim_start();
            let digits = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
            if digits == 0 {
                return Err(err());
            }
            let value: u64 = rest[..digits].parse().map_err(|_| err())?;
            rest = &rest[digits..];
            let unit_len = rest.find(|c: char| !c.is_ascii_alphabetic()).unwrap_or(rest.len());
            let unit = &rest[..unit_len];
            rest = &rest[unit_len..];
            let part = match unit {
                "ms" => Duration::from_millis(value),
                "s" => Duration::from_secs(value),
                "m" => Duration::from_secs(value.checked_mul(60).ok_or_else(err)?),
                "h" => Duration::from_secs(value.checked_mul(3600).ok_or_else(err)?),
                "d" => Duration::from_secs(value.checked_mul(86_400).ok_or_else(err)?),
                "w" => Duration::from_secs(value.checked_mul(604_800).ok_or_else(err)?),
                _ => return Err(err()),
            };
            total = total.checked_add(part).ok_or_else(err)?;
        }
        Ok(Dur(total))
    }
}

impl fmt::Display for Dur {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ms = self.0.as_millis();
        if ms == 0 {
            return f.write_str("0s");
        }
        for (unit, size) in [("d", 86_400_000), ("h", 3_600_000), ("m", 60_000), ("s", 1000)] {
            if ms >= size {
                write!(f, "{}{unit}", ms / size)?;
                ms %= size;
            }
        }
        if ms > 0 {
            write!(f, "{ms}ms")?;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for Dur {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Seconds(u64),
            Text(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Seconds(s) => Ok(Dur::secs(s)),
            Raw::Text(t) => t.parse().map_err(serde::de::Error::custom),
        }
    }
}

impl Serialize for Dur {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units_and_combinations() {
        assert_eq!("500ms".parse::<Dur>().unwrap(), Dur::millis(500));
        assert_eq!("30s".parse::<Dur>().unwrap(), Dur::secs(30));
        assert_eq!("1h30m".parse::<Dur>().unwrap(), Dur::secs(5400));
        assert_eq!("1h 30m".parse::<Dur>().unwrap(), Dur::secs(5400));
        assert_eq!("14d".parse::<Dur>().unwrap(), Dur::secs(14 * 86_400));
        assert_eq!("2w".parse::<Dur>().unwrap(), Dur::secs(14 * 86_400));
        assert_eq!("0".parse::<Dur>().unwrap(), Dur::ZERO);
    }

    #[test]
    fn rejects_garbage() {
        for bad in ["", "s", "10", "10x", "1.5s", "-1s", "h1"] {
            assert!(bad.parse::<Dur>().is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn display_roundtrips() {
        for d in ["1d2h3m4s5ms", "30s", "0s", "250ms"] {
            let parsed: Dur = d.parse().unwrap();
            assert_eq!(parsed.to_string(), d);
        }
    }
}
