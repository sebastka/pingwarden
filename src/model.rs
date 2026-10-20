//! Status codes shared by the engine, the store and the API.

use serde::{Serialize, Serializer};

/// Monitor status. The numeric codes are stored in the database and exported
/// by `/metrics`; never renumber them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Status {
    Down = 0,
    Up = 1,
    Pending = 2,
    Maintenance = 3,
    Degraded = 4,
    Paused = 5,
    Unknown = 6,
}

impl Status {
    pub fn code(self) -> i16 {
        self as i16
    }

    pub fn from_code(code: i16) -> Self {
        match code {
            0 => Status::Down,
            1 => Status::Up,
            2 => Status::Pending,
            3 => Status::Maintenance,
            4 => Status::Degraded,
            5 => Status::Paused,
            _ => Status::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Status::Down => "down",
            Status::Up => "up",
            Status::Pending => "pending",
            Status::Maintenance => "maintenance",
            Status::Degraded => "degraded",
            Status::Paused => "paused",
            Status::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "down" => Status::Down,
            "up" => Status::Up,
            "pending" => Status::Pending,
            "maintenance" => Status::Maintenance,
            "degraded" => Status::Degraded,
            "paused" => Status::Paused,
            "unknown" => Status::Unknown,
            _ => return None,
        })
    }

    /// Whether the monitored service is considered reachable.
    pub fn is_available(self) -> bool {
        matches!(self, Status::Up | Status::Degraded)
    }
}

impl Serialize for Status {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// Result of a single check execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Up,
    Degraded,
    Down,
}

impl Outcome {
    pub fn status(self) -> Status {
        match self {
            Outcome::Up => Status::Up,
            Outcome::Degraded => Status::Degraded,
            Outcome::Down => Status::Down,
        }
    }

    pub fn as_str(self) -> &'static str {
        self.status().as_str()
    }

    /// The worse of two outcomes.
    pub fn worst(self, other: Outcome) -> Outcome {
        use Outcome::*;
        match (self, other) {
            (Down, _) | (_, Down) => Down,
            (Degraded, _) | (_, Degraded) => Degraded,
            _ => Up,
        }
    }
}

pub fn now_ms() -> i64 {
    jiff::Timestamp::now().as_millisecond()
}
