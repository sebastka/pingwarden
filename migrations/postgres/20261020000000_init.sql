-- Timestamps are milliseconds since the Unix epoch (UTC), stored as BIGINT so
-- that the same queries work on PostgreSQL and MariaDB.

CREATE TABLE monitors (
    id          VARCHAR(128)  PRIMARY KEY,
    name        VARCHAR(255)  NOT NULL,
    kind        VARCHAR(32)   NOT NULL,
    target      VARCHAR(1024) NOT NULL,
    description TEXT          NULL,
    created_at  BIGINT        NOT NULL,
    updated_at  BIGINT        NOT NULL,
    -- Set when the monitor disappears from the configuration.
    removed_at  BIGINT        NULL
);

-- Live state, restored on start so that a restart neither forgets an outage
-- nor notifies twice.
CREATE TABLE monitor_state (
    monitor_id       VARCHAR(128) PRIMARY KEY REFERENCES monitors (id) ON DELETE CASCADE,
    status           SMALLINT     NOT NULL,
    since            BIGINT       NOT NULL,
    notified_status  SMALLINT     NULL,
    last_notified_at BIGINT       NULL,
    paused           SMALLINT     NOT NULL DEFAULT 0,
    updated_at       BIGINT       NOT NULL
);

CREATE TABLE heartbeats (
    id         BIGSERIAL     PRIMARY KEY,
    monitor_id VARCHAR(128)  NOT NULL,
    ts         BIGINT        NOT NULL,
    status     SMALLINT      NOT NULL,
    latency_us BIGINT        NULL,
    message    VARCHAR(1024) NULL
);
CREATE INDEX heartbeats_monitor_ts ON heartbeats (monitor_id, ts);
CREATE INDEX heartbeats_ts ON heartbeats (ts);

-- Aggregates per hour (resolution 3600) and per day (86400).
CREATE TABLE rollups (
    monitor_id        VARCHAR(128) NOT NULL,
    resolution        INTEGER      NOT NULL,
    bucket            BIGINT       NOT NULL,
    up_count          BIGINT       NOT NULL,
    degraded_count    BIGINT       NOT NULL,
    down_count        BIGINT       NOT NULL,
    maintenance_count BIGINT       NOT NULL,
    latency_sum_us    BIGINT       NOT NULL,
    latency_count     BIGINT       NOT NULL,
    latency_min_us    BIGINT       NULL,
    latency_max_us    BIGINT       NULL,
    PRIMARY KEY (monitor_id, resolution, bucket)
);
CREATE INDEX rollups_resolution_bucket ON rollups (resolution, bucket);

-- State transitions.
CREATE TABLE events (
    id                BIGSERIAL     PRIMARY KEY,
    monitor_id        VARCHAR(128)  NOT NULL,
    ts                BIGINT        NOT NULL,
    from_status       SMALLINT      NULL,
    to_status         SMALLINT      NOT NULL,
    message           VARCHAR(1024) NULL,
    -- Why no notification was sent, if none was.
    suppressed_reason VARCHAR(255)  NULL
);
CREATE INDEX events_monitor_ts ON events (monitor_id, ts);
CREATE INDEX events_ts ON events (ts);

CREATE TABLE notifications (
    id         BIGSERIAL     PRIMARY KEY,
    ts         BIGINT        NOT NULL,
    monitor_id VARCHAR(128)  NULL,
    notifier   VARCHAR(128)  NOT NULL,
    event      VARCHAR(32)   NOT NULL,
    success    SMALLINT      NOT NULL,
    error      VARCHAR(1024) NULL
);
CREATE INDEX notifications_ts ON notifications (ts);
