-- Runtime actions from the API: acknowledgements and silences of monitors,
-- and maintenance windows created at runtime (configured windows stay in
-- the configuration).

ALTER TABLE monitor_state
    ADD COLUMN ack_by         VARCHAR(255) NULL,
    ADD COLUMN ack_at         BIGINT       NULL,
    ADD COLUMN ack_comment    VARCHAR(512) NULL,
    ADD COLUMN silenced_until BIGINT       NULL,
    ADD COLUMN silenced_by    VARCHAR(255) NULL;

CREATE TABLE maintenance_windows (
    id          VARCHAR(128)  PRIMARY KEY,
    description VARCHAR(1024) NULL,
    -- JSON: {"all": bool, "monitors": [...], "groups": [...], "tags": [...]}
    selection   TEXT          NOT NULL,
    start_ms    BIGINT        NOT NULL,
    end_ms      BIGINT        NOT NULL,
    created_by  VARCHAR(255)  NOT NULL,
    created_at  BIGINT        NOT NULL
);
CREATE INDEX maintenance_windows_end ON maintenance_windows (end_ms);
