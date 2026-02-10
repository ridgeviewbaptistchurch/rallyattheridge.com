-- Adds table for API rate limiting windows.
CREATE TABLE IF NOT EXISTS rate_limits (
  k TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  hit_count INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (k, window_start)
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_expires ON rate_limits(expires_at);
