PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS registrations (
  id TEXT PRIMARY KEY,
  reg_number INTEGER NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  address TEXT,
  car_year TEXT NOT NULL,
  car_make TEXT NOT NULL,
  car_model TEXT NOT NULL,
  car_color TEXT NOT NULL,
  class TEXT NOT NULL CHECK (class IN ('car_truck','motorcycle','other')),
  attended_before TEXT CHECK (attended_before IN ('yes','no')),
  tshirt_size TEXT CHECK (tshirt_size IN ('small','medium','large','xl','2xl','3xl')),
  has_home_church TEXT CHECK (has_home_church IN ('yes','no')),
  home_church_name TEXT,
  checked_in_at TEXT,
  notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_reg_name ON registrations(name);
CREATE INDEX IF NOT EXISTS idx_reg_checkedin ON registrations(checked_in_at);

CREATE TABLE IF NOT EXISTS votes (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  class TEXT NOT NULL CHECK (class IN ('car_truck','motorcycle','other')),
  reg_number INTEGER NOT NULL,
  ballot_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_votes_class ON votes(class);
CREATE INDEX IF NOT EXISTS idx_votes_reg ON votes(reg_number);

CREATE TABLE IF NOT EXISTS prize_winners (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  prize_name TEXT NOT NULL,
  reg_number INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_prize_reg ON prize_winners(reg_number);

CREATE TABLE IF NOT EXISTS rate_limits (
  k TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  hit_count INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (k, window_start)
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_expires ON rate_limits(expires_at);
