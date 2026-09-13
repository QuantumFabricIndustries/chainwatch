-- ChainWatch Cloud — PostgreSQL schema
-- Run with: psql -f schema.sql

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS workspaces (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  slug        TEXT UNIQUE NOT NULL,
  tier        TEXT NOT NULL DEFAULT 'free',  -- 'free' | 'team' | 'enterprise'
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_keys (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  UUID REFERENCES workspaces(id) ON DELETE CASCADE,
  key_hash      TEXT NOT NULL UNIQUE,  -- bcrypt of the actual key (never store raw)
  key_sha256    TEXT UNIQUE,           -- sha256 lookup index (O(1) auth; bcrypt still verifies)
  label         TEXT,                  -- e.g. "ci-prod", "dev-mike"
  last_used_at  TIMESTAMPTZ,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- For databases created before key_sha256 existed.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_sha256 TEXT UNIQUE;
CREATE INDEX IF NOT EXISTS api_keys_sha256 ON api_keys(key_sha256);

CREATE TABLE IF NOT EXISTS repos (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  UUID REFERENCES workspaces(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,  -- "org/repo-name"
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(workspace_id, name)
);

CREATE TABLE IF NOT EXISTS findings (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  repo_id       UUID REFERENCES repos(id) ON DELETE CASCADE,
  run_id        TEXT NOT NULL,          -- CI run ID or local timestamp
  severity      TEXT NOT NULL,          -- critical|high|medium|low
  signal        TEXT NOT NULL,          -- CW001–CW007
  package       TEXT NOT NULL,          -- "name@version"
  description   TEXT NOT NULL,
  file          TEXT,
  evidence      TEXT,
  chain_score   INTEGER,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS findings_repo_severity ON findings(repo_id, severity, created_at DESC);
CREATE INDEX IF NOT EXISTS findings_created_at ON findings(created_at DESC);

CREATE TABLE IF NOT EXISTS baselines (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  repo_id       UUID REFERENCES repos(id) ON DELETE CASCADE,
  lockfile_hash TEXT NOT NULL,           -- sha256 of package-lock.json
  content       BYTEA NOT NULL,          -- gzip-compressed JSONL
  run_count     INTEGER DEFAULT 1,
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(repo_id, lockfile_hash)
);

CREATE TABLE IF NOT EXISTS alert_configs (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  UUID REFERENCES workspaces(id) ON DELETE CASCADE,
  type          TEXT NOT NULL,           -- 'slack' | 'webhook'
  config        JSONB NOT NULL,          -- {url, channel} for slack; {url, secret} for webhook
  min_severity  TEXT NOT NULL DEFAULT 'high',
  enabled       BOOLEAN DEFAULT TRUE,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);
