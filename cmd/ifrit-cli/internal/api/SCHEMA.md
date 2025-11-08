# IFRIT Database Schema

## Core Tables

### api_tokens
```sql
CREATE TABLE api_tokens (
  id INTEGER PRIMARY KEY,
  user_id INTEGER,
  token_name TEXT,
  token_hash TEXT UNIQUE,
  token_prefix TEXT,
  app_id TEXT,
  permissions TEXT,
  expires_at TEXT,
  created_at TEXT
);
```

Example:
```bash
sqlite3 data/ifrit.db << EOF
INSERT INTO api_tokens (user_id, token_name, token_hash, token_prefix, app_id, permissions, expires_at, created_at)
VALUES (1, 'dashboard', 'hash_here', 'ifr_abc', 'default', '["read","write"]', datetime('now', '+90 days'), datetime('now'));
EOF
```

### attack_instances
```sql
CREATE TABLE attack_instances (
  id INTEGER PRIMARY KEY,
  app_id TEXT,
  pattern_id INTEGER,
  source_ip TEXT,
  user_agent TEXT,
  requested_path TEXT,
  http_method TEXT,
  timestamp TEXT
);
```

### attacker_profiles
```sql
CREATE TABLE attacker_profiles (
  id INTEGER PRIMARY KEY,
  app_id TEXT,
  source_ip TEXT,
  total_requests INTEGER,
  attack_types TEXT,
  first_seen TEXT,
  last_seen TEXT
);
```

## Check Your Database
```bash
# List all tables
sqlite3 data/ifrit.db ".tables"

# Check api_tokens schema
sqlite3 data/ifrit.db ".schema api_tokens"

# List existing tokens
sqlite3 data/ifrit.db "SELECT id, token_name, token_prefix, expires_at FROM api_tokens;"
```
