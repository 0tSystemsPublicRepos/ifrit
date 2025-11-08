i# IFRIT Web Dashboard

Real-time threat detection and monitoring interface for IFRIT Proxy.

## Quick Start

### 1. Create Admin User

First, create an admin user in the database (required for token validation):
```bash
sqlite3 data/ifrit.db << 'EOF'
INSERT INTO api_users (username, email, role, is_active, created_at)
VALUES ('admin', 'admin@ifrit.local', 'admin', 1, datetime('now'));

SELECT id, username, role, is_active FROM api_users;
EOF
```

### 2. Generate API Token

Use the CLI to create a new token:
```bash
cmd/ifrit-cli/ifrit-cli token create 1 "dashboard-token"
```

Output:
```
✓ Token created successfully
  ID:       2
  Token:    ifr_4lTzVPXhjjiTcEFDBOStvc7ZqXf9zQnX
  Expires:  2026-02-06T02:00:58+01:00

Save this token - you won't see it again!
```

**Save this token** - you'll need it to access the dashboard.

### 3. Start API Server
```bash
./ifrit &
```

Server listens on: `https://localhost:8443`

### 4. Access Dashboard

Open browser:
```
http://localhost:8443/
```

Or:
```
http://localhost:8443/dashboard
http://localhost:8443/dashboard.html
```

### 5. Login

Paste your API token in the login form:
```
ifr_4lTzVPXhjjiTcEFDBOStvc7ZqXf9zQnX
```

Token is stored locally in browser `localStorage` under key `ifrit_api_token`.

### 6. View Dashboard

Once authenticated, you'll see:

- **Total Attacks**: All detected malicious requests
- **Unique Attackers**: Number of distinct attacker IPs
- **Detection Rate**: Percentage of requests flagged (always 100%)

### Detection Stages

Three-stage threat detection pipeline:

- **S1 (Local Rules)**: Pattern matching against known signatures
- **S2 (Database Patterns)**: Historical pattern matching
- **S3 (LLM Analysis)**: AI-powered threat analysis

### Recent Attacks Table

Last 10 detected attacks showing:
- **Time**: When attack was detected
- **IP**: Source IP address
- **Type**: Attack classification (SQLi, XSS, etc.)
- **Path**: Target endpoint
- **Method**: HTTP method (GET, POST, etc.)

### Top Attackers

Most active attackers ranked by:
- Source IP address
- Total attack count
- Last seen timestamp

Auto-refreshes every 5 seconds.

## Token Management

### List All Tokens
```bash
cmd/ifrit-cli/ifrit-cli token list
```

Output:
```
ID  USER ID  NAME             PREFIX       EXPIRES AT                 STATUS
2   1        dashboard-token  ifr_4lTz...  2026-02-06T02:00:58+01:00  Active
1   1        dashboard        ifr_abcd...  2026-02-06T01:55:27+01:00  Active

Total: 2 API tokens
```

### Create Token
```bash
cmd/ifrit-cli/ifrit-cli token create [user_id] [token_name]
```

Example:
```bash
cmd/ifrit-cli/ifrit-cli token create 1 "monitoring"
```

Default expiration: **90 days**

### Validate Token
```bash
cmd/ifrit-cli/ifrit-cli token validate ifr_4lTzVPXhjjiTcEFDBOStvc7ZqXf9zQnX
```

Output shows:
- Status (Valid/EXPIRED)
- User ID
- Token name
- App ID
- Permissions
- Expiration date

### Revoke Token
```bash
cmd/ifrit-cli/ifrit-cli token revoke [id]
```

Example:
```bash
cmd/ifrit-cli/ifrit-cli token revoke 2
```

## API Endpoints

All endpoints require `X-API-Token` header.

### Public Endpoints (No Auth)
```bash
# Health check
curl http://localhost:8443/api/health

# Log attacker interaction
curl -X POST http://localhost:8443/api/intel/log \
  -H "Content-Type: application/json" \
  -d '{"data": "value"}'
```

### Protected Endpoints (Auth Required)
```bash
# Get attacks
curl -H "X-API-Token: ifr_token..." http://localhost:8443/api/attacks

# Get attackers
curl -H "X-API-Token: ifr_token..." http://localhost:8443/api/attackers

# Get statistics
curl -H "X-API-Token: ifr_token..." http://localhost:8443/api/stats

# Get patterns
curl -H "X-API-Token: ifr_token..." http://localhost:8443/api/patterns

# List exceptions
curl -H "X-API-Token: ifr_token..." http://localhost:8443/api/exceptions

# Get cache stats
curl -H "X-API-Token: ifr_token..." http://localhost:8443/api/cache/stats

# Get intel stats
curl -H "X-API-Token: ifr_token..." http://localhost:8443/api/intel/stats
```

## Setup Checklist

- [x] Create admin user in database
- [x] Generate API token via CLI
- [x] Start IFRIT API server (`./ifrit`)
- [x] Open dashboard (`http://localhost:8443/`)
- [x] Paste API token in login form
- [x] View real-time threat monitoring

## Troubleshooting

### "Invalid API token" Error

**Cause**: Token doesn't exist or user doesn't exist

**Solution**:
```bash
# Check if admin user exists
sqlite3 data/ifrit.db "SELECT * FROM api_users WHERE id = 1;"

# If empty, create user
sqlite3 data/ifrit.db << 'EOF'
INSERT INTO api_users (username, email, role, is_active, created_at)
VALUES ('admin', 'admin@ifrit.local', 'admin', 1, datetime('now'));
EOF

# Regenerate token
cmd/ifrit-cli/ifrit-cli token create 1 "dashboard-token"
```

### Dashboard Won't Load

**Cause**: API server not running or wrong port

**Solution**:
```bash
# Check if server is listening
lsof -i :8443

# Start server if not running
./ifrit &

# Verify API is responding
curl -H "X-API-Token: ifr_token..." http://localhost:8443/api/attacks
```

### "No attacks detected yet"

**Cause**: No malicious traffic has been logged

**Solution**: 
- Configure IFRIT proxy to forward traffic
- Send test attack requests
- Check: `cmd/ifrit-cli/ifrit-cli attack stats`

### Token Expired

**Cause**: Token expiration date passed

**Solution**: Create new token
```bash
cmd/ifrit-cli/ifrit-cli token create 1 "new-dashboard-token"
```

### Browser Console Errors

**CORS Issues**: Check browser F12 → Console tab for CORS errors. Ensure CORS is enabled in `config/default.json`:
```json
"api": {
  "cors": {
    "enabled": true,
    "allowed_origins": ["*"]
  }
}
```

## Security

### Token Storage

- Tokens stored in `localStorage` (browser only)
- Never transmitted to external services
- Cleared on logout
- Expires automatically after 90 days

### Best Practices

1. **Never commit tokens** to version control
2. **Rotate tokens regularly** - revoke old ones
3. **Use HTTPS in production** - configure TLS
4. **Restrict API access** - use firewall rules
5. **Monitor token usage** - check `token list` regularly

## Configuration

Dashboard settings in `config/default.json`:
```json
"dashboard": {
  "enabled": true,
  "listen_addr": ":5601",
  "authentication": {
    "enabled": true,
    "token_header": "X-Dashboard-Token"
  }
}
```

API server settings:
```json
"api": {
  "listen_addr": ":8443",
  "authentication": {
    "enabled": true,
    "token_header": "X-API-Token",
    "require_auth": true,
    "token_expiry_days": 90
  }
}
```

## Development

### Add New Dashboard Widget

Edit `internal/api/handlers.go` in `handleDashboard()` function - the HTML/JavaScript is embedded as a string.

### Rebuild Dashboard

Changes to dashboard HTML require rebuilding the API server:
```bash
go build -o ifrit ./cmd/ifrit/main.go
./ifrit &
```

### Test API Directly
```bash
# Get your token
TOKEN=$(cmd/ifrit-cli/ifrit-cli token list | grep dashboard | awk '{print $NF}')

# Test endpoint
curl -H "X-API-Token: $TOKEN" http://localhost:8443/api/attacks | jq
```

## Support

For issues or feature requests, check:
- CLI help: `cmd/ifrit-cli/ifrit-cli --help`
- Database schema: `cmd/ifrit-cli/ifrit-cli db schema`
- Attack stats: `cmd/ifrit-cli/ifrit-cli attack stats`
