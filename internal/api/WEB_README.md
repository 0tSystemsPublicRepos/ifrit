# IFRIT Web Dashboard

Real-time threat detection and monitoring interface for IFRIT Proxy.

## Quick Start

### 1. Generate API Token

Use the CLI to create a new token:
```bash
cmd/ifrit-cli/ifrit-cli token create 1 "dashboard-token"
```

Output:
```
✓ Token created successfully
  ID:       1
  Token:    ifr_abcd1234efgh5678ijkl9012mnop3456
  Expires:  2025-02-06T12:34:56Z

Save this token - you won't see it again!
```

**Save this token** - you'll need it to access the dashboard.

### 2. Access Dashboard

Open browser:
```
http://localhost:8443/
```

Or:
```
http://localhost:8443/dashboard
```

### 3. Login

Paste your API token in the login form. Token is stored locally in browser localStorage.

### 4. View Metrics

- **Total Attacks**: All detected malicious requests
- **Unique Attackers**: Number of distinct attacker IPs
- **Detection Rate**: Percentage of requests flagged
- **Detection Stages**:
  - S1: Local Rules (pattern matching)
  - S2: Database Patterns (historical matching)
  - S3: LLM Analysis (AI detection)

### 5. Monitor Activity

- **Recent Attacks**: Last 10 detected attacks with IP, type, path, method
- **Top Attackers**: Most active attackers ranked by request count

## Token Management

### List Tokens
```bash
cmd/ifrit-cli/ifrit-cli token list
```

### Validate Token
```bash
cmd/ifrit-cli/ifrit-cli token validate ifr_abcd1234...
```

### Revoke Token
```bash
cmd/ifrit-cli/ifrit-cli token revoke [id]
```

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

## API Endpoints

All dashboard endpoints require `X-API-Token` header:
```bash
curl -H "X-API-Token: ifr_token..." http://localhost:8443/api/attacks
curl -H "X-API-Token: ifr_token..." http://localhost:8443/api/attackers
curl -H "X-API-Token: ifr_token..." http://localhost:8443/api/stats
```

## Troubleshooting

### "Invalid API token"
- Token doesn't exist or has expired
- Solution: Generate new token with CLI

### Dashboard won't load
- API server not running on port 8443
- Check: `lsof -i :8443`

### Attacks not showing
- No attacks detected yet
- Check: `cmd/ifrit-cli/ifrit-cli attack stats`

## Browser Storage

- Token stored in `localStorage` under key `ifrit_api_token`
- Logout clears local storage
- Token never sent to external servers

## Security Notes

- Tokens expire in 90 days by default
- Always revoke unused tokens
- Don't share tokens in version control
- Use HTTPS in production (configure TLS in config.json)
