# Detection Modes

IFRIT supports two different security modes: **Detection Mode** (default) and **Allowlist Mode**. Choose the mode that matches your security requirements.

---

## Detection Mode (Default)

**Use when:** You want smart threat detection with minimal false positives.

### How It Works

All traffic is analyzed by the detection pipeline:

```
Request arrives
    ↓
Is IP/path whitelisted? → YES → Allow through ✓
    ↓ NO
Stage 1: Check local rules → Attack? → Block with honeypot
    ↓
Stage 2: Check learned patterns → Attack? → Block with honeypot
    ↓
Stage 3: LLM analysis (POST/PUT/DELETE) → Attack? → Block with honeypot
    ↓
Legitimate traffic → Forward to backend ✓
```

### Configuration

```json
{
  "detection": {
    "mode": "detection",
    "enable_local_rules": true,
    "enable_llm": true,
    "llm_only_on": ["POST", "PUT", "DELETE"],
    "whitelist_ips": [],
    "whitelist_paths": []
  }
}
```

### Whitelist (Optional)

Bypass detection for trusted IPs or paths:

```json
{
  "detection": {
    "mode": "detection",
    "whitelist_ips": [
      "192.168.1.100",
      "10.0.0.50"
    ],
    "whitelist_paths": [
      "/health",
      "/status",
      "^/metrics.*"
    ]
  }
}
```

**Whitelisted IPs:** ALL paths allowed  
**Whitelisted paths:** Allowed from ANY IP

### Use Cases

-  Standard deployment
-  Detect attacks + learn patterns
-  Some traffic exceptions needed
-  False positive tolerance

---

## Allowlist Mode

**Use when:** You need strict access control - only authorized IPs/paths allowed.

### How It Works

Only whitelisted traffic is allowed. Everything else is blocked with a fake response:

```
Request arrives
    ↓
Is IP/path whitelisted? → YES → Allow through ✓
    ↓ NO
Block request and return fantasy response (via payload management)
```

### Configuration

```json
{
  "detection": {
    "mode": "allowlist",
    "whitelist_ips": [
      "192.168.1.100",
      "10.0.0.50",
      "203.0.113.0"
    ],
    "whitelist_paths": [
      "/health",
      "/status"
    ]
  }
}
```

### How Allowlist Works

**Whitelisted IP** (e.g., `192.168.1.100`):
- ALL paths allowed
- No detection needed
- Instant response

**Whitelisted path** (e.g., `/health`):
- Allowed from ANY IP
- No detection needed
- Instant response

**Non-whitelisted request** (e.g., `203.0.113.5` to `/api/users`):
- Blocked immediately
- Returns fake response (from `blocked_by_allowlist` in payload config)
- Logged as attack

### Blocked Request Response

When a non-whitelisted request arrives, IFRIT returns:

**If `generate_dynamic_payload: true`:**
```
LLM generates realistic fake response
```

**If `generate_dynamic_payload: false`:**
```
Config default response
Status: 403 Forbidden (or configured)
Body: {"error": "Forbidden"}
(this response can be customized)
```

### Use Cases

-  VPN-only access
-  Admin portal (IP restricted)
-  Internal network only
-  API gateway (authorized IPs only)
-  Strict zero-trust network
-  Honeypot for unauthorized access

---

## Comparison

| Feature | Detection Mode | Allowlist Mode |
|---------|----------------|----------------|
| **Default action** | Analyze traffic | Block traffic |
| **Whitelisted IPs** | Bypass detection | Allow all paths |
| **Whitelisted paths** | Allow from any IP | Allow from any IP |
| **Non-whitelisted** | Detection pipeline | Immediate block |
| **False positives** | Possible (~5%) | None (by design) |
| **Setup complexity** | Low | Very low |
| **Learning capability** | Yes | No |
| **Logging** | Full detection logs | Access denied logs |

---

## Configuration Examples

### Example 1: Standard Detection (Most Users)

```json
{
  "detection": {
    "mode": "detection",
    "enable_local_rules": true,
    "enable_llm": true,
    "llm_only_on": ["POST", "PUT", "DELETE"],
    "whitelist_ips": [],
    "whitelist_paths": []
  }
}
```

**Result:** Smart threat detection, learns patterns, blocks attacks

---

### Example 2: Detection with Admin Bypass

```json
{
  "detection": {
    "mode": "detection",
    "enable_local_rules": true,
    "enable_llm": true,
    "whitelist_ips": [
      "192.168.1.100",
      "10.0.0.50"
    ],
    "whitelist_paths": [
      "/health",
      "/status"
    ]
  }
}
```

**Result:** Admin IPs bypass detection, health checks always allowed, all other traffic analyzed

---

### Example 3: Strict Allowlist (VPN Only)

```json
{
  "detection": {
    "mode": "allowlist",
    "whitelist_ips": [
      "10.0.0.0/8"
    ],
    "whitelist_paths": []
  }
}
```

**Result:** Only internal network (10.0.0.0/8) allowed, everything else blocked

---

### Example 4: Allowlist with Public Endpoints

```json
{
  "detection": {
    "mode": "allowlist",
    "whitelist_ips": [
      "192.168.1.100"
    ],
    "whitelist_paths": [
      "/api/health",
      "/api/status",
      "^/public/.*"
    ]
  }
}
```

**Result:**
- Admin IP (192.168.1.100) can access everything
- Any IP can access `/api/health`, `/api/status`, `/public/*`
- Everything else blocked

---

## Switching Modes

### From Detection to Allowlist

```bash
# Stop IFRIT
# Edit config/default.json
sed -i '' 's/"mode": "detection"/"mode": "allowlist"/' config/default.json

# Add your whitelisted IPs/paths
# Restart
./ifrit
```

### From Allowlist to Detection

```bash
# Stop IFRIT
# Edit config/default.json
sed -i '' 's/"mode": "allowlist"/"mode": "detection"/' config/default.json

# Restart
./ifrit
```

No database changes needed - all learned patterns are preserved.

---

## Monitoring Blocked Requests

### View blocked requests in allowlist mode

```bash
# CLI - show all attacks (includes blocked requests)
./ifrit-cli attack list

# Show attacks from specific IP
./ifrit-cli attack by-ip 203.0.113.5

# Show attacks on specific path
./ifrit-cli attack by-path /api/admin
```

### Check logs

```bash
# Watch logs in real-time
tail -f logs/ifrit.log | grep ALLOWLIST

# Count blocked requests
grep "ALLOWLIST" logs/ifrit.log | wc -l
```

---

## Best Practices

### For Detection Mode

1. **Start with no whitelist** - Let IFRIT learn your traffic
2. **Monitor first week** - Check for false positives
3. **Add exceptions gradually** - Whitelist only necessary paths/IPs
4. **Review learned patterns** - `./ifrit-cli pattern list`

### For Allowlist Mode

1. **List all IPs** - Be explicit about what's allowed
2. **Use IP ranges** - `10.0.0.0/8` instead of individual IPs
3. **Keep paths minimal** - Only public endpoints if needed
4. **Document exceptions** - Why is this IP/path whitelisted?

---

## Troubleshooting

### All requests blocked in allowlist mode?

Check if you've added your own IP to whitelist:

```json
"whitelist_ips": ["YOUR.IP.HERE"]
```

Test locally: `127.0.0.1` or `::1` for IPv6

### Getting false positives in detection mode?

Add the path to whitelist:

```json
"whitelist_paths": ["/your/path"]
```

Or check logs for the pattern and adjust detection rules.

### Need to allow specific IP but block one path?

Use detection mode with selective whitelist:

```json
{
  "detection": {
    "mode": "detection",
    "whitelist_ips": ["192.168.1.100"],
    "whitelist_paths": []
  }
}
```

Then manually block by running detection on that path separately.

---

## Summary

- **Detection Mode**: Smart analysis, learns threats, some false positives possible
- **Allowlist Mode**: Strict control, zero false positives, explicit whitelist required

Choose based on your security posture and traffic patterns. You can switch anytime without data loss.
