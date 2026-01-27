# Cookie Domain Rewriting

## Overview

IFRIT Proxy can automatically rewrite `Set-Cookie` headers from backend services to add a `Domain` attribute. This is useful when:

- Running multiple subdomains that need to share authentication cookies
- Using IFRIT as a reverse proxy for applications across different subdomains
- Implementing cross-subdomain session sharing

## Configuration

Add the `cookie_options` section to your `server` configuration in `config/default.json`:
```json
{
  "server": {
    "listen_addr": ":8080",
    "api_listen_addr": ":8443",
    "proxy_target": "http://localhost:5001",
    "cookie_options": {
      "rewrite_domain": true,
      "domain": ".example.com"
    }
  }
}
```

### Configuration Options

- **`rewrite_domain`** (boolean): Enable or disable cookie domain rewriting
  - `true`: Enable domain rewriting for Set-Cookie headers
  - `false`: Disable (default behavior, no rewriting)

- **`domain`** (string): The domain to add to cookies
  - Must start with a dot (`.`) for subdomain matching (e.g., `.example.com`)
  - Example: `.algoverde.ai` allows cookies to work on `app.algoverde.ai`, `api.algoverde.ai`, etc.
  - Leave empty (`""`) to disable rewriting even if `rewrite_domain` is true

## How It Works

When `rewrite_domain` is enabled and a `domain` is configured:

1. IFRIT intercepts all `Set-Cookie` headers from backend responses
2. If a cookie doesn't already have a `Domain` attribute, IFRIT adds one
3. The cookie becomes accessible across all subdomains matching the configured domain
4. If a cookie already has a `Domain` attribute, it's left unchanged

## Example Use Case

### Problem
You have three services:
- `app.example.com` (main application on port 3000)
- `api.example.com` (API server on port 5000)
- `auth.example.com` (authentication service on port 8000)

Authentication cookies set by `auth.example.com` don't work on `app.example.com` because they're domain-specific.

### Solution

Configure IFRIT with:
```json
{
  "server": {
    "multi_app_mode": true,
    "app_id_header": "X-App-ID",
    "cookie_options": {
      "rewrite_domain": true,
      "domain": ".example.com"
    }
  },
  "apps": {
    "app": {
      "proxy_target": "http://localhost:3000",
      "enabled": true
    },
    "api": {
      "proxy_target": "http://localhost:5000",
      "enabled": true
    },
    "auth": {
      "proxy_target": "http://localhost:8000",
      "enabled": true
    }
  }
}
```

Now all cookies from any backend will have `Domain=.example.com`, allowing them to work across all subdomains.

## Security Considerations

1. **Use with caution**: Setting a wildcard domain (`.example.com`) means cookies are shared across ALL subdomains
2. **HTTPS recommended**: Always use HTTPS when sharing cookies across domains
3. **SameSite attribute**: Consider also setting appropriate `SameSite` attributes on your backend cookies
4. **Scope carefully**: Only enable this for domains you control completely

## Debugging

To verify cookie domain rewriting is working:

1. Enable debug logging in `config/default.json`:
```json
   "system": {
     "debug": true,
     "log_level": "debug"
   }
```

2. Watch the logs for cookie modifications:
```bash
   tail -f logs/ifrit.log | grep "Set-Cookie"
```

3. Use browser developer tools to inspect cookies and verify the `Domain` attribute

## Disabling Cookie Rewriting

To disable cookie domain rewriting:
```json
{
  "server": {
    "cookie_options": {
      "rewrite_domain": false,
      "domain": ""
    }
  }
}
```

Or simply omit the `cookie_options` section entirely (it's optional).
