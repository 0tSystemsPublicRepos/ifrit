# IFRIT Proxy - Installation & Setup Guide

**Version:** 0.3.0  
**Last Updated:** December 1st, 2025

---

## Quick Start (5 minutes)

### Prerequisites
- Go 1.21+
- SQLite3 (default) or PostgreSQL (optional)
- Claude or Gemini API key (or both if you are using fallback mechanism for redundancy) 

### 1. Clone Repository
```bash
git clone https://github.com/0tSystemsPublicRepos/ifrit.git
cd ifrit
```

### 2. Configure
```bash
cp config/default.json.example config/default.json
nano config/default.json
```

Add your Claude/Gemini API key under the relevant section in configuration:
```json
{
  "llm": {
    "claude": {
      "api_key": "sk-ant-YOUR-KEY-HERE"
    }
  }
}
```

### 3. Build
```bash
go build -o ifrit ./cmd/ifrit
go build -o ifrit-cli ./cmd/ifrit-cli
```
PS: also make sure ifrit-cli can access the database file!

### 4. Run
```bash
./ifrit
```

Output:
```
..
..
Configuration loaded
Database: ./data/ifrit.db (type: sqlite)
Proxy target: http://localhost:80
LLM Provider: claude

✓ Database initialized
✓ LLM Manager initialized (primary: claude)
✓ Anonymization engine initialized (strategy: hybrid)
✓ Detection engine initialized
  Mode: detection
✓ Payload manager initialized
✓ Execution mode: detection

Starting API server on :8443
Starting proxy server on :8080
..
..
```

### 5. Test
```bash
# Test attack detection
curl http://localhost:8080/?q=<script>alert(1)</script>

# Check CLI
./ifrit-cli exception list
```

---

## Database Configuration

IFRIT supports two database backends: **SQLite** (default) and **PostgreSQL**.

### SQLite (Default)

No setup required - SQLite database is created automatically at `./data/ifrit.db` on first run.

**Pros:**
- Zero configuration
- Embedded (no separate server)
- Perfect for development and small deployments
- Fast for <1M records

**Cons:**
- Single writer (no clustering)
- Limited concurrent connections
- May be slow for very large datasets (>1M attacks)

**Configuration:**
```json
{
  "database": {
    "type": "sqlite",
    "path": "./data/ifrit.db"
  }
}
```

---

### PostgreSQL (Recommended for Production)

For high-volume deployments, multiple IFRIT instances, or large datasets.

**Pros:**
- Multi-writer support (clustering)
- Better performance at scale (>1M records)
- Advanced features (replication, backups)
- Industry-standard RDBMS

**Cons:**
- Requires separate PostgreSQL server
- More complex setup
- Additional infrastructure

#### Step 1: Install PostgreSQL

**macOS (Homebrew):**
```bash
brew install postgresql@15
brew services start postgresql@15
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

**Docker:**
```bash
docker run -d \
  --name ifrit-postgres \
  -e POSTGRES_PASSWORD=your_secure_password \
  -e POSTGRES_DB=ifrit \
  -p 5432:5432 \
  postgres:15
```

#### Step 2: Create Database and User
```bash
# Connect as postgres user
sudo -u postgres psql

# Create database and user
CREATE DATABASE ifrit;
CREATE USER ifrit_user WITH ENCRYPTED PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE ifrit TO ifrit_user;

# Exit
\q
```

**For Docker:**
```bash
docker exec -it ifrit-postgres psql -U postgres

# Then run the same SQL commands above
```

#### Step 3: Configure IFRIT

Edit `config/default.json`:
```json
{
  "database": {
    "type": "postgres",
    "host": "localhost",
    "port": 5432,
    "user": "ifrit_user",
    "password": "your_secure_password",
    "dbname": "ifrit"
  }
}
```

**Environment Variables (Recommended for Production):**
```bash
export IFRIT_DB_PASSWORD="your_secure_password"
```

Then in config:
```json
{
  "database": {
    "type": "postgres",
    "host": "localhost",
    "port": 5432,
    "user": "ifrit_user",
    "password": "${IFRIT_DB_PASSWORD}",
    "dbname": "ifrit"
  }
}
```

#### Step 4: Start IFRIT
```bash
./ifrit
```

**Expected Output:**
```
[INFO] Initializing PostgreSQL database provider...
[INFO] Connected to PostgreSQL: localhost:5432/ifrit
[INFO] Creating database schema...
[INFO] Created 21 tables successfully
[INFO] Database initialization complete
[INFO] Starting proxy server on :8080
```

#### Step 5: Verify Tables
```bash
psql -U ifrit_user -d ifrit -h localhost

\dt

# You should see 21 tables:
# - attack_instances
# - attack_patterns
# - attacker_profiles
# - threat_intelligence
# - notification_history
# ... and 16 more
```

---

### Switching Between Databases

**SQLite → PostgreSQL:**

1. **Export SQLite data** (optional - for migration):
```bash
   sqlite3 ./data/ifrit.db .dump > ifrit_backup.sql
```

2. **Update config:**
```bash
   nano config/default.json
   # Change "type": "sqlite" to "type": "postgres"
   # Add PostgreSQL connection details
```

3. **Restart IFRIT:**
```bash
   pkill ifrit
   ./ifrit
```

4. **Import data** (manual - if migrating):
   - Convert SQLite dump to PostgreSQL format
   - Use `psql` to import

**PostgreSQL → SQLite:**

1. **Export PostgreSQL data** (optional):
```bash
   pg_dump -U ifrit_user ifrit > ifrit_backup.sql
```

2. **Update config:**
```bash
   nano config/default.json
   # Change "type": "postgres" to "type": "sqlite"
```

3. **Restart IFRIT:**
```bash
   pkill ifrit
   ./ifrit
```

---

### Database Comparison

| Feature | SQLite | PostgreSQL |
|---------|--------|------------|
| **Setup** | Automatic | Manual setup required |
| **Performance (<1M records)** | Fast | Fast |
| **Performance (>1M records)** | Slower | Fast |
| **Concurrent writes** | Single writer | Multiple writers |
| **Clustering** | Not supported | Supported |
| **Backup** | Copy file | pg_dump / replication |
| **Production ready** | Small deployments | All deployments |
| **Resource usage** | Minimal | Moderate |

**Recommendation:**
- **Development/Testing:** SQLite
- **Small deployments (<100k attacks/day):** SQLite
- **Production (>100k attacks/day):** PostgreSQL
- **Multi-instance clustering:** PostgreSQL required

---

### Troubleshooting Database Issues

#### PostgreSQL Connection Failed

**Error:** `pq: password authentication failed`

**Solution:**
```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Verify user exists
psql -U postgres -c "\du"

# Reset password
psql -U postgres -c "ALTER USER ifrit_user WITH PASSWORD 'new_password';"
```

#### Tables Not Created

**Error:** `relation "attack_instances" does not exist`

**Solution:**
```bash
# Check IFRIT logs for schema creation errors
tail -f logs/ifrit.log | grep "CREATE TABLE"

# Restart IFRIT to retry schema creation
pkill ifrit
./ifrit
```

#### Permission Denied on PostgreSQL

**Error:** `pq: permission denied for database ifrit`

**Solution:**
```bash
psql -U postgres << EOF
GRANT ALL PRIVILEGES ON DATABASE ifrit TO ifrit_user;
GRANT ALL ON SCHEMA public TO ifrit_user;
EOF
```

#### CLI Not Working with PostgreSQL

**Issue:** CLI commands fail after switching to PostgreSQL

**Solution:** CLI automatically detects database type from `config/default.json`. Ensure config is correct:
```bash
cat config/default.json | grep -A7 '"database"'
```

---

## Detailed Installation

### macOS

#### Install Go
```bash
brew install go@1.21
```

#### Install Dependencies
```bash
brew install sqlite3
# Optional: Install PostgreSQL
brew install postgresql@15
```

#### Clone & Build
```bash
git clone https://github.com/0tSystemsPublicRepos/ifrit.git
cd ifrit
go build -o ifrit ./cmd/ifrit
go build -o ifrit-cli ./cmd/ifrit-cli
```

#### Run Locally
```bash
./ifrit
```

#### Optional: Install to System Path
```bash
sudo mv ifrit /usr/local/bin/
sudo mv ifrit-cli /usr/local/bin/

# Then run from anywhere
ifrit
ifrit-cli pattern list
```

---

### Linux (Ubuntu/Debian)

#### Install Go
```bash
wget https://go.dev/dl/go1.21.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Make permanent
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

#### Install Dependencies
```bash
sudo apt-get update
sudo apt-get install sqlite3
# Optional: Install PostgreSQL
sudo apt-get install postgresql postgresql-contrib
```

#### Clone & Build
```bash
git clone https://github.com/0tSystemsPublicRepos/ifrit.git
cd ifrit
go build -o ifrit ./cmd/ifrit
go build -o ifrit-cli ./cmd/ifrit-cli
```

#### Create System User (Recommended)
```bash
sudo useradd -r -s /bin/false ifrit
sudo mkdir -p /opt/ifrit/{data,logs,config}
sudo cp -r . /opt/ifrit/
sudo chown -R ifrit:ifrit /opt/ifrit
```

#### Systemd Service (Optional)

Create `/etc/systemd/system/ifrit.service`:
```ini
[Unit]
Description=IFRIT Proxy - Intelligent Threat Detection
After=network.target
Documentation=https://github.com/0tSystemsPublicRepos/ifrit

[Service]
Type=simple
User=ifrit
Group=ifrit
WorkingDirectory=/opt/ifrit
ExecStart=/opt/ifrit/ifrit
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ifrit
sudo systemctl start ifrit
sudo systemctl status ifrit

# View logs
sudo journalctl -u ifrit -f
```

---

### Linux (RHEL/CentOS/Fedora)

#### Install Go
```bash
sudo dnf install golang
go version
```

#### Install Dependencies
```bash
sudo dnf install sqlite-devel
# Optional: Install PostgreSQL
sudo dnf install postgresql-server postgresql-contrib
```

#### Clone & Build
```bash
git clone https://github.com/0tSystemsPublicRepos/ifrit.git
cd ifrit
go build -o ifrit ./cmd/ifrit
go build -o ifrit-cli ./cmd/ifrit-cli
```

#### SELinux Considerations (Optional)

If SELinux is enforced:
```bash
sudo semanage fcontext -a -t bin_t "/opt/ifrit/ifrit"
sudo restorecon /opt/ifrit/ifrit
```

---

### Docker

#### Build Image

Create `Dockerfile` (if not included):
```dockerfile
FROM golang:1.21-alpine as builder
WORKDIR /app
COPY . .
RUN go build -o ifrit ./cmd/ifrit
RUN go build -o ifrit-cli ./cmd/ifrit-cli

FROM alpine:latest
RUN apk --no-cache add ca-certificates sqlite
WORKDIR /app
COPY --from=builder /app/ifrit .
COPY --from=builder /app/ifrit-cli .
COPY config/default.json.example config/default.json
EXPOSE 8080 8443
CMD ["./ifrit"]
```

Build:
```bash
docker build -t ifrit:latest .
```

#### Run Container
```bash
docker run -d \
  -p 8080:8080 \
  -p 8443:8443 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  -e IFRIT_PROXY_TARGET="http://backend:3000" \
  --name ifrit \
  ifrit:latest
```

View logs:
```bash
docker logs -f ifrit
```

#### Docker Compose

Create `docker-compose.yml`:
```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: ifrit
      POSTGRES_USER: ifrit_user
      POSTGRES_PASSWORD: your_secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - ifrit-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ifrit_user"]
      interval: 10s
      timeout: 5s
      retries: 5

  ifrit:
    build: .
    ports:
      - "8080:8080"
      - "8443:8443"
    volumes:
      - ./config:/app/config
      - ./data:/app/data
      - ./logs:/app/logs
    environment:
      IFRIT_PROXY_TARGET: "http://backend:3000"
      IFRIT_MODE: "detection"
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped
    networks:
      - ifrit-network

  backend:
    image: your-app:latest
    networks:
      - ifrit-network
    expose:
      - "3000"

networks:
  ifrit-network:
    driver: bridge

volumes:
  postgres_data:
```

Run:
```bash
docker-compose up -d
docker-compose logs -f ifrit
```

Stop:
```bash
docker-compose down
```

---

## Configuration

### File Location
```
config/default.json
```

### Minimal Configuration (Onboarding)
```json
{
  "server": {
    "listen_addr": ":8080",
    "proxy_target": "http://localhost:80"
  },
  "database": {
    "type": "sqlite",
    "path": "./data/ifrit.db"
  },
  "llm": {
    "primary": "claude",
    "claude": {
      "api_key": "sk-ant-YOUR-KEY-HERE",
      "model": "claude-3-5-haiku-20241022"
    }
  },
  "execution_mode": {
    "mode": "onboarding"
  }
}
```

### Production Configuration (Normal Mode - SQLite)
```json
{
  "server": {
    "listen_addr": "0.0.0.0:8080",
    "api_listen_addr": "127.0.0.1:8443",
    "proxy_target": "http://app-backend:3000",
    "multi_app_mode": false,
    "tls": {
      "enabled": false
    }
  },
  "database": {
    "type": "sqlite",
    "path": "./data/ifrit.db"
  },
  "llm": {
    "primary": "claude",
    "claude": {
      "api_key": "sk-ant-YOUR-KEY-HERE",
      "model": "claude-3-5-haiku-20241022"
    }
  },
  "detection": {
    "mode": "detection",
    "enable_local_rules": true,
    "enable_llm": true,
    "llm_only_on": ["POST", "PUT", "DELETE"],
    "skip_body_check_on_whitelist": false,
    "whitelist_ips": [],
    "whitelist_paths": ["/health", "/metrics"]
  },
  "execution_mode": {
    "mode": "deception"
  },
  "anonymization": {
    "enabled": true,
    "strategy": "hybrid",
    "store_original": false,
    "sensitive_headers": [
      "Authorization",
      "Cookie",
      "X-API-Key"
    ]
  },
  "payload_management": {
    "generate_dynamic_payload": true,
    "dynamic_llm_cache_ttl": 86400
  },
  "system": {
    "log_dir": "./logs",
    "log_level": "info",
    "debug": false
  }
}
```

### Production Configuration (PostgreSQL)
```json
{
  "server": {
    "listen_addr": "0.0.0.0:8080",
    "api_listen_addr": "127.0.0.1:8443",
    "proxy_target": "http://app-backend:3000"
  },
  "database": {
    "type": "postgres",
    "host": "localhost",
    "port": 5432,
    "user": "ifrit_user",
    "password": "your_secure_password",
    "dbname": "ifrit"
  },
  "llm": {
    "primary": "claude",
    "claude": {
      "api_key": "sk-ant-YOUR-KEY-HERE",
      "model": "claude-3-5-haiku-20241022"
    }
  },
  "detection": {
    "mode": "detection",
    "enable_local_rules": true,
    "enable_llm": true
  },
  "execution_mode": {
    "mode": "deception"
  },
  "system": {
    "log_dir": "./logs",
    "log_level": "info"
  }
}
```

### Configuration Parameters

#### Server Section
```json
{
  "server": {
    "listen_addr": ":8080",           // Proxy listener
    "api_listen_addr": ":8443",       // API listener
    "proxy_target": "http://...",     // Backend target
    "multi_app_mode": false,          // Multi-app support
    "app_id_header": "X-App-ID",      // App ID header
    "app_id_fallback": "default"      // Default app ID
  }
}
```

#### Database Section (NEW in 0.3.0)
```json
{
  "database": {
    "type": "sqlite",                 // "sqlite" or "postgres"
    "path": "./data/ifrit.db",        // SQLite only
    "host": "localhost",              // PostgreSQL only
    "port": 5432,                     // PostgreSQL only
    "user": "ifrit_user",             // PostgreSQL only
    "password": "password",           // PostgreSQL only
    "dbname": "ifrit"                 // PostgreSQL only
  }
}
```

#### Detection Section
```json
{
  "detection": {
    "mode": "detection",              // detection or allowlist
    "enable_local_rules": true,       // Stage 1
    "enable_llm": true,               // Stage 3
    "llm_only_on": ["POST", "PUT"],   // LLM for these methods
    "skip_body_check_on_whitelist": false,  // NEW in 0.1.1
    "whitelist_ips": [],              // Whitelisted IPs
    "whitelist_paths": []             // Whitelisted paths
  }
}
```

#### Execution Mode Section
```json
{
  "execution_mode": {
    "mode": "onboarding",             // onboarding, deception 
    "onboarding_auto_whitelist": true,
    "onboarding_duration_days": 7,
    "onboarding_log_file": "./logs/onboarding.log"
  }
}
```

#### Anonymization Section
```json
{
  "anonymization": {
    "enabled": true,                  // Enable anonymization
    "strategy": "hybrid",             // hybrid, header-only, or disabled
    "store_original": false,          // Store original data?
    "sensitive_headers": [            // Headers to redact
      "Authorization",
      "Cookie",
      "X-API-Key"
    ]
  }
}
```

#### System Section
```json
{
  "system": {
    "home_dir": "./",
    "log_dir": "./logs",
    "log_level": "info",              // info, debug, warn, error
    "debug": false                    // Enable debug logging
  }
}
```

### Environment Variables

Override config with environment variables (optional):
```bash
export IFRIT_LISTEN=":9000"
export IFRIT_TARGET="http://backend:8080"
export IFRIT_MODE="deception"
export IFRIT_DEBUG="false"
export CLAUDE_API_KEY="sk-ant-..."
export IFRIT_DB_PASSWORD="your_password"
```

---

## Networking Setup

### Single Machine (Development)
```
┌─────────┐
│ Client  │
└────┬────┘
     │ :8080
     ▼
┌──────────────┐
│ IFRIT Proxy  │
└─────┬────────┘
      │ http://localhost:3000
      ▼
┌──────────────┐
│ Backend App  │
└──────────────┘
```

### Behind Load Balancer (Production)
```
┌─────────┐
│ Internet│
└────┬────┘
     │ :443 (HTTPS)
     ▼
┌──────────────────┐
│ Load Balancer    │
└──────┬───────────┘
       │
       ├─── IFRIT 1 :8080
       ├─── IFRIT 2 :8080
       └─── IFRIT 3 :8080
           │
           ▼
      ┌──────────────┐
      │ Backend App  │
      └──────────────┘
```

### High Availability with PostgreSQL
```
Multiple IFRIT instances sharing PostgreSQL database

┌─────────┐
│ Load    │
│Balancer │
└────┬────┘
     │
     ├─── IFRIT 1 ──┐
     ├─── IFRIT 2 ──┼─── PostgreSQL (Shared DB)
     └─── IFRIT 3 ──┘
```

---

## Firewall Configuration

### Inbound Rules
```bash
# Allow proxy traffic from internet
Allow TCP 8080 from 0.0.0.0/0

# Restrict API to internal network only
Allow TCP 8443 from 10.0.0.0/8
Allow TCP 8443 from 192.168.0.0/16

# PostgreSQL (if remote)
Allow TCP 5432 from IFRIT_SERVERS only
```

### Outbound Rules
```bash
# Allow outbound to Claude API / Google Gemini
Allow TCP 443 to api.anthropic.com
Allow TCP 443 to generativelanguage.googleapis.com

# Allow DNS
Allow UDP 53 to 0.0.0.0/0

# PostgreSQL (if remote)
Allow TCP 5432 to POSTGRES_SERVER
```

### UFW (Ubuntu Firewall)
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (if remote)
sudo ufw allow 22/tcp

# Allow proxy
sudo ufw allow 8080/tcp

# Allow API from internal only
sudo ufw allow from 10.0.0.0/8 to any port 8443

# PostgreSQL (if remote)
sudo ufw allow from IFRIT_IP to any port 5432

sudo ufw enable
sudo ufw status
```

---

## Verification

### Check Installation
```bash
# Verify Go installation
go version

# Verify SQLite
sqlite3 --version

# Verify PostgreSQL (if using)
psql --version

# Verify binaries built
ls -la ifrit ifrit-cli
```

### Test Proxy
```bash
# Start IFRIT (if not already running)
./ifrit &

# In another terminal - test attack detection
curl http://localhost:8080/.env

# Check exceptions (should see /health added)
./ifrit-cli exception list

# Kill IFRIT
pkill ifrit
```

### Test CLI
```bash
# List patterns
./ifrit-cli pattern list

# Show statistics
./ifrit-cli db stats

# View exceptions
./ifrit-cli exception list
```

### Check Database
```bash
# SQLite
sqlite3 ./data/ifrit.db "SELECT COUNT(*) FROM attack_instances;"

# PostgreSQL
psql -U ifrit_user -d ifrit -h localhost -c "SELECT COUNT(*) FROM attack_instances;"
```

### Check Logs
```bash
# View logs
cat logs/ifrit.log

# Watch logs in real-time
tail -f logs/ifrit.log

# Filter for attacks
grep "ATTACK" logs/ifrit.log

# Filter for errors
grep "ERROR" logs/ifrit.log
```

---

## Troubleshooting

### Port Already in Use

**Error:**
```
listen tcp :8080: bind: address already in use
```

**Solution 1: Change port**
```json
{
  "server": {
    "listen_addr": ":9000"
  }
}
```

**Solution 2: Kill existing process**
```bash
lsof -i :8080
kill -9 <PID>
```

**Solution 3: Check what's using port**
```bash
netstat -tlnp | grep 8080
```

### Database Locked (SQLite)

**Error:**
```
database is locked
```

**Solution:**
```bash
# Delete and recreate database
rm data/ifrit.db

# Restart IFRIT
./ifrit
```

### API Key Invalid

**Error:**
```
Error: "API key is invalid"
```

**Checklist:**
1. API key format: starts with `sk-ant-`
2. API key is active in Anthropic console
3. No extra whitespace in config
4. Correct model name: `claude-3-5-haiku-20241022`

**Test API key:**
```bash
curl https://api.anthropic.com/v1/models \
  -H "x-api-key: sk-ant-YOUR-KEY"
```

### LLM Not Responding

**Error:**
```
dial tcp: connection timeout
```

**Checklist:**
1. Internet connection working
2. Firewall allows outbound 443
3. Claude/Gemini API is accessible
4. Enable debug logging to see full error

### Build Errors

**Error:**
```
go: no such file or directory
```

**Solution:**
```bash
# Install Go first
brew install go@1.21  # macOS
sudo apt install golang-go  # Ubuntu
```

**Error:**
```
module declarations do not match
```

**Solution:**
```bash
# Update dependencies
go mod tidy
go mod download
```

### Permission Denied

**Error:**
```
permission denied: ./ifrit
```

**Solution:**
```bash
chmod +x ifrit ifrit-cli
```

### Database File Permissions

**Error:**
```
permission denied
```

**Solution:**
```bash
# SQLite
chmod 600 data/ifrit.db
chown ifrit:ifrit data/ifrit.db  # If running as ifrit user

# PostgreSQL
# Check pg_hba.conf for authentication settings
```

---

## Upgrading IFRIT

### From 0.2.0 to 0.3.0
```bash
# Stop IFRIT
pkill ifrit

# Pull latest code
git pull origin main

# Rebuild
go build -o ifrit ./cmd/ifrit
go build -o ifrit-cli ./cmd/ifrit-cli

# Database schema automatically migrates on start
./ifrit

# Verify
./ifrit-cli db stats
```

**What's New in 0.3.0:**
- ✅ PostgreSQL support
- ✅ Multi-database architecture
- ✅ CLI works with both databases
- ✅ Improved foreign key handling
- ✅ Better NULL handling for pattern IDs

### Configuration Migration

Configuration format is mostly backward compatible. New database section:
```json
{
  "database": {
    "type": "sqlite",           // NEW: specify database type
    "path": "./data/ifrit.db"   // Existing SQLite path
  }
}
```

For PostgreSQL:
```json
{
  "database": {
    "type": "postgres",
    "host": "localhost",
    "port": 5432,
    "user": "ifrit_user",
    "password": "your_password",
    "dbname": "ifrit"
  }
}
```

---

## Uninstalling IFRIT

### Remove Binaries
```bash
rm ifrit ifrit-cli
```

### Remove System Service (if installed)
```bash
sudo systemctl stop ifrit
sudo systemctl disable ifrit
sudo rm /etc/systemd/system/ifrit.service
sudo systemctl daemon-reload
```

### Remove Data
```bash
# SQLite
rm -rf data/ logs/ config/

# PostgreSQL
psql -U postgres << EOF
DROP DATABASE ifrit;
DROP USER ifrit_user;
EOF
```

### Remove User (if created)
```bash
sudo userdel -r ifrit
```

---

## Next Steps

1. **Read FEATURES.md** - Understand all capabilities
2. **Configure for your environment** - Adjust proxy_target, whitelist_paths
3. **Choose your database** - SQLite for simple, PostgreSQL for production
4. **Start in Onboarding Mode** - Zero false positives guarantee
5. **Monitor for 1 week** - Let IFRIT learn your traffic
6. **Switch to Normal Mode** - Full detection enabled

See START_HERE.md for more guidance.

---

## Getting Help

- **Docs:** See docs/ directory
- **Email:** ifrit@0t.systems

---

**Last Updated:** December 1st, 2025  
**Version:** 0.3.0
