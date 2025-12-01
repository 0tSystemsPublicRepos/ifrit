# IFRIT Proxy - Complete Feature List

**Version:** 0.3.0  
**Last Updated:** December 1st, 2025

---

## Core Features

### 1. Intelligent Reverse Proxy
- **Transparent Interception** - Sits between clients and backend
- **Zero Code Changes** - No modifications to your application
- **Multi-App Support** - Route traffic by `X-App-ID` header
- **TLS/HTTPS Support** - Secure communication
- **Configurable Targets** - Point to any backend (HTTP/HTTPS)

### 2. Multi-Database Support (NEW in 0.3.0)
- **SQLite (Default)** - Zero-config embedded database
  - Perfect for development and small deployments
  - Single-file storage (`./data/ifrit.db`)
  - Fast for <1M attack records
  - No separate database server needed
- **PostgreSQL (Production)** - Enterprise-grade RDBMS
  - Production-ready at scale (>1M records)
  - Multi-instance clustering support
  - Advanced replication and backup
  - Connection pooling
  - Industry-standard security
- **Automatic Schema Migration** - Tables created on first run
- **Zero-Downtime Switching** - Change database type in config only
- **Provider Abstraction** - Same API for both databases
- **CLI Compatibility** - All commands work with both databases

### 3. Four-Stage Attack Detection

#### Stage 0: Whitelist Check
- **IP Whitelisting** - Bypass detection for trusted IPs
- **Path Whitelisting** - Allow specific endpoints without analysis
- **Skip Body Check Flag** - Optional body/header analysis for whitelisted paths
- **Regex Support** - Pattern-based path matching

#### Stage 1: Local Rules (Pattern Matching)
- **XSS Detection** - `<script>`, `javascript:`, `onerror=`
- **SQL Injection** - `UNION SELECT`, `'; DROP TABLE`, `OR 1=1`
- **Path Traversal** - `../`, `..\\`, directory escape attempts
- **Command Injection** - `;`, `|`, `&&`, backticks
- **LDAP Injection** - `*)(uid=*`, `)(objectClass=*`
- **NoSQL Injection** - `$ne`, `$gt`, MongoDB operators
- **XXE (XML External Entity)** - `<!ENTITY`, `SYSTEM`, `PUBLIC`
- **SSRF (Server-Side Request Forgery)** - `file://`, `gopher://`, `dict://`
- **Template Injection** - `{{`, `${`, `<%`, Jinja/ERB patterns
- **Custom Rules** - Add your own patterns via config

#### Stage 2: Database Patterns (Learning)
- **Attack Signature Matching** - Checks learned patterns
- **HTTP Method Matching** - GET, POST, PUT, DELETE
- **Path Pattern Matching** - `/api/users`, `/login`, etc.
- **Confidence Scoring** - LLM-assigned confidence levels
- **Automatic Caching** - 95% of attacks cached after week 1
- **Pattern Management** - CLI commands to add/remove/view

#### Stage 3: LLM Analysis (AI-Powered)
- **Claude Integration** - Anthropic Claude 3.5 Haiku/Sonnet
- **Gemini Integration** - Google Gemini 2.0/2.5 Flash/Pro (NEW in 0.2.0)
- **Multi-LLM Support** - Primary/fallback provider configuration
- **Real-Time Analysis** - ~3 seconds per novel attack
- **Attack Classification** - SQL injection, XSS, credential stuffing, etc.
- **Confidence Scoring** - 0.0-1.0 scale
- **Pattern Learning** - New patterns stored for future use
- **Configurable Methods** - LLM only on POST/PUT/DELETE (optional)
- **Context-Aware** - Analyzes request method, path, headers, body
- **Cost Optimization** - 90% savings via caching after learning

### 4. Execution Modes

#### Onboarding Mode
- **Zero False Positives** - All traffic allowed
- **Automatic Learning** - Baseline created from legitimate traffic
- **Auto-Whitelisting** - Legitimate paths added to exceptions
- **Duration Control** - Configurable learning period (default: 7 days)
- **Traffic Logging** - All requests logged to `onboarding_traffic.log`
- **Best For** - New deployments, establishing baseline

#### Detection Mode (Normal/Deception)
- **Full Detection Pipeline** - All 4 stages enabled
- **Honeypot Responses** - Fake data returned to attackers
- **Real-Time Learning** - Patterns stored for future detection
- **LLM Integration** - Claude/Gemini analysis on novel attacks
- **Attack Logging** - Comprehensive attack database
- **Attacker Profiling** - Track IPs, patterns, techniques
- **Best For** - Production deployments after onboarding

### 5. Detection Modes

#### Detection Mode (Default)
- **Smart Analysis** - 4-stage detection pipeline
- **Optional Whitelist** - Exceptions for trusted IPs/paths
- **Learning Capability** - Continuously improves
- **~5% False Positive Rate** - Acceptable for most deployments
- **Flexible Configuration** - Fine-tune sensitivity

#### Allowlist Mode
- **Strict Access Control** - Only whitelisted traffic allowed
- **Zero False Positives** - Everything else blocked by design
- **Optional Body Check** - Analyze whitelisted requests if needed
- **Fast Response** - <1ms for whitelist checks
- **Best For** - VPN-only, admin portals, zero-trust environments

### 6. Honeypot & Deception

#### Dynamic Payload Generation
- **LLM-Generated Responses** - Realistic fake data
- **Context-Aware** - Matches request type (SQL, API, etc.)
- **Automatic Caching** - Generated payloads stored for reuse
- **Four-Stage Selection**:
  1. Database patterns (learned)
  2. LLM generation (novel attacks)
  3. Config defaults (fallback)
  4. Generic error (last resort)

#### Payload Management
- **Configurable Responses** - Custom responses per attack type
- **Status Code Control** - 200, 403, 404, 500, etc.
- **Content-Type Support** - JSON, HTML, plain text
- **Template System** - Reusable response templates
- **CLI Management** - Add/view/remove payloads

#### Intelligence Collection
- **Attacker Interaction Logging** - Track what attackers submit
- **Credential Harvesting** - Log fake credentials used
- **Tool Fingerprinting** - Identify attacker tools/scripts
- **Technique Analysis** - Understand attack methodologies
- **Public Endpoint** - `/api/intel/log` for honeypot forms

### 7. Data Anonymization & Privacy

#### Anonymization Engine
- **Hybrid Strategy** - Headers + pattern-based redaction
- **Sensitive Header Redaction** - Authorization, Cookie, API keys
- **Pattern Redaction** - JWT tokens, emails, API keys
- **Configurable** - Add custom sensitive headers
- **GDPR Compliant** - No PII sent to external LLMs
- **HIPAA Compliant** - PHI anonymized
- **PCI-DSS Compliant** - Credit card data redacted

#### Privacy Controls
- **Store Original Flag** - Optional local storage of original requests
- **Redaction Logging** - Track what was anonymized
- **Case-Insensitive** - Header matching works with any case

### 8. Attack Intelligence & Profiling

#### Attacker Profiles
- **IP Tracking** - Unique attacker identification
- **Request Counting** - Total requests per IP
- **Attack Type Aggregation** - SQL injection, XSS, etc.
- **First/Last Seen** - Temporal tracking
- **Success Rate** - Successful vs. blocked probes
- **CLI Access** - `ifrit-cli attacker list/view/search`

#### Attack Instances
- **Comprehensive Logging** - Every attack logged
- **Detection Stage Tracking** - Which stage caught it
- **Request Payload Storage** - What was sent
- **Timestamp Precision** - Microsecond accuracy
- **Pattern Attribution** - Links to learned patterns
- **CLI Access** - `ifrit-cli attack list/view/stats`

#### Pattern Database
- **Attack Signatures** - Unique attack patterns
- **HTTP Method** - GET, POST, PUT, DELETE
- **Path Patterns** - `/api/users`, `/login`
- **Times Seen** - Frequency tracking
- **Confidence Scores** - LLM-assigned confidence
- **Created By** - Claude, Gemini, config, manual
- **CLI Management** - Add/remove/view patterns

### 9. Threat Intelligence (NEW in 0.2.0)

#### Multi-API Enrichment
- **AbuseIPDB Integration** - IP reputation (40% weight)
- **VirusTotal Integration** - Malware detection (35% weight)
- **IPInfo Integration** - Geolocation + privacy (25% weight)
- **Parallel API Calls** - All 3 APIs queried simultaneously
- **24-Hour Caching** - 90% cost reduction
- **Background Workers** - 3 goroutines for non-blocking enrichment

#### Risk Scoring
- **0-100 Risk Score** - Weighted formula across 3 APIs
- **Threat Level Classification**:
  - 🚨 CRITICAL (80-100)
  - ⚠️ HIGH (60-79)
  - ⚡ MEDIUM (40-59)
  - ℹ️ LOW (0-39)
- **Configurable Thresholds** - Adjust levels in config
- **Configurable Weights** - Adjust API importance

#### Enrichment Data
- **AbuseIPDB** - Confidence score, total reports, last reported
- **VirusTotal** - Malicious/suspicious/harmless/undetected counts
- **IPInfo** - Country, city, organization
- **Privacy Detection** - VPN, proxy, hosting, Tor flags
- **Last Attack Tracking** - Most recent attack timestamp
- **Total Attack Count** - Cumulative attacks per IP

#### CLI Commands
- `ifrit-cli threat list` - List all enriched IPs
- `ifrit-cli threat view [ip]` - Detailed IP intelligence
- `ifrit-cli threat top [n]` - Top threats by risk score
- `ifrit-cli threat stats` - Threat statistics

### 10. Notifications System (NEW in 0.2.0)

#### Multi-Channel Support
- **Email (SMTP)** - HTML-formatted alerts via any SMTP server
- **Slack** - Webhook integration with color-coded messages
- **Twilio SMS** - SMS alerts to configured numbers
- **Custom Webhooks** - JSON payload delivery with retry logic

#### Rule-Based Filtering
- **Alert on CRITICAL** - Always enabled by default
- **Alert on HIGH** - Optional (disabled by default)
- **Alert on MEDIUM** - Optional (disabled by default)
- **Alert on LOW** - Optional (disabled by default)
- **Config-Driven** - Rules in `config/default.json`
- **API-Configurable** - Update rules via REST API

#### Notification Features
- **Retry Logic** - 3 retries with exponential backoff
- **Timeout Control** - Configurable per provider
- **Notification History** - Audit trail of all sent alerts
- **Threat Context** - Full threat intel in notifications
- **Rate Limiting** - Prevent alert fatigue
- **Parallel Delivery** - All enabled providers notified simultaneously

### 11. Exception Management

#### IP Exceptions
- **Whitelist IPs** - Bypass detection entirely
- **Regex Support** - CIDR notation, IP ranges
- **Reason Tracking** - Document why exception exists
- **Enable/Disable** - Toggle without deleting
- **CLI Management** - `ifrit-cli exception add/remove/list`

#### Path Exceptions
- **Whitelist Paths** - `/health`, `/metrics`, etc.
- **Regex Patterns** - `^/api/public.*`
- **Body Check Override** - Optional analysis even when whitelisted
- **Reason Tracking** - Document purpose
- **CLI Management** - Same as IP exceptions

#### Keyword Exceptions
- **Attack Type Specific** - SQL injection, XSS, etc.
- **Keyword Matching** - "UNION SELECT", "DROP TABLE"
- **Reason Tracking** - Document false positives
- **Enable/Disable** - Toggle exceptions
- **CLI Management** - `ifrit-cli keyword add/remove/list`

### 12. REST API

#### Authentication
- **API Token System** - Bearer-style tokens (`ifr_...`)
- **User Management** - Multiple users with roles
- **Role-Based Access** - Admin, analyst, viewer roles
- **Token Expiry** - Configurable (default: 90 days)
- **Token Revocation** - Immediate invalidation
- **CLI Token Management** - `ifrit-cli token create/list/revoke`

#### Endpoints (30+)
- **Attack Data** - `/api/attacks`, `/api/attackers`, `/api/patterns`
- **Statistics** - `/api/stats`, `/api/intel/stats`, `/api/cache/stats`
- **Threat Intelligence** - `/api/threat-intel/*` (list, view, top, stats)
- **Notifications** - `/api/notifications/*` (config, history, update)
- **Exceptions** - `/api/exceptions`, `/api/keyword-exceptions`
- **Cache Management** - `/api/cache/clear`
- **Health Check** - `/api/health`
- **Intel Logging** - `/api/intel/log` (public, no auth)

#### API Features
- **JSON Responses** - Consistent format
- **Error Handling** - Descriptive error messages
- **Rate Limiting** - 100 requests/minute
- **CORS Support** - Configurable origins
- **Pagination** - Limit/offset support
- **Filtering** - app_id, IP, time ranges

### 13. Web Dashboard

#### Real-Time Monitoring
- **Attack Statistics** - Total attacks, unique attackers
- **Detection Rate** - Percentage of malicious requests
- **Stage Breakdown** - S1 (Local), S2 (DB), S3 (LLM)
- **Recent Attacks** - Last 10 detected attacks
- **Top Attackers** - Most active IPs
- **Threat Intelligence Cards** - CRITICAL/HIGH/MEDIUM/LOW counts (NEW)
- **Top Risky IPs** - Most dangerous attackers with risk scores (NEW)
- **Auto-Refresh** - 5-second intervals

#### Access Control
- **Token Authentication** - Same as API
- **localStorage Storage** - Token persisted in browser
- **Logout Support** - Clear token
- **Role-Based Views** - Future enhancement

#### Dashboard Features
- **Embedded HTML** - No separate web server needed
- **Responsive Design** - Works on mobile/tablet/desktop
- **Color-Coded Threats** - Visual severity indicators
- **Clickable Links** - Direct links to attack details

### 14. Command-Line Interface (CLI)

#### Database Management
- `ifrit-cli db stats` - Database statistics
- `ifrit-cli db schema` - View schema

#### Attack Management
- `ifrit-cli attack list` - List all attacks
- `ifrit-cli attack view [id]` - Detailed attack info
- `ifrit-cli attack stats` - Attack statistics
- `ifrit-cli attack by-ip [ip]` - Attacks from specific IP
- `ifrit-cli attack by-path [path]` - Attacks on specific path

#### Pattern Management
- `ifrit-cli pattern list` - List learned patterns
- `ifrit-cli pattern view [id]` - Pattern details
- `ifrit-cli pattern add` - Manually add pattern
- `ifrit-cli pattern remove [id]` - Delete pattern

#### Attacker Management
- `ifrit-cli attacker list` - List all attackers
- `ifrit-cli attacker view [id]` - Attacker profile
- `ifrit-cli attacker search [ip]` - Search by IP
- `ifrit-cli attacker remove [id]` - Delete attacker

#### Exception Management
- `ifrit-cli exception list` - List all exceptions
- `ifrit-cli exception view [id]` - Exception details
- `ifrit-cli exception add` - Add IP/path exception
- `ifrit-cli exception remove [id]` - Delete exception
- `ifrit-cli exception enable/disable [id]` - Toggle

#### Keyword Management
- `ifrit-cli keyword list` - List keyword exceptions
- `ifrit-cli keyword view [id]` - Keyword details
- `ifrit-cli keyword add` - Add keyword exception
- `ifrit-cli keyword remove [id]` - Delete keyword

#### Threat Intelligence
- `ifrit-cli threat list` - List enriched IPs
- `ifrit-cli threat view [ip]` - Detailed threat intel
- `ifrit-cli threat top [n]` - Top threats by risk
- `ifrit-cli threat stats` - Threat statistics

#### Token Management
- `ifrit-cli token list` - List all tokens
- `ifrit-cli token create [user_id] [name]` - Create token
- `ifrit-cli token revoke [id]` - Revoke token
- `ifrit-cli token validate [token]` - Check token validity

#### Payload Management
- `ifrit-cli payload list` - List all payloads
- `ifrit-cli payload view [id]` - Payload details
- `ifrit-cli payload stats` - Payload statistics

#### Interaction Management
- `ifrit-cli interaction list` - List attacker interactions
- `ifrit-cli interaction by-ip [ip]` - Interactions from IP

#### Legitimate Traffic
- `ifrit-cli legitimate list` - List legitimate requests (onboarding)
- `ifrit-cli legitimate stats` - Legitimate traffic stats

### 15. Logging & Monitoring

#### Log Levels
- **DEBUG** - Verbose output (development only)
- **INFO** - Standard operational logs
- **WARN** - Warnings (non-critical issues)
- **ERROR** - Errors (requires attention)

#### Log Categories
- **[SERVER]** - Proxy server events
- **[API]** - API server events
- **[DETECTION]** - Attack detection events
- **[STAGE_1/2/3]** - Detection stage logs
- **[PAYLOAD]** - Payload management events
- **[LLM]** - Claude/Gemini API calls
- **[ANON]** - Anonymization events
- **[DB]** - Database operations
- **[THREAT_INTEL]** - Threat intelligence events (NEW)
- **[NOTIFICATIONS]** - Notification events (NEW)
- **[EMAIL/SLACK/TWILIO/WEBHOOK]** - Provider-specific logs (NEW)

#### Log Features
- **Timestamped** - Precise timestamps
- **Color-Coded** - Terminal color support
- **File Output** - `./logs/ifrit.log`
- **Log Rotation** - Automatic rotation (configurable)
- **Debug Toggle** - Enable/disable via config
- **Structured Format** - Easy to parse

### 16. Configuration Management

#### Configuration File
- **JSON Format** - `config/default.json`
- **Environment Variables** - Override with `${VAR_NAME}`
- **Hot Reload** - Future enhancement
- **Validation** - Startup validation of config

#### Configuration Sections
- **server** - Proxy and API server settings
- **database** - Database type and connection (NEW in 0.3.0)
- **llm** - Claude/Gemini configuration
- **detection** - Detection mode and rules
- **execution_mode** - Onboarding vs. normal
- **anonymization** - Privacy settings
- **payload_management** - Honeypot configuration
- **threat_intelligence** - API keys and settings (NEW in 0.2.0)
- **notifications** - Alert configuration (NEW in 0.2.0)
- **system** - Logging and debug settings

#### Configuration Features
- **Comments Allowed** - JSON with comments (JSONC)
- **Sensible Defaults** - Works out of the box
- **Example Config** - `default.json.example` included
- **Documentation** - Inline comments in example

### 17. Performance & Scalability

#### Response Times
- **Whitelist Check** - <1ms
- **Local Rules** - <5ms
- **Database Patterns (SQLite)** - <10ms
- **Database Patterns (PostgreSQL)** - <8ms (NEW in 0.3.0)
- **LLM Analysis** - ~3 seconds (first time)
- **Cached Patterns** - <10ms (95% of requests)

#### Throughput
- **Whitelist Mode** - 10,000 requests/sec
- **Local Rules** - 200 requests/sec
- **Database Patterns** - 100 requests/sec
- **LLM Analysis** - 0.3 requests/sec

#### Scalability (NEW in 0.3.0)
- **SQLite** - Single instance, <1M records
- **PostgreSQL** - Multi-instance, >1M records
- **Connection Pooling** - Efficient resource usage
- **Horizontal Scaling** - Multiple IFRIT instances with PostgreSQL
- **Load Balancing** - Support for upstream LB

#### Optimization
- **Pattern Caching** - 90% cost reduction after week 1
- **Threat Intel Caching** - 24-hour TTL, 90% API call savings
- **Parallel Processing** - Background workers for enrichment
- **Database Indexing** - Optimized queries

### 18. Security & Compliance

#### Security Features
- **TLS/HTTPS Support** - Encrypted communication
- **Token-Based Auth** - Secure API access
- **Role-Based Access** - Admin/analyst/viewer roles
- **Password Hashing** - bcrypt for credentials
- **API Rate Limiting** - 100 req/min
- **Input Validation** - All inputs sanitized

#### Compliance
- **GDPR** - PII anonymization
- **HIPAA** - PHI redaction
- **PCI-DSS** - Credit card data masked
- **CCPA** - Data minimization
- **SOC 2** - Audit logging

#### Data Privacy
- **Anonymization Engine** - Redacts sensitive data
- **Local Storage** - No external data leaks
- **Configurable Retention** - Control data lifetime
- **Secure Deletion** - CLI commands to purge data

### 19. Deployment Options

#### Standalone
- **Single Binary** - Go compiled executable
- **No Dependencies** - SQLite embedded (optional PostgreSQL)
- **Systemd Support** - Linux service integration
- **Docker Support** - Containerized deployment
- **Docker Compose** - Multi-container orchestration

#### Production
- **Load Balancer Integration** - Works with nginx, HAProxy
- **Multi-Instance** - PostgreSQL for clustering (NEW in 0.3.0)
- **Health Checks** - `/api/health` endpoint
- **Graceful Shutdown** - SIGTERM handling
- **Automatic Restart** - Systemd service restart

#### Cloud Deployment
- **AWS** - EC2, ECS, Lambda (future)
- **GCP** - Compute Engine, Cloud Run
- **Azure** - VM, Container Instances
- **DigitalOcean** - Droplets, App Platform

### 20. Developer Features

#### Open Source
- **Apache 2.0 License** - Permissive license
- **GitHub Repository** - Public source code
- **Issue Tracking** - GitHub Issues
- **Pull Requests** - Community contributions welcome

#### Extensibility
- **Plugin System** - Future enhancement
- **Custom Providers** - Add new databases easily
- **Custom Rules** - Extend detection logic
- **Webhook Integration** - Custom notifications

#### Testing
- **Unit Tests** - Core functionality tested
- **Integration Tests** - End-to-end scenarios
- **Manual Testing** - Documented test cases
- **CI/CD Ready** - GitHub Actions support

---

## Feature Comparison Matrix

| Feature | SQLite | PostgreSQL |
|---------|--------|------------|
| Zero Config | ✅ | ❌ |
| Production Ready | ⚠️ (<1M records) | ✅ |
| Multi-Instance | ❌ | ✅ |
| Clustering | ❌ | ✅ |
| Connection Pooling | ❌ | ✅ |
| Backup/Replication | Manual | Built-in |
| Performance (<1M) | Fast | Fast |
| Performance (>1M) | Slow | Fast |

---

## Coming Soon (v0.4.0+)

- [ ] Machine learning for attack prediction
- [ ] Behavioral analysis
- [ ] Custom LLM providers (Ollama, local models)
- [ ] GraphQL API
- [ ] Web UI for configuration
- [ ] Advanced SIEM integrations
- [ ] Automated response policies
- [ ] Threat actor profiling
- [ ] Geo-blocking
- [ ] Rate limiting per IP
- [ ] Custom plugin system
- [ ] Kubernetes Helm charts
- [ ] Terraform modules

---

## Feature Summary

**Core Capabilities:**
- ✅ 4-stage attack detection
- ✅ LLM-powered analysis (Claude + Gemini)
- ✅ Multi-database support (SQLite + PostgreSQL)
- ✅ Honeypot deception
- ✅ Real-time learning
- ✅ Threat intelligence enrichment
- ✅ Multi-channel notifications
- ✅ Data anonymization (GDPR/HIPAA)
- ✅ REST API (30+ endpoints)
- ✅ Web dashboard
- ✅ Comprehensive CLI
- ✅ Token authentication
- ✅ Multi-app support
- ✅ Exception management
- ✅ Attack profiling
- ✅ Pattern database

**Deployment:**
- ✅ Standalone binary
- ✅ Docker support
- ✅ Systemd service
- ✅ Multi-instance clustering (PostgreSQL)
- ✅ Cloud-ready

**Security:**
- ✅ TLS/HTTPS
- ✅ Token auth
- ✅ RBAC
- ✅ Rate limiting
- ✅ Compliance (GDPR/HIPAA/PCI-DSS)

---

**Last Updated:** December 1st, 2025  
**Version:** 0.3.0
