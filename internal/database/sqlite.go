package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/0tSystemsPublicRepos/ifrit/internal/logging"
)

// SQLiteProvider implements DatabaseProvider for SQLite
type SQLiteProvider struct {
	db     *sql.DB
	config *SQLiteConfig
}

// SQLiteDB is the legacy wrapper (kept for backward compatibility)
type SQLiteDB struct {
	db *sql.DB
}

func (s *SQLiteDB) GetDB() *sql.DB {
	return s.db
}

// NewSQLiteProvider creates a new SQLite database provider
func NewSQLiteProvider(config *SQLiteConfig) (*SQLiteProvider, error) {
	provider := &SQLiteProvider{
		config: config,
	}
	
	if err := provider.Connect(); err != nil {
		return nil, err
	}
	
	return provider, nil
}

// Connect establishes connection to SQLite database
func (sp *SQLiteProvider) Connect() error {
	db, err := sql.Open("sqlite3", sp.config.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// Set journal mode
	if sp.config.JournalMode != "" {
		if _, err := db.Exec(fmt.Sprintf("PRAGMA journal_mode = %s", sp.config.JournalMode)); err != nil {
			return fmt.Errorf("failed to set journal mode: %w", err)
		}
	}

	// Set synchronous mode
	if sp.config.Synchronous != "" {
		if _, err := db.Exec(fmt.Sprintf("PRAGMA synchronous = %s", sp.config.Synchronous)); err != nil {
			return fmt.Errorf("failed to set synchronous mode: %w", err)
		}
	}

	sp.db = db
	logging.Info("[SQLite] Connected to database: %s", sp.config.Path)
	return nil
}

// Close closes the database connection
func (sp *SQLiteProvider) Close() error {
	if sp.db != nil {
		return sp.db.Close()
	}
	return nil
}

// GetDB returns the underlying sql.DB instance
func (sp *SQLiteProvider) GetDB() *sql.DB {
	return sp.db
}

// Ping checks if database connection is alive
func (sp *SQLiteProvider) Ping() error {
	return sp.db.Ping()
}

// Migrate runs database migrations
func (sp *SQLiteProvider) Migrate() error {
	// Create all tables
	if err := createAllTables(sp.db); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Run data migrations
	if err := RunMigrations(sp.db); err != nil {
		logging.Error("Warning: Migrations failed: %v", err)
	}

	logging.Info("[SQLite] Database migration completed")
	return nil
}

// === ATTACK PATTERNS ===

func (sp *SQLiteProvider) StoreAttackPattern(appID, signature, attackType, classification, method, path, payloadTemplate string, responseCode int, createdBy string, confidence float64) error {
	query := `
		INSERT INTO attack_patterns 
		(app_id, attack_signature, attack_type, attack_classification, http_method, path_pattern, payload_template, response_code, times_seen, first_seen, last_seen, created_by, claude_confidence)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, datetime('now'), datetime('now'), ?, ?)
		ON CONFLICT(app_id, attack_signature) DO UPDATE SET 
			times_seen = times_seen + 1,
			last_seen = datetime('now')
	`
	_, err := sp.db.Exec(query, appID, signature, attackType, classification, method, path, payloadTemplate, responseCode, createdBy, confidence)
	return err
}

// StoreAttackPatternEnhanced stores attack pattern with enhanced pattern matching fields
func (s *SQLiteProvider) StoreAttackPatternEnhanced(
	appID, signature, attackType, classification, method, pathPattern,
	payloadTemplate string, responseCode int, createdBy string,
	confidence float64, patternType, headerPattern, bodyPattern,
	queryPattern string,
) error {
	query := `
		INSERT INTO attack_patterns (
			app_id, attack_signature, attack_type, attack_classification,
			http_method, path_pattern, payload_template, response_code,
			created_by, claude_confidence, pattern_type, header_pattern,
			body_pattern, query_pattern, times_seen, first_seen, last_seen
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, datetime('now'), datetime('now'))
		ON CONFLICT(app_id, attack_signature) DO UPDATE SET
			times_seen = times_seen + 1,
			last_seen = datetime('now'),
			pattern_type = excluded.pattern_type,
			header_pattern = excluded.header_pattern,
			body_pattern = excluded.body_pattern,
			query_pattern = excluded.query_pattern
	`

	_, err := s.db.Exec(query,
		appID, signature, attackType, classification, method, pathPattern,
		payloadTemplate, responseCode, createdBy, confidence, patternType,
		headerPattern, bodyPattern, queryPattern,
	)

	if err != nil {
		return fmt.Errorf("failed to store enhanced attack pattern: %w", err)
	}

	return nil
}


func (sp *SQLiteProvider) GetAllPatterns(appID string) ([]map[string]interface{}, error) {
	query := `
		SELECT id, attack_signature, attack_type, attack_classification, http_method, 
		       path_pattern, payload_template, response_code, times_seen, claude_confidence
		FROM attack_patterns 
		WHERE app_id = ?
		ORDER BY times_seen DESC
	`
	
	rows, err := sp.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var patterns []map[string]interface{}
	for rows.Next() {
		var id int64
		var signature, attackType, classification, method, pathPattern string
		var payloadTemplate sql.NullString
		var responseCode, timesSeen int
		var confidence float64
		
		err := rows.Scan(&id, &signature, &attackType, &classification, &method, &pathPattern, &payloadTemplate, &responseCode, &timesSeen, &confidence)
		if err != nil {
			continue
		}

		// Convert sql.NullString to regular string
		payloadTemplateStr := ""
		if payloadTemplate.Valid {
			payloadTemplateStr = payloadTemplate.String
		}
	
		patterns = append(patterns, map[string]interface{}{
			"id":                    id,
			"attack_signature":      signature,
			"attack_type":           attackType,
			"attack_classification": classification,
			"http_method":           method,
			"path_pattern":          pathPattern,
			"payload_template":      payloadTemplateStr,
			"response_code":         responseCode,
			"times_seen":            timesSeen,
			"confidence":            confidence,
		})
	}
	return patterns, rows.Err()
}

func (sp *SQLiteProvider) GetPatternBySignature(appID, signature string) (map[string]interface{}, error) {
	query := `
		SELECT id, attack_type, attack_classification, http_method, path_pattern, 
		       payload_template, response_code, claude_confidence
		FROM attack_patterns 
		WHERE app_id = ? AND attack_signature = ?
	`
	
	var id int64
	var attackType, classification, method, pathPattern, payloadTemplate string
	var responseCode int
	var confidence float64

	err := sp.db.QueryRow(query, appID, signature).Scan(&id, &attackType, &classification, &method, &pathPattern, &payloadTemplate, &responseCode, &confidence)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"id":                    id,
		"attack_type":           attackType,
		"attack_classification": classification,
		"http_method":           method,
		"path_pattern":          pathPattern,
		"payload_template":      payloadTemplate,
		"response_code":         responseCode,
		"confidence":            confidence,
	}, nil
}

func (sp *SQLiteProvider) UpdatePatternTimestamp(appID, signature string) error {
	query := `
		UPDATE attack_patterns 
		SET last_seen = datetime('now'), times_seen = times_seen + 1
		WHERE app_id = ? AND attack_signature = ?
	`
	_, err := sp.db.Exec(query, appID, signature)
	return err
}

// === ATTACK INSTANCES ===
func (sp *SQLiteProvider) LogAttackInstance(appID string, patternID *int64, sourceIP, userAgent, path, method string, returnedHoneypot, attackerAccepted bool) error {
	query := `
		INSERT INTO attack_instances 
		(app_id, pattern_id, source_ip, user_agent, requested_path, http_method, returned_honeypot, attacker_accepted, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
	`
	_, err := sp.db.Exec(query, appID, patternID, sourceIP, userAgent, path, method, returnedHoneypot, attackerAccepted)
	return err
}

func (sp *SQLiteProvider) GetAttackInstances(appID string, limit int) ([]map[string]interface{}, error) {
	query := `
		SELECT ai.id, ai.source_ip, ai.user_agent, ai.requested_path, ai.http_method,
		       ai.returned_honeypot, ai.attacker_accepted, ai.timestamp,
		       ap.attack_type, ap.attack_classification
		FROM attack_instances ai
		LEFT JOIN attack_patterns ap ON ai.pattern_id = ap.id
		WHERE ai.app_id = ?
		ORDER BY ai.timestamp DESC
		LIMIT ?
	`
	
	rows, err := sp.db.Query(query, appID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var instances []map[string]interface{}
	for rows.Next() {
		var id int64
		var sourceIP, userAgent, path, method, timestamp string
		var returnedHoneypot, attackerAccepted bool
		var attackType, classification sql.NullString

		err := rows.Scan(&id, &sourceIP, &userAgent, &path, &method, &returnedHoneypot, &attackerAccepted, &timestamp, &attackType, &classification)
		if err != nil {
			continue
		}

		instances = append(instances, map[string]interface{}{
			"id":                 id,
			"source_ip":          sourceIP,
			"user_agent":         userAgent,
			"path":               path,
			"method":             method,
			"returned_honeypot":  returnedHoneypot,
			"attacker_accepted":  attackerAccepted,
			"timestamp":          timestamp,
			"attack_type":        attackType.String,
			"classification":     classification.String,
		})
	}

	return instances, rows.Err()
}

// === ATTACKER PROFILES ===

func (sp *SQLiteProvider) UpdateAttackerProfile(appID, sourceIP string, attackTypes []string, successfulProbe bool) error {
	attackTypesJSON, _ := json.Marshal(attackTypes)
	
	query := `
		INSERT INTO attacker_profiles 
		(app_id, source_ip, total_requests, successful_probes, attack_types, first_seen, last_seen)
		VALUES (?, ?, 1, ?, ?, datetime('now'), datetime('now'))
		ON CONFLICT(app_id, source_ip) DO UPDATE SET
			total_requests = total_requests + 1,
			successful_probes = successful_probes + ?,
			attack_types = ?,
			last_seen = datetime('now')
	`
	
	successCount := 0
	if successfulProbe {
		successCount = 1
	}
	
	_, err := sp.db.Exec(query, appID, sourceIP, successCount, string(attackTypesJSON), successCount, string(attackTypesJSON))
	return err
}

func (sp *SQLiteProvider) GetAttackerProfile(appID, sourceIP string) (map[string]interface{}, error) {
	query := `
		SELECT total_requests, successful_probes, attack_types, first_seen, last_seen
		FROM attacker_profiles
		WHERE app_id = ? AND source_ip = ?
	`
	
	var totalRequests, successfulProbes int
	var attackTypes, firstSeen, lastSeen string

	err := sp.db.QueryRow(query, appID, sourceIP).Scan(&totalRequests, &successfulProbes, &attackTypes, &firstSeen, &lastSeen)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"total_requests":    totalRequests,
		"successful_probes": successfulProbes,
		"attack_types":      attackTypes,
		"first_seen":        firstSeen,
		"last_seen":         lastSeen,
	}, nil
}

func (sp *SQLiteProvider) GetTopAttackers(appID string, limit int) ([]map[string]interface{}, error) {
	query := `
		SELECT source_ip, total_requests, successful_probes, attack_types, last_seen
		FROM attacker_profiles
		WHERE app_id = ?
		ORDER BY total_requests DESC
		LIMIT ?
	`
	
	rows, err := sp.db.Query(query, appID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attackers []map[string]interface{}
	for rows.Next() {
		var sourceIP, attackTypes, lastSeen string
		var totalRequests, successfulProbes int

		err := rows.Scan(&sourceIP, &totalRequests, &successfulProbes, &attackTypes, &lastSeen)
		if err != nil {
			continue
		}

		attackers = append(attackers, map[string]interface{}{
			"source_ip":         sourceIP,
			"total_requests":    totalRequests,
			"successful_probes": successfulProbes,
			"attack_types":      attackTypes,
			"last_seen":         lastSeen,
		})
	}

	return attackers, rows.Err()
}


// GetAttackerProfiles returns all attacker profiles for an app
func (sp *SQLiteProvider) GetAttackerProfiles(appID string) ([]map[string]interface{}, error) {
	query := `
		SELECT source_ip, total_requests, successful_probes, attack_types, first_seen, last_seen
		FROM attacker_profiles
		WHERE app_id = ?
		ORDER BY total_requests DESC
	`
	
	rows, err := sp.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attackers []map[string]interface{}
	for rows.Next() {
		var sourceIP, attackTypes, firstSeen, lastSeen string
		var totalRequests, successfulProbes int

		err := rows.Scan(&sourceIP, &totalRequests, &successfulProbes, &attackTypes, &firstSeen, &lastSeen)
		if err != nil {
			continue
		}

		attackers = append(attackers, map[string]interface{}{
			"source_ip":         sourceIP,
			"total_requests":    totalRequests,
			"successful_probes": successfulProbes,
			"attack_types":      attackTypes,
			"first_seen":        firstSeen,
			"last_seen":         lastSeen,
		})
	}

	return attackers, rows.Err()
}



// === EXCEPTIONS (WHITELIST) ===

func (sp *SQLiteProvider) AddException(appID, ipAddress, path, reason string) error {
	query := `
		INSERT INTO exceptions (app_id, ip_address, path, reason, created_at, enabled)
		VALUES (?, ?, ?, ?, datetime('now'), 1)
		ON CONFLICT(app_id, ip_address, path) DO UPDATE SET
			reason = ?,
			enabled = 1
	`
	_, err := sp.db.Exec(query, appID, ipAddress, path, reason, reason)
	return err
}

func (sp *SQLiteProvider) RemoveException(appID, ipAddress, path string) error {
	query := `DELETE FROM exceptions WHERE app_id = ? AND ip_address = ? AND path = ?`
	_, err := sp.db.Exec(query, appID, ipAddress, path)
	return err
}

// GetExceptions returns all exceptions (alias for GetAllExceptions)
func (sp *SQLiteProvider) GetExceptions(appID string) ([]map[string]interface{}, error) {
	return sp.GetAllExceptions(appID)
}


func (sp *SQLiteProvider) GetAllExceptions(appID string) ([]map[string]interface{}, error) {
	query := `
		SELECT id, ip_address, path, reason, created_at, enabled
		FROM exceptions
		WHERE app_id = ?
	`
	
	rows, err := sp.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exceptions []map[string]interface{}
	for rows.Next() {
		var id int64
		var ipAddress, path, reason, createdAt string
		var enabled bool

		err := rows.Scan(&id, &ipAddress, &path, &reason, &createdAt, &enabled)
		if err != nil {
			continue
		}

		exceptions = append(exceptions, map[string]interface{}{
			"id":         id,
			"ip_address": ipAddress,
			"path":       path,
			"reason":     reason,
			"created_at": createdAt,
			"enabled":    enabled,
		})
	}

	return exceptions, rows.Err()
}

// === LEGITIMATE REQUESTS CACHE ===

func (sp *SQLiteProvider) StoreLegitimateRequest(appID, method, path, pathSig, bodySig, headersSig string) error {
	query := `
		INSERT INTO legitimate_requests 
		(app_id, http_method, path, path_signature, body_signature, headers_signature, first_seen, last_seen, hit_count, claude_validated)
		VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), 1, 1)
		ON CONFLICT(app_id, path_signature, body_signature, headers_signature) DO UPDATE SET
			last_seen = datetime('now'),
			hit_count = hit_count + 1
	`
	_, err := sp.db.Exec(query, appID, method, path, pathSig, bodySig, headersSig)
	return err
}

func (sp *SQLiteProvider) GetLegitimateRequest(appID, pathSig, bodySig, headersSig string) (bool, error) {
	query := `
		SELECT id FROM legitimate_requests
		WHERE app_id = ? AND path_signature = ? AND body_signature = ? AND headers_signature = ?
	`
	
	var id int64
	err := sp.db.QueryRow(query, appID, pathSig, bodySig, headersSig).Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	
	return true, nil
}

// === KEYWORD EXCEPTIONS ===

func (sp *SQLiteProvider) AddKeywordException(appID, exceptionType, keyword, reason string) error {
	query := `
		INSERT INTO keyword_exceptions (app_id, exception_type, keyword, reason, enabled, created_at)
		VALUES (?, ?, ?, ?, 1, datetime('now'))
		ON CONFLICT(app_id, exception_type, keyword) DO UPDATE SET
			reason = ?,
			enabled = 1
	`
	_, err := sp.db.Exec(query, appID, exceptionType, keyword, reason, reason)
	return err
}

func (sp *SQLiteProvider) RemoveKeywordException(appID, exceptionType, keyword string) error {
	query := `DELETE FROM keyword_exceptions WHERE app_id = ? AND exception_type = ? AND keyword = ?`
	_, err := sp.db.Exec(query, appID, exceptionType, keyword)
	return err
}

func (sp *SQLiteProvider) GetKeywordExceptions(appID string) ([]map[string]interface{}, error) {
	query := `
		SELECT id, exception_type, keyword, reason, enabled, created_at
		FROM keyword_exceptions
		WHERE app_id = ? AND enabled = 1
	`
	
	rows, err := sp.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exceptions []map[string]interface{}
	for rows.Next() {
		var id int64
		var exceptionType, keyword, reason, createdAt string
		var enabled bool

		err := rows.Scan(&id, &exceptionType, &keyword, &reason, &enabled, &createdAt)
		if err != nil {
			continue
		}

		exceptions = append(exceptions, map[string]interface{}{
			"id":             id,
			"exception_type": exceptionType,
			"keyword":        keyword,
			"reason":         reason,
			"enabled":        enabled,
			"created_at":     createdAt,
		})
	}

	return exceptions, rows.Err()
}

// === LLM API CALLS ===

func (sp *SQLiteProvider) LogLLMCall(appID, fingerprint, provider string, wasAttack bool, attackType string, confidence float64, tokensUsed int) error {
	query := `
		INSERT INTO llm_api_calls 
		(app_id, request_fingerprint, llm_provider, was_attack, attack_type, confidence, tokens_used, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
	`
	_, err := sp.db.Exec(query, appID, fingerprint, provider, wasAttack, attackType, confidence, tokensUsed)
	return err
}

// === ATTACKER INTERACTIONS ===

// StoreAttackerInteraction stores attacker interaction data
func (sp *SQLiteProvider) StoreAttackerInteraction(appID string, patternID int64, sourceIP, interactionType, interactionData string) error {
	query := `
		INSERT INTO attacker_interactions 
		(app_id, pattern_id, source_ip, interaction_type, interaction_data, timestamp)
		VALUES (?, ?, ?, ?, ?, datetime('now'))
	`
	_, err := sp.db.Exec(query, appID, patternID, sourceIP, interactionType, interactionData)
	return err
}

// === INTELLIGENCE COLLECTION TEMPLATES ===

// GetIntelCollectionTemplates returns all intelligence collection templates
func (sp *SQLiteProvider) GetIntelCollectionTemplates() ([]map[string]interface{}, error) {
	query := `
		SELECT id, name, description, payload_template, conditions, is_active, created_at
		FROM intel_collection_templates
		ORDER BY id
	`
	
	rows, err := sp.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []map[string]interface{}
	for rows.Next() {
		var id int64
		var name, description, payloadTemplate, conditions, createdAt string
		var isActive bool

		err := rows.Scan(&id, &name, &description, &payloadTemplate, &conditions, &isActive, &createdAt)
		if err != nil {
			continue
		}

		templates = append(templates, map[string]interface{}{
			"id":               id,
			"name":             name,
			"description":      description,
			"payload_template": payloadTemplate,
			"conditions":       conditions,
			"is_active":         isActive,
			"created_at":       createdAt,
		})
	}

	return templates, rows.Err()
}

// === API TOKENS ===

// CreateAPIToken creates a new API token
func (sp *SQLiteProvider) CreateAPIToken(userID int64, tokenName, tokenHash, tokenPrefix, appID, permissions, expiresAt string) (int64, error) {
	query := `
		INSERT INTO api_tokens 
		(user_id, token_name, token_hash, token_prefix, app_id, permissions, expires_at, created_at, last_used_at, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), NULL, 1)
	`
	
	result, err := sp.db.Exec(query, userID, tokenName, tokenHash, tokenPrefix, appID, permissions, expiresAt)
	if err != nil {
		return 0, err
	}
	
	return result.LastInsertId()
}

// ValidateAPIToken validates an API token and returns user information
func (sp *SQLiteProvider) ValidateAPIToken(tokenHash string) (map[string]interface{}, error) {
	query := `
		SELECT t.id, t.user_id, t.token_name, t.app_id, t.permissions, t.expires_at, 
		       u.username, u.email, u.role
		FROM api_tokens t
		JOIN api_users u ON t.user_id = u.id
		WHERE t.token_hash = ? AND t.is_active = 1 
		  AND (t.expires_at IS NULL OR t.expires_at > datetime('now'))
	`
	
	var tokenID, userID int64
	var tokenName, appID, permissions, username, email, role string
	var expiresAt sql.NullString
	
	err := sp.db.QueryRow(query, tokenHash).Scan(
		&tokenID, &userID, &tokenName, &appID, &permissions, &expiresAt,
		&username, &email, &role,
	)
	
	if err != nil {
		return nil, err
	}
	
	// Update last_used_at
	updateQuery := `UPDATE api_tokens SET last_used_at = datetime('now') WHERE id = ?`
	sp.db.Exec(updateQuery, tokenID)
	
	return map[string]interface{}{
		"token_id":    tokenID,
		"user_id":     userID,
		"username":    username,
		"email":       email,
		"role":        role,
		"app_id":      appID,
		"permissions": permissions,
		"expires_at":  expiresAt.String,
	}, nil
}

// === THREAT INTELLIGENCE ===

func (sp *SQLiteProvider) StoreThreatIntelligence(appID, sourceIP string, riskScore int, abuseScore *float64, abuseReports *int, vtMalicious, vtSuspicious bool, isVPN, isProxy bool, country, org, privacyType, threatLevel string) error {
	query := `
		INSERT INTO threat_intelligence 
		(app_id, source_ip, risk_score, threat_level, abuseipdb_score, abuseipdb_reports, 
		 virustotal_malicious, virustotal_suspicious, is_vpn, is_proxy, 
		 ipinfo_country, ipinfo_org, ipinfo_privacy_type, enriched_at, cached_until, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now', '+24 hours'), datetime('now'))
		ON CONFLICT(app_id, source_ip) DO UPDATE SET
			risk_score = ?,
			threat_level = ?,
			abuseipdb_score = ?,
			abuseipdb_reports = ?,
			virustotal_malicious = ?,
			virustotal_suspicious = ?,
			is_vpn = ?,
			is_proxy = ?,
			ipinfo_country = ?,
			ipinfo_org = ?,
			ipinfo_privacy_type = ?,
			enriched_at = datetime('now'),
			cached_until = datetime('now', '+24 hours'),
			updated_at = datetime('now')
	`
	
	vtMaliciousInt := 0
	if vtMalicious {
		vtMaliciousInt = 1
	}
	vtSuspiciousInt := 0
	if vtSuspicious {
		vtSuspiciousInt = 1
	}
	
	_, err := sp.db.Exec(query, 
		appID, sourceIP, riskScore, threatLevel, abuseScore, abuseReports, 
		vtMaliciousInt, vtSuspiciousInt, isVPN, isProxy, 
		country, org, privacyType,
		// For UPDATE clause
		riskScore, threatLevel, abuseScore, abuseReports,
		vtMaliciousInt, vtSuspiciousInt, isVPN, isProxy,
		country, org, privacyType,
	)
	return err
}

func (sp *SQLiteProvider) GetThreatIntelligence(appID, sourceIP string) (map[string]interface{}, error) {
	query := `
		SELECT risk_score, threat_level, abuseipdb_score, abuseipdb_reports,
		       virustotal_malicious, virustotal_suspicious, is_vpn, is_proxy,
		       ipinfo_country, ipinfo_org, ipinfo_privacy_type, enriched_at, cached_until
		FROM threat_intelligence
		WHERE app_id = ? AND source_ip = ?
	`
	
	var riskScore int
	var threatLevel string
	var abuseScore sql.NullFloat64
	var abuseReports sql.NullInt64
	var vtMalicious, vtSuspicious, isVPN, isProxy bool
	var country, org, privacyType, enrichedAt, cachedUntil string

	err := sp.db.QueryRow(query, appID, sourceIP).Scan(
		&riskScore, &threatLevel, &abuseScore, &abuseReports,
		&vtMalicious, &vtSuspicious, &isVPN, &isProxy,
		&country, &org, &privacyType, &enrichedAt, &cachedUntil,
	)
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"risk_score":            riskScore,
		"threat_level":          threatLevel,
		"is_vpn":                isVPN,
		"is_proxy":              isProxy,
		"ipinfo_country":        country,
		"ipinfo_org":            org,
		"ipinfo_privacy_type":   privacyType,
		"enriched_at":           enrichedAt,
		"cached_until":          cachedUntil,
		"virustotal_malicious":  vtMalicious,
		"virustotal_suspicious": vtSuspicious,
	}

	if abuseScore.Valid {
		result["abuseipdb_score"] = abuseScore.Float64
	}
	if abuseReports.Valid {
		result["abuseipdb_reports"] = abuseReports.Int64
	}

	return result, nil
}

func (sp *SQLiteProvider) IsThreatIntelligenceCached(appID, sourceIP string) (bool, error) {
	query := `
		SELECT COUNT(*) FROM threat_intelligence
		WHERE app_id = ? AND source_ip = ? AND cached_until > datetime('now')
	`
	
	var count int
	err := sp.db.QueryRow(query, appID, sourceIP).Scan(&count)
	if err != nil {
		return false, err
	}
	
	return count > 0, nil
}


// GetThreatIntelList returns list of threat intelligence records
func (sp *SQLiteProvider) GetThreatIntelList(appID string, limit int) ([]map[string]interface{}, error) {
	query := `
		SELECT ip_address, risk_score, threat_level, abuseipdb_score, abuseipdb_reports, 
		       virustotal_malicious, virustotal_suspicious, country, last_seen 
		FROM threat_intelligence 
		WHERE app_id = ? 
		ORDER BY last_seen DESC 
		LIMIT ?
	`
	
	rows, err := sp.db.Query(query, appID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var results []map[string]interface{}
	for rows.Next() {
		var ipAddress, threatLevel, country, lastSeen string
		var riskScore, abuseScore, abuseReports, vtMalicious, vtSuspicious int
		
		if err := rows.Scan(&ipAddress, &riskScore, &threatLevel, &abuseScore, &abuseReports,
			&vtMalicious, &vtSuspicious, &country, &lastSeen); err != nil {
			continue
		}
		
		results = append(results, map[string]interface{}{
			"ip_address":            ipAddress,
			"risk_score":            riskScore,
			"threat_level":          threatLevel,
			"abuseipdb_score":       abuseScore,
			"abuseipdb_reports":     abuseReports,
			"virustotal_malicious":  vtMalicious,
			"virustotal_suspicious": vtSuspicious,
			"country":               country,
			"last_seen":             lastSeen,
		})
	}
	
	return results, rows.Err()
}

// GetTopThreatsByRiskScore returns top threats ordered by risk score
func (sp *SQLiteProvider) GetTopThreatsByRiskScore(appID string, limit int) ([]map[string]interface{}, error) {
	query := `
		SELECT ip_address, risk_score, threat_level, abuseipdb_reports, 
		       virustotal_malicious, country, last_seen
		FROM threat_intelligence
		WHERE app_id = ?
		ORDER BY risk_score DESC
		LIMIT ?
	`
	
	rows, err := sp.db.Query(query, appID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var results []map[string]interface{}
	for rows.Next() {
		var ipAddress, threatLevel, country, lastSeen string
		var riskScore, abuseReports, vtMalicious int
		
		if err := rows.Scan(&ipAddress, &riskScore, &threatLevel, &abuseReports,
			&vtMalicious, &country, &lastSeen); err != nil {
			continue
		}
		
		results = append(results, map[string]interface{}{
			"ip_address":           ipAddress,
			"risk_score":           riskScore,
			"threat_level":         threatLevel,
			"abuseipdb_reports":    abuseReports,
			"virustotal_malicious": vtMalicious,
			"country":              country,
			"last_seen":            lastSeen,
		})
	}
	
	return results, rows.Err()
}

// GetThreatIntelStats returns threat intelligence statistics by level
func (sp *SQLiteProvider) GetThreatIntelStats(appID string) (int64, int64, int64, int64, int64, error) {
	var totalIPs, critical, high, medium, low int64
	
	if err := sp.db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE app_id = ?", appID).Scan(&totalIPs); err != nil {
		return 0, 0, 0, 0, 0, err
	}
	
	sp.db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE app_id = ? AND threat_level = 'CRITICAL'", appID).Scan(&critical)
	sp.db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE app_id = ? AND threat_level = 'HIGH'", appID).Scan(&high)
	sp.db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE app_id = ? AND threat_level = 'MEDIUM'", appID).Scan(&medium)
	sp.db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE app_id = ? AND threat_level = 'LOW'", appID).Scan(&low)
	
	return totalIPs, critical, high, medium, low, nil
}

// GetThreatIntelDetail returns detailed threat intelligence for a specific IP
func (sp *SQLiteProvider) GetThreatIntelDetail(appID, ipAddress string) (map[string]interface{}, error) {
	query := `
		SELECT ip_address, risk_score, threat_level, abuseipdb_score, abuseipdb_reports,
		       virustotal_malicious, virustotal_suspicious, ipinfo_city, ipinfo_country, 
		       last_seen, created_at
		FROM threat_intelligence
		WHERE ip_address = ? AND app_id = ?
	`
	
	var ip, threatLevel, city, country, lastSeen, createdAt string
	var riskScore, abuseScore, abuseReports, vtMalicious, vtSuspicious int
	
	err := sp.db.QueryRow(query, ipAddress, appID).Scan(
		&ip, &riskScore, &threatLevel, &abuseScore, &abuseReports,
		&vtMalicious, &vtSuspicious, &city, &country, &lastSeen, &createdAt,
	)
	
	if err != nil {
		return nil, err
	}
	
	return map[string]interface{}{
		"ip_address":            ip,
		"risk_score":            riskScore,
		"threat_level":          threatLevel,
		"abuseipdb_score":       abuseScore,
		"abuseipdb_reports":     abuseReports,
		"virustotal_malicious":  vtMalicious,
		"virustotal_suspicious": vtSuspicious,
		"ipinfo_city":           city,
		"ipinfo_country":        country,
		"last_seen":             lastSeen,
		"created_at":            createdAt,
	}, nil
}

// === NOTIFICATIONS ===

// GetNotificationHistory returns notification send history
func (sp *SQLiteProvider) GetNotificationHistory(appID string, limit int) ([]map[string]interface{}, error) {
	query := `
		SELECT threat_level, source_ip, attack_type, notification_type, status, sent_at
		FROM notification_history
		WHERE app_id = ?
		ORDER BY sent_at DESC
		LIMIT ?
	`
	
	rows, err := sp.db.Query(query, appID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var history []map[string]interface{}
	for rows.Next() {
		var threatLevel, sourceIP, attackType, notificationType, status, sentAt string
		
		if err := rows.Scan(&threatLevel, &sourceIP, &attackType, &notificationType, &status, &sentAt); err != nil {
			continue
		}
		
		history = append(history, map[string]interface{}{
			"threat_level":      threatLevel,
			"source_ip":         sourceIP,
			"attack_type":       attackType,
			"notification_type": notificationType,
			"status":            status,
			"sent_at":           sentAt,
		})
	}
	
	return history, rows.Err()
}

// === ATTACKER INTERACTIONS ===

// GetAttackerInteractionsCount returns count of attacker interactions
func (sp *SQLiteProvider) GetAttackerInteractionsCount(appID string) (int64, error) {
	var count int64
	err := sp.db.QueryRow("SELECT COUNT(*) FROM attacker_interactions WHERE app_id = ?", appID).Scan(&count)
	return count, err
}

// === EXCEPTIONS ===

// CheckException checks if a request matches an exception rule
func (sp *SQLiteProvider) CheckException(appID, path, clientIP string) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM exceptions 
			WHERE enabled = 1 
			AND app_id = ?
			AND path = ? 
			AND (ip_address = ? OR ip_address = '*')
		)
	`
	err := sp.db.QueryRow(query, appID, path, clientIP).Scan(&exists)
	return exists, err
}

// === WEBHOOKS ===

func (sp *SQLiteProvider) GetActiveWebhooks(appID string) ([]map[string]interface{}, error) {
	query := `
		SELECT id, endpoint, auth_type, auth_value
		FROM webhooks_config
		WHERE app_id = ? AND enabled = 1
	`
	
	rows, err := sp.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var webhooks []map[string]interface{}
	for rows.Next() {
		var id int64
		var endpoint, authType string
		var authValue sql.NullString

		err := rows.Scan(&id, &endpoint, &authType, &authValue)
		if err != nil {
			continue
		}

		authVal := ""
		if authValue.Valid {
			authVal = authValue.String
		}

		webhooks = append(webhooks, map[string]interface{}{
			"id":         id,
			"endpoint":   endpoint,
			"auth_type":  authType,
			"auth_value": authVal,
		})
	}

	return webhooks, rows.Err()
}

// === PAYLOAD TEMPLATES ===

// GetPayloadTemplate retrieves active payload template for attack type
func (sp *SQLiteProvider) GetPayloadTemplate(attackType string) (string, string, int, error) {
	var content, contentType string
	var statusCode int

	query := `
		SELECT content, content_type, http_status_code 
		FROM payload_templates 
		WHERE attack_type = ? AND is_active = 1 
		ORDER BY priority DESC 
		LIMIT 1
	`

	err := sp.db.QueryRow(query, attackType).Scan(&content, &contentType, &statusCode)
	if err != nil {
		return "", "", 0, err
	}

	return content, contentType, statusCode, nil
}


// CachePayloadTemplate stores a generated payload in the database cache
func (sp *SQLiteProvider) CachePayloadTemplate(name, attackType, content string) error {
	query := `
		INSERT OR REPLACE INTO payload_templates 
		(name, attack_type, payload_type, content, content_type, http_status_code, is_active, created_at, created_by)
		VALUES (?, ?, 'dynamic', ?, 'application/json', 200, 1, datetime('now'), 'llm_cache')
	`
	_, err := sp.db.Exec(query, name, attackType, content)
	return err
}

// GetPayloadCacheStats returns statistics about cached payloads
func (sp *SQLiteProvider) GetPayloadCacheStats() (int64, int64, error) {
	var totalActive, activeLLM int64
	
	err := sp.db.QueryRow("SELECT COUNT(*) FROM payload_templates WHERE is_active = 1").Scan(&totalActive)
	if err != nil {
		return 0, 0, err
	}
	
	err = sp.db.QueryRow("SELECT COUNT(*) FROM payload_templates WHERE is_active = 1 AND created_by = 'llm_cache'").Scan(&activeLLM)
	if err != nil {
		return 0, 0, err
	}
	
	return totalActive, activeLLM, nil
}

// AddPayloadCondition adds a condition to a payload template
func (sp *SQLiteProvider) AddPayloadCondition(payloadID int64, conditionType, conditionValue, operator string) error {
	query := `
		INSERT INTO payload_conditions (payload_template_id, condition_type, condition_value, operator)
		VALUES (?, ?, ?, ?)
	`
	_, err := sp.db.Exec(query, payloadID, conditionType, conditionValue, operator)
	return err
}

// RemovePayloadCondition removes a condition from a payload template
func (sp *SQLiteProvider) RemovePayloadCondition(conditionID int64) error {
	query := `DELETE FROM payload_conditions WHERE id = ?`
	_, err := sp.db.Exec(query, conditionID)
	return err
}

// GetPayloadConditions retrieves all conditions for a payload template
func (sp *SQLiteProvider) GetPayloadConditions(payloadID int64) ([]map[string]interface{}, error) {
	query := `
		SELECT id, condition_type, condition_value, operator
		FROM payload_conditions
		WHERE payload_template_id = ?
		ORDER BY id ASC
	`
	
	rows, err := sp.db.Query(query, payloadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var conditions []map[string]interface{}
	for rows.Next() {
		var id int64
		var conditionType, conditionValue, operator string
		
		if err := rows.Scan(&id, &conditionType, &conditionValue, &operator); err != nil {
			continue
		}
		
		conditions = append(conditions, map[string]interface{}{
			"id":              id,
			"condition_type":  conditionType,
			"condition_value": conditionValue,
			"operator":        operator,
		})
	}
	
	return conditions, rows.Err()
}

// UpdatePayloadCondition updates an existing payload condition
func (sp *SQLiteProvider) UpdatePayloadCondition(conditionID int64, conditionType, conditionValue, operator string) error {
	query := `
		UPDATE payload_conditions
		SET condition_type = ?, condition_value = ?, operator = ?
		WHERE id = ?
	`
	_, err := sp.db.Exec(query, conditionType, conditionValue, operator, conditionID)
	return err
}

// === CONFIGURATION (NEW) ===

func (sp *SQLiteProvider) GetConfigValue(appID, category, key string) (string, error) {
	query := `SELECT value FROM config_settings WHERE app_id = ? AND category = ? AND key = ?`
	var value string
	err := sp.db.QueryRow(query, appID, category, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (sp *SQLiteProvider) SetConfigValue(appID, category, key, value, dataType string, isSensitive bool, updatedBy string) error {
	query := `
		INSERT INTO config_settings (app_id, category, key, value, data_type, is_sensitive, updated_at, updated_by)
		VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
		ON CONFLICT(app_id, category, key) DO UPDATE SET
			value = ?,
			data_type = ?,
			is_sensitive = ?,
			updated_at = datetime('now'),
			updated_by = ?
	`
	_, err := sp.db.Exec(query, appID, category, key, value, dataType, isSensitive, updatedBy, value, dataType, isSensitive, updatedBy)
	return err
}

func (sp *SQLiteProvider) GetConfigByCategory(appID, category string) ([]map[string]interface{}, error) {
	query := `
		SELECT key, value, data_type, is_sensitive, updated_at
		FROM config_settings
		WHERE app_id = ? AND category = ?
	`
	
	rows, err := sp.db.Query(query, appID, category)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []map[string]interface{}
	for rows.Next() {
		var key, value, dataType, updatedAt string
		var isSensitive bool

		err := rows.Scan(&key, &value, &dataType, &isSensitive, &updatedAt)
		if err != nil {
			continue
		}

		configs = append(configs, map[string]interface{}{
			"key":          key,
			"value":        value,
			"data_type":    dataType,
			"is_sensitive": isSensitive,
			"updated_at":   updatedAt,
		})
	}

	return configs, rows.Err()
}

func (sp *SQLiteProvider) GetAllConfig(appID string) ([]map[string]interface{}, error) {
	query := `
		SELECT category, key, value, data_type, is_sensitive, updated_at
		FROM config_settings
		WHERE app_id = ?
	`
	
	rows, err := sp.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []map[string]interface{}
	for rows.Next() {
		var category, key, value, dataType, updatedAt string
		var isSensitive bool

		err := rows.Scan(&category, &key, &value, &dataType, &isSensitive, &updatedAt)
		if err != nil {
			continue
		}

		configs = append(configs, map[string]interface{}{
			"category":     category,
			"key":          key,
			"value":        value,
			"data_type":    dataType,
			"is_sensitive": isSensitive,
			"updated_at":   updatedAt,
		})
	}

	return configs, rows.Err()
}

func (sp *SQLiteProvider) DeleteConfigValue(appID, category, key string) error {
	query := `DELETE FROM config_settings WHERE app_id = ? AND category = ? AND key = ?`
	_, err := sp.db.Exec(query, appID, category, key)
	return err
}

// === KEYCLOAK CONFIGURATION (NEW) ===

func (sp *SQLiteProvider) GetKeycloakConfig(appID string) (map[string]interface{}, error) {
	query := `
		SELECT realm, auth_server_url, client_id, client_secret, enabled
		FROM keycloak_config
		WHERE app_id = ?
	`
	
	var realm, authServerURL, clientID, clientSecret string
	var enabled bool

	err := sp.db.QueryRow(query, appID).Scan(&realm, &authServerURL, &clientID, &clientSecret, &enabled)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"realm":           realm,
		"auth_server_url": authServerURL,
		"client_id":       clientID,
		"client_secret":   clientSecret,
		"enabled":         enabled,
	}, nil
}

func (sp *SQLiteProvider) SetKeycloakConfig(appID, realm, authServerURL, clientID, clientSecret string) error {
	query := `
		INSERT INTO keycloak_config (app_id, realm, auth_server_url, client_id, client_secret, enabled, updated_at)
		VALUES (?, ?, ?, ?, ?, 1, datetime('now'))
		ON CONFLICT(app_id) DO UPDATE SET
			realm = ?,
			auth_server_url = ?,
			client_id = ?,
			client_secret = ?,
			updated_at = datetime('now')
	`
	_, err := sp.db.Exec(query, appID, realm, authServerURL, clientID, clientSecret, realm, authServerURL, clientID, clientSecret)
	return err
}

func (sp *SQLiteProvider) GetRoleMapping(appID, keycloakRole string) ([]string, error) {
	query := `
		SELECT ifrit_permissions FROM keycloak_role_mappings
		WHERE app_id = ? AND keycloak_role = ?
	`
	
	var permissionsJSON string
	err := sp.db.QueryRow(query, appID, keycloakRole).Scan(&permissionsJSON)
	if err != nil {
		return nil, err
	}

	var permissions []string
	if err := json.Unmarshal([]byte(permissionsJSON), &permissions); err != nil {
		return nil, err
	}

	return permissions, nil
}

func (sp *SQLiteProvider) SetRoleMapping(appID, keycloakRole string, permissions []string) error {
	permissionsJSON, _ := json.Marshal(permissions)
	
	query := `
		INSERT INTO keycloak_role_mappings (app_id, keycloak_role, ifrit_permissions, created_at)
		VALUES (?, ?, ?, datetime('now'))
		ON CONFLICT(app_id, keycloak_role) DO UPDATE SET
			ifrit_permissions = ?
	`
	_, err := sp.db.Exec(query, appID, keycloakRole, string(permissionsJSON), string(permissionsJSON))
	return err
}

// === SERVICE TOKENS (NEW) ===

func (sp *SQLiteProvider) CreateServiceToken(appID, tokenName, tokenHash, tokenPrefix, keycloakServiceAccountID string, permissions []string, expiresAt *string) (int64, error) {
	permissionsJSON, _ := json.Marshal(permissions)
	
	query := `
		INSERT INTO service_tokens 
		(app_id, token_name, token_hash, token_prefix, keycloak_service_account_id, permissions, is_active, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, datetime('now'))
	`
	
	result, err := sp.db.Exec(query, appID, tokenName, tokenHash, tokenPrefix, keycloakServiceAccountID, string(permissionsJSON), expiresAt)
	if err != nil {
		return 0, err
	}
	
	return result.LastInsertId()
}

func (sp *SQLiteProvider) ValidateServiceToken(tokenHash string) (map[string]interface{}, error) {
	query := `
		SELECT id, app_id, token_name, permissions, is_active, expires_at, keycloak_service_account_id
		FROM service_tokens
		WHERE token_hash = ? AND is_active = 1
	`
	
	var id int64
	var appID, tokenName, permissionsJSON string
	var isActive bool
	var expiresAt, keycloakServiceAccountID sql.NullString

	err := sp.db.QueryRow(query, tokenHash).Scan(&id, &appID, &tokenName, &permissionsJSON, &isActive, &expiresAt, &keycloakServiceAccountID)
	if err != nil {
		return nil, err
	}

	// Check expiry
	if expiresAt.Valid {
		expiry, _ := time.Parse(time.RFC3339, expiresAt.String)
		if time.Now().After(expiry) {
			return nil, fmt.Errorf("token expired")
		}
	}

	var permissions []string
	json.Unmarshal([]byte(permissionsJSON), &permissions)

	result := map[string]interface{}{
		"id":          id,
		"app_id":      appID,
		"token_name":  tokenName,
		"permissions": permissions,
		"is_active":   isActive,
	}

	if keycloakServiceAccountID.Valid {
		result["keycloak_service_account_id"] = keycloakServiceAccountID.String
	}

	return result, nil
}

func (sp *SQLiteProvider) RevokeServiceToken(tokenID int64) error {
	query := `UPDATE service_tokens SET is_active = 0 WHERE id = ?`
	_, err := sp.db.Exec(query, tokenID)
	return err
}

func (sp *SQLiteProvider) GetServiceTokens(appID string) ([]map[string]interface{}, error) {
	query := `
		SELECT id, token_name, token_prefix, permissions, is_active, created_at, last_used_at, expires_at
		FROM service_tokens
		WHERE app_id = ?
		ORDER BY created_at DESC
	`
	
	rows, err := sp.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []map[string]interface{}
	for rows.Next() {
		var id int64
		var tokenName, tokenPrefix, permissionsJSON, createdAt string
		var isActive bool
		var lastUsedAt, expiresAt sql.NullString

		err := rows.Scan(&id, &tokenName, &tokenPrefix, &permissionsJSON, &isActive, &createdAt, &lastUsedAt, &expiresAt)
		if err != nil {
			continue
		}

		var permissions []string
		json.Unmarshal([]byte(permissionsJSON), &permissions)

		token := map[string]interface{}{
			"id":           id,
			"token_name":   tokenName,
			"token_prefix": tokenPrefix,
			"permissions":  permissions,
			"is_active":    isActive,
			"created_at":   createdAt,
		}

		if lastUsedAt.Valid {
			token["last_used_at"] = lastUsedAt.String
		}
		if expiresAt.Valid {
			token["expires_at"] = expiresAt.String
		}

		tokens = append(tokens, token)
	}

	return tokens, rows.Err()
}

func (sp *SQLiteProvider) UpdateServiceTokenLastUsed(tokenID int64) error {
	query := `UPDATE service_tokens SET last_used_at = datetime('now') WHERE id = ?`
	_, err := sp.db.Exec(query, tokenID)
	return err
}
