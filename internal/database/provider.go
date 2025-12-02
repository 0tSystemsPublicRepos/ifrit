package database

import (
	"database/sql"
	"fmt"
)

// DatabaseProvider defines the interface that all database implementations must follow
type DatabaseProvider interface {
	// Connection management
	Connect() error
	Close() error
	GetDB() *sql.DB
	Migrate() error
	Ping() error

	// Attack Patterns
	StoreAttackPattern(appID, signature, attackType, classification, method, path, payloadTemplate string, responseCode int, createdBy string, confidence float64) error
	// StoreAttackPatternEnhanced stores attack pattern with enhanced fields (pattern_type, header_pattern, etc.)
	StoreAttackPatternEnhanced(appID, signature, attackType, classification, method, pathPattern, payloadTemplate string, responseCode int, createdBy string, confidence float64, patternType, headerPattern, bodyPattern, queryPattern string,) error
	GetAllPatterns(appID string) ([]map[string]interface{}, error)
	GetPatternBySignature(appID, signature string) (map[string]interface{}, error)
	UpdatePatternTimestamp(appID, signature string) error

	// Attack Instances
	LogAttackInstance(appID string, patternID *int64, sourceIP, userAgent, path, method string, returnedHoneypot, attackerAccepted bool) error
	GetAttackInstances(appID string, limit int) ([]map[string]interface{}, error)

	// Attacker Profiles
	UpdateAttackerProfile(appID, sourceIP string, attackTypes []string, successfulProbe bool) error
	GetAttackerProfile(appID, sourceIP string) (map[string]interface{}, error)
	GetAttackerProfiles(appID string) ([]map[string]interface{}, error)
	GetTopAttackers(appID string, limit int) ([]map[string]interface{}, error)

	// Exceptions (Whitelist)
	AddException(appID, ipAddress, path, reason string) error
	RemoveException(appID, ipAddress, path string) error
	GetExceptions(appID string) ([]map[string]interface{}, error)
	GetAllExceptions(appID string) ([]map[string]interface{}, error)

	// Legitimate Requests Cache
	StoreLegitimateRequest(appID, method, path, pathSig, bodySig, headersSig string) error
	GetLegitimateRequest(appID, pathSig, bodySig, headersSig string) (bool, error)

	// Keyword Exceptions
	AddKeywordException(appID, exceptionType, keyword, reason string) error
	RemoveKeywordException(appID, exceptionType, keyword string) error
	GetKeywordExceptions(appID string) ([]map[string]interface{}, error)

	// LLM API Calls Log
	LogLLMCall(appID, fingerprint, provider string, wasAttack bool, attackType string, confidence float64, tokensUsed int) error
	
	// Attacker Interactions
	StoreAttackerInteraction(appID string, patternID int64, sourceIP, interactionType, interactionData string) error

	// Intelligence Collection Templates
	GetIntelCollectionTemplates() ([]map[string]interface{}, error)

	// Threat Intelligence
	StoreThreatIntelligence(appID, sourceIP string, riskScore int, abuseScore *float64, abuseReports *int, vtMalicious, vtSuspicious bool, isVPN, isProxy bool, country, org, privacyType, threatLevel string) error
	GetThreatIntelligence(appID, sourceIP string) (map[string]interface{}, error)
	IsThreatIntelligenceCached(appID, sourceIP string) (bool, error)
	GetThreatIntelList(appID string, limit int) ([]map[string]interface{}, error)
	GetTopThreatsByRiskScore(appID string, limit int) ([]map[string]interface{}, error)
	GetThreatIntelStats(appID string) (totalIPs, critical, high, medium, low int64, err error)
	GetThreatIntelDetail(appID, ipAddress string) (map[string]interface{}, error)
	
	
	// Attacker Interactions
	GetAttackerInteractionsCount(appID string) (int64, error)
	
	// Exceptions
	CheckException(appID, path, clientIP string) (bool, error)

	// Notifications
	GetNotificationHistory(appID string, limit int) ([]map[string]interface{}, error)
	
	// Webhooks
	GetActiveWebhooks(appID string) ([]map[string]interface{}, error)

	// Payload Templates (NEW)
	GetPayloadTemplate(attackType string) (content string, contentType string, statusCode int, err error)
	
	CachePayloadTemplate(name, attackType, content string) error
	GetPayloadCacheStats() (totalActive int64, activeLLM int64, err error)
	
	// Payload Conditions
	AddPayloadCondition(payloadID int64, conditionType, conditionValue, operator string) error
	RemovePayloadCondition(conditionID int64) error
	GetPayloadConditions(payloadID int64) ([]map[string]interface{}, error)
	UpdatePayloadCondition(conditionID int64, conditionType, conditionValue, operator string) error


	// Configuration (NEW - for config in DB feature)
	GetConfigValue(appID, category, key string) (string, error)
	SetConfigValue(appID, category, key, value, dataType string, isSensitive bool, updatedBy string) error
	GetConfigByCategory(appID, category string) ([]map[string]interface{}, error)
	GetAllConfig(appID string) ([]map[string]interface{}, error)
	DeleteConfigValue(appID, category, key string) error

	// Keycloak Configuration (NEW)
	GetKeycloakConfig(appID string) (map[string]interface{}, error)
	SetKeycloakConfig(appID, realm, authServerURL, clientID, clientSecret string) error
	GetRoleMapping(appID, keycloakRole string) ([]string, error)
	SetRoleMapping(appID, keycloakRole string, permissions []string) error

	// Service Tokens (NEW)
	CreateServiceToken(appID, tokenName, tokenHash, tokenPrefix, keycloakServiceAccountID string, permissions []string, expiresAt *string) (int64, error)
	ValidateServiceToken(tokenHash string) (map[string]interface{}, error)
	RevokeServiceToken(tokenID int64) error
	GetServiceTokens(appID string) ([]map[string]interface{}, error)
	UpdateServiceTokenLastUsed(tokenID int64) error
	
	// API Tokens (NEW)
	CreateAPIToken(userID int64, tokenName, tokenHash, tokenPrefix, appID, permissions, expiresAt string) (int64, error)
	ValidateAPIToken(tokenHash string) (map[string]interface{}, error) // (duplicate of ValidateServiceToken but for backward compatibility)	

}

// ProviderFactory creates database providers based on type
type ProviderFactory struct{}

// Create returns a database provider based on the specified type
func (pf *ProviderFactory) Create(dbType string, config interface{}) (DatabaseProvider, error) {
	switch dbType {
	case "sqlite":
		cfg, ok := config.(*SQLiteConfig)
		if !ok {
			return nil, fmt.Errorf("invalid config type for sqlite")
		}
		return NewSQLiteProvider(cfg)
	case "postgres", "postgresql":
		cfg, ok := config.(*PostgresConfig)
		if !ok {
			return nil, fmt.Errorf("invalid config type for postgres")
		}
		return NewPostgresProvider(cfg)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}
}

// Config types for different databases
type SQLiteConfig struct {
	Path        string
	JournalMode string
	Synchronous string
}

type PostgresConfig struct {
	Host           string
	Port           int
	Database       string
	User           string
	Password       string
	SSLMode        string
	MaxConnections int
}


