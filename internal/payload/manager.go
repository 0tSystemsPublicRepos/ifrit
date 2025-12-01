package payload

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
	"github.com/0tSystemsPublicRepos/ifrit/internal/llm"
	"github.com/0tSystemsPublicRepos/ifrit/internal/logging"
)

type AttackerContext struct {
	SourceIP       string
	AttackType     string
	Classification string
	Path           string
}

type PayloadResponse struct {
	Body        string
	StatusCode  int
	ContentType string
}

type PayloadTemplate struct {
	ID              int64
	Name            string
	AttackType      string
	PayloadType     string
	Content         string
	ContentType     string
	HTTPStatusCode  int
	IsActive        bool
	Priority        int
	CreatedBy       string
}

type PayloadCondition struct {
	ID                 int64
	PayloadTemplateID  int64
	ConditionType      string
	ConditionValue     string
	Operator           string
}

type PayloadManager struct {
	db         database.DatabaseProvider	
	llmManager *llm.Manager
}

func NewPayloadManager(db database.DatabaseProvider) *PayloadManager { 
	return &PayloadManager{
		db:         db,
		llmManager: nil,
	}
}

func (pm *PayloadManager) SetLLMManager(manager *llm.Manager) {
	pm.llmManager = manager
}

// GetPayloadForAttack returns appropriate honeypot payload for detected attack
func (pm *PayloadManager) GetPayloadForAttack(ctx AttackerContext, cfg *config.PayloadManagement, llmManager *llm.Manager) (*PayloadResponse, error) {
	logging.Info("[PAYLOAD] Getting payload for attack type: %s from %s", ctx.AttackType, ctx.SourceIP)

	// 1. Check if we should use database payloads
	if cfg.UseDBPayloads {
		payload, err := pm.getPayloadFromDB(ctx.AttackType)
		if err == nil && payload != nil {
			logging.Info("[PAYLOAD] Using cached payload from DB for: %s", ctx.AttackType)
			return payload, nil
		}
	}

	// 2. Try to generate dynamic payload via LLM
	if cfg.GenerateDynamicPayload && llmManager != nil {
		logging.Info("[PAYLOAD] Generating dynamic payload via LLM for: %s", ctx.AttackType)
		payload, err := pm.generateLLMPayload(ctx, cfg, llmManager)
		if err == nil && payload != nil {
			return payload, nil
		}
	}

	// 3. Fall back to default responses
	logging.Info("[PAYLOAD] Using default response for: %s", ctx.AttackType)
	return pm.getDefaultPayload(ctx.AttackType, cfg), nil
}



// getPayloadFromDB retrieves payload template from database
func (pm *PayloadManager) getPayloadFromDB(attackType string) (*PayloadResponse, error) {
	content, contentType, statusCode, err := pm.db.GetPayloadTemplate(attackType)
	
	if err != nil {
		if err == sql.ErrNoRows {
			logging.Debug("[PAYLOAD] No payload template found in DB for: %s", attackType)
			return nil, nil
		}
		logging.Error("[PAYLOAD] Error querying DB for payload: %v", err)
		return nil, err
	}

	return &PayloadResponse{
		Body:        content,
		ContentType: contentType,
		StatusCode:  statusCode,
	}, nil
}


// generateLLMPayload generates payload via LLM with intel injection
func (pm *PayloadManager) generateLLMPayload(ctx AttackerContext, cfg *config.PayloadManagement, llmManager *llm.Manager) (*PayloadResponse, error) {
	// Get LLM provider
	provider := llmManager.GetProvider(llmManager.GetPrimaryName())
	if provider == nil {
		return nil, fmt.Errorf("LLM provider not available")
	}

	// Try Claude provider first
	if claudeProvider, ok := provider.(*llm.ClaudeProvider); ok {
		intelTemplates, err := pm.getIntelTemplates()
		if err != nil {
			logging.Error("[PAYLOAD] Error getting intel templates: %v", err)
			intelTemplates = []map[string]interface{}{}
		}

		claudeProvider.SetIntelTemplates(intelTemplates)

		intelTemplateID := cfg.IntelCollectionPayloadID
		if intelTemplateID <= 0 {
			intelTemplateID = 1
		}

		payloadData, err := claudeProvider.GeneratePayloadWithIntel(ctx.AttackType, intelTemplateID)
		if err != nil {
			logging.Error("[PAYLOAD] Error generating LLM payload: %v", err)
			return nil, err
		}

		payloadJSON, err := json.Marshal(payloadData)
		if err != nil {
			return nil, err
		}

		if cfg.CacheLLMPayloadsToDb {
			pm.cachePayloadToDB(ctx.AttackType, string(payloadJSON))
		}

		return &PayloadResponse{
			Body:        string(payloadJSON),
			ContentType: "application/json",
			StatusCode:  200,
		}, nil
	}

	// Try Gemini provider
	if geminiProvider, ok := provider.(*llm.GeminiProvider); ok {
		intelTemplates, err := pm.getIntelTemplates()
		if err != nil {
			logging.Error("[PAYLOAD] Error getting intel templates: %v", err)
			intelTemplates = []map[string]interface{}{}
		}

		geminiProvider.SetIntelTemplates(intelTemplates)

		intelTemplateID := cfg.IntelCollectionPayloadID
		if intelTemplateID <= 0 {
			intelTemplateID = 1
		}

		payloadData, err := geminiProvider.GeneratePayloadWithIntel(ctx.AttackType, intelTemplateID)
		if err != nil {
			logging.Error("[PAYLOAD] Error generating LLM payload: %v", err)
			return nil, err
		}

		payloadJSON, err := json.Marshal(payloadData)
		if err != nil {
			return nil, err
		}

		if cfg.CacheLLMPayloadsToDb {
			pm.cachePayloadToDB(ctx.AttackType, string(payloadJSON))
		}

		return &PayloadResponse{
			Body:        string(payloadJSON),
			ContentType: "application/json",
			StatusCode:  200,
		}, nil
	}

	return nil, fmt.Errorf("unsupported LLM provider type")
}

// getDefaultPayload returns default payload for attack type
func (pm *PayloadManager) getDefaultPayload(attackType string, cfg *config.PayloadManagement) *PayloadResponse {
	// Check default responses in config
	if response, ok := cfg.DefaultResponses[attackType]; ok {
		if respMap, ok := response.(map[string]interface{}); ok {
			content := respMap["content"]
			statusCode := int64(500)
			if sc, ok := respMap["status_code"].(float64); ok {
				statusCode = int64(sc)
			}

			contentJSON, _ := json.Marshal(content)
			return &PayloadResponse{
				Body:        string(contentJSON),
				ContentType: "application/json",
				StatusCode:  int(statusCode),
			}
		}
	}

	// Ultimate fallback
	fallback := cfg.DefaultResponses["fallback"]
	if respMap, ok := fallback.(map[string]interface{}); ok {
		content := respMap["content"]
		statusCode := int64(500)
		if sc, ok := respMap["status_code"].(float64); ok {
			statusCode = int64(sc)
		}

		contentJSON, _ := json.Marshal(content)
		return &PayloadResponse{
			Body:        string(contentJSON),
			ContentType: "application/json",
			StatusCode:  int(statusCode),
		}
	}

	return &PayloadResponse{
		Body:        `{"error": "Internal server error"}`,
		ContentType: "application/json",
		StatusCode:  500,
	}
}

func (pm *PayloadManager) getIntelTemplates() ([]map[string]interface{}, error) {
	return pm.db.GetIntelCollectionTemplates()
}

// cachePayloadToDB stores generated payload in database for future use
func (pm *PayloadManager) cachePayloadToDB(attackType, payloadJSON string) error {
	name := fmt.Sprintf("dynamic_%s_%d", attackType, getCurrentUnixTimestamp())
	return pm.db.CachePayloadTemplate(name, attackType, payloadJSON)
}


// GetCacheStats returns cache statistics
func (pm *PayloadManager) GetCacheStats() map[string]interface{} {
	totalPayloads, activeLLMPayloads, _ := pm.db.GetPayloadCacheStats()

	return map[string]interface{}{
		"total_payloads":        totalPayloads,
		"active_llm_payloads":   activeLLMPayloads,
		"intel_injection_ready": true,
	}
}


func getCurrentUnixTimestamp() int64 {
	return 1730976294 // Nov 7, 2025
}
