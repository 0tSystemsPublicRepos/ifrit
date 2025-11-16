package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/0tSystemsPublicRepos/ifrit/internal/anonymization"
	"github.com/0tSystemsPublicRepos/ifrit/internal/logging"
)

type GeminiProvider struct {
	apiKey         string
	model          string
	anonEngine     *anonymization.AnonymizationEngine
	intelTemplates []map[string]interface{}
}

type GeminiRequest struct {
	Contents []GeminiContent `json:"contents"`
}

type GeminiContent struct {
	Parts []GeminiPart `json:"parts"`
}

type GeminiPart struct {
	Text string `json:"text"`
}

type GeminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	UsageMetadata struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
	} `json:"usageMetadata"`
}

func NewGeminiProvider(apiKey, model string) *GeminiProvider {
	return &GeminiProvider{
		apiKey:         apiKey,
		model:          model,
		intelTemplates: []map[string]interface{}{},
	}
}

func (gp *GeminiProvider) GetName() string {
	return "gemini"
}

func (gp *GeminiProvider) SetAnonymizationEngine(engine *anonymization.AnonymizationEngine) {
	gp.anonEngine = engine
}

func (gp *GeminiProvider) SetIntelTemplates(templates []map[string]interface{}) {
	gp.intelTemplates = templates
}

func (gp *GeminiProvider) AnalyzeRequest(requestData map[string]string) (*AnalysisResult, error) {
	prompt := fmt.Sprintf(`You are a security threat detection AI. Analyze this HTTP request and determine if it's malicious.

Method: %s
Path: %s
Query: %s
Headers: %s
Body: %s

Respond ONLY with a valid JSON object in this exact format:
{
  "is_attack": boolean,
  "attack_type": "string or null",
  "classification": "string or null",
  "confidence": number (0-1),
  "reason": "string"
}

Do NOT include any text outside the JSON object. Your entire response MUST be a single, valid JSON object.
Be strict. Return true only for clear attacks.`,
		requestData["method"],
		requestData["path"],
		requestData["query"],
		requestData["headers"],
		requestData["body"],
	)

	geminiReq := GeminiRequest{
		Contents: []GeminiContent{
			{
				Parts: []GeminiPart{
					{
						Text: prompt,
					},
				},
			},
		},
	}

	reqBody, _ := json.Marshal(geminiReq)
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", gp.model, gp.apiKey)

	logging.Debug("[GEMINI] Making request to: %s (model: %s)", url, gp.model)

	httpReq, _ := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		logging.Error("[GEMINI] HTTP error: %v", err)
		return nil, fmt.Errorf("failed to call Gemini API: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	logging.Debug("[GEMINI] HTTP Status: %d", resp.StatusCode)
	logging.Debug("[GEMINI] Raw response body: %s", string(body))

	var geminiResp GeminiResponse
	if err := json.Unmarshal(body, &geminiResp); err != nil {
		logging.Error("[GEMINI] Failed to parse Gemini response: %v", err)
		return nil, err
	}

	// Add detailed logging
	logging.Debug("[GEMINI] Response candidates count: %d", len(geminiResp.Candidates))
	if len(geminiResp.Candidates) > 0 {
		logging.Debug("[GEMINI] First candidate content parts: %d", len(geminiResp.Candidates[0].Content.Parts))
		if len(geminiResp.Candidates[0].Content.Parts) > 0 {
			logging.Debug("[GEMINI] First part text length: %d", len(geminiResp.Candidates[0].Content.Parts[0].Text))
		}
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		logging.Error("[GEMINI] Empty response - candidates=%d", len(geminiResp.Candidates))
		logging.Debug("[GEMINI] Full response object: %+v", geminiResp)
		return nil, fmt.Errorf("empty response from Gemini")
	}

	// Get the text response
	responseText := geminiResp.Candidates[0].Content.Parts[0].Text

	// Strip markdown code blocks (```json ... ```)
	responseText = strings.TrimPrefix(responseText, "```json\n")
	responseText = strings.TrimPrefix(responseText, "```json")
	responseText = strings.TrimSuffix(responseText, "\n```")
	responseText = strings.TrimSuffix(responseText, "```")
	responseText = strings.TrimSpace(responseText)

	logging.Debug("[GEMINI] Raw response (after markdown strip): %s", responseText)

	// Parse the JSON response
	var result AnalysisResult
	if err := json.Unmarshal([]byte(responseText), &result); err != nil {
		logging.Error("[GEMINI] Failed to parse JSON analysis: %v. Raw: %s", err, responseText)
		return nil, err
	}

	result.TokensUsed = geminiResp.UsageMetadata.PromptTokenCount + geminiResp.UsageMetadata.CandidatesTokenCount

	logging.Info("[GEMINI] Analysis complete - is_attack=%v, attack_type=%s, confidence=%.2f", result.IsAttack, result.AttackType, result.Confidence)

	return &result, nil
}

func (gp *GeminiProvider) GeneratePayload(attackType string) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"status":    "success",
		"message":   "Request processed",
		"data":      map[string]interface{}{},
		"timestamp": getCurrentTimestamp(),
	}

	// Add attack-specific responses
	switch attackType {
	case "sql_injection":
		payload = map[string]interface{}{
			"error": "Invalid query",
			"code":  1064,
		}
	case "xss":
		payload = map[string]interface{}{
			"error":   "Invalid input",
			"message": "XSS prevention enabled",
		}
	case "path_traversal":
		payload = map[string]interface{}{
			"error":   "Access denied",
			"message": "Path traversal detected",
		}
	case "reconnaissance":
		payload = map[string]interface{}{
			"error": "Not found",
		}
	}

	return payload, nil
}

// GeneratePayloadWithIntel creates payload with intel collection tracking
func (gp *GeminiProvider) GeneratePayloadWithIntel(attackType string, intelTemplateID int) (map[string]interface{}, error) {
	// Get base payload
	basePayload, err := gp.GeneratePayload(attackType)
	if err != nil {
		return nil, err
	}

	// If no intel templates configured, return base payload
	if len(gp.intelTemplates) == 0 {
		return basePayload, nil
	}

	// Find the intel template to inject
	var selectedTemplate map[string]interface{}
	if intelTemplateID > 0 && intelTemplateID <= len(gp.intelTemplates) {
		selectedTemplate = gp.intelTemplates[intelTemplateID-1]
	} else if len(gp.intelTemplates) > 0 {
		selectedTemplate = gp.intelTemplates[0]
	}

	if selectedTemplate == nil {
		return basePayload, nil
	}

	// Create enhanced payload with intel collection
	enhancedPayload := map[string]interface{}{
		"status":  "ok",
		"message": "Request processed successfully",
		"data":    basePayload,
		"meta": map[string]interface{}{
			"timestamp": getCurrentTimestamp(),
			"intel_id":  intelTemplateID,
		},
	}

	// For HTML/JavaScript responses, inject tracking
	if templateType, ok := selectedTemplate["template_type"].(string); ok && templateType == "javascript" {
		if content, ok := selectedTemplate["content"].(string); ok {
			enhancedPayload["_tracking"] = content
			logging.Info("[INTEL] Injected JavaScript tracking into payload for attack type: %s", attackType)
		}
	}

	return enhancedPayload, nil
}
