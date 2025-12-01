package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
	"github.com/0tSystemsPublicRepos/ifrit/internal/logging"
)


type WebhookProvider struct {
	config *config.WebhooksConfig
	db     database.DatabaseProvider
	client *http.Client
}


func NewWebhookProvider(cfg *config.WebhooksConfig, db database.DatabaseProvider) *WebhookProvider {
	return &WebhookProvider{
		config: cfg,
		db:     db,
		client: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
		},
	}
}


// SetDatabase sets the database provider for the webhook provider
func (wp *WebhookProvider) SetDatabase(db database.DatabaseProvider) {
	wp.db = db
}

func (wp *WebhookProvider) Name() string {
	return "webhook"
}

func (wp *WebhookProvider) IsEnabled() bool {
	return wp.config.Enabled
}

// Send fires webhook to configured endpoints
func (wp *WebhookProvider) Send(notification *Notification) error {
	if !wp.IsEnabled() {
		return nil
	}

	// Build webhook payload
	payload := wp.buildWebhookPayload(notification)

	// Get all active webhooks for this app
	webhooks, err := wp.getActiveWebhooks(notification.AppID)
	if err != nil {
		logging.Error("[WEBHOOK] Error fetching webhooks: %v", err)
		return err
	}

	if len(webhooks) == 0 {
		logging.Info("[WEBHOOK] No active webhooks configured for app_id: %s", notification.AppID)
		return nil
	}

	// Fire each webhook
	for _, webhook := range webhooks {
		go wp.fireWebhook(webhook, payload, notification)
	}

	return nil
}

// fireWebhook sends webhook with retry logic
func (wp *WebhookProvider) fireWebhook(webhook map[string]interface{}, payload *WebhookPayload, notification *Notification) {
	webhookID := int64(webhook["id"].(int64))
	endpoint := webhook["endpoint"].(string)
	authType := webhook["auth_type"].(string)
	authValue := webhook["auth_value"].(string)

	payloadJSON, _ := json.Marshal(payload)

	var lastErr error
	for attempt := 1; attempt <= wp.config.RetryCount; attempt++ {
		err := wp.sendWebhookRequest(endpoint, authType, authValue, payloadJSON)
		if err == nil {
			logging.Info("[WEBHOOK] ✓ Webhook %d fired successfully to %s (threat: %s/%d)", webhookID, endpoint, notification.ThreatLevel, notification.RiskScore)
			wp.recordWebhookFire(webhookID, "success", "")
			return
		}

		lastErr = err
		logging.Error("[WEBHOOK] Attempt %d/%d failed for webhook %d: %v", attempt, wp.config.RetryCount, webhookID, err)

		if attempt < wp.config.RetryCount {
			time.Sleep(time.Duration(wp.config.RetryDelaySeconds) * time.Second)
		}
	}

	logging.Error("[WEBHOOK] ✗ Webhook %d failed after %d attempts: %v", webhookID, wp.config.RetryCount, lastErr)
	wp.recordWebhookFire(webhookID, "failed", lastErr.Error())
}

// sendWebhookRequest makes HTTP request to webhook endpoint
func (wp *WebhookProvider) sendWebhookRequest(endpoint, authType, authValue string, payload []byte) error {
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "IFRIT-Webhook/1.0")

	// Add authentication if configured
	if authType == "bearer" && authValue != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authValue))
	} else if authType == "apikey" && authValue != "" {
		req.Header.Set("X-API-Key", authValue)
	} else if authType == "basic" && authValue != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", authValue))
	}

	resp, err := wp.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// buildWebhookPayload constructs the webhook payload
func (wp *WebhookProvider) buildWebhookPayload(notification *Notification) *WebhookPayload {
	payload := &WebhookPayload{
		Event:       "threat_detected",
		Timestamp:   notification.Timestamp,
		AppID:       notification.AppID,
		ThreatLevel: notification.ThreatLevel,
		RiskScore:   notification.RiskScore,
		SourceIP:    notification.SourceIP,
		Country:     notification.Country,
		AttackType:  notification.AttackType,
		Path:        notification.Path,
		Method:      notification.Method,
	}

	// Add AbuseIPDB data
	if notification.AbuseIPDBScore > 0 || notification.AbuseIPDBReports > 0 {
		payload.AbuseIPDB = map[string]interface{}{
			"confidence_score": notification.AbuseIPDBScore,
			"reports":          notification.AbuseIPDBReports,
		}
	}

	// Add VirusTotal data
	if notification.VirusTotalMalicious > 0 || notification.VirusTotalSuspicious > 0 {
		payload.VirusTotal = map[string]interface{}{
			"malicious":  notification.VirusTotalMalicious,
			"suspicious": notification.VirusTotalSuspicious,
		}
	}

	return payload
}

// getActiveWebhooks retrieves all active webhooks for an app
func (wp *WebhookProvider) getActiveWebhooks(appID string) ([]map[string]interface{}, error) {
	webhooks, err := wp.db.GetActiveWebhooks(appID)
	if err != nil {
		logging.Error("[WEBHOOK] Error fetching webhooks: %v", err)
		return nil, err
	}
	
	if len(webhooks) == 0 {
		logging.Debug("[WEBHOOK] No active webhooks found for app_id: %s", appID)
	} else {
		logging.Info("[WEBHOOK] Found %d active webhook(s) for app_id: %s", len(webhooks), appID)
	}
	
	return webhooks, nil
}

// recordWebhookFire logs webhook fire attempt
func (wp *WebhookProvider) recordWebhookFire(webhookID int64, status, errorMsg string) {
	// This could be extended to store webhook fire history in database
	// For now, just log it
	if status == "success" {
		logging.Info("[WEBHOOK] Fire recorded: webhook_id=%d status=success", webhookID)
	} else {
		logging.Error("[WEBHOOK] Fire recorded: webhook_id=%d status=failed error=%s", webhookID, errorMsg)
	}
}
