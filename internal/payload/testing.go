package payload

import (
	"encoding/json"
	"log"
	"time"
)

// TestPayload validates a payload before saving
func (pm *PayloadManager) TestPayload(template PayloadTemplate) (bool, []string) {
	var errors []string

	// Validate required fields
	if template.Name == "" {
		errors = append(errors, "Payload name is required")
	}

	if template.AttackType == "" {
		errors = append(errors, "Attack type is required")
	}

	if template.Content == "" {
		errors = append(errors, "Payload content is required")
	}

	if template.HTTPStatusCode < 100 || template.HTTPStatusCode > 599 {
		errors = append(errors, "HTTP status code must be between 100 and 599")
	}

	if template.Priority < 1 || template.Priority > 100 {
		errors = append(errors, "Priority must be between 1 and 100")
	}

	// Validate payload type
	validTypes := map[string]bool{"fixed": true, "conditional": true, "dynamic": true}
	if !validTypes[template.PayloadType] {
		errors = append(errors, "Payload type must be 'fixed', 'conditional', or 'dynamic'")
	}

	// Validate content type
	validContentTypes := map[string]bool{
		"application/json":       true,
		"text/plain":             true,
		"text/html":              true,
		"application/xml":        true,
		"text/xml":               true,
		"application/javascript": true,
	}
	if !validContentTypes[template.ContentType] {
		errors = append(errors, "Content type not in approved list")
	}

	return len(errors) == 0, errors
}

// TestPayloadDelivery simulates payload delivery and validates response
func (pm *PayloadManager) TestPayloadDelivery(ctx AttackerContext) (bool, string) {
	start := time.Now()

	payload, err := pm.GetPayloadForAttack(ctx)
	if err != nil {
		return false, "Error retrieving payload: " + err.Error()
	}

	elapsed := time.Since(start)

	// Validate response
	if payload == nil {
		return false, "No payload returned"
	}

	if payload.StatusCode < 100 || payload.StatusCode > 599 {
		return false, "Invalid HTTP status code"
	}

	if payload.Body == "" {
		return false, "Payload body is empty"
	}

	if payload.ContentType == "" {
		return false, "Content type not set"
	}

	// Check response time (should be fast)
	if elapsed > 500*time.Millisecond {
		log.Printf("Warning: Slow payload delivery: %v", elapsed)
	}

	return true, "Payload test successful (" + elapsed.String() + ")"
}

// ValidatePayloadContent checks if payload content is safe
func (pm *PayloadManager) ValidatePayloadContent(content, contentType string) (bool, []string) {
	var errors []string

	// Check for suspicious patterns that might leak real data
	suspiciousPatterns := []string{
		"127.0.0.1",   // localhost
		"localhost",   // localhost
		"/etc/shadow", // real file
		"/var/log",    // real path
		"root:",       // real user
	}

	for _, pattern := range suspiciousPatterns {
		if content == pattern {
			errors = append(errors, "Payload contains suspicious pattern: "+pattern)
		}
	}

	// Validate JSON if content type is JSON
	if contentType == "application/json" {
		var obj interface{}
		if err := json.Unmarshal([]byte(content), &obj); err != nil {
			errors = append(errors, "Invalid JSON in payload: "+err.Error())
		}
	}

	return len(errors) == 0, errors
}

