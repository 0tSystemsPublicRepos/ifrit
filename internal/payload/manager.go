package payload

import (
	"database/sql"
	"encoding/json"
	"log"
	"regexp"
	"strings"
)

type PayloadManager struct {
	db *sql.DB
}

// NewPayloadManager creates a new payload manager instance
func NewPayloadManager(db *sql.DB) *PayloadManager {
	return &PayloadManager{db: db}
}

// PayloadTemplate represents a stored payload template
type PayloadTemplate struct {
	ID             int
	Name           string
	AttackType     string
	Classification string
	PayloadType    string
	Content        string
	ContentType    string
	HTTPStatusCode int
	Conditions     string
	Priority       int
	IsActive       bool
	CreatedBy      string
}

// PayloadResponse represents the response to send to attacker
type PayloadResponse struct {
	StatusCode  int
	Headers     map[string]string
	Body        string
	ContentType string
	DelayMS     int
}

// AttackerContext contains information about the current attack
type AttackerContext struct {
	SourceIP         string
	AttackType       string
	Classification   string
	Path             string
	TotalRequests    int
	PreviousHoneypot bool
	AttackerProfile  string // beginner, intermediate, advanced
	GeographicOrigin string
}

// GetPayloadForAttack selects the best payload for the given attack
func (pm *PayloadManager) GetPayloadForAttack(ctx AttackerContext) (*PayloadResponse, error) {
	// Try to get conditional payload first (highest priority)
	payload, err := pm.getConditionalPayload(ctx)
	if err == nil && payload != nil {
		return payload, nil
	}

	// Fall back to attack-type based payload
	payload, err = pm.getPayloadByAttackType(ctx.AttackType)
	if err == nil && payload != nil {
		return payload, nil
	}

	// Fall back to generic payload
	payload, err = pm.getGenericPayload()
	if err == nil && payload != nil {
		return payload, nil
	}

	log.Printf("Warning: No payload found for attack type %s", ctx.AttackType)
	return &PayloadResponse{
		StatusCode:  403,
		ContentType: "application/json",
		Body:        `{"error": "Forbidden"}`,
		Headers:     make(map[string]string),
	}, nil
}

// getConditionalPayload finds payload matching specific conditions
func (pm *PayloadManager) getConditionalPayload(ctx AttackerContext) (*PayloadResponse, error) {
	query := `
		SELECT id, name, content, content_type, http_status_code, payload_type
		FROM payload_templates
		WHERE is_active = 1 AND payload_type IN ('conditional', 'dynamic')
		ORDER BY priority DESC
		LIMIT 20
	`

	rows, err := pm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var name, content, contentType, payloadType string
		var statusCode int

		if err := rows.Scan(&id, &name, &content, &contentType, &statusCode, &payloadType); err != nil {
			log.Printf("Error scanning payload: %v", err)
			continue
		}

		// Get conditions for this payload
		conditions, err := pm.getPayloadConditions(id)
		if err != nil {
			continue
		}

		// Check if conditions match
		if pm.conditionsMatch(conditions, ctx) {
			return &PayloadResponse{
				StatusCode:  statusCode,
				ContentType: contentType,
				Body:        content,
				Headers:     make(map[string]string),
				DelayMS:     50, // Realistic response delay
			}, nil
		}
	}

	return nil, nil
}

// getPayloadByAttackType gets payload for specific attack type
func (pm *PayloadManager) getPayloadByAttackType(attackType string) (*PayloadResponse, error) {
	query := `
		SELECT content, content_type, http_status_code
		FROM payload_templates
		WHERE is_active = 1 
		AND attack_type = ?
		AND payload_type = 'fixed'
		ORDER BY priority DESC
		LIMIT 1
	`

	var content, contentType string
	var statusCode int

	err := pm.db.QueryRow(query, attackType).Scan(&content, &contentType, &statusCode)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &PayloadResponse{
		StatusCode:  statusCode,
		ContentType: contentType,
		Body:        content,
		Headers:     make(map[string]string),
		DelayMS:     50,
	}, nil
}

// getGenericPayload gets the default fallback payload
func (pm *PayloadManager) getGenericPayload() (*PayloadResponse, error) {
	query := `
		SELECT content, content_type, http_status_code
		FROM payload_templates
		WHERE is_active = 1 
		AND attack_type = 'unknown'
		LIMIT 1
	`

	var content, contentType string
	var statusCode int

	err := pm.db.QueryRow(query).Scan(&content, &contentType, &statusCode)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &PayloadResponse{
		StatusCode:  statusCode,
		ContentType: contentType,
		Body:        content,
		Headers:     make(map[string]string),
		DelayMS:     50,
	}, nil
}

// getPayloadConditions retrieves all conditions for a payload template
func (pm *PayloadManager) getPayloadConditions(payloadID int) ([]PayloadCondition, error) {
	query := `
		SELECT condition_type, condition_value, operator
		FROM payload_conditions
		WHERE payload_template_id = ?
	`

	rows, err := pm.db.Query(query, payloadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var conditions []PayloadCondition

	for rows.Next() {
		var conditionType, conditionValue, operator string

		if err := rows.Scan(&conditionType, &conditionValue, &operator); err != nil {
			continue
		}

		conditions = append(conditions, PayloadCondition{
			Type:     conditionType,
			Value:    conditionValue,
			Operator: operator,
		})
	}

	return conditions, nil
}

// conditionsMatch checks if all conditions match the attacker context
func (pm *PayloadManager) conditionsMatch(conditions []PayloadCondition, ctx AttackerContext) bool {
	if len(conditions) == 0 {
		return false
	}

	for _, cond := range conditions {
		if !pm.conditionMatches(cond, ctx) {
			return false
		}
	}

	return true
}

// conditionMatches checks if a single condition matches
func (pm *PayloadManager) conditionMatches(cond PayloadCondition, ctx AttackerContext) bool {
	switch cond.Type {
	case "source_ip":
		return pm.ipMatches(cond.Value, ctx.SourceIP)
	case "attacker_profile":
		return strings.EqualFold(cond.Value, ctx.AttackerProfile)
	case "attack_type":
		return strings.EqualFold(cond.Value, ctx.AttackType)
	case "geographic":
		return strings.EqualFold(cond.Value, ctx.GeographicOrigin)
	case "classification":
		return strings.EqualFold(cond.Value, ctx.Classification)
	default:
		return false
	}
}

// ipMatches checks if IP matches pattern (supports wildcards)
func (pm *PayloadManager) ipMatches(pattern, ip string) bool {
	// Convert wildcard pattern to regex
	// 192.168.* becomes 192\.168\..*
	regexPattern := strings.ReplaceAll(pattern, ".", "\\.")
	regexPattern = strings.ReplaceAll(regexPattern, "*", ".*")
	regexPattern = "^" + regexPattern + "$"

	matched, err := regexp.MatchString(regexPattern, ip)
	if err != nil {
		log.Printf("IP pattern error: %v", err)
		return false
	}

	return matched
}

// CreatePayload creates a new payload template
func (pm *PayloadManager) CreatePayload(template PayloadTemplate) (int, error) {
	query := `
		INSERT INTO payload_templates 
		(name, attack_type, classification, payload_type, content, content_type, http_status_code, priority, is_active, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := pm.db.Exec(query,
		template.Name,
		template.AttackType,
		template.Classification,
		template.PayloadType,
		template.Content,
		template.ContentType,
		template.HTTPStatusCode,
		template.Priority,
		template.IsActive,
		template.CreatedBy,
	)

	if err != nil {
		return 0, err
	}

	id, err := result.LastInsertId()
	return int(id), err
}

// GetPayload retrieves a specific payload by ID
func (pm *PayloadManager) GetPayload(id int) (*PayloadTemplate, error) {
	query := `
		SELECT id, name, attack_type, classification, payload_type, content, content_type, http_status_code, conditions, priority, is_active, created_by
		FROM payload_templates
		WHERE id = ?
	`

	var template PayloadTemplate
	var conditions sql.NullString

	err := pm.db.QueryRow(query, id).Scan(
		&template.ID,
		&template.Name,
		&template.AttackType,
		&template.Classification,
		&template.PayloadType,
		&template.Content,
		&template.ContentType,
		&template.HTTPStatusCode,
		&conditions,
		&template.Priority,
		&template.IsActive,
		&template.CreatedBy,
	)

	if err != nil {
		return nil, err
	}

	if conditions.Valid {
		template.Conditions = conditions.String
	}

	return &template, nil
}

// ListPayloads retrieves all active payloads
func (pm *PayloadManager) ListPayloads(attackType string) ([]PayloadTemplate, error) {
	query := `
		SELECT id, name, attack_type, classification, payload_type, content, content_type, http_status_code, priority, is_active, created_by
		FROM payload_templates
		WHERE is_active = 1
	`

	if attackType != "" {
		query += ` AND attack_type = ?`
	}

	query += ` ORDER BY priority DESC`

	var rows *sql.Rows
	var err error

	if attackType != "" {
		rows, err = pm.db.Query(query, attackType)
	} else {
		rows, err = pm.db.Query(query)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var payloads []PayloadTemplate

	for rows.Next() {
		var template PayloadTemplate

		err := rows.Scan(
			&template.ID,
			&template.Name,
			&template.AttackType,
			&template.Classification,
			&template.PayloadType,
			&template.Content,
			&template.ContentType,
			&template.HTTPStatusCode,
			&template.Priority,
			&template.IsActive,
			&template.CreatedBy,
		)

		if err != nil {
			continue
		}

		payloads = append(payloads, template)
	}

	return payloads, nil
}

// UpdatePayload updates an existing payload
func (pm *PayloadManager) UpdatePayload(id int, template PayloadTemplate) error {
	query := `
		UPDATE payload_templates
		SET name = ?, attack_type = ?, classification = ?, payload_type = ?, 
		    content = ?, content_type = ?, http_status_code = ?, priority = ?, is_active = ?,
		    updated_at = datetime('now')
		WHERE id = ?
	`

	_, err := pm.db.Exec(query,
		template.Name,
		template.AttackType,
		template.Classification,
		template.PayloadType,
		template.Content,
		template.ContentType,
		template.HTTPStatusCode,
		template.Priority,
		template.IsActive,
		id,
	)

	return err
}

// DeletePayload deletes a payload template
func (pm *PayloadManager) DeletePayload(id int) error {
	query := `DELETE FROM payload_templates WHERE id = ?`
	_, err := pm.db.Exec(query, id)
	return err
}

// PayloadCondition represents a single condition for payload matching
type PayloadCondition struct {
	Type     string
	Value    string
	Operator string
}

