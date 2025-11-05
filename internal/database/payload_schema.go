package database

// PayloadTemplate represents a configurable honeypot response
type PayloadTemplate struct {
	ID              int
	Name            string
	AttackType      string
	Classification  string
	PayloadType     string // fixed, conditional, dynamic
	Content         string
	ContentType     string
	HTTPStatusCode  int
	Conditions      string // JSON: {"ip": "192.168.1.*", "attacker_profile": "beginner"}
	Priority        int    // 1-100, higher = checked first
	IsActive        bool
	CreatedAt       string
	UpdatedAt       string
	CreatedBy       string
}

// PayloadCondition represents conditions for payload selection
type PayloadCondition struct {
	SourceIP          string   // Can use wildcards: 192.168.*
	AttackerProfile   string   // beginner, intermediate, advanced
	AttackTypes       []string // specific attack types
	GeographicOrigin  string   // country code
	MinimumRequests   int      // attacker must have made N requests
	ReturnAfterHoneypot bool   // if attacker returned after honeypot
}

// PayloadResponse represents the actual response to return
type PayloadResponse struct {
	StatusCode  int
	Headers     map[string]string
	Body        string
	ContentType string
	DelayMS     int // artificial delay to seem legitimate
}
