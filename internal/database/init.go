package database

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

// InitializeDatabase creates tables and runs migrations
func InitializeDatabase(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, err
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, err
	}

	// Create tables
	if err := createTables(db); err != nil {
		return nil, err
	}

	// Run migrations (including seed data)
	if err := RunMigrations(db); err != nil {
		log.Printf("Warning: Migrations failed: %v", err)
		// Don't fail on migration errors
	}

	log.Println("Database initialized successfully")
	return db, nil
}

// createTables creates all required database tables
func createTables(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS attack_patterns (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		attack_signature TEXT UNIQUE,
		attack_type TEXT NOT NULL,
		attack_classification TEXT,
		http_method TEXT,
		path_pattern TEXT,
		payload_template TEXT,
		response_code INTEGER,
		times_seen INTEGER DEFAULT 0,
		first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		created_by TEXT,
		claude_confidence REAL
	);

	CREATE TABLE IF NOT EXISTS attack_instances (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		pattern_id INTEGER,
		source_ip TEXT,
		user_agent TEXT,
		requested_path TEXT,
		http_method TEXT,
		returned_honeypot BOOLEAN,
		attacker_accepted BOOLEAN,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(pattern_id) REFERENCES attack_patterns(id)
	);

	CREATE TABLE IF NOT EXISTS attacker_profiles (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		source_ip TEXT UNIQUE,
		total_requests INTEGER DEFAULT 0,
		successful_probes INTEGER DEFAULT 0,
		attack_types TEXT,
		first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS exceptions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip_address TEXT,
		path TEXT,
		reason TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		enabled BOOLEAN DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS llm_api_calls (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_fingerprint TEXT,
		llm_provider TEXT,
		was_attack BOOLEAN,
		attack_type TEXT,
		confidence REAL,
		tokens_used INTEGER,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS anonymization_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		attack_instance_id INTEGER,
		field_type TEXT,
		field_name TEXT,
		redaction_action TEXT,
		original_length INTEGER,
		redacted_value TEXT,
		token_mapping TEXT,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(attack_instance_id) REFERENCES attack_instances(id)
	);

	CREATE INDEX IF NOT EXISTS idx_attack_instances_source_ip ON attack_instances(source_ip);
	CREATE INDEX IF NOT EXISTS idx_attack_instances_pattern_id ON attack_instances(pattern_id);
	CREATE INDEX IF NOT EXISTS idx_attack_patterns_type ON attack_patterns(attack_type);
	CREATE INDEX IF NOT EXISTS idx_attacker_profiles_ip ON attacker_profiles(source_ip);
	`

	_, err := db.Exec(schema)
	return err
}
