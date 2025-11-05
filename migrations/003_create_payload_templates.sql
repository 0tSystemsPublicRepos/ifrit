-- Create payload templates table for honeypot responses
CREATE TABLE IF NOT EXISTS payload_templates (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	attack_type TEXT NOT NULL,
	classification TEXT,
	payload_type TEXT NOT NULL, -- 'fixed', 'conditional', 'dynamic'
	content TEXT NOT NULL,
	content_type TEXT DEFAULT 'application/json',
	http_status_code INTEGER DEFAULT 200,
	conditions TEXT, -- JSON object with matching conditions
	priority INTEGER DEFAULT 50, -- 1-100, higher checked first
	is_active BOOLEAN DEFAULT 1,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	created_by TEXT DEFAULT 'system'
);

-- Create payload conditions table for complex matching
CREATE TABLE IF NOT EXISTS payload_conditions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	payload_template_id INTEGER NOT NULL,
	condition_type TEXT NOT NULL, -- 'source_ip', 'attacker_profile', 'attack_type', 'geographic'
	condition_value TEXT NOT NULL,
	operator TEXT DEFAULT '=', -- '=', 'LIKE', 'IN', '>', '<'
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY(payload_template_id) REFERENCES payload_templates(id) ON DELETE CASCADE
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_payload_templates_attack_type ON payload_templates(attack_type);
CREATE INDEX IF NOT EXISTS idx_payload_templates_active ON payload_templates(is_active);
CREATE INDEX IF NOT EXISTS idx_payload_templates_priority ON payload_templates(priority DESC);
CREATE INDEX IF NOT EXISTS idx_payload_conditions_template ON payload_conditions(payload_template_id);

-- Seed default payloads for common attack types

-- .env file probe
INSERT OR IGNORE INTO payload_templates (name, attack_type, classification, payload_type, content, content_type, http_status_code, priority, created_by)
VALUES (
	'env_probe_fake_credentials',
	'reconnaissance',
	'env_probe',
	'fixed',
	'DATABASE_URL=postgres://user:password@db.internal:5432/app
API_KEY=sk-1234567890abcdefghijklmnop
JWT_SECRET=super-secret-jwt-key-12345
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ADMIN_PASSWORD=P@ssw0rd123!
DATABASE_PASSWORD=db_password_here',
	'text/plain',
	200,
	95,
	'seed'
);

-- SQL injection honeypot response
INSERT OR IGNORE INTO payload_templates (name, attack_type, classification, payload_type, content, content_type, http_status_code, priority, created_by)
VALUES (
	'sql_injection_fake_data',
	'sql_injection',
	'sqli_attempt',
	'fixed',
	'[
  {"id": 1, "username": "admin", "email": "admin@example.com", "role": "administrator", "created_at": "2023-01-15"},
  {"id": 2, "username": "user", "email": "user@example.com", "role": "user", "created_at": "2023-02-20"},
  {"id": 3, "username": "guest", "email": "guest@example.com", "role": "guest", "created_at": "2023-03-10"}
]',
	'application/json',
	200,
	95,
	'seed'
);

-- XSS payload response
INSERT OR IGNORE INTO payload_templates (name, attack_type, classification, payload_type, content, content_type, http_status_code, priority, created_by)
VALUES (
	'xss_safe_response',
	'xss',
	'xss_attempt',
	'fixed',
	'{"status": "success", "message": "Request processed", "data": {}}',
	'application/json',
	200,
	95,
	'seed'
);

-- Path traversal response
INSERT OR IGNORE INTO payload_templates (name, attack_type, classification, payload_type, content, content_type, http_status_code, priority, created_by)
VALUES (
	'path_traversal_fake_etc_passwd',
	'path_traversal',
	'lfi_attempt',
	'fixed',
	'root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin',
	'text/plain',
	200,
	95,
	'seed'
);

-- Admin panel fake login
INSERT OR IGNORE INTO payload_templates (name, attack_type, classification, payload_type, content, content_type, http_status_code, priority, created_by)
VALUES (
	'admin_panel_redirect',
	'reconnaissance',
	'directory_enumeration',
	'fixed',
	'<html><head><title>Redirecting...</title><meta http-equiv="refresh" content="0;url=/login"></head><body>Redirecting to login...</body></html>',
	'text/html',
	302,
	90,
	'seed'
);

-- WordPress xmlrpc fake response
INSERT OR IGNORE INTO payload_templates (name, attack_type, classification, payload_type, content, content_type, http_status_code, priority, created_by)
VALUES (
	'wordpress_xmlrpc_error',
	'reconnaissance',
	'cms_probe',
	'fixed',
	'<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><i4>405</i4></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>XML-RPC server accepts POST requests only.</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>',
	'application/xml',
	405,
	90,
	'seed'
);

-- Command injection response
INSERT OR IGNORE INTO payload_templates (name, attack_type, classification, payload_type, content, content_type, http_status_code, priority, created_by)
VALUES (
	'command_injection_fake_output',
	'command_injection',
	'rce_attempt',
	'fixed',
	'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
	'text/plain',
	200,
	95,
	'seed'
);

-- Generic 403 Forbidden
INSERT OR IGNORE INTO payload_templates (name, attack_type, classification, payload_type, content, content_type, http_status_code, priority, created_by)
VALUES (
	'generic_forbidden',
	'unknown',
	'generic',
	'fixed',
	'{"error": "Forbidden", "message": "Access denied", "code": 403}',
	'application/json',
	403,
	1,
	'seed'
);

