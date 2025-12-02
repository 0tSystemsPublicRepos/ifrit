-- Migration 006: Enhanced Pattern Matching
-- Adds support for different pattern types (exact, prefix, regex, contains)
-- and separate patterns for headers, body, and query parameters

-- Add new columns to attack_patterns table
ALTER TABLE attack_patterns ADD COLUMN header_pattern TEXT;
ALTER TABLE attack_patterns ADD COLUMN body_pattern TEXT;
ALTER TABLE attack_patterns ADD COLUMN query_pattern TEXT;
ALTER TABLE attack_patterns ADD COLUMN pattern_type TEXT DEFAULT 'exact';
ALTER TABLE attack_patterns ADD COLUMN full_request_pattern TEXT;

-- Update existing patterns to use 'prefix' type for path patterns
-- (paths that look like directories should use prefix matching)
UPDATE attack_patterns 
SET pattern_type = 'prefix' 
WHERE path_pattern LIKE '%/%' 
  AND path_pattern NOT LIKE '%?%'
  AND path_pattern NOT LIKE '%*%'
  AND length(path_pattern) > 1;

-- Update /api pattern to be exact match only
UPDATE attack_patterns 
SET pattern_type = 'exact'
WHERE path_pattern = '/api';

-- Update /api/admin patterns to be prefix match
UPDATE attack_patterns 
SET pattern_type = 'prefix'
WHERE path_pattern LIKE '/api/admin%';

-- Create indexes for new columns (improves query performance)
CREATE INDEX IF NOT EXISTS idx_pattern_type ON attack_patterns(pattern_type);
CREATE INDEX IF NOT EXISTS idx_header_pattern ON attack_patterns(header_pattern) WHERE header_pattern IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_body_pattern ON attack_patterns(body_pattern) WHERE body_pattern IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_query_pattern ON attack_patterns(query_pattern) WHERE query_pattern IS NOT NULL;
