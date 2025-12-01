package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"

	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
)

var (
	dbProvider database.DatabaseProvider
	db         *sql.DB
	configPath string
)

func initDB() {
	var err error

	// Default to SQLite, check if config specifies PostgreSQL
	configPath = "./config/default.json"
	
	// Try to read config file
	configData, err := os.ReadFile(configPath)
	if err == nil {
		// Parse config to check database type
		var cfg struct {
			Database struct {
				Type     string `json:"type"`
				Path     string `json:"path"`
				Host     string `json:"host"`
				Port     int    `json:"port"`
				User     string `json:"user"`
				Password string `json:"password"`
				DBName   string `json:"dbname"`
			} `json:"database"`
		}
		
	if err := json.Unmarshal(configData, &cfg); err == nil {
			if cfg.Database.Type == "postgres" {
				// Initialize PostgreSQL
				pgConfig := &database.PostgresConfig{
					Host:     cfg.Database.Host,
					Port:     cfg.Database.Port,
					User:     cfg.Database.User,
					Password: cfg.Database.Password,
					Database: cfg.Database.DBName,
				}
				dbProvider, err = database.NewPostgresProvider(pgConfig)
				if err != nil {
					fmt.Printf("Error connecting to PostgreSQL: %v\n", err)
					os.Exit(1)
				}
				db = dbProvider.GetDB()
				return
			}
		}
	}
	
	// Default to SQLite
	sqliteConfig := &database.SQLiteConfig{
		Path: "./data/ifrit.db",
	}
	dbProvider, err = database.NewSQLiteProvider(sqliteConfig)
	if err != nil {
		fmt.Printf("Error opening SQLite database: %v\n", err)
		os.Exit(1)
	}
	db = dbProvider.GetDB()	
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "ifrit-cli",
		Short: "IFRIT CLI - Complete Database Management",
		Long: `IFRIT CLI manages all IFRIT Proxy database entities.
Manage attacks, patterns, attackers, exceptions, keyword exceptions, intel templates, and more.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			initDB()
		},
	}

	// Attack commands
	attackCmd := &cobra.Command{
		Use:   "attack",
		Short: "Manage attack instances",
	}
	attackCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List recent attacks", Run: listAttacks},
		&cobra.Command{Use: "view [id]", Short: "View attack details", Args: cobra.ExactArgs(1), Run: viewAttack},
		&cobra.Command{Use: "stats", Short: "Show attack statistics", Run: attackStats},
		&cobra.Command{Use: "by-ip [ip]", Short: "Attacks from IP", Args: cobra.ExactArgs(1), Run: attacksByIP},
		&cobra.Command{Use: "by-path [path]", Short: "Attacks on path", Args: cobra.ExactArgs(1), Run: attacksByPath},
	)

	// Pattern commands
	patternCmd := &cobra.Command{
		Use:   "pattern",
		Short: "Manage attack patterns",
	}
	patternCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all patterns", Run: listPatterns},
		&cobra.Command{Use: "view [id]", Short: "View pattern details", Args: cobra.ExactArgs(1), Run: viewPattern},
		&cobra.Command{Use: "add [type] [signature]", Short: "Add new pattern", Args: cobra.MinimumNArgs(2), Run: addPattern},
		&cobra.Command{Use: "remove [id]", Short: "Remove pattern", Args: cobra.ExactArgs(1), Run: removePattern},
	)

	// Attacker commands
	attackerCmd := &cobra.Command{
		Use:   "attacker",
		Short: "Manage attacker profiles",
	}
	attackerCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all attackers", Run: listAttackers},
		&cobra.Command{Use: "view [id]", Short: "View attacker details", Args: cobra.ExactArgs(1), Run: viewAttacker},
		&cobra.Command{Use: "search [ip]", Short: "Search attacker by IP", Args: cobra.ExactArgs(1), Run: searchAttacker},
		&cobra.Command{Use: "remove [id]", Short: "Remove attacker profile", Args: cobra.ExactArgs(1), Run: removeAttacker},
	)

	// Exception commands
	exceptionCmd := &cobra.Command{
		Use:   "exception",
		Short: "Manage exceptions (whitelists)",
	}
	exceptionCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all exceptions", Run: listExceptions},
		&cobra.Command{Use: "view [id]", Short: "View exception details", Args: cobra.ExactArgs(1), Run: viewException},
		&cobra.Command{Use: "add [ip] [path]", Short: "Add exception (use - for any)", Args: cobra.ExactArgs(2), Run: addException},
		&cobra.Command{Use: "remove [id]", Short: "Remove exception", Args: cobra.ExactArgs(1), Run: removeException},
		&cobra.Command{Use: "enable [id]", Short: "Enable exception", Args: cobra.ExactArgs(1), Run: enableException},
		&cobra.Command{Use: "disable [id]", Short: "Disable exception", Args: cobra.ExactArgs(1), Run: disableException},
	)

	// Keyword Exception commands
	keywordCmd := &cobra.Command{
		Use:   "keyword",
		Short: "Manage keyword exceptions",
	}
	keywordCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all keyword exceptions", Run: listKeywordExceptions},
		&cobra.Command{Use: "view [id]", Short: "View keyword exception details", Args: cobra.ExactArgs(1), Run: viewKeywordException},
		&cobra.Command{Use: "add [type] [keyword]", Short: "Add keyword exception (path|body_field|header)", Args: cobra.ExactArgs(2), Run: addKeywordException},
		&cobra.Command{Use: "remove [id]", Short: "Remove keyword exception", Args: cobra.ExactArgs(1), Run: removeKeywordException},
	)

	// Intel Template commands
	intelCmd := &cobra.Command{
		Use:   "intel",
		Short: "Manage intel collection templates",
	}
	intelCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all intel templates", Run: listIntelTemplates},
		&cobra.Command{Use: "view [id]", Short: "View intel template details", Args: cobra.ExactArgs(1), Run: viewIntelTemplate},
		&cobra.Command{Use: "toggle [id]", Short: "Toggle intel template active status", Args: cobra.ExactArgs(1), Run: toggleIntelTemplate},
	)

	// Payload Template commands
	payloadCmd := &cobra.Command{
		Use:   "payload",
		Short: "Manage payload templates",
	}
	payloadCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all payload templates", Run: listPayloads},
		&cobra.Command{Use: "view [id]", Short: "View payload template details", Args: cobra.ExactArgs(1), Run: viewPayload},
		&cobra.Command{Use: "stats", Short: "Payload statistics", Run: payloadStats},
	)

	// Legitimate requests commands
	legitimateCmd := &cobra.Command{
		Use:   "legitimate",
		Short: "Query legitimate requests cache",
	}
	legitimateCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List cached legitimate requests", Run: listLegitimate},
		&cobra.Command{Use: "stats", Short: "Cache statistics", Run: legitimateStats},
	)

	// Attacker interactions commands
	interactionCmd := &cobra.Command{
		Use:   "interaction",
		Short: "Query attacker interactions",
	}
	interactionCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List recent interactions", Run: listInteractions},
		&cobra.Command{Use: "by-ip [ip]", Short: "Interactions from IP", Args: cobra.ExactArgs(1), Run: interactionsByIP},
	)

	// Threat Intelligence commands
	threatCmd := &cobra.Command{
		Use:   "threat",
		Short: "Query threat intelligence data",
	}
	threatCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all enriched threats", Run: listThreats},
		&cobra.Command{Use: "view [ip]", Short: "View threat details for IP", Args: cobra.ExactArgs(1), Run: viewThreat},
		&cobra.Command{Use: "top [limit]", Short: "Top threats by risk score", Args: cobra.MaximumNArgs(1), Run: topThreats},
		&cobra.Command{Use: "stats", Short: "Threat intelligence statistics", Run: threatStats},
	)

	// Database commands
	dbCmd := &cobra.Command{
		Use:   "db",
		Short: "Database operations",
	}
	dbCmd.AddCommand(
		&cobra.Command{Use: "stats", Short: "Database statistics", Run: dbStats},
		&cobra.Command{Use: "schema", Short: "Show database schema", Run: showSchema},
	)

	// API Token commands
	tokenCmd := &cobra.Command{
		Use:   "token",
		Short: "Manage API tokens",
	}
	tokenCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all API tokens", Run: listTokens},
		&cobra.Command{Use: "create [user_id] [token_name]", Short: "Create new API token", Args: cobra.ExactArgs(2), Run: createToken},
		&cobra.Command{Use: "revoke [id]", Short: "Revoke API token", Args: cobra.ExactArgs(1), Run: revokeToken},
		&cobra.Command{Use: "validate [token]", Short: "Validate API token", Args: cobra.ExactArgs(1), Run: validateToken},
	)

	rootCmd.AddCommand(attackCmd, patternCmd, attackerCmd, exceptionCmd, keywordCmd, intelCmd, payloadCmd, legitimateCmd, interactionCmd, threatCmd, dbCmd, tokenCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// ==========================
// Attack Instance Commands
// ==========================

func listAttacks(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, source_ip, requested_path, http_method, timestamp 
		FROM attack_instances 
		ORDER BY timestamp DESC 
		LIMIT 20
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tIP\tPATH\tMETHOD\tTIME")
	for rows.Next() {
		var id int
		var ip, path, method, timestamp string
		rows.Scan(&id, &ip, &path, &method, &timestamp)
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", id, ip, path, method, timestamp)
	}
	w.Flush()
}

func viewAttack(cmd *cobra.Command, args []string) {
	var id, ip, path, method, timestamp, userAgent string
	var patternID sql.NullInt64
	var returnedHoneypot, attackerAccepted bool

	db.QueryRow(`
		SELECT id, source_ip, user_agent, requested_path, http_method, 
		       pattern_id, returned_honeypot, attacker_accepted, timestamp
		FROM attack_instances WHERE id = ?
	`, args[0]).Scan(&id, &ip, &userAgent, &path, &method, &patternID, &returnedHoneypot, &attackerAccepted, &timestamp)

	fmt.Printf("Attack ID: %s\n", id)
	fmt.Printf("Source IP: %s\n", ip)
	fmt.Printf("User Agent: %s\n", userAgent)
	fmt.Printf("Path: %s\n", path)
	fmt.Printf("Method: %s\n", method)
	if patternID.Valid {
		fmt.Printf("Pattern ID: %d\n", patternID.Int64)
	} else {
		fmt.Printf("Pattern ID: None\n")
	}
	fmt.Printf("Returned Honeypot: %v\n", returnedHoneypot)
	fmt.Printf("Attacker Accepted: %v\n", attackerAccepted)
	fmt.Printf("Timestamp: %s\n", timestamp)
}

func attackStats(cmd *cobra.Command, args []string) {
	var total, honeypot, accepted int
	db.QueryRow("SELECT COUNT(*) FROM attack_instances").Scan(&total)
	db.QueryRow("SELECT COUNT(*) FROM attack_instances WHERE returned_honeypot = 1").Scan(&honeypot)
	db.QueryRow("SELECT COUNT(*) FROM attack_instances WHERE attacker_accepted = 1").Scan(&accepted)

	fmt.Printf("Total Attacks: %d\n", total)
	fmt.Printf("Honeypot Delivered: %d (%.1f%%)\n", honeypot, float64(honeypot)/float64(total)*100)
	fmt.Printf("Attacker Accepted: %d (%.1f%%)\n", accepted, float64(accepted)/float64(total)*100)
}

func attacksByIP(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, requested_path, http_method, timestamp 
		FROM attack_instances 
		WHERE source_ip = ? 
		ORDER BY timestamp DESC
	`, args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tPATH\tMETHOD\tTIME")
	for rows.Next() {
		var id int
		var path, method, timestamp string
		rows.Scan(&id, &path, &method, &timestamp)
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", id, path, method, timestamp)
	}
	w.Flush()
}

func attacksByPath(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, source_ip, http_method, timestamp 
		FROM attack_instances 
		WHERE requested_path = ? 
		ORDER BY timestamp DESC
	`, args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tIP\tMETHOD\tTIME")
	for rows.Next() {
		var id int
		var ip, method, timestamp string
		rows.Scan(&id, &ip, &method, &timestamp)
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", id, ip, method, timestamp)
	}
	w.Flush()
}

// ==========================
// Attack Pattern Commands
// ==========================

func listPatterns(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, attack_signature, attack_type, times_seen, claude_confidence 
		FROM attack_patterns 
		ORDER BY times_seen DESC 
		LIMIT 20
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tSIGNATURE\tTYPE\tSEEN\tCONFIDENCE")
	for rows.Next() {
		var id, timesSeen int
		var signature, attackType string
		var confidence float64
		rows.Scan(&id, &signature, &attackType, &timesSeen, &confidence)
		fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%.2f\n", id, signature, attackType, timesSeen, confidence)
	}
	w.Flush()
}

func viewPattern(cmd *cobra.Command, args []string) {
	var id, signature, attackType, classification, method, pathPattern string
	var responseCode, timesSeen int
	var confidence float64

	err := db.QueryRow(`
		SELECT id, attack_signature, attack_type, attack_classification, http_method, 
		       path_pattern, response_code, times_seen, claude_confidence
		FROM attack_patterns WHERE id = ?
	`, args[0]).Scan(&id, &signature, &attackType, &classification, &method, &pathPattern, &responseCode, &timesSeen, &confidence)

	if err != nil {
		fmt.Printf("Pattern not found: %v\n", err)
		return
	}

	fmt.Printf("Pattern ID: %s\n", id)
	fmt.Printf("Signature: %s\n", signature)
	fmt.Printf("Attack Type: %s\n", attackType)
	fmt.Printf("Classification: %s\n", classification)
	fmt.Printf("HTTP Method: %s\n", method)
	fmt.Printf("Path Pattern: %s\n", pathPattern)
	fmt.Printf("Response Code: %d\n", responseCode)
	fmt.Printf("Times Seen: %d\n", timesSeen)
	fmt.Printf("Confidence: %.2f\n", confidence)
}

func addPattern(cmd *cobra.Command, args []string) {
	attackType := args[0]
	signature := args[1]

	stmt, _ := db.Prepare("INSERT INTO attack_patterns (attack_signature, attack_type) VALUES (?, ?)")
	result, err := stmt.Exec(signature, attackType)
	if err != nil {
		fmt.Printf("Error adding pattern: %v\n", err)
		return
	}
	id, _ := result.LastInsertId()
	fmt.Printf("✓ Pattern added (ID: %d)\n", id)
}

func removePattern(cmd *cobra.Command, args []string) {
	stmt, _ := db.Prepare("DELETE FROM attack_patterns WHERE id = ?")
	result, err := stmt.Exec(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	affected, _ := result.RowsAffected()
	if affected > 0 {
		fmt.Println("✓ Pattern removed")
	} else {
		fmt.Println("Pattern not found")
	}
}

// ==========================
// Attacker Profile Commands
// ==========================

func listAttackers(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, source_ip, total_requests, successful_probes, attack_types, last_seen 
		FROM attacker_profiles 
		ORDER BY total_requests DESC 
		LIMIT 20
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tIP\tREQUESTS\tPROBES\tATTACK TYPES\tLAST SEEN")
	for rows.Next() {
		var id, totalReq, probes int
		var ip, attackTypes, lastSeen string
		rows.Scan(&id, &ip, &totalReq, &probes, &attackTypes, &lastSeen)
		fmt.Fprintf(w, "%d\t%s\t%d\t%d\t%s\t%s\n", id, ip, totalReq, probes, attackTypes, lastSeen)
	}
	w.Flush()
}

func viewAttacker(cmd *cobra.Command, args []string) {
	var id, ip, attackTypes, firstSeen, lastSeen string
	var totalReq, probes int

	err := db.QueryRow(`
		SELECT id, source_ip, total_requests, successful_probes, attack_types, first_seen, last_seen
		FROM attacker_profiles WHERE id = ?
	`, args[0]).Scan(&id, &ip, &totalReq, &probes, &attackTypes, &firstSeen, &lastSeen)

	if err != nil {
		fmt.Printf("Attacker not found: %v\n", err)
		return
	}

	fmt.Printf("Profile ID: %s\n", id)
	fmt.Printf("IP Address: %s\n", ip)
	fmt.Printf("Total Requests: %d\n", totalReq)
	fmt.Printf("Successful Probes: %d\n", probes)
	fmt.Printf("Attack Types: %s\n", attackTypes)
	fmt.Printf("First Seen: %s\n", firstSeen)
	fmt.Printf("Last Seen: %s\n", lastSeen)
}

func searchAttacker(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, source_ip, total_requests, successful_probes, attack_types 
		FROM attacker_profiles 
		WHERE source_ip LIKE ?
	`, "%"+args[0]+"%")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tIP\tREQUESTS\tPROBES\tATTACK TYPES")
	for rows.Next() {
		var id, totalReq, probes int
		var ip, attackTypes string
		rows.Scan(&id, &ip, &totalReq, &probes, &attackTypes)
		fmt.Fprintf(w, "%d\t%s\t%d\t%d\t%s\n", id, ip, totalReq, probes, attackTypes)
	}
	w.Flush()
}

func removeAttacker(cmd *cobra.Command, args []string) {
	stmt, _ := db.Prepare("DELETE FROM attacker_profiles WHERE id = ?")
	result, err := stmt.Exec(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	affected, _ := result.RowsAffected()
	if affected > 0 {
		fmt.Println("✓ Attacker profile removed")
	} else {
		fmt.Println("Attacker not found")
	}
}

// ==========================
// Exception Commands
// ==========================

func listExceptions(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, ip_address, path, reason, enabled 
		FROM exceptions 
		ORDER BY id DESC
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tIP\tPATH\tREASON\tENABLED")
	for rows.Next() {
		var id, enabled int
		var ip, path, reason string
		rows.Scan(&id, &ip, &path, &reason, &enabled)
		enabledStr := "No"
		if enabled == 1 {
			enabledStr = "Yes"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", id, ip, path, reason, enabledStr)
	}
	w.Flush()
}

func viewException(cmd *cobra.Command, args []string) {
	var id, ip, path, reason, createdAt string
	var enabled int

	err := db.QueryRow(`
		SELECT id, ip_address, path, reason, enabled, created_at
		FROM exceptions WHERE id = ?
	`, args[0]).Scan(&id, &ip, &path, &reason, &enabled, &createdAt)

	if err != nil {
		fmt.Printf("Exception not found: %v\n", err)
		return
	}

	fmt.Printf("Exception ID: %s\n", id)
	fmt.Printf("IP Address: %s\n", ip)
	fmt.Printf("Path: %s\n", path)
	fmt.Printf("Reason: %s\n", reason)
	fmt.Printf("Enabled: %v\n", enabled == 1)
	fmt.Printf("Created: %s\n", createdAt)
}

func addException(cmd *cobra.Command, args []string) {
	ip := args[0]
	path := args[1]
	now := time.Now().Format(time.RFC3339)

	if ip == "-" {
		ip = "*"
	}
	if path == "-" {
		path = "*"
	}

	stmt, _ := db.Prepare("INSERT INTO exceptions (ip_address, path, reason, created_at) VALUES (?, ?, ?, ?)")
	result, err := stmt.Exec(ip, path, "CLI whitelist", now)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	id, _ := result.LastInsertId()
	fmt.Printf("✓ Exception added (ID: %d)\n", id)
}

func removeException(cmd *cobra.Command, args []string) {
	stmt, _ := db.Prepare("DELETE FROM exceptions WHERE id = ?")
	result, err := stmt.Exec(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	affected, _ := result.RowsAffected()
	if affected > 0 {
		fmt.Println("✓ Exception removed")
	} else {
		fmt.Println("Exception not found")
	}
}

func enableException(cmd *cobra.Command, args []string) {
	stmt, _ := db.Prepare("UPDATE exceptions SET enabled = 1 WHERE id = ?")
	stmt.Exec(args[0])
	fmt.Println("✓ Exception enabled")
}

func disableException(cmd *cobra.Command, args []string) {
	stmt, _ := db.Prepare("UPDATE exceptions SET enabled = 0 WHERE id = ?")
	stmt.Exec(args[0])
	fmt.Println("✓ Exception disabled")
}

// ==========================
// Keyword Exception Commands
// ==========================

func listKeywordExceptions(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, exception_type, keyword, reason 
		FROM keyword_exceptions 
		ORDER BY exception_type, keyword
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tTYPE\tKEYWORD\tREASON")
	for rows.Next() {
		var id int
		var exceptionType, keyword, reason string
		rows.Scan(&id, &exceptionType, &keyword, &reason)
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", id, exceptionType, keyword, reason)
	}
	w.Flush()
}

func viewKeywordException(cmd *cobra.Command, args []string) {
	var id, exceptionType, keyword, reason, createdAt string

	err := db.QueryRow(`
		SELECT id, exception_type, keyword, reason, created_at
		FROM keyword_exceptions WHERE id = ?
	`, args[0]).Scan(&id, &exceptionType, &keyword, &reason, &createdAt)

	if err != nil {
		fmt.Printf("Keyword exception not found: %v\n", err)
		return
	}

	fmt.Printf("Exception ID: %s\n", id)
	fmt.Printf("Type: %s\n", exceptionType)
	fmt.Printf("Keyword: %s\n", keyword)
	fmt.Printf("Reason: %s\n", reason)
	fmt.Printf("Created: %s\n", createdAt)
}

func addKeywordException(cmd *cobra.Command, args []string) {
	exceptionType := args[0]
	keyword := args[1]
	now := time.Now().Format(time.RFC3339)

	stmt, _ := db.Prepare("INSERT INTO keyword_exceptions (exception_type, keyword, reason, created_at) VALUES (?, ?, ?, ?)")
	result, err := stmt.Exec(exceptionType, keyword, "CLI exception", now)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	id, _ := result.LastInsertId()
	fmt.Printf("✓ Keyword exception added (ID: %d)\n", id)
}

func removeKeywordException(cmd *cobra.Command, args []string) {
	stmt, _ := db.Prepare("DELETE FROM keyword_exceptions WHERE id = ?")
	result, err := stmt.Exec(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	affected, _ := result.RowsAffected()
	if affected > 0 {
		fmt.Println("✓ Keyword exception removed")
	} else {
		fmt.Println("Exception not found")
	}
}

// ==========================
// Intel Template Commands
// ==========================

func listIntelTemplates(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, name, template_type, description, is_active 
		FROM intel_collection_templates 
		ORDER BY name
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tTYPE\tDESCRIPTION\tACTIVE")
	for rows.Next() {
		var id, active int
		var name, templateType, description string
		rows.Scan(&id, &name, &templateType, &description, &active)
		activeStr := "No"
		if active == 1 {
			activeStr = "Yes"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", id, name, templateType, description, activeStr)
	}
	w.Flush()
}

func viewIntelTemplate(cmd *cobra.Command, args []string) {
	var id, name, templateType, content, description string
	var isActive int

	err := db.QueryRow(`
		SELECT id, name, template_type, content, description, is_active
		FROM intel_collection_templates WHERE id = ?
	`, args[0]).Scan(&id, &name, &templateType, &content, &description, &isActive)

	if err != nil {
		fmt.Printf("Intel template not found: %v\n", err)
		return
	}

	fmt.Printf("Template ID: %s\n", id)
	fmt.Printf("Name: %s\n", name)
	fmt.Printf("Type: %s\n", templateType)
	fmt.Printf("Description: %s\n", description)
	fmt.Printf("Active: %v\n", isActive == 1)
	fmt.Printf("\nContent:\n%s\n", content)
}

func toggleIntelTemplate(cmd *cobra.Command, args []string) {
	var active int
	err := db.QueryRow("SELECT is_active FROM intel_collection_templates WHERE id = ?", args[0]).Scan(&active)
	if err != nil {
		fmt.Printf("Template not found: %v\n", err)
		return
	}

	newStatus := 0
	if active == 0 {
		newStatus = 1
	}

	stmt, _ := db.Prepare("UPDATE intel_collection_templates SET is_active = ? WHERE id = ?")
	stmt.Exec(newStatus, args[0])

	if newStatus == 1 {
		fmt.Println("✓ Intel template activated")
	} else {
		fmt.Println("✓ Intel template deactivated")
	}
}

// ==========================
// Payload Template Commands
// ==========================

func listPayloads(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, name, attack_type, payload_type, status_code, priority, is_active 
		FROM payload_templates 
		ORDER BY priority DESC
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tATTACK TYPE\tPAYLOAD TYPE\tSTATUS\tPRIORITY\tACTIVE")
	for rows.Next() {
		var id, statusCode, priority, active int
		var name, attackType, payloadType string
		rows.Scan(&id, &name, &attackType, &payloadType, &statusCode, &priority, &active)
		activeStr := "No"
		if active == 1 {
			activeStr = "Yes"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%d\t%s\n", id, name, attackType, payloadType, statusCode, priority, activeStr)
	}
	w.Flush()
}

func viewPayload(cmd *cobra.Command, args []string) {
	var id, name, attackType, payloadType, content, contentType string
	var statusCode, priority, isActive int

	err := db.QueryRow(`
		SELECT id, name, attack_type, payload_type, content, content_type, status_code, priority, is_active
		FROM payload_templates WHERE id = ?
	`, args[0]).Scan(&id, &name, &attackType, &payloadType, &content, &contentType, &statusCode, &priority, &isActive)

	if err != nil {
		fmt.Printf("Payload not found: %v\n", err)
		return
	}

	fmt.Printf("Payload ID: %s\n", id)
	fmt.Printf("Name: %s\n", name)
	fmt.Printf("Attack Type: %s\n", attackType)
	fmt.Printf("Payload Type: %s\n", payloadType)
	fmt.Printf("Content Type: %s\n", contentType)
	fmt.Printf("Status Code: %d\n", statusCode)
	fmt.Printf("Priority: %d\n", priority)
	fmt.Printf("Active: %v\n", isActive == 1)
	fmt.Printf("\nContent:\n%s\n", content)
}

func payloadStats(cmd *cobra.Command, args []string) {
	var total, active int
	db.QueryRow("SELECT COUNT(*) FROM payload_templates").Scan(&total)
	db.QueryRow("SELECT COUNT(*) FROM payload_templates WHERE is_active = 1").Scan(&active)

	fmt.Printf("Total Payloads: %d\n", total)
	fmt.Printf("Active Payloads: %d\n", active)
	fmt.Printf("Inactive Payloads: %d\n", total-active)
}

// ==========================
// Legitimate Requests Commands
// ==========================

func listLegitimate(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT path_signature, http_method, hit_count, last_seen 
		FROM legitimate_requests 
		ORDER BY hit_count DESC 
		LIMIT 20
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "PATH SIG\tMETHOD\tHITS\tLAST SEEN")
	for rows.Next() {
		var pathSig, method, lastSeen string
		var hits int
		rows.Scan(&pathSig, &method, &hits, &lastSeen)
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", pathSig, method, hits, lastSeen)
	}
	w.Flush()
}

func legitimateStats(cmd *cobra.Command, args []string) {
	var total int
	var hitCount sql.NullInt64
	db.QueryRow("SELECT COUNT(*) FROM legitimate_requests").Scan(&total)
	db.QueryRow("SELECT SUM(hit_count) FROM legitimate_requests").Scan(&hitCount)

	hits := int64(0)
	if hitCount.Valid {
		hits = hitCount.Int64
	}

	fmt.Printf("Total Cached Paths: %d\n", total)
	fmt.Printf("Total Cache Hits: %d\n", hits)
	if total > 0 {
		fmt.Printf("Average Hits per Path: %.1f\n", float64(hits)/float64(total))
	}
}

// ==========================
// Attacker Interaction Commands
// ==========================

func listInteractions(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, source_ip, interaction_type, content, timestamp 
		FROM attacker_interactions 
		ORDER BY timestamp DESC 
		LIMIT 20
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tIP\tTYPE\tCONTENT\tTIME")
	for rows.Next() {
		var id int
		var ip, intType, content, timestamp string
		rows.Scan(&id, &ip, &intType, &content, &timestamp)
		if len(content) > 50 {
			content = content[:50] + "..."
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", id, ip, intType, content, timestamp)
	}
	w.Flush()
}

func interactionsByIP(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, interaction_type, content, timestamp 
		FROM attacker_interactions 
		WHERE source_ip = ? 
		ORDER BY timestamp DESC
	`, args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tTYPE\tCONTENT\tTIME")
	for rows.Next() {
		var id int
		var intType, content, timestamp string
		rows.Scan(&id, &intType, &content, &timestamp)
		if len(content) > 60 {
			content = content[:60] + "..."
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", id, intType, content, timestamp)
	}
	w.Flush()
}

// ==========================
// Threat Intelligence Commands
// ==========================

func listThreats(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT ip_address, risk_score, threat_level, country, last_seen 
		FROM threat_intelligence 
		ORDER BY risk_score DESC 
		LIMIT 20
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "IP\tRISK\tLEVEL\tCOUNTRY\tLAST SEEN")
	for rows.Next() {
		var ip, threatLevel, country, lastSeen string
		var riskScore int
		rows.Scan(&ip, &riskScore, &threatLevel, &country, &lastSeen)
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n", ip, riskScore, threatLevel, country, lastSeen)
	}
	w.Flush()
}

func viewThreat(cmd *cobra.Command, args []string) {
	var ip, threatLevel, country, org, lastSeen string
	var riskScore, abuseScore, abuseReports, vtMal, vtSusp int

	err := db.QueryRow(`
		SELECT ip_address, risk_score, threat_level, abuseipdb_score, abuseipdb_reports,
		       virustotal_malicious, virustotal_suspicious, ipinfo_country, ipinfo_org, last_seen
		FROM threat_intelligence WHERE ip_address = ?
	`, args[0]).Scan(&ip, &riskScore, &threatLevel, &abuseScore, &abuseReports, &vtMal, &vtSusp, &country, &org, &lastSeen)

	if err != nil {
		fmt.Printf("Threat not found: %v\n", err)
		return
	}

	fmt.Printf("IP Address: %s\n", ip)
	fmt.Printf("Risk Score: %d\n", riskScore)
	fmt.Printf("Threat Level: %s\n", threatLevel)
	fmt.Printf("Country: %s\n", country)
	fmt.Printf("Organization: %s\n", org)
	fmt.Printf("\nAbuseIPDB:\n")
	fmt.Printf("  Score: %d\n", abuseScore)
	fmt.Printf("  Reports: %d\n", abuseReports)
	fmt.Printf("\nVirusTotal:\n")
	fmt.Printf("  Malicious: %d\n", vtMal)
	fmt.Printf("  Suspicious: %d\n", vtSusp)
	fmt.Printf("\nLast Seen: %s\n", lastSeen)
}

func topThreats(cmd *cobra.Command, args []string) {
	limit := 10
	if len(args) > 0 {
		if parsed, err := strconv.Atoi(args[0]); err == nil {
			limit = parsed
		}
	}

	rows, err := db.Query(`
		SELECT ip_address, risk_score, threat_level, country 
		FROM threat_intelligence 
		ORDER BY risk_score DESC 
		LIMIT ?
	`, limit)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "IP\tRISK\tLEVEL\tCOUNTRY")
	for rows.Next() {
		var ip, threatLevel, country string
		var riskScore int
		rows.Scan(&ip, &riskScore, &threatLevel, &country)
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", ip, riskScore, threatLevel, country)
	}
	w.Flush()
}

func threatStats(cmd *cobra.Command, args []string) {
	var total, critical, high, medium, low int
	var avgScore float64
	db.QueryRow("SELECT COUNT(*) FROM threat_intelligence").Scan(&total)
	db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE threat_level = 'CRITICAL'").Scan(&critical)
	db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE threat_level = 'HIGH'").Scan(&high)
	db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE threat_level = 'MEDIUM'").Scan(&medium)
	db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE threat_level = 'LOW'").Scan(&low)
	db.QueryRow("SELECT COALESCE(AVG(risk_score), 0) FROM threat_intelligence").Scan(&avgScore)

	fmt.Printf("Total Threats: %d\n", total)
	fmt.Printf("Critical: %d\n", critical)
	fmt.Printf("High: %d\n", high)
	fmt.Printf("Medium: %d\n", medium)
	fmt.Printf("Low: %d\n", low)
	fmt.Printf("Average Risk Score: %.1f\n", avgScore)
}

// ==========================
// Database Commands
// ==========================

func dbStats(cmd *cobra.Command, args []string) {
	var attacks, patterns, attackers, exceptions, keywords, intel, payloads, legitimate, interactions, threats int

	db.QueryRow("SELECT COUNT(*) FROM attack_instances").Scan(&attacks)
	db.QueryRow("SELECT COUNT(*) FROM attack_patterns").Scan(&patterns)
	db.QueryRow("SELECT COUNT(*) FROM attacker_profiles").Scan(&attackers)
	db.QueryRow("SELECT COUNT(*) FROM exceptions").Scan(&exceptions)
	db.QueryRow("SELECT COUNT(*) FROM keyword_exceptions").Scan(&keywords)
	db.QueryRow("SELECT COUNT(*) FROM intel_collection_templates").Scan(&intel)
	db.QueryRow("SELECT COUNT(*) FROM payload_templates").Scan(&payloads)
	db.QueryRow("SELECT COUNT(*) FROM legitimate_requests").Scan(&legitimate)
	db.QueryRow("SELECT COUNT(*) FROM attacker_interactions").Scan(&interactions)
	db.QueryRow("SELECT COUNT(*) FROM threat_intelligence").Scan(&threats)

	fmt.Println("=== IFRIT Database Statistics ===")
	fmt.Printf("Attack Instances: %d\n", attacks)
	fmt.Printf("Attack Patterns: %d\n", patterns)
	fmt.Printf("Attacker Profiles: %d\n", attackers)
	fmt.Printf("Exceptions: %d\n", exceptions)
	fmt.Printf("Keyword Exceptions: %d\n", keywords)
	fmt.Printf("Intel Templates: %d\n", intel)
	fmt.Printf("Payload Templates: %d\n", payloads)
	fmt.Printf("Legitimate Requests (cached): %d\n", legitimate)
	fmt.Printf("Attacker Interactions: %d\n", interactions)
	fmt.Printf("Threat Intelligence Records: %d\n", threats)
}

func showSchema(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT name FROM sqlite_master 
		WHERE type='table' 
		ORDER BY name
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	fmt.Println("=== IFRIT Database Tables ===")
	for rows.Next() {
		var name string
		rows.Scan(&name)
		fmt.Printf("- %s\n", name)
	}
}

// ==========================
// API Token Commands
// ==========================

func listTokens(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, user_id, token_name, token_prefix, is_active, expires_at, created_at 
		FROM api_tokens 
		ORDER BY created_at DESC
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tUSER\tNAME\tPREFIX\tACTIVE\tEXPIRES\tCREATED")
	for rows.Next() {
		var id int
		var userID, tokenName, tokenPrefix, expiresAt, createdAt string
		var isActive bool
		rows.Scan(&id, &userID, &tokenName, &tokenPrefix, &isActive, &expiresAt, &createdAt)
		activeStr := "No"
		if isActive {
			activeStr = "Yes"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", id, userID, tokenName, tokenPrefix, activeStr, expiresAt, createdAt)
	}
	w.Flush()
}

func createToken(cmd *cobra.Command, args []string) {
	userID := args[0]
	tokenName := args[1]

	// Check if user exists, create if not
	var exists bool
	db.QueryRow("SELECT EXISTS(SELECT 1 FROM api_users WHERE id = ?)", userID).Scan(&exists)
	if !exists {
		db.Exec("INSERT INTO api_users (id, username, role, is_active) VALUES (?, ?, 'admin', 1)", userID, "user_"+userID)
	}

	// Generate token (simplified - in production use crypto/rand)
	token := fmt.Sprintf("ifrit_%s_%d", userID, time.Now().Unix())
	tokenHash := fmt.Sprintf("hash_%s", token) // In production: bcrypt hash
	tokenPrefix := token[:12]

	expiresAt := time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	now := time.Now().Format(time.RFC3339)

	stmt, _ := db.Prepare("INSERT INTO api_tokens (user_id, token_name, token_hash, token_prefix, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)")
	result, err := stmt.Exec(userID, tokenName, tokenHash, tokenPrefix, expiresAt, now)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	id, _ := result.LastInsertId()
	fmt.Printf("✓ Token created (ID: %d)\n", id)
	fmt.Printf("Token: %s\n", token)
	fmt.Printf("⚠️  Save this token - it won't be shown again!\n")
}

func revokeToken(cmd *cobra.Command, args []string) {
	stmt, _ := db.Prepare("UPDATE api_tokens SET is_active = 0 WHERE id = ?")
	result, err := stmt.Exec(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	affected, _ := result.RowsAffected()
	if affected > 0 {
		fmt.Println("✓ Token revoked")
	} else {
		fmt.Println("Token not found")
	}
}

func validateToken(cmd *cobra.Command, args []string) {
	var id int
	var isActive bool
	var expiresAt string

	err := db.QueryRow(`
		SELECT id, is_active, expires_at 
		FROM api_tokens 
		WHERE token_prefix = ?
	`, args[0][:12]).Scan(&id, &isActive, &expiresAt)

	if err != nil {
		fmt.Println("✗ Invalid token")
		return
	}

	expires, _ := time.Parse(time.RFC3339, expiresAt)
	if !isActive {
		fmt.Println("✗ Token revoked")
	} else if time.Now().After(expires) {
		fmt.Println("✗ Token expired")
	} else {
		fmt.Println("✓ Token valid")
		fmt.Printf("Expires: %s\n", expiresAt)
	}
}
