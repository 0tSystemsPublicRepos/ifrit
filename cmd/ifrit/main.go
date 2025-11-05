package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/0tSystemsPublicRepos/ifrit/internal/api"
	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
	"github.com/0tSystemsPublicRepos/ifrit/internal/detection"
	"github.com/0tSystemsPublicRepos/ifrit/internal/llm"
	"github.com/0tSystemsPublicRepos/ifrit/internal/logging"
	"github.com/0tSystemsPublicRepos/ifrit/internal/proxy"
)

func main() {
	fmt.Println("========================================")
	fmt.Println("IFRIT Proxy - Intelligent Threat Deception Platform")
	fmt.Println("Version: 0.1 (MVP)")
	fmt.Println("========================================\n")

	// Load configuration
	cfg, err := config.Load("")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	fmt.Printf("Configuration loaded\n")
	fmt.Printf("Database: %s\n", cfg.Database.Path)
	fmt.Printf("Proxy target: %s\n", cfg.Server.ProxyTarget)
	fmt.Printf("LLM Provider: %s\n", cfg.LLM.Primary)
	fmt.Println()

	// Initialize logging
	fmt.Println("Initializing logging...")
	if err := logging.Init(cfg.System.LogDir); err != nil {
		log.Printf("Warning: Failed to initialize logging: %v\n", err)
	}
	defer logging.Close()

	// Initialize database
	fmt.Println("Initializing database...")
	db, err := database.InitializeDatabase(cfg.Database.Path)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()
	fmt.Println("✓ Database initialized")

	// Initialize LLM Manager
	fmt.Println("Initializing LLM providers...")
	llmManager := llm.NewManager(
		cfg.LLM.Primary,
		cfg.LLM.Claude.APIKey,
		cfg.LLM.Claude.Model,
		"claude", // fallback to claude
		cfg.LLM.Claude.APIKey,
		cfg.LLM.Claude.Model,
	)
	fmt.Printf("✓ LLM Manager initialized (primary: %s)\n", llmManager.GetPrimaryName())

	// Initialize detection engine
	fmt.Println("Initializing detection engine...")
	detectionEngine := detection.NewDetectionEngine(
		cfg.Detection.WhitelistIPs,
		cfg.Detection.WhitelistPaths,
		db,
		llmManager,
	)
	fmt.Println("✓ Detection engine initialized")

	// Initialize reverse proxy
	fmt.Println("Initializing reverse proxy...")
	reverseProxy, err := proxy.NewReverseProxy(cfg.Server.ProxyTarget)
	if err != nil {
		log.Fatalf("Failed to initialize reverse proxy: %v", err)
	}
	fmt.Println("✓ Reverse proxy initialized")

	// Initialize API server
	fmt.Println("Initializing API server...")
	apiServer := api.NewAPIServer(cfg.Server.APIListenAddr, "", db, llmManager)
	fmt.Println("✓ API server initialized")

	// Start API server in goroutine
	fmt.Printf("\nStarting API server on %s\n", cfg.Server.APIListenAddr)
	go func() {
		if err := apiServer.Start(); err != nil && err != http.ErrServerClosed {
			log.Printf("API server error: %v", err)
		}
	}()

	// Start main proxy server
	fmt.Printf("Starting proxy server on %s\n", cfg.Server.ListenAddr)
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Check exceptions first
		clientIP := proxy.GetClientIP(r)
		if detectionEngine.CheckExceptions(r, clientIP) {
			logging.Debug("Request from whitelisted IP: %s", clientIP)
			resp, err := reverseProxy.ForwardRequest(r)
			if err != nil {
				http.Error(w, "Bad Gateway", http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			reverseProxy.CopyResponse(w, resp)
			return
		}

		// Stage 1: Check local rules
		result := detectionEngine.CheckLocalRules(r)
		if result != nil && result.IsAttack {
			logging.Attack(clientIP, r.Method, r.URL.Path, result.AttackType, "Stage 2: Local Rules")
			db.StoreAttackInstance(0, clientIP, "", r.URL.Path, r.Method)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "Forbidden"}`))
			return
		}

		// Stage 2: Check database patterns
		result = detectionEngine.CheckDatabasePatterns(r)
		if result != nil && result.IsAttack {
			logging.Attack(clientIP, r.Method, r.URL.Path, result.AttackType, "Stage 3: Database Patterns")
			db.StoreAttackInstance(0, clientIP, "", r.URL.Path, r.Method)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(result.PayloadTemplate))
			return
		}

		// Stage 3: LLM Analysis for POST/PUT/DELETE
		if contains(cfg.Detection.LLMOnlyOn, r.Method) && cfg.Detection.EnableLLM {
			result = detectionEngine.CheckLLMAnalysis(r)
			if result != nil && result.IsAttack {
				logging.Attack(clientIP, r.Method, r.URL.Path, result.AttackType, "Stage 4: LLM Analysis")
				db.StoreAttackInstance(0, clientIP, "", r.URL.Path, r.Method)
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(result.PayloadTemplate))
				return
			}
		}

		// Not an attack, forward to backend
		resp, err := reverseProxy.ForwardRequest(r)
		if err != nil {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		reverseProxy.CopyResponse(w, resp)
	})

	// Start proxy
	if err := http.ListenAndServe(cfg.Server.ListenAddr, mux); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Proxy server error: %v", err)
	}

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down...")
}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}
