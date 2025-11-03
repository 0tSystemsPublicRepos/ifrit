package main

import (
	"fmt"
	"log"
	"os"

	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
)

func main() {
	// Initialize database with seed data
	db, err := database.InitializeDatabase("data/ifrit.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	fmt.Println("IFRIT Proxy initialized successfully")
	fmt.Println("Database: data/ifrit.db")
	fmt.Println("Proxy listening on :8080")
	fmt.Println("Dashboard: http://localhost:8080/dashboard")

	// TODO: Start proxy server
	// TODO: Start API server
	// TODO: Start detection engine

	// Keep running
	select {}
}
