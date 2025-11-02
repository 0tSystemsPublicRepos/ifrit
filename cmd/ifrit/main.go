package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("IFRIT Proxy - Intelligent Threat Deception Platform")
	fmt.Println("Status: MVP Development (v0.1)")
	fmt.Println("Build: Ready for implementation")
	
	if len(os.Args) > 1 {
		fmt.Printf("Command: %v\n", os.Args[1:])
	} else {
		fmt.Println("\nUsage: ifrit [command] [flags]")
		fmt.Println("\nAvailable commands:")
		fmt.Println("  start    - Start IFRIT proxy")
		fmt.Println("  config   - Manage configuration")
		fmt.Println("  version  - Show version")
		fmt.Println("  help     - Show this help message")
	}
}
