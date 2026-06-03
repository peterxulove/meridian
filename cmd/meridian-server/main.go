// Meridian server CLI entrypoint.
package main

import (
	"flag"
	"fmt"
	"os"

	"meridian/pkg/anti"
	"meridian/pkg/config"
)

func main() {
	cfgPath, listen, showFP, debug := flagParse()
	config.DebugMode = debug

	if showFP {
		fmt.Println("Available TLS Fingerprints:")
		anti.PrintFingerprints()
		return
	}

	cfg, err := config.LoadServerConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}
	if listen != "" {
		cfg.ListenAddr = listen
	}

	fmt.Printf("Meridian Server v1.0.0\n")
	fmt.Printf("  Listen:    %s\n", cfg.ListenAddr)
	fmt.Printf("  Transport: %s\n", cfg.Transport)
	fmt.Printf("  Cipher:    %s\n", cfg.CipherSuite)
	fmt.Printf("  REALITY:   %v\n", cfg.RealityMode)
	fmt.Printf("  Backend:   %v\n", formatDestinations(cfg.Destinations))

	server, err := NewServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create server: %v\n", err)
		os.Exit(1)
	}

	// Fix #12: signal channel was created but never registered with signal.Notify,
	// causing <-sigch to block forever. Now registers SIGINT and SIGTERM.
	sigch := make(chan os.Signal, 1)
	notifySignals(sigch)

	if err := server.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting server: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Server running on %s (PID %d)\n", cfg.ListenAddr, os.Getpid())
	fmt.Println("Press Ctrl+C to stop.")

	<-sigch
	fmt.Println("\nShutting down...")
	server.Stop()
}

// flagParse parses command-line flags.
// Fix #14: was an empty function; CLI flags had no effect.
func flagParse() (cfgPath, listen string, showFP bool, debug bool) {
	flag.StringVar(&cfgPath, "config", "server.yaml", "path to server config file")
	flag.StringVar(&listen, "listen", "", "override listen address (e.g. 0.0.0.0:443)")
	flag.BoolVar(&showFP, "fingerprints", false, "list available TLS fingerprints and exit")
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
	flag.Parse()
	return
}

func formatDestinations(dests []config.DestinationConfig) string {
	if len(dests) == 0 {
		return "none"
	}
	var parts []string
	for _, d := range dests {
		parts = append(parts, fmt.Sprintf("%s(%s)", d.Addr, d.Protocol))
	}
	return fmt.Sprintf("%v", parts)
}

func printConfigHelp() {
	fmt.Println("Server config: see server.example.yaml")
}
