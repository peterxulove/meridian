// Meridian server CLI entrypoint.
package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	"meridian/pkg/anti"
	"meridian/pkg/config"
)

// Version and BuildTime are overridden at link time by the release workflow:
//
//	go build -ldflags "-X main.Version=v1.6.0 -X main.BuildTime=..."
//
// The defaults keep a plain `go build` from printing an empty version.
var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	cfgPath, listen, showFP, showVersion, debug := flagParse()
	config.DebugMode = debug

	if showVersion {
		fmt.Printf("Meridian Server %s (%s)\n", Version, BuildTime)
		return
	}
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

	fmt.Printf("Meridian Server %s\n", Version)
	fmt.Printf("  Listen:    %s\n", cfg.ListenAddr)
	fmt.Printf("  Transport: %s\n", cfg.Transport)
	fmt.Printf("  Cipher:    %s\n", cfg.CipherSuite)
	fmt.Printf("  REALITY:   %v\n", cfg.RealityMode)
	fmt.Printf("  Backend:   %v\n", formatDestinations(cfg.Destinations))
	reportCertificate(cfg.ServerCertFile)
	if cfg.FallbackURL != "" {
		fmt.Printf("  Fallback:  %s\n", cfg.FallbackURL)
	}

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
func flagParse() (cfgPath, listen string, showFP, showVersion bool, debug bool) {
	flag.StringVar(&cfgPath, "config", "server.yaml", "path to server config file")
	flag.StringVar(&listen, "listen", "", "override listen address (e.g. 0.0.0.0:443)")
	flag.BoolVar(&showFP, "fingerprints", false, "list available TLS fingerprints and exit")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
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

// reportCertificate prints the identity the server actually presents.
//
// A self-signed certificate is the loudest passive fingerprint a tunnel can
// emit: no real website serves one, so an observer that sees issuer == subject
// has classified the endpoint without looking at a single payload byte. That
// is cheap to check at start-up and easy to miss in a YAML file, so it is
// printed on every start rather than buried in the docs.
func reportCertificate(path string) {
	if path == "" {
		fmt.Fprintln(os.Stderr, "  [WARN] No server_cert configured: an ephemeral self-signed certificate is used")
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [WARN] Cannot read %s: %v\n", path, err)
		return
	}
	block, _ := pem.Decode(data)
	if block == nil {
		fmt.Fprintf(os.Stderr, "  [WARN] %s does not contain a PEM certificate\n", path)
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [WARN] Cannot parse %s: %v\n", path, err)
		return
	}
	fmt.Printf("  Cert:      %s, expires %s\n", cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02"))
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		fmt.Fprintln(os.Stderr, "  [WARN] Certificate is self-signed. Issuer == subject is the single")
		fmt.Fprintln(os.Stderr, "         clearest 'this is not a website' signal a passive observer")
		fmt.Fprintln(os.Stderr, "         can read. Point server_cert/server_key at a CA-issued pair.")
	}
	if left := time.Until(cert.NotAfter); left < 14*24*time.Hour {
		fmt.Fprintf(os.Stderr, "  [WARN] Certificate expires in %d days; clients that verify the chain will start failing\n",
			int(left.Hours()/24))
	}
}
