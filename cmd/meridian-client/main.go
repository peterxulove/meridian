// Meridian client CLI entrypoint.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"meridian/pkg/anti"
	"meridian/pkg/config"
	"meridian/pkg/crypto"
	"meridian/pkg/mtp"
)

func main() {
	cfgPath, listen, showFP := flagParse()

	if showFP {
		fmt.Println("Available TLS Fingerprints:")
		anti.PrintFingerprints()
		return
	}

	cfg, err := config.LoadClientConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}
	if listen != "" {
		cfg.ListenAddr = listen
	}

	fmt.Printf("Meridian Client v1.0.0\n")
	fmt.Printf("  Server:    %s\n", cfg.ServerAddr)
	fmt.Printf("  Transport: %s\n", cfg.Transport)
	fmt.Printf("  Cipher:    %s\n", cfg.CipherSuite)
	fmt.Printf("  Proxy:     %s (%s)\n", cfg.ListenAddr, cfg.ProxyProtocol)

	client, err := NewClient(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create client: %v\n", err)
		os.Exit(1)
	}

	// Fix #12: signal channel was created but never passed to signal.Notify,
	// causing <-sigch to block forever and Ctrl+C to be ignored.
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)

	if err := client.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting client: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Client listening on %s (PID %d)\n", cfg.ListenAddr, os.Getpid())
	fmt.Println("Press Ctrl+C to stop.")

	<-sigch
	fmt.Println("\nShutting down...")
	client.Stop()
}

// flagParse parses command-line flags and returns the resolved values.
// Fix #14: was an empty function; all CLI flags were ignored.
func flagParse() (cfgPath, listen string, showFP bool) {
	flag.StringVar(&cfgPath, "config", "client.yaml", "path to client config file")
	flag.StringVar(&listen, "listen", "", "override local proxy listen address (e.g. 127.0.0.1:1080)")
	flag.BoolVar(&showFP, "fingerprints", false, "list available TLS fingerprints and exit")
	flag.Parse()
	return
}

// Client holds the active connection and configuration.
type Client struct {
	cfg config.ClientConfig
	c   net.Conn
}

// NewClient initialises a Client, generating a session ID if none is set.
func NewClient(cfg config.ClientConfig) (*Client, error) {
	if cfg.SessionID == [16]byte{} {
		b, err := crypto.GenerateRandom(16)
		if err != nil {
			return nil, fmt.Errorf("client: failed to generate session ID: %w", err)
		}
		copy(cfg.SessionID[:], b)
	}
	return &Client{cfg: cfg}, nil
}

// Start performs the initial handshake and starts the local proxy listener.
func (c *Client) Start() error {
	// Generate ephemeral ECDHE key pair.
	// Fix: GenerateKeyPair now returns (*KeyPair, error).
	ek, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("client: key generation failed: %w", err)
	}

	// Generate client random.
	cr, err := crypto.GenerateRandom(32)
	if err != nil {
		return fmt.Errorf("client: failed to generate client random: %w", err)
	}
	var crArr [32]byte
	copy(crArr[:], cr)

	// Build the ClientHello.
	_, err = mtp.BuildClientHello(c.cfg, &crArr, ek.PubKey)
	if err != nil {
		return fmt.Errorf("client: BuildClientHello failed: %w", err)
	}

	// Fix #13: server address port was hardcoded to 443; now parsed from cfg.ServerAddr.
	host, port, err := net.SplitHostPort(c.cfg.ServerAddr)
	if err != nil {
		// If no port is specified, assume 443.
		host = c.cfg.ServerAddr
		port = "443"
	}
	udp, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP(host),
		Port: mustParsePort(port),
	})
	if err != nil {
		return fmt.Errorf("client: failed to dial server: %w", err)
	}
	c.c = udp

	go c.startLocalProxy()
	return nil
}

// startLocalProxy starts the local SOCKS5/HTTP proxy listener.
// TODO: implement full SOCKS5/HTTP proxy logic.
func (c *Client) startLocalProxy() {
	ln, err := net.Listen("tcp", c.cfg.ListenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client: proxy listen failed: %v\n", err)
		return
	}
	defer ln.Close()
	fmt.Printf("  [Proxy] Listening on %s (%s)\n", c.cfg.ListenAddr, c.cfg.ProxyProtocol)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		conn.Close() // placeholder: actual proxy logic goes here
	}
}

// Stop closes the upstream connection.
func (c *Client) Stop() {
	if c.c != nil {
		c.c.Close()
	}
}

// mustParsePort converts a port string to int; returns 443 on error.
func mustParsePort(s string) int {
	var p int
	fmt.Sscan(s, &p)
	if p == 0 {
		return 443
	}
	return p
}

func printClientConfigHelp() {
	fmt.Println("Client config: see client.example.yaml")
}
