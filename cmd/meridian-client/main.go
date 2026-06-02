// Meridian client CLI entrypoint.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"sync"

	"meridian/pkg/anti"
	"meridian/pkg/config"
	"meridian/pkg/crypto"
)

func main() {
	cfgPath, listen, showFP, debug := flagParse()
	config.DebugMode = debug

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

	fmt.Printf("Meridian Client v1.0.1\n")
	fmt.Printf("  Server:    %s\n", cfg.ServerAddr)
	fmt.Printf("  Transport: %s\n", cfg.Transport)
	fmt.Printf("  Cipher:    %s\n", cfg.CipherSuite)
	fmt.Printf("  SOCKS5:    %s\n", cfg.ListenAddr)

	client, err := NewClient(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create client: %v\n", err)
		os.Exit(1)
	}

	// Raise the open-file descriptor limit before starting so that the
	// SOCKS5 proxy can handle many concurrent connections without hitting
	// "too many open files".
	RaiseFileLimit(65535)

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)

	if err := client.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting client: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Client running (PID %d). Press Ctrl+C to stop.\n", os.Getpid())

	// Print stats every 60 seconds
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for range ticker.C {
			active, total, failed, in, out := client.proxy.Stats()
			fmt.Printf("  [Stats] active=%d total=%d failed=%d in=%dKB out=%dKB\n",
				active, total, failed, in/1024, out/1024)
		}
	}()

	<-sigch
	ticker.Stop()
	fmt.Println("\nShutting down...")
	client.Stop()
}

// flagParse parses command-line flags.
func flagParse() (cfgPath, listen string, showFP bool, debug bool) {
	flag.StringVar(&cfgPath, "config", "client.yaml", "path to client config file")
	flag.StringVar(&listen, "listen", "", "override local SOCKS5 listen address (e.g. 0.0.0.0:1080)")
	flag.BoolVar(&showFP, "fingerprints", false, "list available TLS fingerprints and exit")
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
	flag.Parse()
	return
}

// Client manages the Meridian upstream connection and the local SOCKS5 proxy.
type Client struct {
	cfg    config.ClientConfig
	mu     sync.RWMutex
	tunnel *TunnelClient
	proxy  *Socks5Server
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

func (c *Client) maintainTunnel() {
	for {
		tunnel := NewTunnelClient(c.cfg)
		if err := tunnel.Connect(); err != nil {
			fmt.Printf("  [Tunnel] Connection failed: %v. Retrying in 5s...\n", err)
			time.Sleep(5 * time.Second)
			continue
		}
		
		c.mu.Lock()
		c.tunnel = tunnel
		c.mu.Unlock()

		// Wait until tunnel is closed
		for !tunnel.closed.Load() {
			time.Sleep(1 * time.Second)
		}
		fmt.Printf("  [Tunnel] Disconnected. Reconnecting...\n")
	}
}

// Start performs the initial handshake with the Meridian server and
// starts the SOCKS5 proxy listener.
func (c *Client) Start() error {
	// Start secure multiplexed tunnel maintenance in background
	go c.maintainTunnel()

	// ── Step 4: Start SOCKS5 proxy ────────────────────────────────────────
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		c.mu.RLock()
		t := c.tunnel
		c.mu.RUnlock()

		if t != nil && !t.closed.Load() {
			return t.DialStream(ctx, addr)
		}
		return nil, fmt.Errorf("tunnel not connected or unavailable")
	}

	c.proxy = NewSocks5Server(c.cfg.ListenAddr, "", "", dialFn)
	return c.proxy.Start()
}

// Stop closes the upstream tunnel connection and the SOCKS5 listener.
func (c *Client) Stop() {
	if c.proxy != nil {
		c.proxy.Stop()
	}
	c.mu.RLock()
	if c.tunnel != nil {
		c.tunnel.Close()
	}
	c.mu.RUnlock()
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
