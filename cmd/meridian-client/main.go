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
func flagParse() (cfgPath, listen string, showFP bool) {
	flag.StringVar(&cfgPath, "config", "client.yaml", "path to client config file")
	flag.StringVar(&listen, "listen", "", "override local SOCKS5 listen address (e.g. 0.0.0.0:1080)")
	flag.BoolVar(&showFP, "fingerprints", false, "list available TLS fingerprints and exit")
	flag.Parse()
	return
}

// Client manages the Meridian upstream connection and the local SOCKS5 proxy.
type Client struct {
	cfg   config.ClientConfig
	udp   *net.UDPConn
	proxy *Socks5Server
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

// Start performs the initial handshake with the Meridian server and
// starts the SOCKS5 proxy listener.
func (c *Client) Start() error {
	// ── Step 1: Generate ephemeral ECDHE key pair ─────────────────────────
	ek, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("client: key generation failed: %w", err)
	}

	cr, err := crypto.GenerateRandom(32)
	if err != nil {
		return fmt.Errorf("client: failed to generate client random: %w", err)
	}
	var crArr [32]byte
	copy(crArr[:], cr)

	// ── Step 2: Build ClientHello ─────────────────────────────────────────
	_, err = mtp.BuildClientHello(c.cfg, &crArr, ek.PubKey)
	if err != nil {
		return fmt.Errorf("client: BuildClientHello failed: %w", err)
	}

	// ── Step 3: Dial Meridian server (QUIC/UDP) ───────────────────────────
	host, port, err := net.SplitHostPort(c.cfg.ServerAddr)
	if err != nil {
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
	c.udp = udp
	fmt.Printf("  [Tunnel] Connected to Meridian server at %s\n", c.cfg.ServerAddr)

	// ── Step 4: Start SOCKS5 proxy ────────────────────────────────────────
	// dialFn uses publicDialer (8.8.8.8 / 1.1.1.1) to resolve external hostnames,
	// bypassing the system's local DNS which may not resolve public domains.
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return publicDialer.DialContext(ctx, network, addr)
	}

	c.proxy = NewSocks5Server(c.cfg.ListenAddr, "", "", dialFn)
	return c.proxy.Start()
}

// Stop closes the upstream UDP connection and the SOCKS5 listener.
func (c *Client) Stop() {
	if c.proxy != nil {
		c.proxy.Stop()
	}
	if c.udp != nil {
		c.udp.Close()
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
