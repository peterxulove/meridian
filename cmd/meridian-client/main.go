// Meridian client CLI entrypoint.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"meridian/pkg/anti"
	"meridian/pkg/config"
	"meridian/pkg/crypto"
	"meridian/pkg/mtp"
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
		fmt.Printf("Meridian Client %s (%s)\n", Version, BuildTime)
		return
	}
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

	fmt.Printf("Meridian Client %s\n", Version)
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
	notifySignals(sigch)

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
func flagParse() (cfgPath, listen string, showFP, showVersion bool, debug bool) {
	flag.StringVar(&cfgPath, "config", "client.yaml", "path to client config file")
	flag.StringVar(&listen, "listen", "", "override local SOCKS5 listen address (e.g. 0.0.0.0:1080)")
	flag.BoolVar(&showFP, "fingerprints", false, "list available TLS fingerprints and exit")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
	flag.Parse()
	return
}

// Client manages the Meridian upstream connection and the local SOCKS5 proxy.
type Client struct {
	cfg          config.ClientConfig
	mu           sync.RWMutex
	tunnels      []*TunnelClient
	laneSessions [][16]byte
	tunnelCursor atomic.Uint32
	stopping     atomic.Bool
	stopCh       chan struct{}
	stopOnce     sync.Once
	proxy        ProxyServer
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
	laneCount := config.NormalizeTunnelConnections(cfg.TunnelConnections)
	cfg.TunnelConnections = laneCount
	sessions := make([][16]byte, laneCount)
	sessions[0] = cfg.SessionID
	for i := 1; i < laneCount; i++ {
		b, err := crypto.GenerateRandom(16)
		if err != nil {
			return nil, fmt.Errorf("client: failed to generate lane session ID: %w", err)
		}
		copy(sessions[i][:], b)
	}
	return &Client{
		cfg:          cfg,
		tunnels:      make([]*TunnelClient, laneCount),
		laneSessions: sessions,
		stopCh:       make(chan struct{}),
	}, nil
}

func (c *Client) maintainTunnel(lane int) {
	cfg := c.cfg
	cfg.SessionID = c.laneSessions[lane]
	store := mtp.NewSessionStore()

	for !c.stopping.Load() {
		tunnel := NewTunnelClient(cfg, store)
		if err := tunnel.Connect(); err != nil {
			fmt.Printf("  [Tunnel %d/%d] Connection failed: %v. Retrying in 5s...\n",
				lane+1, len(c.tunnels), err)
			select {
			case <-time.After(5 * time.Second):
			case <-c.stopCh:
				return
			}
			continue
		}

		c.mu.Lock()
		c.tunnels[lane] = tunnel
		c.mu.Unlock()

		for !tunnel.closed.Load() && !c.stopping.Load() {
			time.Sleep(1 * time.Second)
		}
		c.mu.Lock()
		if c.tunnels[lane] == tunnel {
			c.tunnels[lane] = nil
		}
		c.mu.Unlock()
		if !c.stopping.Load() {
			fmt.Printf("  [Tunnel %d/%d] Disconnected. Reconnecting...\n", lane+1, len(c.tunnels))
		}
	}
}

func (c *Client) pickTunnel() (*TunnelClient, int) {
	c.mu.RLock()
	tunnels := make([]*TunnelClient, len(c.tunnels))
	copy(tunnels, c.tunnels)
	c.mu.RUnlock()

	start := int(c.tunnelCursor.Add(1)-1) % len(tunnels)
	var best *TunnelClient
	bestLane := -1
	var bestLoad int64

	for offset := 0; offset < len(tunnels); offset++ {
		lane := (start + offset) % len(tunnels)
		tunnel := tunnels[lane]
		if tunnel == nil || tunnel.closed.Load() {
			continue
		}
		load := tunnel.ActiveLoad()
		if best == nil || load < bestLoad {
			best = tunnel
			bestLane = lane
			bestLoad = load
		}
	}
	return best, bestLane
}

func (c *Client) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	tunnel, lane := c.pickTunnel()
	if tunnel == nil {
		return nil, fmt.Errorf("tunnel not connected or unavailable")
	}

	conn, err := tunnel.DialStream(ctx, addr)
	if err == nil {
		return conn, nil
	}

	// A lane may have died between selection and use. Try the remaining lanes
	// once so a transient reconnect does not surface as a proxy failure.
	c.mu.RLock()
	tunnels := make([]*TunnelClient, len(c.tunnels))
	copy(tunnels, c.tunnels)
	c.mu.RUnlock()
	for i, candidate := range tunnels {
		if i == lane || candidate == nil || candidate == tunnel || candidate.closed.Load() {
			continue
		}
		if next, nextErr := candidate.DialStream(ctx, addr); nextErr == nil {
			return next, nil
		}
	}
	return nil, err
}

// Start performs the initial handshake with the Meridian server and
// starts the SOCKS5 proxy listener.
func (c *Client) Start() error {
	for lane := range c.tunnels {
		go c.maintainTunnel(lane)
	}

	// ── Step 4: Start SOCKS5 proxy ────────────────────────────────────────
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return c.dial(ctx, network, addr)
	}

	switch c.cfg.ProxyProtocol {
	case "http":
		c.proxy = NewHttpProxyServer(c.cfg.ListenAddr, "", "", dialFn)
	default:
		c.proxy = NewSocks5Server(c.cfg.ListenAddr, "", "", dialFn)
	}
	return c.proxy.Start()
}

// Stop closes the upstream tunnel connection and the SOCKS5 listener.
func (c *Client) Stop() {
	c.stopOnce.Do(func() {
		c.stopping.Store(true)
		close(c.stopCh)
	})
	if c.proxy != nil {
		c.proxy.Stop()
	}
	c.mu.RLock()
	tunnels := make([]*TunnelClient, len(c.tunnels))
	copy(tunnels, c.tunnels)
	c.mu.RUnlock()
	for _, tunnel := range tunnels {
		if tunnel != nil {
			tunnel.Close()
		}
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
