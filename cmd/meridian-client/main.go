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

const (
	// minProxyConcurrency keeps the local listener at least as permissive as
	// the historical fixed limit.
	minProxyConcurrency = 512
	// maxProxyConcurrency bounds file-descriptor use on small routers.
	maxProxyConcurrency = 4096
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
	if len(cfg.TransportSchedule) == 0 {
		fmt.Printf("  Transport: %s\n", cfg.Transport)
	} else {
		fmt.Printf("  Transport: %s by default, scheduled:\n", cfg.Transport)
		for _, w := range cfg.TransportSchedule {
			fmt.Printf("             %s  %s-%s\n", w.Transport, w.From, w.To)
		}
	}
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
	// schedule switches the outer transport through the day; empty means the
	// static cfg.Transport is used for the client's whole life.
	schedule     []config.CompiledTransportWindow
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
	schedule, err := config.CompileTransportSchedule(cfg.TransportSchedule)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg:          cfg,
		tunnels:      make([]*TunnelClient, laneCount),
		laneSessions: sessions,
		schedule:     schedule,
		stopCh:       make(chan struct{}),
	}, nil
}

// desiredTransport is the transport the schedule asks for right now, or the
// configured one when no window matches.
func (c *Client) desiredTransport() config.TransportType {
	now := time.Now()
	for _, w := range c.schedule {
		if w.Contains(now) {
			return w.Transport
		}
	}
	return c.cfg.Transport
}

// scheduledSwitchGrace bounds how long a lane that was replaced by a schedule
// change keeps serving its existing streams. New streams go to the replacement
// immediately; this only decides when the old outermost connection is closed.
const scheduledSwitchGrace = 5 * time.Minute

func withTransport(cfg config.ClientConfig, t config.TransportType) config.ClientConfig {
	cfg.Transport = t
	return cfg
}

// retireLane stops a replaced lane from taking new streams and closes it once
// its streams finish, or when the grace expires.
func (c *Client) retireLane(lane int, tunnel *TunnelClient, grace time.Duration) {
	tunnel.draining.Store(true)
	deadline := time.Now().Add(grace)
	for !tunnel.closed.Load() {
		if tunnel.ActiveLoad() == 0 {
			tunnel.Close()
			return
		}
		if time.Now().After(deadline) {
			fmt.Printf("  [Tunnel %d/%d] Retired lane still had %d active at grace expiry, closing\n",
				lane+1, len(c.tunnels), tunnel.ActiveLoad())
			tunnel.Close()
			return
		}
		time.Sleep(time.Second)
	}
}

func (c *Client) maintainTunnel(lane int) {
	cfg := c.cfg
	cfg.SessionID = c.laneSessions[lane]
	store := mtp.NewSessionStore()
	active := c.desiredTransport()

	for !c.stopping.Load() {
		cfg.Transport = active
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

		lifetime := staggerLifetime(c.cfg.SessionLifetime, lane, len(c.tunnels))
		var drainDeadline time.Time
		for !tunnel.closed.Load() && !c.stopping.Load() {
			// A transport window boundary just passed. Build the replacement
			// on the new transport first and swap it in, so the lane never has
			// a gap where new streams have nowhere to go; only then retire the
			// old tunnel, which keeps serving the streams already on it.
			if want := c.desiredTransport(); want != active {
				replacement := NewTunnelClient(withTransport(cfg, want), store)
				if err := replacement.Connect(); err != nil {
					fmt.Printf("  [Tunnel %d/%d] Switch to %s failed: %v. Staying on %s.\n",
						lane+1, len(c.tunnels), want, err, active)
					time.Sleep(5 * time.Second)
					continue
				}
				c.mu.Lock()
				c.tunnels[lane] = replacement
				c.mu.Unlock()
				fmt.Printf("  [Tunnel %d/%d] Schedule switched %s -> %s (draining %d active)\n",
					lane+1, len(c.tunnels), active, want, tunnel.ActiveLoad())
				go c.retireLane(lane, tunnel, scheduledSwitchGrace)
				active = want
				tunnel = replacement
				drainDeadline = time.Time{}
				continue
			}
			// A lane that reaches session_lifetime stops taking new streams and
			// is closed once the streams already on it finish. This refreshes
			// the outer TCP/TLS connection periodically without cutting an
			// active download.
			if lifetime > 0 && !tunnel.Draining() && time.Since(tunnel.ConnectedAt()) >= lifetime {
				tunnel.draining.Store(true)
				drainDeadline = time.Now().Add(drainGrace(lifetime))
				fmt.Printf("  [Tunnel %d/%d] Session lifetime reached, draining (%d active)\n",
					lane+1, len(c.tunnels), tunnel.ActiveLoad())
			}
			if tunnel.Draining() && (tunnel.ActiveLoad() == 0 || time.Now().After(drainDeadline)) {
				if tunnel.ActiveLoad() > 0 {
					fmt.Printf("  [Tunnel %d/%d] Drain grace expired with %d active, closing\n",
						lane+1, len(c.tunnels), tunnel.ActiveLoad())
				}
				tunnel.Close()
				break
			}
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

// drainGrace bounds how long a draining lane may keep its remaining streams.
//
// It has to be generous: a lane is closed forcibly once the grace expires, and
// that kills whatever is running on it. With a 5 minute cap, a video playing
// on a lane that reached its lifetime was cut mid-stream roughly every
// lifetime/lanes minutes, which the player reports as an interruption. The
// lane takes no new streams while draining, so waiting for it to go idle is
// the normal path; the grace only bounds a stream that never ends.
func drainGrace(lifetime time.Duration) time.Duration {
	grace := lifetime / 2
	if grace < 5*time.Minute {
		grace = 5 * time.Minute
	}
	if grace > 30*time.Minute {
		grace = 30 * time.Minute
	}
	return grace
}

// staggerLifetime spreads lane deadlines so lanes that were opened together do
// not all drain at the same instant and leave the client without a tunnel.
// Lanes are offset by up to 15% of the configured lifetime.
func staggerLifetime(lifetime time.Duration, lane, lanes int) time.Duration {
	if lifetime <= 0 || lanes <= 1 || lane <= 0 {
		return lifetime
	}
	step := lifetime / 20
	return lifetime + step*time.Duration(lane)
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
		if tunnel == nil || tunnel.closed.Load() || tunnel.Draining() {
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
		if i == lane || candidate == nil || candidate == tunnel ||
			candidate.closed.Load() || candidate.Draining() {
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

	// The per-tunnel cap protects a single lane; the local proxy needs room
	// for every lane at once so a busy LAN is not throttled below the old
	// fixed limit.
	proxyLimit := int(c.cfg.MaxConcurrentStream) * len(c.tunnels)
	if proxyLimit < minProxyConcurrency {
		proxyLimit = minProxyConcurrency
	}
	if proxyLimit > maxProxyConcurrency {
		proxyLimit = maxProxyConcurrency
	}

	// ── Step 4: Start SOCKS5 proxy ────────────────────────────────────────
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return c.dial(ctx, network, addr)
	}

	switch c.cfg.ProxyProtocol {
	case "http":
		c.proxy = NewHttpProxyServer(c.cfg.ListenAddr, "", "", dialFn, proxyLimit)
	default:
		c.proxy = NewSocks5Server(c.cfg.ListenAddr, "", "", dialFn, proxyLimit)
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
