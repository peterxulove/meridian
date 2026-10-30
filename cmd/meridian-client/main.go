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

	// Install the log sink before anything else logs: a router's syslog ring
	// is small enough that a burst of errors erases its own evidence, so the
	// file is where the timeline has to live.
	if err := setupLogging(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cannot open log file %q: %v\n", cfg.LogFile, err)
	} else if cfg.LogFile != "" {
		defer closeLogging()
	}
	if logSetupWarning != nil {
		logf("[warn] log_timezone ignored: %v", logSetupWarning)
	}

	logf("Meridian Client %s", Version)
	logf("  Server:    %s", cfg.ServerAddr)
	if len(cfg.TransportSchedule) == 0 {
		logf("  Transport: %s", cfg.Transport)
	} else {
		logf("  Transport: %s by default, scheduled:", cfg.Transport)
		for _, w := range cfg.TransportSchedule {
			logf("             %s  %s-%s", w.Transport, w.From, w.To)
		}
	}
	logf("  Cipher:    %s", cfg.CipherSuite)
	logf("  SOCKS5:    %s", cfg.ListenAddr)
	if cfg.StreamIdleTimeout > 0 {
		logf("  Idle:      reclaim streams silent for %v", cfg.StreamIdleTimeout)
	} else {
		logf("  Idle:      reclamation disabled")
	}
	if cfg.MaxPendingDials > 0 {
		logf("  Dial cap:  %d pending per lane", cfg.MaxPendingDials)
	} else {
		logf("  Dial cap:  unlimited")
	}
	if usesQUIC(cfg) {
		if cfg.QUICFallbackFailures > 0 {
			logf("  Fallback:  %d QUIC failures in a row => WebSocket for %v (min uptime %v)",
				cfg.QUICFallbackFailures, cfg.QUICFallbackHold, cfg.QUICFallbackMinUptime)
		} else {
			logf("  Fallback:  disabled, QUIC failures retry forever")
		}
	}
	if cfg.FirstByteTimeout > 0 {
		if cfg.FirstByteFailures > 0 {
			logf("  Watchdog:  stream reset if the server says nothing for %v; %d in a row reconnect the lane",
				cfg.FirstByteTimeout, cfg.FirstByteFailures)
		} else {
			logf("  Watchdog:  stream reset if the server says nothing for %v", cfg.FirstByteTimeout)
		}
	} else {
		logf("  Watchdog:  disabled")
	}

	client, err := NewClient(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create client: %v\n", err)
		os.Exit(1)
	}
	if len(cfg.TransportSchedule) > 0 {
		now := time.Now().In(client.scheduleLoc)
		logf("  Schedule:  now %s %s (UTC%s) => %s",
			now.Format("15:04"), client.scheduleLoc, now.Format("-07:00"), client.desiredTransport())
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
	logf("Client running (PID %d). Press Ctrl+C to stop.", os.Getpid())

	// Failure/interaction counters are reported once per interval, not once per
	// connection: the per-connection form flooded the log badly enough to push
	// out the very window it described.
	stopEvents := make(chan struct{})
	startEventReporter(summaryInterval, stopEvents)

	// Print stats every 60 seconds
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for range ticker.C {
			active, total, failed, in, out := client.proxy.Stats()
			logf("  [Stats] active=%d total=%d failed=%d in=%dKB out=%dKB",
				active, total, failed, in/1024, out/1024)
		}
	}()

	<-sigch
	ticker.Stop()
	close(stopEvents)
	logf("Shutting down...")
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
	scheduleLoc  *time.Location
	tunnelCursor atomic.Uint32
	stopping     atomic.Bool
	stopCh       chan struct{}
	stopOnce     sync.Once
	proxy        ProxyServer
	// staleLogAt throttles the "serving on a retired lane" warning to one line
	// per minute while a rotation is in progress.
	staleLogAt atomic.Int64
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
	scheduleLoc, err := config.LoadScheduleLocation(cfg.ScheduleTimezone)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg:          cfg,
		tunnels:      make([]*TunnelClient, laneCount),
		laneSessions: sessions,
		schedule:     schedule,
		scheduleLoc:  scheduleLoc,
		stopCh:       make(chan struct{}),
	}, nil
}

// usesQUIC reports whether this config may run on QUIC at some point of the
// day. It only decides whether the fallback policy is worth a log line.
func usesQUIC(cfg config.ClientConfig) bool {
	if cfg.Transport == config.TransportHysteria {
		return true
	}
	for _, w := range cfg.TransportSchedule {
		if w.Transport == config.TransportHysteria {
			return true
		}
	}
	return false
}

// desiredTransport is the transport the schedule asks for right now, or the
// configured one when no window matches.
func (c *Client) desiredTransport() config.TransportType {
	now := time.Now().In(c.scheduleLoc)
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
// its streams finish, or when the grace expires with nothing still moving.
//
// The grace is not a hard deadline. A retired lane no longer accepts streams,
// so the only thing holding it is a transfer that is still running — exactly
// the video that used to be cut every time its lane came up for rotation. Each
// expiry is therefore re-armed while some stream has moved a byte recently;
// a lane whose streams have all gone quiet is closed on schedule.
func (c *Client) retireLane(lane int, tunnel *TunnelClient, grace time.Duration) {
	tunnel.draining.Store(true)
	deadline := time.Now().Add(grace)
	for !tunnel.closed.Load() {
		if tunnel.ActiveLoad() == 0 {
			tunnel.Close()
			return
		}
		if time.Now().After(deadline) {
			if n := tunnel.ActiveWithin(drainActiveWindow); n > 0 {
				deadline = time.Now().Add(grace)
				logf("[Tunnel %d/%d] retired lane still moving %d/%d streams, holding it for another %v",
					lane+1, len(c.tunnels), n, tunnel.ActiveLoad(), grace)
				time.Sleep(time.Second)
				continue
			}
			logf("[Tunnel %d/%d] retired lane had %d stalled streams at grace expiry, closing",
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
	guard := newTransportGuard(c.cfg)
	active := guard.effective(c.desiredTransport())

	for !c.stopping.Load() {
		cfg.Transport = active
		tunnel := NewTunnelClient(cfg, store)
		if err := tunnel.Connect(); err != nil {
			logf("[Tunnel %d/%d] %s connect failed: %v, retrying in 5s",
				lane+1, len(c.tunnels), active, err)
			if guard.failure(active) {
				next := guard.effective(c.desiredTransport())
				logf("[Tunnel %d/%d] %s failed %d times in a row, falling back to %s for %v",
					lane+1, len(c.tunnels), active, guard.after, next, guard.remaining().Round(time.Second))
				active = next
				continue
			}
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
		for !tunnel.closed.Load() && !c.stopping.Load() {
			// A transport window boundary just passed, or the fallback hold on
			// this lane ended. Build the replacement on the new transport
			// first and swap it in, so the lane never has a gap where new
			// streams have nowhere to go; only then retire the old tunnel,
			// which keeps serving the streams already on it.
			if target := guard.effective(c.desiredTransport()); target != active {
				replacement := NewTunnelClient(withTransport(cfg, target), store)
				if err := replacement.Connect(); err != nil {
					logf("[Tunnel %d/%d] switch to %s failed: %v, staying on %s",
						lane+1, len(c.tunnels), target, err, active)
					if guard.failure(target) {
						logf("[Tunnel %d/%d] %s still unreachable after %d tries, staying on %s for %v",
							lane+1, len(c.tunnels), target, guard.after, active,
							guard.remaining().Round(time.Second))
					}
					time.Sleep(5 * time.Second)
					continue
				}
				c.mu.Lock()
				c.tunnels[lane] = replacement
				c.mu.Unlock()
				logf("[Tunnel %d/%d] transport switched %s -> %s (draining %d active)",
					lane+1, len(c.tunnels), active, target, tunnel.ActiveLoad())
				go c.retireLane(lane, tunnel, scheduledSwitchGrace)
				active = target
				tunnel = replacement
				continue
			}
			// A lane that reaches session_lifetime rotates its outer connection:
			// the successor is built and put in place first, then this lane is
			// retired with the streams it still carries.
			//
			// Draining in place instead — stop taking streams, close when the
			// last one finishes — looks equivalent and is not: it relies on the
			// other lanes to accept everything in the meantime. On router 111
			// four lanes reached their 1h lifetime three minutes apart while
			// each still carried long-lived streams (Telegram), so all four
			// were draining at once. Nothing accepted a new connection and the
			// proxy answered "tunnel not connected" for every request until the
			// 30m grace expired. The lane now hands over, it does not step
			// aside.
			if lifetime > 0 && time.Since(tunnel.ConnectedAt()) >= lifetime {
				replacement := NewTunnelClient(withTransport(cfg, active), store)
				if err := replacement.Connect(); err != nil {
					logf("[Tunnel %d/%d] rotation failed: %v, still serving on the current connection",
						lane+1, len(c.tunnels), err)
					if guard.failure(active) {
						next := guard.effective(c.desiredTransport())
						logf("[Tunnel %d/%d] %s failed %d times in a row, falling back to %s for %v",
							lane+1, len(c.tunnels), active, guard.after, next,
							guard.remaining().Round(time.Second))
						active = next
						continue
					}
					time.Sleep(5 * time.Second)
					continue
				}
				c.mu.Lock()
				c.tunnels[lane] = replacement
				c.mu.Unlock()
				logf("[Tunnel %d/%d] session lifetime reached, rotating (draining %d active)",
					lane+1, len(c.tunnels), tunnel.ActiveLoad())
				go c.retireLane(lane, tunnel, drainGrace(lifetime))
				tunnel = replacement
				continue
			}
			time.Sleep(1 * time.Second)
		}
		c.mu.Lock()
		if c.tunnels[lane] == tunnel {
			c.tunnels[lane] = nil
		}
		c.mu.Unlock()
		if c.stopping.Load() {
			return
		}
		// A connection that carried traffic for a while proves the transport
		// works; one that died sooner is a failure like a refused handshake,
		// and enough of them move the lane to the fallback transport.
		uptime := time.Since(tunnel.ConnectedAt())
		used := active
		if guard.ended(used, uptime) {
			active = guard.effective(c.desiredTransport())
			logf("[Tunnel %d/%d] %s kept dropping (last one after %v), falling back to %s for %v",
				lane+1, len(c.tunnels), used, uptime.Round(time.Second), active,
				guard.remaining().Round(time.Second))
		}
		logf("[Tunnel %d/%d] %s disconnected after %v, reconnecting",
			lane+1, len(c.tunnels), used, uptime.Round(time.Second))
	}
}

// drainActiveWindow is how recently a stream must have moved a byte for the
// drain path to treat it as alive. Two minutes is far above the gap between
// chunks of a playing video and far below any pause a viewer takes, so a
// paused stream still counts as stalled and the lane is released.
const drainActiveWindow = 2 * time.Minute

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
	if best != nil {
		return best, bestLane
	}

	// Every lane has been retired but at least one is still open, carrying the
	// streams it had when it rotated. Refusing the connection at this point is
	// what turned a slow lane rotation into a whole-proxy outage: the caller
	// gets "tunnel not connected" even though a retired lane would have served
	// the request perfectly well. Prefer a fresh lane, but never prefer
	// nothing.
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
	if best != nil {
		c.noteStaleLane(len(tunnels), bestLane, bestLoad)
	}
	return best, bestLane
}

// noteStaleLane reports that no fresh lane was available, at most once a
// minute: the condition lasts as long as a rotation does, and a line per
// connection would bury it.
func (c *Client) noteStaleLane(lanes, lane int, load int64) {
	now := time.Now().Unix()
	last := c.staleLogAt.Load()
	if now-last < 60 || !c.staleLogAt.CompareAndSwap(last, now) {
		return
	}
	logf("[Proxy] no fresh lane, serving on retired lane %d/%d (%d active)", lane+1, lanes, load)
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
