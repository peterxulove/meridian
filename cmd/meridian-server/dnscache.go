package main

import (
	"context"
	"net"
	"sync"
	"time"
)

// dnsTTL is how long a resolved address set is reused. Media hosts rotate
// slowly, and a stale answer only costs one failed dial before the entry is
// dropped, so a minute is a safe trade for skipping a lookup on every new
// stream.
const dnsTTL = 60 * time.Second

// maxDNSEntries bounds the cache so a client cannot grow it without limit by
// cycling through hostnames.
const maxDNSEntries = 2048

type dnsEntry struct {
	addrs   []string
	expires time.Time
}

// dnsCache caches resolver answers and collapses concurrent lookups of the
// same host into one query. Without it every new stream pays a full lookup,
// which is visible as a few hundred milliseconds of extra start-up latency
// when a player opens several connections to a host it has not used yet.
type dnsCache struct {
	mu       sync.Mutex
	entries  map[string]dnsEntry
	inflight map[string]chan struct{}
	now      func() time.Time
	lookup   func(ctx context.Context, host string) ([]string, error)
}

func newDNSCache() *dnsCache {
	return &dnsCache{
		entries:  make(map[string]dnsEntry),
		inflight: make(map[string]chan struct{}),
		now:      time.Now,
		lookup:   systemLookup,
	}
}

func systemLookup(ctx context.Context, host string) ([]string, error) {
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

// Resolve returns cached addresses for host, or performs one lookup shared by
// every caller asking for the same host at the same time.
func (c *dnsCache) Resolve(ctx context.Context, host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}, nil
	}

	c.mu.Lock()
	if e, ok := c.entries[host]; ok && c.now().Before(e.expires) {
		addrs := e.addrs
		c.mu.Unlock()
		return addrs, nil
	}
	if wait, ok := c.inflight[host]; ok {
		c.mu.Unlock()
		select {
		case <-wait:
			return c.Resolve(ctx, host)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	done := make(chan struct{})
	c.inflight[host] = done
	c.mu.Unlock()

	addrs, err := c.lookup(ctx, host)

	c.mu.Lock()
	delete(c.inflight, host)
	if err == nil && len(addrs) > 0 {
		if len(c.entries) >= maxDNSEntries {
			c.pruneLocked()
		}
		c.entries[host] = dnsEntry{addrs: addrs, expires: c.now().Add(dnsTTL)}
	}
	c.mu.Unlock()
	close(done)

	return addrs, err
}

// Invalidate drops an entry so the next dial re-resolves. Called when a dial
// to every cached address failed.
func (c *dnsCache) Invalidate(host string) {
	c.mu.Lock()
	delete(c.entries, host)
	c.mu.Unlock()
}

func (c *dnsCache) pruneLocked() {
	now := c.now()
	for host, e := range c.entries {
		if now.After(e.expires) {
			delete(c.entries, host)
		}
	}
	if len(c.entries) >= maxDNSEntries {
		for host := range c.entries {
			delete(c.entries, host)
			if len(c.entries) < maxDNSEntries/2 {
				break
			}
		}
	}
}
