package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSCacheReusesAnswerUntilExpiry(t *testing.T) {
	var calls int64
	now := time.Unix(1700000000, 0)
	c := newDNSCache()
	c.now = func() time.Time { return now }
	c.lookup = func(context.Context, string) ([]string, error) {
		atomic.AddInt64(&calls, 1)
		return []string{"10.0.0.1"}, nil
	}

	for i := 0; i < 5; i++ {
		addrs, err := c.Resolve(context.Background(), "media.example.com")
		if err != nil || len(addrs) != 1 {
			t.Fatalf("resolve %d: %v %v", i, addrs, err)
		}
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("lookups = %d, want 1 (answer should be cached)", got)
	}

	now = now.Add(dnsTTL + time.Second)
	if _, err := c.Resolve(context.Background(), "media.example.com"); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Fatalf("lookups = %d, want 2 after expiry", got)
	}
}

func TestDNSCacheCollapsesConcurrentLookups(t *testing.T) {
	var calls int64
	release := make(chan struct{})
	c := newDNSCache()
	c.lookup = func(context.Context, string) ([]string, error) {
		atomic.AddInt64(&calls, 1)
		<-release
		return []string{"10.0.0.2"}, nil
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Resolve(context.Background(), "burst.example.com"); err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("lookups = %d, want 1 for 16 concurrent resolves", got)
	}
}

func TestDNSCacheInvalidateAndLiteral(t *testing.T) {
	var calls int64
	c := newDNSCache()
	c.lookup = func(context.Context, string) ([]string, error) {
		atomic.AddInt64(&calls, 1)
		return []string{"10.0.0.3"}, nil
	}

	if _, err := c.Resolve(context.Background(), "a.example.com"); err != nil {
		t.Fatal(err)
	}
	c.Invalidate("a.example.com")
	if _, err := c.Resolve(context.Background(), "a.example.com"); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Fatalf("lookups = %d, want 2 after invalidate", got)
	}

	// A literal address must never hit the resolver.
	addrs, err := c.Resolve(context.Background(), "192.0.2.7")
	if err != nil || len(addrs) != 1 || addrs[0] != "192.0.2.7" {
		t.Fatalf("literal resolve = %v %v", addrs, err)
	}
	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Fatalf("lookups = %d, want 2 (literal must not resolve)", got)
	}
}

func TestDNSCacheDoesNotCacheErrors(t *testing.T) {
	var calls int64
	c := newDNSCache()
	c.lookup = func(context.Context, string) ([]string, error) {
		if atomic.AddInt64(&calls, 1) == 1 {
			return nil, errors.New("temporary failure")
		}
		return []string{"10.0.0.4"}, nil
	}

	if _, err := c.Resolve(context.Background(), "flaky.example.com"); err == nil {
		t.Fatal("expected the first resolve to fail")
	}
	addrs, err := c.Resolve(context.Background(), "flaky.example.com")
	if err != nil || len(addrs) != 1 {
		t.Fatalf("second resolve = %v %v", addrs, err)
	}
}
