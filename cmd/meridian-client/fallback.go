// QUIC → WebSocket fallback.
//
// QUIC rides on UDP, which is the first thing an unfriendly path drops, and it
// fails in a way that is indistinguishable from the server being down: the
// handshake times out, or an established association dies with "no recent
// network activity". Retrying is the wrong response — every retry is sent into
// the same black hole, and the lane stays down for as long as the path keeps
// dropping it. The WebSocket transport shares the port and the handshake, so a
// lane that gives up on QUIC after a few attempts keeps working.
//
// The policy lives per lane, not per client: lanes fail independently, and the
// staggering this produces is exactly what keeps a single blocked window from
// taking every lane down at once.
package main

import (
	"time"

	"meridian/pkg/config"
)

// maxFallbackHold bounds the doubling of the hold so a path that has been
// blocked all evening is still re-probed once an hour.
const maxFallbackHold = time.Hour

// transportGuard decides which transport a lane should try next and remembers
// how badly the preferred one has been behaving.
type transportGuard struct {
	// primary is the transport failures are counted against, alt the one the
	// lane falls back to. Only QUIC has a cheap alternative on the same port,
	// so anything else leaves the guard inert.
	primary config.TransportType
	alt     config.TransportType

	after int           // consecutive failures that trip the fallback
	hold  time.Duration // first hold; doubles on each consecutive trip
	minUp time.Duration // uptime that makes a connection count as healthy

	fails int       // consecutive failures on primary
	trips int       // times the fallback has tripped without a healthy spell
	until time.Time // fallback deadline; zero means "on primary"

	now func() time.Time // injectable clock for tests
}

// newTransportGuard builds the fallback policy from the client config.
func newTransportGuard(cfg config.ClientConfig) *transportGuard {
	return &transportGuard{
		primary: config.TransportHysteria,
		alt:     config.TransportWebSocket,
		after:   cfg.QUICFallbackFailures,
		hold:    cfg.QUICFallbackHold,
		minUp:   cfg.QUICFallbackMinUptime,
		now:     time.Now,
	}
}

// enabled reports whether the fallback is configured at all.
func (g *transportGuard) enabled() bool {
	return g != nil && g.after > 0
}

// effective is the transport the lane should actually use right now, given what
// the schedule asks for.
func (g *transportGuard) effective(want config.TransportType) config.TransportType {
	if !g.enabled() || want != g.primary {
		return want
	}
	if g.holding() {
		return g.alt
	}
	return want
}

// holding reports whether the lane is parked on the fallback transport.
func (g *transportGuard) holding() bool {
	return g.enabled() && !g.until.IsZero() && g.now().Before(g.until)
}

// remaining is how long the current hold has left; zero when not holding.
func (g *transportGuard) remaining() time.Duration {
	if !g.holding() {
		return 0
	}
	return g.until.Sub(g.now())
}

// failure records one failed attempt on the given transport and reports
// whether that attempt tripped the fallback.
func (g *transportGuard) failure(used config.TransportType) bool {
	if !g.enabled() || used != g.primary {
		return false
	}
	g.fails++
	if g.fails < g.after {
		return false
	}
	return g.trip()
}

// ended records a connection that was established and later closed. A
// connection that carried traffic for at least minUp proves the transport
// works and clears the streak; anything shorter is another failure, because a
// handshake that immediately dies is what a blocked UDP path looks like.
func (g *transportGuard) ended(used config.TransportType, uptime time.Duration) bool {
	if !g.enabled() || used != g.primary {
		return false
	}
	if uptime >= g.minUp {
		g.fails = 0
		g.trips = 0
		g.until = time.Time{}
		return false
	}
	g.fails++
	if g.fails < g.after {
		return false
	}
	return g.trip()
}

// trip parks the lane on the fallback transport.
func (g *transportGuard) trip() bool {
	g.fails = 0
	g.trips++
	g.until = g.now().Add(g.holdFor(g.trips))
	return true
}

// holdFor is the hold length for the n-th consecutive trip: the configured
// value, doubled per trip, capped at maxFallbackHold.
func (g *transportGuard) holdFor(trips int) time.Duration {
	hold := g.hold
	for i := 1; i < trips; i++ {
		if hold >= maxFallbackHold {
			return maxFallbackHold
		}
		hold *= 2
	}
	if hold > maxFallbackHold {
		return maxFallbackHold
	}
	return hold
}
