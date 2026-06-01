// Meridian server — high-performance, anti-detection secure proxy.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"meridian/pkg/config"
	"meridian/pkg/crypto"
	"meridian/pkg/mfp"
	"meridian/pkg/mtp"
	"meridian/pkg/transport"
)

// Server manages Meridian connections.
type Server struct {
	cfg     config.ServerConfig
	udp     *net.UDPConn
	conns   sync.Map
	stopped atomic.Bool
	wg      sync.WaitGroup
	stats   ServerStats
}

// ServerStats tracks connection metrics.
type ServerStats struct {
	Active  atomic.Uint64
	Handled atomic.Uint64
	In      atomic.Uint64
	Out     atomic.Uint64
}

// NewServer creates a new Meridian server.
func NewServer(cfg config.ServerConfig) (*Server, error) {
	return &Server{cfg: cfg}, nil
}

// Start begins listening on the configured address.
func (s *Server) Start() error {
	if s.cfg.Transport == config.TransportWebSocket {
		return s.startWS()
	}
	return s.startQUIC()
}

func (s *Server) startQUIC() error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	s.udp, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		buf := make([]byte, 1500)
		for {
			if s.stopped.Load() {
				break
			}
			s.udp.SetReadDeadline(time.Now().Add(time.Second))
			n, remote, err := s.udp.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				if !s.stopped.Load() {
					fmt.Printf("  [UDP] Read error: %v\n", err)
				}
				continue
			}
			// Copy packet so the goroutine can use it safely.
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			go s.handlePacket(pkt, remote)
		}
	}()
	return nil
}

func (s *Server) startWS() error {
	// WebSocket listener is not yet fully implemented.
	// The stub returns an error so the caller knows it's unavailable.
	return fmt.Errorf("server: WebSocket transport not yet implemented")
}

func (s *Server) handlePacket(data []byte, remote *net.UDPAddr) {
	if len(data) < 14 {
		return
	}

	// Fix #24: use crypto.Magic constant instead of a duplicated literal.
	if binary.BigEndian.Uint32(data[0:4]) != crypto.Magic {
		return
	}

	s.stats.Handled.Add(1)
	s.stats.In.Add(uint64(len(data)))

	// Distinguish handshake packets (version byte at offset 4) from data frames.
	if data[4] == crypto.CurrentVersion {
		s.doHandshake(data, remote)
	} else {
		frame, err := mfp.ParseFrame(data)
		if err == nil {
			s.forwardFrame(frame, remote)
		}
	}
}

func (s *Server) doHandshake(data []byte, remote *net.UDPAddr) {
	// Parse client hello using the fixed MTP parser.
	hs, err := mtp.ParseClientHello(data)
	if err != nil {
		fmt.Printf("  [Handshake] Parse error from %s: %v\n", remote, err)
		return
	}

	// Generate server ECDHE key pair.
	// Fix: GenerateKeyPair now returns (*KeyPair, error) after the crypto fix.
	serverEK, err := crypto.GenerateKeyPair()
	if err != nil {
		fmt.Printf("  [Handshake] Key generation failed: %v\n", err)
		return
	}

	// Compute shared secret via X25519.
	shared, err := crypto.SharedKey(
		&crypto.KeyPair{PrivKey: serverEK.PrivKey},
		hs.ClientECDHE,
	)
	if err != nil {
		fmt.Printf("  [Handshake] SharedKey failed: %v\n", err)
		return
	}

	// Generate server random.
	serverRandomBytes, err := crypto.GenerateRandom(32)
	if err != nil {
		fmt.Printf("  [Handshake] GenerateRandom failed: %v\n", err)
		return
	}
	var serverRandom [32]byte
	copy(serverRandom[:], serverRandomBytes)

	// Derive session keys.
	keys, err := crypto.DeriveKeys(shared, hs.ClientRandom, serverRandom)
	if err != nil {
		fmt.Printf("  [Handshake] DeriveKeys failed: %v\n", err)
		return
	}
	_ = keys // keys used by the per-connection encoder/decoder (not yet wired)

	s.stats.Active.Add(1)
	defer s.stats.Active.Add(^uint64(0))

	fmt.Printf("  [Handshake] OK from %s cipher=MERIDIAN-CHACHA\n", remote.String())
	// TODO: send ServerHello with serverRandom, serverEK.PubKey, negotiated cipher, derived keys.
}

func (s *Server) forwardFrame(frame *mfp.DataFrame, remote *net.UDPAddr) {
	// TODO: look up the session by remote address, decrypt, and forward to the
	// configured upstream destination.
	_ = frame
	_ = remote
}

// Stop signals the server to shut down and waits for all goroutines to exit.
func (s *Server) Stop() {
	s.stopped.Store(true)
	if s.udp != nil {
		s.udp.Close()
	}
	s.conns.Range(func(k, v interface{}) bool {
		if c, ok := v.(io.Closer); ok {
			c.Close()
		}
		return true
	})
	s.wg.Wait()
}

// Stats returns the current server statistics.
func (s *Server) Stats() (active, handled, bytesIn, bytesOut uint64) {
	return s.stats.Active.Load(), s.stats.Handled.Load(),
		s.stats.In.Load(), s.stats.Out.Load()
}

func (s *Server) writeCertKey(certFile, keyFile string) error {
	_, err := crypto.LoadCert(certFile, keyFile)
	return err
}

func splitHostPort(addr string) (string, string) {
	h, p, _ := net.SplitHostPort(addr)
	return h, p
}

// Compile-time checks that referenced symbols exist.
var (
	_ = transport.TLSConfig
	_ = mtp.BuildClientHello
	_ = mfp.NewFramePool
)
