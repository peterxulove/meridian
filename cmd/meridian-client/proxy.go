package main

// ProxyServer is the interface for proxy servers (SOCKS5, HTTP)
type ProxyServer interface {
	Start() error
	Stop()
	Stats() (active int, total, failed, bytesIn, bytesOut uint64)
}
