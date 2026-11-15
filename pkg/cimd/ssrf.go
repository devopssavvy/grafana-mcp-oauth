package cimd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	blockedIPv4CIDRs []*net.IPNet
	blockedIPv6CIDRs []*net.IPNet
)

func init() {
	ipv4CIDRs := []string{
		"0.0.0.0/8",          // Current network (RFC 1122)
		"10.0.0.0/8",         // Private network (RFC 1918)
		"100.64.0.0/10",      // Shared address space (RFC 6598 - Carrier-grade NAT)
		"127.0.0.0/8",        // Loopback (RFC 1122)
		"169.254.0.0/16",     // Link-local / Cloud metadata (AWS, GCP, Azure 169.254.169.254)
		"172.16.0.0/12",      // Private network (RFC 1918)
		"192.0.0.0/24",       // IETF Protocol Assignments
		"192.0.2.0/24",       // Documentation (TEST-NET-1)
		"192.168.0.0/16",     // Private network (RFC 1918)
		"198.18.0.0/15",      // Network benchmark tests
		"198.51.100.0/24",    // Documentation (TEST-NET-2)
		"203.0.113.0/24",     // Documentation (TEST-NET-3)
		"224.0.0.0/4",        // Multicast
		"240.0.0.0/4",        // Reserved
		"255.255.255.255/32", // Broadcast
	}

	ipv6CIDRs := []string{
		"::/128",        // Unspecified
		"::1/128",       // Loopback
		"64:ff9b::/96",  // IPv4/IPv6 translation
		"64:ff9b:1::/48", // Local-use IPv4/IPv6 translation (RFC 8215)
		"100::/64",      // Discard prefix
		"2001::/23",     // IETF Protocol Assignments
		"2001:db8::/32", // Documentation
		"fc00::/7",      // Unique Local Address (ULA)
		"fe80::/10",     // Link-local unicast
		"ff00::/8",      // Multicast
	}

	for _, c := range ipv4CIDRs {
		_, ipNet, err := net.ParseCIDR(c)
		if err == nil {
			blockedIPv4CIDRs = append(blockedIPv4CIDRs, ipNet)
		}
	}

	for _, c := range ipv6CIDRs {
		_, ipNet, err := net.ParseCIDR(c)
		if err == nil {
			blockedIPv6CIDRs = append(blockedIPv6CIDRs, ipNet)
		}
	}
}

// IsBlockedIP returns true if the IP address belongs to a private, loopback, or reserved range.
func IsBlockedIP(ip net.IP, allowLoopback bool) bool {
	if ip == nil {
		return true
	}

	if allowLoopback && ip.IsLoopback() {
		return false
	}

	// Handle IPv4
	if ip4 := ip.To4(); ip4 != nil {
		for _, cidr := range blockedIPv4CIDRs {
			if cidr.Contains(ip4) {
				if allowLoopback && cidr.String() == "127.0.0.0/8" {
					continue
				}
				return true
			}
		}
		return false
	}

	// Handle IPv6
	for _, cidr := range blockedIPv6CIDRs {
		if cidr.Contains(ip) {
			if allowLoopback && cidr.String() == "::1/128" {
				continue
			}
			return true
		}
	}

	return false
}

// NewSSRFSafeClient creates an http.Client configured with DNS resolution verification,
// strict timeouts, no redirects (per CIMD draft BCP), and custom DialContext preventing SSRF.
func NewSSRFSafeClient(timeout time.Duration, allowLoopback bool) *http.Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	resolver := &net.Resolver{
		PreferGo: true,
	}

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		Proxy:                 nil, // Disable proxies to prevent proxy bypass SSRF
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address %q: %w", addr, err)
			}

			// If host is an IP literal
			if ip := net.ParseIP(host); ip != nil {
				if IsBlockedIP(ip, allowLoopback) {
					return nil, fmt.Errorf("blocked IP address: %s", ip)
				}
				return dialer.DialContext(ctx, network, addr)
			}

			// Special case for localhost hostname when loopback is allowed
			if allowLoopback && strings.EqualFold(host, "localhost") {
				return dialer.DialContext(ctx, network, addr)
			}

			// Resolve host
			ips, err := resolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("no IP addresses resolved for %s", host)
			}

			// Check all resolved IPs; if any is blocked, reject
			var safeIPs []net.IP
			for _, ip := range ips {
				if IsBlockedIP(ip, allowLoopback) {
					return nil, fmt.Errorf("host %s resolved to blocked IP %s", host, ip)
				}
				safeIPs = append(safeIPs, ip)
			}

			// Dial validated safe IPs with fallback (dual-stack IPv6/IPv4 support)
			var lastErr error
			for _, sip := range safeIPs {
				safeAddr := net.JoinHostPort(sip.String(), port)
				conn, err := dialer.DialContext(ctx, network, safeAddr)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, fmt.Errorf("failed to connect to resolved IPs for %s: %w", host, lastErr)
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Per draft-ietf-oauth-client-id-metadata-document Section 3:
			// Authorization servers SHOULD NOT follow redirects when fetching client metadata documents.
			return fmt.Errorf("redirects are not permitted when fetching CIMD metadata: %s", req.URL)
		},
	}
}
