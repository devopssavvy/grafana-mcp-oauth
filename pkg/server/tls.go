package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"grafana-mcp-oauth/pkg/config"
)

// KeyPairReloader provides thread-safe dynamic auto-reloading of TLS client certificates and private keys.
type KeyPairReloader struct {
	certPath    string
	keyPath     string
	mu          sync.RWMutex
	cert        *tls.Certificate
	modTimeCert time.Time
	modTimeKey  time.Time
	logger      *slog.Logger
}

// NewKeyPairReloader initializes a KeyPairReloader with initial validation of certificate files.
// It fails fast if either path is missing, unreadable, or invalid PEM syntax.
func NewKeyPairReloader(certPath, keyPath string, logger *slog.Logger) (*KeyPairReloader, error) {
	if certPath == "" && keyPath == "" {
		return nil, nil
	}
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("both REDIS_CERT_PATH and REDIS_KEY_PATH must be provided for mTLS")
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client keypair from %s and %s: %w", certPath, keyPath, err)
	}

	statCert, err := os.Stat(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat client cert %s: %w", certPath, err)
	}
	statKey, err := os.Stat(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat client key %s: %w", keyPath, err)
	}

	if logger == nil {
		logger = slog.Default()
	}

	return &KeyPairReloader{
		certPath:    certPath,
		keyPath:     keyPath,
		cert:        &cert,
		modTimeCert: statCert.ModTime(),
		modTimeKey:  statKey.ModTime(),
		logger:      logger,
	}, nil
}

// GetClientCertificate returns the currently loaded client certificate, automatically reloading
// from disk if the certificate or key file modification timestamps have changed.
// Disk I/O and key parsing are performed outside the write lock to prevent lock contention.
func (r *KeyPairReloader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	currentCert := r.cert
	modCert := r.modTimeCert
	modKey := r.modTimeKey
	r.mu.RUnlock()

	statCert, errCert := os.Stat(r.certPath)
	if errCert != nil {
		r.logger.Warn("Failed to stat Redis client certificate path during reload check",
			"cert_path", r.certPath,
			"error", errCert,
		)
	}
	statKey, errKey := os.Stat(r.keyPath)
	if errKey != nil {
		r.logger.Warn("Failed to stat Redis client private key path during reload check",
			"key_path", r.keyPath,
			"error", errKey,
		)
	}

	if errCert == nil && errKey == nil {
		if !statCert.ModTime().Equal(modCert) || !statKey.ModTime().Equal(modKey) {
			// Read and parse files from disk BEFORE acquiring write lock to avoid contention
			newCert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
			if err != nil {
				r.logger.Warn("Failed to reload Redis client keypair; retaining active certificate",
					"cert_path", r.certPath,
					"key_path", r.keyPath,
					"error", err,
				)
			} else {
				// Re-stat immediately to ensure timestamp matches loaded content
				if curStatCert, err := os.Stat(r.certPath); err == nil {
					statCert = curStatCert
				}
				if curStatKey, err := os.Stat(r.keyPath); err == nil {
					statKey = curStatKey
				}

				r.mu.Lock()
				if !statCert.ModTime().Before(r.modTimeCert) || !statKey.ModTime().Before(r.modTimeKey) {
					r.cert = &newCert
					r.modTimeCert = statCert.ModTime()
					r.modTimeKey = statKey.ModTime()
					currentCert = &newCert
					r.logger.Info("Successfully reloaded Redis client keypair",
						"cert_path", r.certPath,
						"key_path", r.keyPath,
					)
				} else {
					currentCert = r.cert
				}
				r.mu.Unlock()
			}
		}
	}

	if currentCert == nil {
		return nil, fmt.Errorf("no valid client certificate available")
	}
	return currentCert, nil
}

// CurrentCertificate returns the currently cached client certificate.
func (r *KeyPairReloader) CurrentCertificate() *tls.Certificate {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert
}

// BuildRedisTLSConfig constructs a *tls.Config configured with TLS 1.2+, Root CAs,
// dynamic client certificate reloader (mTLS), ServerName (SNI), and InsecureSkipVerify.
func BuildRedisTLSConfig(cfg *config.AppConfig, logger *slog.Logger) (*tls.Config, error) {
	if cfg == nil || !cfg.RedisTLSEnabled {
		return nil, nil
	}

	if logger == nil {
		logger = slog.Default()
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// 1. Root CAs (CA verification)
	if cfg.RedisCAPath != "" {
		caData, err := os.ReadFile(cfg.RedisCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read Redis CA certificate from %s: %w", cfg.RedisCAPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("failed to parse Redis CA certificate PEM from %s", cfg.RedisCAPath)
		}
		tlsConfig.RootCAs = pool
	} else {
		// When custom CA is omitted, attempt to load the system cert pool.
		// If SystemCertPool fails or is unavailable, leave RootCAs = nil so Go's crypto/tls
		// can lazily verify using host-specific roots, rather than injecting an empty pool.
		if pool, err := x509.SystemCertPool(); err == nil && pool != nil {
			tlsConfig.RootCAs = pool
		}
	}

	// 2. Client Certificates (mTLS) with dynamic reloader
	// Dynamic mTLS in Go crypto/tls relies solely on GetClientCertificate without static copies
	if cfg.RedisCertPath != "" || cfg.RedisKeyPath != "" {
		reloader, err := NewKeyPairReloader(cfg.RedisCertPath, cfg.RedisKeyPath, logger)
		if err != nil {
			return nil, err
		}
		tlsConfig.GetClientCertificate = reloader.GetClientCertificate
	}

	// 3. Server Name Indication (SNI)
	if cfg.RedisTLSServerName != "" {
		tlsConfig.ServerName = cfg.RedisTLSServerName
	} else if cfg.RedisAddr != "" {
		host, _, err := net.SplitHostPort(cfg.RedisAddr)
		if err == nil && host != "" && net.ParseIP(host) == nil {
			tlsConfig.ServerName = host
		}
	}

	// 4. Insecure Skip Verify (for local dev / testing)
	if cfg.RedisTLSInsecureSkipVerify {
		logger.Warn("CRITICAL SECURITY WARNING: REDIS_TLS_INSECURE_SKIP_VERIFY is enabled! Redis server certificate verification is disabled. Do NOT use this in production.")
		// #nosec G402 -- Configurable opt-in for development and test environments
		tlsConfig.InsecureSkipVerify = true
	}

	return tlsConfig, nil
}
