package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grafana-mcp-oauth/pkg/config"
	"grafana-mcp-oauth/pkg/server"
)

// Helper: generates a self-signed CA certificate and private key.
func generateTestCA(t *testing.T) ([]byte, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Redis CA",
			Organization: []string{"Grafana MCP Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return certPEM, priv, caCert
}

// Helper: generates a client certificate signed by the test CA.
func generateTestCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, commonName string, serial int64) ([]byte, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Grafana MCP Test Client"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &priv.PublicKey, caKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM
}

func TestBuildRedisTLSConfig_Disabled(t *testing.T) {
	cfg := &config.AppConfig{
		RedisTLSEnabled: false,
	}

	tlsConfig, err := server.BuildRedisTLSConfig(cfg, nil)
	require.NoError(t, err)
	assert.Nil(t, tlsConfig)
}

func TestBuildRedisTLSConfig_OneWayTLS_SystemCA(t *testing.T) {
	cfg := &config.AppConfig{
		RedisTLSEnabled: true,
	}

	tlsConfig, err := server.BuildRedisTLSConfig(cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	assert.NotNil(t, tlsConfig.RootCAs)
	assert.Nil(t, tlsConfig.GetClientCertificate)
	assert.False(t, tlsConfig.InsecureSkipVerify)
	assert.Empty(t, tlsConfig.ServerName)
}

func TestBuildRedisTLSConfig_OneWayTLS_CustomCA(t *testing.T) {
	caPEM, _, _ := generateTestCA(t)

	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.crt")
	require.NoError(t, os.WriteFile(caPath, caPEM, 0600))

	cfg := &config.AppConfig{
		RedisTLSEnabled: true,
		RedisCAPath:     caPath,
	}

	tlsConfig, err := server.BuildRedisTLSConfig(cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	assert.NotNil(t, tlsConfig.RootCAs)
}

func TestBuildRedisTLSConfig_CustomCA_Errors(t *testing.T) {
	t.Run("file not found", func(t *testing.T) {
		cfg := &config.AppConfig{
			RedisTLSEnabled: true,
			RedisCAPath:     "/nonexistent/ca.crt",
		}
		_, err := server.BuildRedisTLSConfig(cfg, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read Redis CA certificate")
	})

	t.Run("invalid PEM", func(t *testing.T) {
		tmpDir := t.TempDir()
		invalidPath := filepath.Join(tmpDir, "invalid.crt")
		require.NoError(t, os.WriteFile(invalidPath, []byte("NOT_A_PEM_CERTIFICATE"), 0600))

		cfg := &config.AppConfig{
			RedisTLSEnabled: true,
			RedisCAPath:     invalidPath,
		}
		_, err := server.BuildRedisTLSConfig(cfg, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse Redis CA certificate PEM")
	})
}

func TestBuildRedisTLSConfig_mTLS_Validation(t *testing.T) {
	caPEM, caKey, caCert := generateTestCA(t)
	certPEM, keyPEM := generateTestCert(t, caCert, caKey, "mcp-proxy", 1001)

	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.crt")
	certPath := filepath.Join(tmpDir, "client.crt")
	keyPath := filepath.Join(tmpDir, "client.key")

	require.NoError(t, os.WriteFile(caPath, caPEM, 0600))
	require.NoError(t, os.WriteFile(certPath, certPEM, 0600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	t.Run("successful mTLS setup", func(t *testing.T) {
		cfg := &config.AppConfig{
			RedisTLSEnabled: true,
			RedisCAPath:     caPath,
			RedisCertPath:   certPath,
			RedisKeyPath:    keyPath,
		}

		tlsConfig, err := server.BuildRedisTLSConfig(cfg, nil)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		require.NotNil(t, tlsConfig.GetClientCertificate)

		clientCert, err := tlsConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
		require.NoError(t, err)
		require.NotNil(t, clientCert)
		require.NotEmpty(t, clientCert.Certificate)

		parsed, err := x509.ParseCertificate(clientCert.Certificate[0])
		require.NoError(t, err)
		assert.Equal(t, big.NewInt(1001), parsed.SerialNumber)
		assert.Equal(t, "mcp-proxy", parsed.Subject.CommonName)
	})

	t.Run("asymmetrical mTLS: cert without key", func(t *testing.T) {
		cfg := &config.AppConfig{
			RedisTLSEnabled: true,
			RedisCertPath:   certPath,
		}
		_, err := server.BuildRedisTLSConfig(cfg, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "both REDIS_CERT_PATH and REDIS_KEY_PATH must be provided")
	})

	t.Run("asymmetrical mTLS: key without cert", func(t *testing.T) {
		cfg := &config.AppConfig{
			RedisTLSEnabled: true,
			RedisKeyPath:    keyPath,
		}
		_, err := server.BuildRedisTLSConfig(cfg, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "both REDIS_CERT_PATH and REDIS_KEY_PATH must be provided")
	})

	t.Run("missing client key file", func(t *testing.T) {
		cfg := &config.AppConfig{
			RedisTLSEnabled: true,
			RedisCertPath:   certPath,
			RedisKeyPath:    "/nonexistent/client.key",
		}
		_, err := server.BuildRedisTLSConfig(cfg, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load client keypair")
	})
}

func TestBuildRedisTLSConfig_DevFlags(t *testing.T) {
	t.Run("explicit SNI and InsecureSkipVerify", func(t *testing.T) {
		cfg := &config.AppConfig{
			RedisTLSEnabled:            true,
			RedisTLSInsecureSkipVerify: true,
			RedisTLSServerName:         "redis.internal.cluster",
		}

		tlsConfig, err := server.BuildRedisTLSConfig(cfg, nil)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)

		assert.True(t, tlsConfig.InsecureSkipVerify)
		assert.Equal(t, "redis.internal.cluster", tlsConfig.ServerName)
	})

	t.Run("default SNI from RedisAddr hostname", func(t *testing.T) {
		cfg := &config.AppConfig{
			RedisTLSEnabled: true,
			RedisAddr:       "redis.mycluster.svc.cluster.local:6379",
		}

		tlsConfig, err := server.BuildRedisTLSConfig(cfg, nil)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)

		assert.Equal(t, "redis.mycluster.svc.cluster.local", tlsConfig.ServerName)
	})
}

func TestKeyPairReloader_DynamicReload(t *testing.T) {
	_, caKey, caCert := generateTestCA(t)

	// Certificate 1 (initial)
	certPEM1, keyPEM1 := generateTestCert(t, caCert, caKey, "client-v1", 1001)

	// Certificate 2 (rotated)
	certPEM2, keyPEM2 := generateTestCert(t, caCert, caKey, "client-v2", 2002)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "client.crt")
	keyPath := filepath.Join(tmpDir, "client.key")

	// Write Cert 1 initially
	require.NoError(t, os.WriteFile(certPath, certPEM1, 0600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM1, 0600))

	reloader, err := server.NewKeyPairReloader(certPath, keyPath, nil)
	require.NoError(t, err)
	require.NotNil(t, reloader)

	// 1. First verification: should return Cert 1
	cert1, err := reloader.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	parsed1, err := x509.ParseCertificate(cert1.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(1001), parsed1.SerialNumber)
	assert.Equal(t, "client-v1", parsed1.Subject.CommonName)

	// 2. Rotate cert files on disk with Cert 2 and advance modification time
	newModTime := time.Now().Add(5 * time.Second)
	require.NoError(t, os.WriteFile(certPath, certPEM2, 0600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM2, 0600))
	require.NoError(t, os.Chtimes(certPath, newModTime, newModTime))
	require.NoError(t, os.Chtimes(keyPath, newModTime, newModTime))

	// 3. Second verification: GetClientCertificate should dynamically reload Cert 2
	cert2, err := reloader.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	parsed2, err := x509.ParseCertificate(cert2.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(2002), parsed2.SerialNumber)
	assert.Equal(t, "client-v2", parsed2.Subject.CommonName)

	// 4. Fault tolerance: Corrupt disk files mid-rotation, should retain active Cert 2
	futureModTime := time.Now().Add(10 * time.Second)
	require.NoError(t, os.WriteFile(certPath, []byte("CORRUPTED_CERT_PEM"), 0600))
	require.NoError(t, os.Chtimes(certPath, futureModTime, futureModTime))

	certRetained, err := reloader.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	parsedRetained, err := x509.ParseCertificate(certRetained.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(2002), parsedRetained.SerialNumber)
	assert.Equal(t, "client-v2", parsedRetained.Subject.CommonName)
}

func TestServerNew_FailFastOnInvalidTLS(t *testing.T) {
	cfg := config.LoadFromEnv()
	cfg.RedisTLSEnabled = true
	cfg.RedisCAPath = "/nonexistent/path/to/ca.crt"

	srv, err := server.New(server.Options{
		Config: cfg,
	})
	require.Error(t, err)
	assert.Nil(t, srv)
	assert.Contains(t, err.Error(), "failed to initialize Redis TLS configuration")
}

func TestKeyPairReloader_ConcurrentAccess(t *testing.T) {
	_, caKey, caCert := generateTestCA(t)

	certPEM1, keyPEM1 := generateTestCert(t, caCert, caKey, "client-concurrent-1", 3001)
	certPEM2, keyPEM2 := generateTestCert(t, caCert, caKey, "client-concurrent-2", 3002)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "client.crt")
	keyPath := filepath.Join(tmpDir, "client.key")

	require.NoError(t, os.WriteFile(certPath, certPEM1, 0600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM1, 0600))

	reloader, err := server.NewKeyPairReloader(certPath, keyPath, nil)
	require.NoError(t, err)

	stopCh := make(chan struct{})
	errCh := make(chan error, 20)

	// Spawn 10 concurrent readers calling GetClientCertificate
	for i := 0; i < 10; i++ {
		go func() {
			for {
				select {
				case <-stopCh:
					return
				default:
					cert, err := reloader.GetClientCertificate(&tls.CertificateRequestInfo{})
					if err != nil {
						errCh <- err
						return
					}
					if cert == nil || len(cert.Certificate) == 0 {
						errCh <- fmt.Errorf("returned nil or empty certificate")
						return
					}
				}
			}
		}()
	}

	// Rotate certificate on disk while readers are actively fetching
	time.Sleep(10 * time.Millisecond)
	newMod := time.Now().Add(2 * time.Second)
	require.NoError(t, os.WriteFile(certPath, certPEM2, 0600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM2, 0600))
	require.NoError(t, os.Chtimes(certPath, newMod, newMod))
	require.NoError(t, os.Chtimes(keyPath, newMod, newMod))

	time.Sleep(30 * time.Millisecond)
	close(stopCh)

	select {
	case err := <-errCh:
		t.Fatalf("concurrent access failure: %v", err)
	default:
		// No errors during concurrent rotation
	}

	// Verify final certificate is cert2
	finalCert, err := reloader.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(finalCert.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(3002), parsed.SerialNumber)
}
