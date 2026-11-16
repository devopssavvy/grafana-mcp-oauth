package server_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grafana-mcp-oauth/pkg/config"
	"grafana-mcp-oauth/pkg/server"
)

func testHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
		Timeout: 5 * time.Second,
	}
}

func setupTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return mr, rdb
}

func TestServer_InvalidMode(t *testing.T) {
	_, rdb := setupTestRedis(t)
	cfg := &config.AppConfig{
		Mode:         "unsupported",
		MasterSecret: []byte("01234567890123456789012345678901"),
	}
	_, err := server.New(server.Options{
		Config:      cfg,
		RedisClient: rdb,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid mode")
}

func TestServer_ProxyMode(t *testing.T) {
	_, rdb := setupTestRedis(t)

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	cfg := &config.AppConfig{
		Mode:         server.ModeProxy,
		BaseURL:      "http://" + httpLn.Addr().String(),
		TargetMCPURL: "http://127.0.0.1:9999",
		MasterSecret: []byte("01234567890123456789012345678901"),
		SessionTTL:   time.Hour,
		RefreshTTL:   time.Hour * 24,
	}

	srv, err := server.New(server.Options{
		Config:       cfg,
		HTTPListener: httpLn,
		RedisClient:  rdb,
	})
	require.NoError(t, err)
	assert.Equal(t, server.ModeProxy, srv.Mode())

	errChan, err := srv.Start()
	require.NoError(t, err)
	assert.Empty(t, srv.GRPCAddr(), "Proxy mode should not have gRPC listener")

	client := testHTTPClient()

	// Verify /healthz
	resp, err := client.Get("http://" + srv.HTTPAddr() + "/healthz")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "OK\n", string(body))
	_ = resp.Body.Close()

	// Verify /.well-known/oauth-protected-resource
	respDiscovery, err := client.Get("http://" + srv.HTTPAddr() + "/.well-known/oauth-protected-resource")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, respDiscovery.StatusCode)
	_ = respDiscovery.Body.Close()

	// Verify /extauthz/check is NOT handled (should return 404 or 405)
	respCheck, err := client.Get("http://" + srv.HTTPAddr() + "/extauthz/check")
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, respCheck.StatusCode)
	_ = respCheck.Body.Close()

	// Shutdown
	ctxShut, cancelShut := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelShut()
	err = srv.Shutdown(ctxShut)
	require.NoError(t, err)

	select {
	case srvErr := <-errChan:
		t.Fatalf("Unexpected server error: %v", srvErr)
	default:
	}
}

func TestServer_ExtAuthzMode(t *testing.T) {
	_, rdb := setupTestRedis(t)

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	cfg := &config.AppConfig{
		Mode:         server.ModeExtAuthz,
		BaseURL:      "http://" + httpLn.Addr().String(),
		MasterSecret: []byte("01234567890123456789012345678901"),
		SessionTTL:   time.Hour,
		RefreshTTL:   time.Hour * 24,
	}

	srv, err := server.New(server.Options{
		Config:       cfg,
		HTTPListener: httpLn,
		GRPCListener: grpcLn,
		RedisClient:  rdb,
	})
	require.NoError(t, err)
	assert.Equal(t, server.ModeExtAuthz, srv.Mode())

	errChan, err := srv.Start()
	require.NoError(t, err)
	assert.NotEmpty(t, srv.GRPCAddr(), "ExtAuthz mode must have gRPC listener")

	client := testHTTPClient()

	// Verify /healthz
	resp, err := client.Get("http://" + srv.HTTPAddr() + "/healthz")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Verify /extauthz/check is handled (returns 401 Unauthorized because no Authorization header)
	respCheck, err := client.Get("http://" + srv.HTTPAddr() + "/extauthz/check")
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, respCheck.StatusCode)
	_ = respCheck.Body.Close()

	// Verify /mcp/auth/check is NOT registered (must return 404 to prevent session oracle exposure)
	respOracleCheck, err := client.Get("http://" + srv.HTTPAddr() + "/mcp/auth/check")
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, respOracleCheck.StatusCode)
	_ = respOracleCheck.Body.Close()

	// Shutdown
	ctxShut, cancelShut := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelShut()
	err = srv.Shutdown(ctxShut)
	require.NoError(t, err)

	select {
	case srvErr := <-errChan:
		t.Fatalf("Unexpected server error: %v", srvErr)
	default:
	}
}

func TestServer_AllMode(t *testing.T) {
	_, rdb := setupTestRedis(t)

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	cfg := &config.AppConfig{
		Mode:         server.ModeAll,
		BaseURL:      "http://" + httpLn.Addr().String(),
		TargetMCPURL: "http://127.0.0.1:9999",
		MasterSecret: []byte("01234567890123456789012345678901"),
		SessionTTL:   time.Hour,
		RefreshTTL:   time.Hour * 24,
	}

	srv, err := server.New(server.Options{
		Config:       cfg,
		HTTPListener: httpLn,
		GRPCListener: grpcLn,
		RedisClient:  rdb,
	})
	require.NoError(t, err)
	assert.Equal(t, server.ModeAll, srv.Mode())

	errChan, err := srv.Start()
	require.NoError(t, err)
	assert.NotEmpty(t, srv.GRPCAddr(), "All mode must have gRPC listener")

	client := testHTTPClient()

	// Verify /healthz
	resp, err := client.Get("http://" + srv.HTTPAddr() + "/healthz")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Verify /extauthz/check is handled (returns 401)
	respCheck, err := client.Get("http://" + srv.HTTPAddr() + "/extauthz/check")
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, respCheck.StatusCode)
	_ = respCheck.Body.Close()

	// Verify /mcp/auth/health
	respAuthHealth, err := client.Get("http://" + srv.HTTPAddr() + "/mcp/auth/health")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, respAuthHealth.StatusCode)
	_ = respAuthHealth.Body.Close()

	// Shutdown
	ctxShut, cancelShut := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelShut()
	err = srv.Shutdown(ctxShut)
	require.NoError(t, err)

	select {
	case srvErr := <-errChan:
		t.Fatalf("Unexpected server error: %v", srvErr)
	default:
	}
}

func TestServer_DefaultListenerBinding(t *testing.T) {
	_, rdb := setupTestRedis(t)

	cfg := &config.AppConfig{
		Mode:         server.ModeAll,
		HTTPPort:     "0",
		GRPCPort:     "0",
		BaseURL:      "http://localhost",
		TargetMCPURL: "http://127.0.0.1:9999",
		MasterSecret: []byte("01234567890123456789012345678901"),
		SessionTTL:   time.Hour,
		RefreshTTL:   time.Hour * 24,
	}

	// Supply nil listeners to exercise internal net.Listen socket creation
	srv, err := server.New(server.Options{
		Config:      cfg,
		RedisClient: rdb,
	})
	require.NoError(t, err)

	errChan, err := srv.Start()
	require.NoError(t, err)

	require.NotEmpty(t, srv.HTTPAddr())
	require.NotEmpty(t, srv.GRPCAddr())

	client := testHTTPClient()
	resp, err := client.Get("http://" + srv.HTTPAddr() + "/healthz")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	ctxShut, cancelShut := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelShut()
	err = srv.Shutdown(ctxShut)
	require.NoError(t, err)

	select {
	case srvErr := <-errChan:
		t.Fatalf("Unexpected server error: %v", srvErr)
	default:
	}
}

func TestServer_ExtAuthzDefaultPortResolution(t *testing.T) {
	_, rdb := setupTestRedis(t)

	cfg := &config.AppConfig{
		Mode:         server.ModeExtAuthz,
		HTTPPort:     "", // unset HTTPPort
		MasterSecret: []byte("01234567890123456789012345678901"),
	}

	srv, err := server.New(server.Options{
		Config:      cfg,
		RedisClient: rdb,
	})
	require.NoError(t, err)
	assert.Equal(t, "8081", cfg.HTTPPort, "ExtAuthz mode must default HTTP port to 8081")
	assert.Equal(t, server.ModeExtAuthz, srv.Mode())
}

func TestServer_DefensiveSecurityHeaders(t *testing.T) {
	_, rdb := setupTestRedis(t)

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	cfg := &config.AppConfig{
		Mode:         server.ModeProxy,
		BaseURL:      "http://" + httpLn.Addr().String(),
		TargetMCPURL: "http://127.0.0.1:9999",
		MasterSecret: []byte("01234567890123456789012345678901"),
	}

	srv, err := server.New(server.Options{
		Config:       cfg,
		HTTPListener: httpLn,
		RedisClient:  rdb,
	})
	require.NoError(t, err)

	errChan, err := srv.Start()
	require.NoError(t, err)

	client := testHTTPClient()

	// 1. Check security headers on /healthz
	respHealth, err := client.Get("http://" + srv.HTTPAddr() + "/healthz")
	require.NoError(t, err)
	assert.Equal(t, "nosniff", respHealth.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", respHealth.Header.Get("X-Frame-Options"))
	assert.Equal(t, "strict-origin-when-cross-origin", respHealth.Header.Get("Referrer-Policy"))
	assert.Equal(t, "default-src 'none'; style-src 'unsafe-inline'", respHealth.Header.Get("Content-Security-Policy"))
	_ = respHealth.Body.Close()

	// 2. Check security headers on root /
	respRoot, err := client.Get("http://" + srv.HTTPAddr() + "/")
	require.NoError(t, err)
	assert.Equal(t, "nosniff", respRoot.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", respRoot.Header.Get("X-Frame-Options"))
	assert.Equal(t, "strict-origin-when-cross-origin", respRoot.Header.Get("Referrer-Policy"))
	assert.Equal(t, "default-src 'none'; style-src 'unsafe-inline'", respRoot.Header.Get("Content-Security-Policy"))
	_ = respRoot.Body.Close()

	ctxShut, cancelShut := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelShut()
	err = srv.Shutdown(ctxShut)
	require.NoError(t, err)

	select {
	case srvErr := <-errChan:
		t.Fatalf("Unexpected server error: %v", srvErr)
	default:
	}
}
