package config_test

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"grafana-mcp-oauth/pkg/config"
)

func TestLoadFromEnv_Defaults(t *testing.T) {
	// Clear any relevant env vars
	os.Unsetenv("MODE")
	os.Unsetenv("GATEWAY_MODE")
	os.Unsetenv("PORT")
	os.Unsetenv("HTTP_PORT")
	os.Unsetenv("GRPC_PORT")

	cfg := config.LoadFromEnv()
	assert.Equal(t, "proxy", cfg.Mode)
	assert.Equal(t, "8080", cfg.HTTPPort)
	assert.Equal(t, "9001", cfg.GRPCPort)
	assert.Equal(t, "http://127.0.0.1:8000", cfg.TargetMCPURL)
	assert.Equal(t, 2*time.Hour, cfg.SessionTTL)
	assert.Equal(t, 30*24*time.Hour, cfg.RefreshTTL)
	assert.Equal(t, 5*time.Minute, cfg.PendingAuthTTL)
	assert.Equal(t, 60*time.Second, cfg.AuthCodeTTL)
	assert.Nil(t, cfg.MasterSecret, "MasterSecret should be nil in zero-config mode")
	assert.Equal(t, "zero-config (client-derived)", cfg.MasterSecretFingerprint())
	assert.False(t, cfg.RedisTLSEnabled)
	assert.Empty(t, cfg.RedisCAPath)
	assert.Empty(t, cfg.RedisCertPath)
	assert.Empty(t, cfg.RedisKeyPath)
	assert.False(t, cfg.RedisTLSInsecureSkipVerify)
	assert.Empty(t, cfg.RedisTLSServerName)
}

func TestLoadFromEnv_ProductionWithoutMasterSecret(t *testing.T) {
	t.Setenv("ENV", "production")
	os.Unsetenv("MCP_MASTER_SECRET")

	cfg := config.LoadFromEnv()
	assert.Nil(t, cfg.MasterSecret)
	assert.Equal(t, "zero-config (client-derived)", cfg.MasterSecretFingerprint())
}

func TestLoadFromEnv_WithCustomMasterSecret(t *testing.T) {
	customSecret := "this-is-a-custom-configured-secret-32b!"
	t.Setenv("MCP_MASTER_SECRET", customSecret)

	cfg := config.LoadFromEnv()
	assert.Equal(t, []byte(customSecret), cfg.MasterSecret)
	assert.NotEqual(t, "zero-config (client-derived)", cfg.MasterSecretFingerprint())
}

func TestLoadFromEnv_ExtAuthzModeDefaults(t *testing.T) {
	t.Setenv("MODE", "extauthz")
	os.Unsetenv("PORT")
	os.Unsetenv("HTTP_PORT")

	cfg := config.LoadFromEnv()
	assert.Equal(t, "extauthz", cfg.Mode)
	assert.Equal(t, "8081", cfg.HTTPPort)
	assert.Equal(t, "9001", cfg.GRPCPort)
}

func TestLoadFromEnv_CustomOverrides(t *testing.T) {
	t.Setenv("MODE", "ALL")
	t.Setenv("HTTP_HOST", "127.0.0.1")
	t.Setenv("PORT", "9999")
	t.Setenv("GRPC_HOST", "0.0.0.0")
	t.Setenv("GRPC_PORT", "9998")
	t.Setenv("COOKIE_SECURE", "true")
	t.Setenv("TARGET_MCP_URL", "http://mcp:8080")
	t.Setenv("PENDING_AUTH_TTL_MINUTES", "3")
	t.Setenv("AUTH_CODE_TTL_SECONDS", "30")

	cfg := config.LoadFromEnv()
	assert.Equal(t, "all", cfg.Mode)
	assert.Equal(t, "127.0.0.1", cfg.HTTPHost)
	assert.Equal(t, "9999", cfg.HTTPPort)
	assert.Equal(t, "0.0.0.0", cfg.GRPCHost)
	assert.Equal(t, "9998", cfg.GRPCPort)
	assert.True(t, cfg.CookieSecure)
	assert.Equal(t, "http://mcp:8080", cfg.TargetMCPURL)
	assert.Equal(t, 3*time.Minute, cfg.PendingAuthTTL)
	assert.Equal(t, 30*time.Second, cfg.AuthCodeTTL)
}

func TestLoadFromEnv_RedisTLS(t *testing.T) {
	t.Run("explicit TLS enabled", func(t *testing.T) {
		t.Setenv("REDIS_TLS_ENABLED", "true")
		t.Setenv("REDIS_CA_PATH", "/etc/ssl/ca.crt")
		t.Setenv("REDIS_CERT_PATH", "/etc/ssl/client.crt")
		t.Setenv("REDIS_KEY_PATH", "/etc/ssl/client.key")
		t.Setenv("REDIS_TLS_INSECURE_SKIP_VERIFY", "true")
		t.Setenv("REDIS_TLS_SERVER_NAME", "redis.custom.domain")

		cfg := config.LoadFromEnv()
		assert.True(t, cfg.RedisTLSEnabled)
		assert.Equal(t, "/etc/ssl/ca.crt", cfg.RedisCAPath)
		assert.Equal(t, "/etc/ssl/client.crt", cfg.RedisCertPath)
		assert.Equal(t, "/etc/ssl/client.key", cfg.RedisKeyPath)
		assert.True(t, cfg.RedisTLSInsecureSkipVerify)
		assert.Equal(t, "redis.custom.domain", cfg.RedisTLSServerName)
	})

	t.Run("auto-enable TLS if cert path is provided", func(t *testing.T) {
		os.Unsetenv("REDIS_TLS_ENABLED")
		t.Setenv("REDIS_CERT_PATH", "/certs/client.crt")

		cfg := config.LoadFromEnv()
		assert.True(t, cfg.RedisTLSEnabled)
		assert.Equal(t, "/certs/client.crt", cfg.RedisCertPath)
	})

	t.Run("auto-enable TLS if CA path is provided", func(t *testing.T) {
		os.Unsetenv("REDIS_TLS_ENABLED")
		t.Setenv("REDIS_CA_PATH", "/certs/ca.crt")

		cfg := config.LoadFromEnv()
		assert.True(t, cfg.RedisTLSEnabled)
		assert.Equal(t, "/certs/ca.crt", cfg.RedisCAPath)
	})

	t.Run("explicit TLS false overrides cert path presence", func(t *testing.T) {
		t.Setenv("REDIS_TLS_ENABLED", "false")
		t.Setenv("REDIS_CERT_PATH", "/certs/client.crt")

		cfg := config.LoadFromEnv()
		assert.False(t, cfg.RedisTLSEnabled)
		assert.Equal(t, "/certs/client.crt", cfg.RedisCertPath)
	})
}
