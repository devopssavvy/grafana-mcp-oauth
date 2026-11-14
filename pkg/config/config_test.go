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
