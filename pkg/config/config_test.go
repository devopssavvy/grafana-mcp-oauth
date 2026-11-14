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
	t.Setenv("PORT", "9999")
	t.Setenv("GRPC_PORT", "9998")
	t.Setenv("TARGET_MCP_URL", "http://mcp:8080")

	cfg := config.LoadFromEnv()
	assert.Equal(t, "all", cfg.Mode)
	assert.Equal(t, "9999", cfg.HTTPPort)
	assert.Equal(t, "9998", cfg.GRPCPort)
	assert.Equal(t, "http://mcp:8080", cfg.TargetMCPURL)
}
