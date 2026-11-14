package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// AppConfig contains runtime settings loaded from environment variables.
type AppConfig struct {
	Mode             string
	BaseURL          string
	HTTPPort         string
	GRPCPort         string
	TargetMCPURL     string
	GrafanaURL       string
	GrafanaPublicURL string
	CallbackBaseURL  string
	RedisAddr        string
	RedisPassword    string
	RedisDB          int
	MasterSecret     []byte
	SessionTTL       time.Duration
	RefreshTTL       time.Duration
	LogLevel         slog.Level
}

// LoadFromEnv loads configuration from environment variables with safe defaults.
func LoadFromEnv() *AppConfig {
	mode := strings.ToLower(strings.TrimSpace(getEnv("MODE", getEnv("GATEWAY_MODE", "proxy"))))
	if mode == "" {
		mode = "proxy"
	}

	baseURL := strings.TrimRight(getEnv("BASE_URL", "http://localhost:8080"), "/")

	// Default HTTP port depends on mode: 8081 for extauthz, 8080 for proxy/all
	defaultHTTPPort := "8080"
	if mode == "extauthz" {
		defaultHTTPPort = "8081"
	}
	httpPort := getEnv("PORT", getEnv("HTTP_PORT", defaultHTTPPort))

	grpcPort := getEnv("GRPC_PORT", "9001")
	targetMCPURL := getEnv("TARGET_MCP_URL", "http://127.0.0.1:8000")
	grafanaURL := getEnv("GRAFANA_URL", "http://grafana:3000")
	grafanaPublicURL := strings.TrimRight(getEnv("GRAFANA_PUBLIC_URL", baseURL), "/")
	callbackBaseURL := getEnv("CALLBACK_BASE_URL", baseURL+"/mcp/auth/callback")
	redisAddr := getEnv("REDIS_ADDR", "localhost:6379")
	redisPassword := os.Getenv("REDIS_PASSWORD")

	redisDB := 0
	if dbStr := os.Getenv("REDIS_DB"); dbStr != "" {
		if db, err := strconv.Atoi(dbStr); err == nil {
			redisDB = db
		}
	}

	secretStr := os.Getenv("MCP_MASTER_SECRET")
	var masterSecret []byte
	if secretStr != "" {
		masterSecret = []byte(secretStr)
	} else {
		masterSecret = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, masterSecret); err != nil {
			slog.Error("Failed to read cryptographically secure random bytes for master secret", "error", err)
			os.Exit(1)
		}
		slog.Warn("MCP_MASTER_SECRET not set in environment; generated ephemeral random 32-byte secret. For production, set MCP_MASTER_SECRET.")
	}

	sessionHours := 2
	if shStr := os.Getenv("SESSION_TTL_HOURS"); shStr != "" {
		if sh, err := strconv.Atoi(shStr); err == nil && sh > 0 {
			sessionHours = sh
		}
	}

	refreshDays := 30
	if rdStr := os.Getenv("REFRESH_TTL_DAYS"); rdStr != "" {
		if rd, err := strconv.Atoi(rdStr); err == nil && rd > 0 {
			refreshDays = rd
		}
	}

	logLevel := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}

	return &AppConfig{
		Mode:             mode,
		BaseURL:          baseURL,
		HTTPPort:         httpPort,
		GRPCPort:         grpcPort,
		TargetMCPURL:     targetMCPURL,
		GrafanaURL:       grafanaURL,
		GrafanaPublicURL: grafanaPublicURL,
		CallbackBaseURL:  callbackBaseURL,
		RedisAddr:        redisAddr,
		RedisPassword:    redisPassword,
		RedisDB:          redisDB,
		MasterSecret:     masterSecret,
		SessionTTL:       time.Duration(sessionHours) * time.Hour,
		RefreshTTL:       time.Duration(refreshDays) * 24 * time.Hour,
		LogLevel:         logLevel,
	}
}

// MasterSecretFingerprint returns a cryptographic SHA-256 fingerprint for safe logging without leaking plaintext characters.
func (c *AppConfig) MasterSecretFingerprint() string {
	if len(c.MasterSecret) == 0 {
		return ""
	}
	h := sha256.Sum256(c.MasterSecret)
	return hex.EncodeToString(h[:4]) + "..."
}

// MasterSecretHex is maintained for backward compatibility, returning the safe cryptographic fingerprint.
func (c *AppConfig) MasterSecretHex() string {
	return c.MasterSecretFingerprint()
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
