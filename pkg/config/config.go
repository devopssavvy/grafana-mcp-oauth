package config

import (
	"crypto/sha256"
	"encoding/hex"
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
	HTTPHost         string
	HTTPPort         string
	GRPCHost         string
	GRPCPort         string
	CookieSecure     bool
	TargetMCPURL     string
	GrafanaURL       string
	GrafanaPublicURL string
	CallbackBaseURL  string
	RedisAddr        string
	RedisPassword    string
	RedisDB          int
	MasterSecret      []byte
	SessionTTL        time.Duration
	RefreshTTL        time.Duration
	PendingAuthTTL    time.Duration
	AuthCodeTTL       time.Duration
	RateLimitLoginRPM int
	RateLimitTokenRPM int
	LogLevel          slog.Level
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
	httpHost := getEnv("HTTP_HOST", getEnv("BIND_HOST", ""))
	httpPort := getEnv("PORT", getEnv("HTTP_PORT", defaultHTTPPort))

	grpcHost := getEnv("GRPC_HOST", getEnv("BIND_HOST", ""))
	grpcPort := getEnv("GRPC_PORT", "9001")

	cookieSecure := strings.HasPrefix(baseURL, "https://")
	if csStr := os.Getenv("COOKIE_SECURE"); csStr != "" {
		if cs, err := strconv.ParseBool(csStr); err == nil {
			cookieSecure = cs
		}
	}
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
		if len(secretStr) < 16 {
			slog.Error("MCP_MASTER_SECRET is too short; must be at least 16 bytes (recommended 32 bytes)")
			os.Exit(1)
		}
		masterSecret = []byte(secretStr)
		slog.Info("Loaded custom MCP_MASTER_SECRET from environment")
	} else {
		// Zero-config mode: Pure Client-Derived Key (RFC 5869) with standard domain salt.
		// Eliminates admin burden and multi-pod desynchronization with no master secret required.
		masterSecret = nil
		slog.Info("MCP_MASTER_SECRET not set; running in Zero-Knowledge Client-Derived Key mode (zero-config multi-pod sync)")
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

	pendingAuthMinutes := 5
	if pamStr := os.Getenv("PENDING_AUTH_TTL_MINUTES"); pamStr != "" {
		if pam, err := strconv.Atoi(pamStr); err == nil && pam > 0 {
			pendingAuthMinutes = pam
		}
	}

	authCodeSeconds := 60
	if acsStr := os.Getenv("AUTH_CODE_TTL_SECONDS"); acsStr != "" {
		if acs, err := strconv.Atoi(acsStr); err == nil && acs > 0 {
			authCodeSeconds = acs
		}
	}

	rateLimitLoginRPM := 60
	if loginRpmStr := os.Getenv("RATE_LIMIT_LOGIN_RPM"); loginRpmStr != "" {
		if rpm, err := strconv.Atoi(loginRpmStr); err == nil && rpm > 0 {
			rateLimitLoginRPM = rpm
		}
	}

	rateLimitTokenRPM := 120
	if tokenRpmStr := os.Getenv("RATE_LIMIT_TOKEN_RPM"); tokenRpmStr != "" {
		if rpm, err := strconv.Atoi(tokenRpmStr); err == nil && rpm > 0 {
			rateLimitTokenRPM = rpm
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
		HTTPHost:         httpHost,
		HTTPPort:         httpPort,
		GRPCHost:         grpcHost,
		GRPCPort:         grpcPort,
		CookieSecure:     cookieSecure,
		TargetMCPURL:     targetMCPURL,
		GrafanaURL:       grafanaURL,
		GrafanaPublicURL: grafanaPublicURL,
		CallbackBaseURL:  callbackBaseURL,
		RedisAddr:        redisAddr,
		RedisPassword:    redisPassword,
		RedisDB:          redisDB,
		MasterSecret:      masterSecret,
		SessionTTL:        time.Duration(sessionHours) * time.Hour,
		RefreshTTL:        time.Duration(refreshDays) * 24 * time.Hour,
		PendingAuthTTL:    time.Duration(pendingAuthMinutes) * time.Minute,
		AuthCodeTTL:       time.Duration(authCodeSeconds) * time.Second,
		RateLimitLoginRPM: rateLimitLoginRPM,
		RateLimitTokenRPM: rateLimitTokenRPM,
		LogLevel:          logLevel,
	}
}

// MasterSecretFingerprint returns a cryptographic SHA-256 fingerprint for safe logging without leaking plaintext characters.
func (c *AppConfig) MasterSecretFingerprint() string {
	if len(c.MasterSecret) == 0 {
		return "zero-config (client-derived)"
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
