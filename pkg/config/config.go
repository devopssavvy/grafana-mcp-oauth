package config

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// AppConfig contains runtime settings loaded from environment variables.
type AppConfig struct {
	Mode                       string
	BaseURL                    string
	HTTPHost                   string
	HTTPPort                   string
	GRPCHost                   string
	GRPCPort                   string
	CookieSecure               bool
	TargetMCPURL               string
	GrafanaURL                 string
	GrafanaPublicURL           string
	CallbackBaseURL            string
	RedisAddr                  string
	RedisPassword              string
	RedisDB                    int
	RedisTLSEnabled            bool
	RedisCAPath                string
	RedisCertPath              string
	RedisKeyPath               string
	RedisTLSInsecureSkipVerify bool
	RedisTLSServerName         string
	MasterSecret               []byte
	SessionTTL                 time.Duration
	RefreshTTL                 time.Duration
	PendingAuthTTL             time.Duration
	AuthCodeTTL                time.Duration
	RateLimitLoginRPM          int
	RateLimitTokenRPM          int
	TrustedProxies             []*net.IPNet  // Parsed CIDRs/IPs allowed to supply X-Forwarded-For headers
	TrustedProxiesRaw          string        // Raw comma-separated string from TRUSTED_PROXIES
	CIMDEnforcement            string        // "required" (default), "permissive", "disabled"
	CIMDAllowInsecureHTTP      bool          // Allow http:// and loopback IPs for testing/dev (default false)
	CIMDCacheTTL               time.Duration // Cache TTL for fetched CIMD metadata (default 1 hour)
	InstanceURL                string        // Reachable URL for this proxy instance used for cross-replica peer forwarding (e.g. "http://mcp-proxy-1:8080")
	GrafanaRotationInterval    time.Duration // Sliding keep-alive rotation interval for Grafana session cookie (default 5m)
	ForceDedicatedSession      bool          // Enforce creating a separate, dedicated Grafana session for MCP and restoring web cookie (default true)
	LogLevel                   slog.Level
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
	instanceURL := strings.TrimRight(getEnv("INSTANCE_URL", ""), "/")
	if instanceURL == "" {
		host := httpHost
		if host == "" || host == "0.0.0.0" {
			host = "127.0.0.1"
		}
		instanceURL = "http://" + net.JoinHostPort(host, httpPort)
	}
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

	redisTLSEnabled := false
	redisCAPath := os.Getenv("REDIS_CA_PATH")
	redisCertPath := os.Getenv("REDIS_CERT_PATH")
	redisKeyPath := os.Getenv("REDIS_KEY_PATH")
	redisTLSServerName := os.Getenv("REDIS_TLS_SERVER_NAME")

	if tlsStr := os.Getenv("REDIS_TLS_ENABLED"); tlsStr != "" {
		if b, err := strconv.ParseBool(tlsStr); err == nil {
			redisTLSEnabled = b
		}
	} else if redisCAPath != "" || redisCertPath != "" || redisKeyPath != "" || redisTLSServerName != "" {
		// Auto-enable TLS if cert/key/CA/SNI paths are configured and REDIS_TLS_ENABLED was not explicitly set
		redisTLSEnabled = true
	}

	redisTLSInsecureSkipVerify := false
	if isvStr := os.Getenv("REDIS_TLS_INSECURE_SKIP_VERIFY"); isvStr != "" {
		if b, err := strconv.ParseBool(isvStr); err == nil {
			redisTLSInsecureSkipVerify = b
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

	var sessionTTL time.Duration
	if stStr := os.Getenv("SESSION_TTL"); stStr != "" {
		if d, err := time.ParseDuration(stStr); err == nil && d > 0 {
			sessionTTL = d
		}
	}
	if sessionTTL == 0 {
		sessionHours := 2
		if shStr := os.Getenv("SESSION_TTL_HOURS"); shStr != "" {
			if sh, err := strconv.Atoi(shStr); err == nil && sh > 0 {
				sessionHours = sh
			}
		}
		sessionTTL = time.Duration(sessionHours) * time.Hour
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

	var grafanaRotationInterval time.Duration
	if griStr := os.Getenv("GRAFANA_ROTATION_INTERVAL"); griStr != "" {
		if d, err := time.ParseDuration(griStr); err == nil {
			if d <= 0 {
				grafanaRotationInterval = -1
			} else {
				grafanaRotationInterval = d
			}
		}
	}
	if grafanaRotationInterval == 0 {
		grafanaRotationMinutes := 5
		if grmStr := os.Getenv("GRAFANA_ROTATION_INTERVAL_MINUTES"); grmStr != "" {
			if grm, err := strconv.Atoi(grmStr); err == nil {
				grafanaRotationMinutes = grm
			}
		}
		if grafanaRotationMinutes <= 0 {
			grafanaRotationInterval = -1 // Explicitly disabled
		} else {
			grafanaRotationInterval = time.Duration(grafanaRotationMinutes) * time.Minute
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

	cimdEnforcement := strings.ToLower(strings.TrimSpace(getEnv("CIMD_ENFORCEMENT", "required")))
	if cimdEnforcement != "permissive" && cimdEnforcement != "disabled" {
		cimdEnforcement = "required"
	}

	cimdAllowInsecureHTTP := false
	if v := os.Getenv("CIMD_ALLOW_INSECURE_HTTP"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cimdAllowInsecureHTTP = b
		}
	}

	cimdCacheTTL := 1 * time.Hour
	if v := os.Getenv("CIMD_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cimdCacheTTL = d
		}
	}

	forceDedicatedSession := true
	if v := os.Getenv("FORCE_DEDICATED_SESSION"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			forceDedicatedSession = b
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

	trustedProxiesRaw := getEnv("TRUSTED_PROXIES", "")
	trustedProxies := ParseTrustedProxies(trustedProxiesRaw)

	return &AppConfig{
		Mode:                       mode,
		BaseURL:                    baseURL,
		HTTPHost:                   httpHost,
		HTTPPort:                   httpPort,
		GRPCHost:                   grpcHost,
		GRPCPort:                   grpcPort,
		CookieSecure:               cookieSecure,
		TargetMCPURL:               targetMCPURL,
		GrafanaURL:                 grafanaURL,
		GrafanaPublicURL:           grafanaPublicURL,
		CallbackBaseURL:            callbackBaseURL,
		RedisAddr:                  redisAddr,
		RedisPassword:              redisPassword,
		RedisDB:                    redisDB,
		RedisTLSEnabled:            redisTLSEnabled,
		RedisCAPath:                redisCAPath,
		RedisCertPath:              redisCertPath,
		RedisKeyPath:               redisKeyPath,
		RedisTLSInsecureSkipVerify: redisTLSInsecureSkipVerify,
		RedisTLSServerName:         redisTLSServerName,
		MasterSecret:               masterSecret,
		SessionTTL:                 sessionTTL,
		RefreshTTL:                 time.Duration(refreshDays) * 24 * time.Hour,
		PendingAuthTTL:             time.Duration(pendingAuthMinutes) * time.Minute,
		AuthCodeTTL:                time.Duration(authCodeSeconds) * time.Second,
		RateLimitLoginRPM:          rateLimitLoginRPM,
		RateLimitTokenRPM:          rateLimitTokenRPM,
		TrustedProxies:             trustedProxies,
		TrustedProxiesRaw:          trustedProxiesRaw,
		CIMDEnforcement:            cimdEnforcement,
		CIMDAllowInsecureHTTP:      cimdAllowInsecureHTTP,
		CIMDCacheTTL:               cimdCacheTTL,
		InstanceURL:                instanceURL,
		GrafanaRotationInterval:    grafanaRotationInterval,
		ForceDedicatedSession:      forceDedicatedSession,
		LogLevel:                   logLevel,
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

// ParseTrustedProxies parses a comma-separated list of IP addresses or CIDR blocks.
func ParseTrustedProxies(raw string) []*net.IPNet {
	var list []*net.IPNet
	if raw == "" {
		return list
	}
	parts := strings.Split(raw, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "/") {
			_, ipNet, err := net.ParseCIDR(p)
			if err == nil && ipNet != nil {
				list = append(list, ipNet)
			}
		} else {
			ip := net.ParseIP(p)
			if ip != nil {
				var mask net.IPMask
				if ip.To4() != nil {
					mask = net.CIDRMask(32, 32)
				} else {
					mask = net.CIDRMask(128, 128)
				}
				list = append(list, &net.IPNet{IP: ip, Mask: mask})
			}
		}
	}
	return list
}
