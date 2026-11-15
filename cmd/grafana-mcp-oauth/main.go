package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"grafana-mcp-oauth/pkg/config"
	"grafana-mcp-oauth/pkg/server"
)

var (
	// Version is injected during build time or defaults to dev
	Version = "1.0.0"
)

func main() {
	// Define command-line flags
	var (
		flagMode         = flag.String("mode", "", "Server mode: 'proxy' (default), 'extauthz', or 'all' [env: MODE]")
		flagHost         = flag.String("http-host", "", "HTTP host/interface to listen on [env: HTTP_HOST or BIND_HOST]")
		flagPort         = flag.String("port", "", "HTTP port to listen on [env: PORT or HTTP_PORT]")
		flagGRPCHost     = flag.String("grpc-host", "", "gRPC host/interface to listen on [env: GRPC_HOST or BIND_HOST]")
		flagGRPCPort     = flag.String("grpc-port", "", "gRPC port to listen on for Envoy ext_authz [env: GRPC_PORT]")
		flagCookieSecure = flag.String("cookie-secure", "", "Force Secure flag on cookies ('true' or 'false') [env: COOKIE_SECURE]")
		flagTargetMCPURL    = flag.String("target-mcp-url", "", "Upstream stock MCP Server URL for proxying [env: TARGET_MCP_URL]")
		flagCIMDEnforcement = flag.String("cimd-enforcement", "", "CIMD enforcement mode: 'required' (default), 'permissive', or 'disabled' [env: CIMD_ENFORCEMENT]")
		flagTrustedProxies  = flag.String("trusted-proxies", "", "Comma-separated list of trusted proxy IPs/CIDRs for X-Forwarded-For [env: TRUSTED_PROXIES]")
		flagVersion         = flag.Bool("version", false, "Print version and exit")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Grafana MCP OAuth Gateway - Centralized OIDC Authentication for Grafana MCP Server\n\n")
		fmt.Fprintf(os.Stderr, "Modes:\n")
		fmt.Fprintf(os.Stderr, "  proxy     (Default) Authenticated HTTP reverse proxy to upstream MCP with injected session\n")
		fmt.Fprintf(os.Stderr, "  extauthz  Envoy gRPC and HTTP ext_authz service\n")
		fmt.Fprintf(os.Stderr, "  all       Unified dual-mode (both proxy and ext_authz)\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment Variables:\n")
		fmt.Fprintf(os.Stderr, "  MODE                 Server mode (proxy, extauthz, all)\n")
		fmt.Fprintf(os.Stderr, "  PORT / HTTP_PORT     HTTP listener port (default 8080 for proxy/all, 8081 for extauthz)\n")
		fmt.Fprintf(os.Stderr, "  GRPC_PORT            gRPC listener port for Envoy ext_authz (default 9001)\n")
		fmt.Fprintf(os.Stderr, "  BASE_URL             Public Gateway base URL (e.g. http://localhost:8080)\n")
		fmt.Fprintf(os.Stderr, "  GRAFANA_URL          Internal Grafana URL (e.g. http://grafana:3000)\n")
		fmt.Fprintf(os.Stderr, "  TARGET_MCP_URL       Upstream stock MCP URL (default http://127.0.0.1:8000)\n")
		fmt.Fprintf(os.Stderr, "  REDIS_ADDR           Redis address (default localhost:6379)\n")
		fmt.Fprintf(os.Stderr, "  REDIS_TLS_ENABLED    Enable Redis TLS encryption (default false)\n")
		fmt.Fprintf(os.Stderr, "  REDIS_CA_PATH        Path to custom CA certificate PEM bundle\n")
		fmt.Fprintf(os.Stderr, "  REDIS_CERT_PATH      Path to client certificate PEM for mTLS\n")
		fmt.Fprintf(os.Stderr, "  REDIS_KEY_PATH       Path to client private key PEM for mTLS\n")
		fmt.Fprintf(os.Stderr, "  REDIS_TLS_SERVER_NAME Override Server Name Indication (SNI)\n")
		fmt.Fprintf(os.Stderr, "  REDIS_TLS_INSECURE_SKIP_VERIFY Skip Redis server cert verification (dev only)\n")
		fmt.Fprintf(os.Stderr, "  MCP_MASTER_SECRET    32-byte encryption key for zero-knowledge session store\n")
		fmt.Fprintf(os.Stderr, "  CIMD_ENFORCEMENT     CIMD enforcement mode: required (default), permissive, disabled\n")
		fmt.Fprintf(os.Stderr, "  CIMD_ALLOW_INSECURE_HTTP Allow insecure HTTP and loopback for CIMD in dev (default false)\n")
		fmt.Fprintf(os.Stderr, "  CIMD_CACHE_TTL       Cache TTL for CIMD metadata (default 1h)\n")
		fmt.Fprintf(os.Stderr, "  TRUSTED_PROXIES      Comma-separated list of trusted proxy IPs/CIDRs for X-Forwarded-For\n")
	}

	flag.Parse()

	if *flagVersion {
		fmt.Printf("grafana-mcp-oauth %s\n", Version)
		os.Exit(0)
	}

	cfg := config.LoadFromEnv()

	// Apply CLI flag overrides to configuration with proper port precedence
	if *flagMode != "" {
		cfg.Mode = strings.ToLower(strings.TrimSpace(*flagMode))
	}
	if *flagHost != "" {
		cfg.HTTPHost = *flagHost
	}
	if *flagPort != "" {
		cfg.HTTPPort = *flagPort
	} else if os.Getenv("PORT") == "" && os.Getenv("HTTP_PORT") == "" {
		if cfg.Mode == server.ModeExtAuthz {
			cfg.HTTPPort = "8081"
		} else {
			cfg.HTTPPort = "8080"
		}
	}

	if *flagGRPCHost != "" {
		cfg.GRPCHost = *flagGRPCHost
	}
	if *flagGRPCPort != "" {
		cfg.GRPCPort = *flagGRPCPort
	}
	if *flagCookieSecure != "" {
		if cs, err := strconv.ParseBool(*flagCookieSecure); err == nil {
			cfg.CookieSecure = cs
		}
	}
	if *flagTargetMCPURL != "" {
		cfg.TargetMCPURL = *flagTargetMCPURL
	}
	if *flagCIMDEnforcement != "" {
		cfg.CIMDEnforcement = strings.ToLower(strings.TrimSpace(*flagCIMDEnforcement))
	}
	if *flagTrustedProxies != "" {
		cfg.TrustedProxiesRaw = *flagTrustedProxies
		cfg.TrustedProxies = config.ParseTrustedProxies(*flagTrustedProxies)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	logger.Info("Initializing Grafana MCP OAuth Gateway",
		"version", Version,
		"mode", cfg.Mode,
		"http_host", cfg.HTTPHost,
		"http_port", cfg.HTTPPort,
		"grpc_host", cfg.GRPCHost,
		"grpc_port", cfg.GRPCPort,
		"cookie_secure", cfg.CookieSecure,
		"target_mcp_url", cfg.TargetMCPURL,
		"base_url", cfg.BaseURL,
		"grafana_url", cfg.GrafanaURL,
		"redis_addr", cfg.RedisAddr,
		"redis_tls_enabled", cfg.RedisTLSEnabled,
		"redis_mtls_enabled", (cfg.RedisCertPath != "" && cfg.RedisKeyPath != ""),
		"master_secret_fingerprint", cfg.MasterSecretFingerprint(),
	)

	if cfg.RedisTLSInsecureSkipVerify {
		logger.Warn("CRITICAL SECURITY WARNING: REDIS_TLS_INSECURE_SKIP_VERIFY is enabled! Redis server certificate verification is disabled.")
	}

	// Create and start unified server
	srv, err := server.New(server.Options{
		Config: cfg,
		Logger: logger,
	})
	if err != nil {
		logger.Error("Failed to initialize server", "error", err)
		os.Exit(1)
	}

	errChan, err := srv.Start()
	if err != nil {
		logger.Error("Failed to start server", "error", err)
		os.Exit(1)
	}

	// Listen for OS signals or fatal server errors
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	var fatalErr error
	select {
	case sig := <-sigChan:
		logger.Info("Received termination signal, shutting down gracefully", "signal", sig.String())
	case fatalErr = <-errChan:
		logger.Error("Server encountered fatal error", "error", fatalErr)
	}

	ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()

	if err := srv.Shutdown(ctxShutdown); err != nil {
		logger.Error("Error during server shutdown", "error", err)
		os.Exit(1)
	}

	if fatalErr != nil {
		logger.Error("Server exited abnormally due to fatal error", "error", fatalErr)
		os.Exit(1)
	}

	logger.Info("Grafana MCP OAuth Gateway stopped cleanly")
}
