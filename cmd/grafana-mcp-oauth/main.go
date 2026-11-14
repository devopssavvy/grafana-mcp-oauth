package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
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
		flagPort         = flag.String("port", "", "HTTP port to listen on [env: PORT or HTTP_PORT]")
		flagGRPCPort     = flag.String("grpc-port", "", "gRPC port to listen on for Envoy ext_authz [env: GRPC_PORT]")
		flagTargetMCPURL = flag.String("target-mcp-url", "", "Upstream stock MCP Server URL for proxying [env: TARGET_MCP_URL]")
		flagVersion      = flag.Bool("version", false, "Print version and exit")
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
		fmt.Fprintf(os.Stderr, "  MCP_MASTER_SECRET    32-byte encryption key for zero-knowledge session store\n")
	}

	flag.Parse()

	if *flagVersion {
		fmt.Printf("grafana-mcp-oauth %s\n", Version)
		os.Exit(0)
	}

	cfg := config.LoadFromEnv()

	// Apply CLI flag overrides to configuration
	if *flagMode != "" {
		cfg.Mode = strings.ToLower(strings.TrimSpace(*flagMode))
	}
	if *flagPort != "" {
		cfg.HTTPPort = *flagPort
	}
	if *flagGRPCPort != "" {
		cfg.GRPCPort = *flagGRPCPort
	}
	if *flagTargetMCPURL != "" {
		cfg.TargetMCPURL = *flagTargetMCPURL
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	logger.Info("Initializing Grafana MCP OAuth Gateway",
		"version", Version,
		"mode", cfg.Mode,
		"http_port", cfg.HTTPPort,
		"grpc_port", cfg.GRPCPort,
		"target_mcp_url", cfg.TargetMCPURL,
		"base_url", cfg.BaseURL,
		"grafana_url", cfg.GrafanaURL,
		"redis_addr", cfg.RedisAddr,
		"master_secret_fingerprint", cfg.MasterSecretFingerprint(),
	)

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

	// Listen for OS signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		logger.Info("Received termination signal, shutting down gracefully", "signal", sig.String())
	case err := <-errChan:
		logger.Error("Server encountered fatal error", "error", err)
	}

	ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()

	if err := srv.Shutdown(ctxShutdown); err != nil {
		logger.Error("Error during server shutdown", "error", err)
		os.Exit(1)
	}

	logger.Info("Grafana MCP OAuth Gateway stopped cleanly")
}
