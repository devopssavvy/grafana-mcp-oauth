package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"grafana-mcp-oauth/pkg/config"
	"grafana-mcp-oauth/pkg/oauth"
	"grafana-mcp-oauth/pkg/proxy"
	"grafana-mcp-oauth/pkg/store"
)

func main() {
	cfg := config.LoadFromEnv()

	// Ensure port defaults to 8080 for standard wrapper
	port := os.Getenv("PORT")
	if port == "" {
		port = os.Getenv("HTTP_PORT")
	}
	if port == "" {
		port = "8080"
	}

	targetMCPURL := os.Getenv("TARGET_MCP_URL")
	if targetMCPURL == "" {
		targetMCPURL = "http://127.0.0.1:8000"
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	logger.Info("Starting Grafana MCP OAuth Direct Wrapper (Sidecar / Standalone)",
		"port", port,
		"target_mcp_url", targetMCPURL,
		"grafana_url", cfg.GrafanaURL,
		"base_url", cfg.BaseURL,
		"redis_addr", cfg.RedisAddr,
	)

	// 1. Initialize Redis Client
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	ctxPing, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	if err := rdb.Ping(ctxPing).Err(); err != nil {
		logger.Warn("Could not connect to Redis at startup; will retry on operations", "error", err)
	} else {
		logger.Info("Successfully connected to Redis", "addr", cfg.RedisAddr)
	}
	cancelPing()

	// 2. Zero-Knowledge Encrypted Session Store (XChaCha20-Poly1305 + HMAC-SHA3-512)
	sessionStore, err := store.NewRedisSessionStore(rdb, cfg.MasterSecret)
	if err != nil {
		logger.Error("Failed to initialize session store", "error", err)
		os.Exit(1)
	}

	// 3. OAuth 2.1 & RFC 9728 Discovery Handler
	oauthHandler := oauth.NewHandler(oauth.Config{
		BaseURL:          cfg.BaseURL,
		GrafanaURL:       cfg.GrafanaURL,
		GrafanaPublicURL: cfg.GrafanaPublicURL,
		CallbackBaseURL:  cfg.CallbackBaseURL,
		SessionTTL:       cfg.SessionTTL,
		RefreshTTL:       cfg.RefreshTTL,
		Logger:           logger,
	}, sessionStore)

	// 4. Authenticated Reverse Proxy to Stock mcp-grafana
	mcpProxy, err := proxy.NewProxy(proxy.Config{
		TargetURL: targetMCPURL,
		BaseURL:   cfg.BaseURL,
		Logger:    logger,
	}, sessionStore)
	if err != nil {
		logger.Error("Failed to initialize reverse proxy", "error", err)
		os.Exit(1)
	}

	// 5. Mount Unified Routes
	mux := http.NewServeMux()

	// OAuth & Discovery routes
	oauthHandler.RegisterRoutes(mux)

	// Authenticated MCP Proxy route (handles /mcp/sse, /mcp/messages, etc.)
	mux.Handle("/mcp/", mcpProxy)

	// Health and root status
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Grafana MCP OAuth Wrapper</title></head>
<body style="font-family:sans-serif; text-align:center; padding:40px;">
  <h2>Grafana MCP OAuth Wrapper</h2>
  <p>Zero-Fork Authentication Layer for remote coding agents.</p>
  <p><a href="/mcp/auth/login">Login to Grafana MCP</a> | <a href="/.well-known/oauth-protected-resource">RFC 9728 Resource Discovery</a></p>
</body>
</html>`))
	})

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // 0 for streaming SSE
		IdleTimeout:       120 * time.Second,
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Info(fmt.Sprintf("Grafana MCP OAuth Wrapper listening on :%s", port))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-stopChan
	logger.Info("Shutting down gracefully...")
	ctxShut, cancelShut := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShut()
	_ = server.Shutdown(ctxShut)
	_ = rdb.Close()
	logger.Info("Shutdown complete.")
}
