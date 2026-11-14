package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"grafana-mcp-oauth/pkg/config"
	"grafana-mcp-oauth/pkg/extauthz"
	"grafana-mcp-oauth/pkg/oauth"
	"grafana-mcp-oauth/pkg/store"
)

func main() {
	cfg := config.LoadFromEnv()

	// Configure structured logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))
	slog.SetDefault(logger)

	logger.Info("Starting Grafana MCP Auth Helper",
		"http_port", cfg.HTTPPort,
		"grpc_port", cfg.GRPCPort,
		"grafana_url", cfg.GrafanaURL,
		"callback_base_url", cfg.CallbackBaseURL,
		"redis_addr", cfg.RedisAddr,
		"master_secret_fingerprint", cfg.MasterSecretHex(),
	)

	// Initialize Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	// Ping Redis with timeout
	ctxPing, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	if err := rdb.Ping(ctxPing).Err(); err != nil {
		logger.Warn("Could not connect to Redis at startup; will retry on operations", "error", err)
	} else {
		logger.Info("Successfully connected to Redis", "addr", cfg.RedisAddr)
	}
	cancelPing()

	// Initialize Zero-Knowledge Encrypted Session Store
	sessionStore, err := store.NewRedisSessionStore(rdb, cfg.MasterSecret)
	if err != nil {
		logger.Error("Failed to initialize session store", "error", err)
		os.Exit(1)
	}

	// Initialize OAuth Handler
	oauthHandler := oauth.NewHandler(oauth.Config{
		BaseURL:          cfg.BaseURL,
		GrafanaURL:       cfg.GrafanaURL,
		GrafanaPublicURL: cfg.GrafanaPublicURL,
		CallbackBaseURL:  cfg.CallbackBaseURL,
		SessionTTL:       cfg.SessionTTL,
		RefreshTTL:       cfg.RefreshTTL,
		Logger:           logger,
	}, sessionStore)

	// Initialize Envoy External Authorization Server
	extAuthServer := extauthz.NewServer(sessionStore, cfg.BaseURL, logger)

	// Set up HTTP Server
	httpMux := http.NewServeMux()
	oauthHandler.RegisterRoutes(httpMux)
	// Also register HTTP ext_authz check endpoint for HTTP filter mode (NGINX auth_request, Kong forward-auth, Traefik ForwardAuth)
	httpMux.HandleFunc("GET /extauthz/check", extAuthServer.HandleHTTPCheck)
	httpMux.HandleFunc("POST /extauthz/check", extAuthServer.HandleHTTPCheck)
	httpMux.HandleFunc("GET /mcp/auth/check", extAuthServer.HandleHTTPCheck)
	httpMux.HandleFunc("POST /mcp/auth/check", extAuthServer.HandleHTTPCheck)

	httpServer := &http.Server{
		Addr:              ":" + cfg.HTTPPort,
		Handler:           httpMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Set up gRPC Server for native Envoy gRPC ext_authz
	grpcServer := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcServer, extAuthServer)
	reflection.Register(grpcServer)

	grpcListener, err := net.Listen("tcp", ":"+cfg.GRPCPort)
	if err != nil {
		logger.Error("Failed to listen on gRPC port", "port", cfg.GRPCPort, "error", err)
		os.Exit(1)
	}

	// Start servers in goroutines
	errChan := make(chan error, 2)

	go func() {
		logger.Info(fmt.Sprintf("HTTP OAuth & Check server listening on :%s", cfg.HTTPPort))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("http server error: %w", err)
		}
	}()

	go func() {
		logger.Info(fmt.Sprintf("gRPC Envoy ext_authz server listening on :%s", cfg.GRPCPort))
		if err := grpcServer.Serve(grpcListener); err != nil {
			errChan <- fmt.Errorf("grpc server error: %w", err)
		}
	}()

	// Wait for shutdown signal or fatal error
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		logger.Info("Received termination signal, shutting down gracefully", "signal", sig.String())
	case err := <-errChan:
		logger.Error("Server encountered fatal error", "error", err)
	}

	// Graceful shutdown
	ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()

	grpcServer.GracefulStop()
	if err := httpServer.Shutdown(ctxShutdown); err != nil {
		logger.Error("Error during HTTP server shutdown", "error", err)
	}
	_ = rdb.Close()

	logger.Info("Grafana MCP Auth Helper stopped cleanly")
}
