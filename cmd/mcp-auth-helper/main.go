package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"grafana-mcp-oauth/pkg/config"
	"grafana-mcp-oauth/pkg/server"
)

func main() {
	cfg := config.LoadFromEnv()
	cfg.Mode = server.ModeExtAuthz

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	logger.Warn("DEPRECATION NOTICE: 'mcp-auth-helper' is deprecated and will be removed in a future release. Use 'grafana-mcp-oauth --mode=extauthz' instead.")

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

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		logger.Info("Received termination signal, shutting down gracefully", "signal", sig.String())
	case err := <-errChan:
		logger.Error("Server encountered fatal error", "error", err)
	}

	ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()

	_ = srv.Shutdown(ctxShutdown)
	logger.Info("Shutdown complete")
}
