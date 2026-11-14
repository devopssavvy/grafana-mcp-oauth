package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"grafana-mcp-oauth/pkg/config"
	"grafana-mcp-oauth/pkg/extauthz"
	"grafana-mcp-oauth/pkg/oauth"
	"grafana-mcp-oauth/pkg/proxy"
	"grafana-mcp-oauth/pkg/store"
)

// Mode constants
const (
	ModeProxy    = "proxy"
	ModeExtAuthz = "extauthz"
	ModeAll      = "all"
)

// Server represents the unified Grafana MCP Gateway server.
type Server struct {
	cfg          *config.AppConfig
	logger       *slog.Logger
	rdb          *redis.Client
	sessionStore *store.RedisSessionStore
	oauthHandler *oauth.Handler

	httpServer   *http.Server
	grpcServer   *grpc.Server
	httpListener net.Listener
	grpcListener net.Listener

	httpAddr string
	grpcAddr string

	mu      sync.Mutex
	running bool
}

// Options allows overriding settings when creating a Server instance.
type Options struct {
	Config       *config.AppConfig
	HTTPListener net.Listener
	GRPCListener net.Listener
	Logger       *slog.Logger
	RedisClient  *redis.Client
}

// New creates and configures a unified Server instance based on Mode.
func New(opts Options) (*Server, error) {
	cfg := opts.Config
	if cfg == nil {
		cfg = config.LoadFromEnv()
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = ModeProxy
	}
	if mode != ModeProxy && mode != ModeExtAuthz && mode != ModeAll {
		return nil, fmt.Errorf("invalid mode %q: must be one of 'proxy', 'extauthz', 'all'", mode)
	}
	cfg.Mode = mode

	// Ensure ExtAuthz mode defaults HTTP port to 8081 if no explicit PORT/HTTP_PORT was provided
	if mode == ModeExtAuthz {
		if cfg.HTTPPort == "" || (cfg.HTTPPort == "8080" && os.Getenv("PORT") == "" && os.Getenv("HTTP_PORT") == "") {
			cfg.HTTPPort = "8081"
		}
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	}

	// 1. Initialize Redis Client
	rdb := opts.RedisClient
	if rdb == nil {
		rdb = redis.NewClient(&redis.Options{
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
	}

	// 2. Zero-Knowledge Encrypted Session Store
	sessionStore, err := store.NewRedisSessionStore(rdb, cfg.MasterSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize session store: %w", err)
	}

	// 3. OAuth 2.1 & RFC 9728 Discovery Handler
	oauthHandler := oauth.NewHandler(oauth.Config{
		BaseURL:           cfg.BaseURL,
		GrafanaURL:        cfg.GrafanaURL,
		GrafanaPublicURL:  cfg.GrafanaPublicURL,
		CallbackBaseURL:   cfg.CallbackBaseURL,
		CookieSecure:      cfg.CookieSecure,
		SessionTTL:        cfg.SessionTTL,
		RefreshTTL:        cfg.RefreshTTL,
		PendingAuthTTL:    cfg.PendingAuthTTL,
		AuthCodeTTL:       cfg.AuthCodeTTL,
		RateLimitLoginRPM: cfg.RateLimitLoginRPM,
		RateLimitTokenRPM: cfg.RateLimitTokenRPM,
		Logger:            logger,
	}, sessionStore)

	s := &Server{
		cfg:          cfg,
		logger:       logger,
		rdb:          rdb,
		sessionStore: sessionStore,
		oauthHandler: oauthHandler,
		httpListener: opts.HTTPListener,
		grpcListener: opts.GRPCListener,
	}

	// 4. Setup routes and servers based on mode
	mux := http.NewServeMux()
	oauthHandler.RegisterRoutes(mux)

	// In extauthz or all mode: setup ExtAuthz HTTP check and gRPC server
	if mode == ModeExtAuthz || mode == ModeAll {
		extAuthServer := extauthz.NewServer(sessionStore, cfg.BaseURL, logger)

		// HTTP Check endpoint for internal ingress/reverse proxies (NGINX auth_request, Traefik ForwardAuth)
		// Note: Not exposed under public /mcp/auth/ to prevent external credential oracle attacks
		mux.HandleFunc("/extauthz/check", extAuthServer.HandleHTTPCheck)

		// gRPC Server setup
		grpcServer := grpc.NewServer()
		authv3.RegisterAuthorizationServer(grpcServer, extAuthServer)
		reflection.Register(grpcServer)
		s.grpcServer = grpcServer
	}

	// In proxy or all mode: setup Authenticated Reverse Proxy to upstream MCP
	if mode == ModeProxy || mode == ModeAll {
		mcpProxy, err := proxy.NewProxy(proxy.Config{
			TargetURL: cfg.TargetMCPURL,
			BaseURL:   cfg.BaseURL,
			Logger:    logger,
		}, sessionStore)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize reverse proxy: %w", err)
		}
		mux.Handle("/mcp", mcpProxy)
		mux.Handle("/mcp/", mcpProxy)
	}

	// Common health and index endpoints
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Grafana MCP Gateway (%s mode)</title></head>
<body style="font-family:sans-serif; text-align:center; padding:40px;">
  <h2>Grafana MCP Gateway</h2>
  <p>Mode: <strong>%s</strong></p>
  <p>Zero-Fork Authentication Layer for remote coding agents.</p>
  <p><a href="/mcp/auth/login">Login to Grafana MCP</a> | <a href="/.well-known/oauth-protected-resource">RFC 9728 Resource Discovery</a></p>
</body>
</html>`, mode, mode)
	})

	s.httpServer = &http.Server{
		Addr:              ":" + cfg.HTTPPort,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // 0 for streaming SSE
		IdleTimeout:       120 * time.Second,
	}

	return s, nil
}

// Start binds listeners upfront and starts serving HTTP (and gRPC if enabled).
// Returns an error channel that will receive any fatal server errors.
func (s *Server) Start() (<-chan error, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil, fmt.Errorf("server is already running")
	}

	// 1. Bind HTTP Listener upfront before launching any background goroutines
	if s.httpListener == nil {
		httpAddr := net.JoinHostPort(s.cfg.HTTPHost, s.cfg.HTTPPort)
		ln, err := net.Listen("tcp", httpAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on HTTP %s: %w", httpAddr, err)
		}
		s.httpListener = ln
	}
	s.httpAddr = s.httpListener.Addr().String()

	// 2. Bind gRPC Listener upfront if in extauthz or all mode
	if s.grpcServer != nil {
		if s.grpcListener == nil {
			grpcAddr := net.JoinHostPort(s.cfg.GRPCHost, s.cfg.GRPCPort)
			ln, err := net.Listen("tcp", grpcAddr)
			if err != nil {
				_ = s.httpListener.Close()
				s.httpListener = nil
				return nil, fmt.Errorf("failed to listen on gRPC %s: %w", grpcAddr, err)
			}
			s.grpcListener = ln
		}
		s.grpcAddr = s.grpcListener.Addr().String()
	}

	errChan := make(chan error, 2)

	// 3. Launch HTTP serving goroutine
	go func() {
		s.logger.Info("HTTP server listening", "mode", s.cfg.Mode, "addr", s.httpAddr)
		if err := s.httpServer.Serve(s.httpListener); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("http server error: %w", err)
		}
	}()

	// 4. Launch gRPC serving goroutine if enabled
	if s.grpcServer != nil && s.grpcListener != nil {
		go func() {
			s.logger.Info("gRPC Envoy ext_authz server listening", "mode", s.cfg.Mode, "addr", s.grpcAddr)
			if err := s.grpcServer.Serve(s.grpcListener); err != nil {
				errChan <- fmt.Errorf("grpc server error: %w", err)
			}
		}()
	}

	s.running = true
	return errChan, nil
}

// HTTPAddr returns the bound HTTP address.
func (s *Server) HTTPAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.httpAddr
}

// GRPCAddr returns the bound gRPC address (empty if not enabled).
func (s *Server) GRPCAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.grpcAddr
}

// Mode returns the active server mode.
func (s *Server) Mode() string {
	return s.cfg.Mode
}

// Shutdown gracefully stops both HTTP and gRPC servers concurrently within the context deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.logger.Info("Shutting down Grafana MCP Gateway gracefully...", "mode", s.cfg.Mode)

	var wg sync.WaitGroup
	var httpErr error

	// Concurrently drain gRPC server with deadline protection
	if s.grpcServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stopped := make(chan struct{})
			go func() {
				s.grpcServer.GracefulStop()
				close(stopped)
			}()
			select {
			case <-ctx.Done():
				s.logger.Warn("gRPC ext_authz graceful stop timed out, forcing immediate stop")
				s.grpcServer.Stop()
			case <-stopped:
			}
		}()
	}

	// Concurrently drain HTTP server
	if s.httpServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			httpErr = s.httpServer.Shutdown(ctx)
		}()
	}

	wg.Wait()

	if s.oauthHandler != nil {
		s.oauthHandler.Close()
	}

	if s.rdb != nil {
		_ = s.rdb.Close()
	}

	s.running = false
	s.logger.Info("Shutdown complete")
	return httpErr
}
