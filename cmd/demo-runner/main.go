package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alicebob/miniredis/v2"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"grafana-mcp-oauth/pkg/extauthz"
	"grafana-mcp-oauth/pkg/oauth"
	"grafana-mcp-oauth/pkg/store"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	logger.Info("Starting Live Demo Ecosystem for Agent Verification...")

	// 1. Start In-Memory Miniredis
	mr, err := miniredis.Run()
	if err != nil {
		logger.Error("Failed to start miniredis", "error", err)
		os.Exit(1)
	}
	defer mr.Close()
	logger.Info("Redis started", "addr", mr.Addr())

	// 2. Start Mock Grafana Server on port 3000
	mockGrafanaListener, err := net.Listen("tcp", "127.0.0.1:3000")
	if err != nil {
		logger.Error("Failed to listen on :3000 for Grafana", "error", err)
		os.Exit(1)
	}
	defer mockGrafanaListener.Close()

	var lastGrafanaCookie string
	var cookieMu sync.Mutex

	grafanaMux := http.NewServeMux()
	grafanaMux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><h1>Grafana 11 Enterprise</h1><p>Web User View</p></body></html>"))
	})
	grafanaMux.HandleFunc("GET /login/generic_oauth", func(w http.ResponseWriter, r *http.Request) {
		redirectTarget := r.URL.Query().Get("redirect")
		if redirectTarget == "" {
			redirectTarget = "/"
		}
		// Simulate successful SSO login: set grafana_session cookie and redirect
		http.SetCookie(w, &http.Cookie{
			Name:     "grafana_session",
			Value:    "live_demo_grafana_session_secret_999",
			Path:     "/",
			HttpOnly: true,
		})
		http.Redirect(w, r, redirectTarget, http.StatusFound)
	})
	grafanaMux.HandleFunc("GET /api/user", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("grafana_session")
		if err != nil || cookie.Value != "live_demo_grafana_session_secret_999" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"Unauthorized: invalid session"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(oauth.GrafanaUser{
			ID:    777,
			Email: "alex@company.com",
			Name:  "Alex Principal SRE",
			Login: "alex-sre",
			OrgID: 1,
		})
	})
	grafanaMux.HandleFunc("POST /api/ds/query", func(w http.ResponseWriter, r *http.Request) {
		cookieMu.Lock()
		cookie, _ := r.Cookie("grafana_session")
		if cookie != nil {
			lastGrafanaCookie = cookie.Value
			logger.Info("Grafana Datasource Query received authenticated session cookie", "session", lastGrafanaCookie)
		}
		cookieMu.Unlock()

		if cookie == nil || cookie.Value != "live_demo_grafana_session_secret_999" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"Unauthorized: Missing or invalid Grafana session for OAuth passthru"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"node_cpu_utilization_ratio","instance":"prod-cluster-01"},"values":[[1700000000,"0.14"]]}]}}`))
	})

	grafanaServer := &http.Server{Handler: grafanaMux}
	go func() { _ = grafanaServer.Serve(mockGrafanaListener) }()
	logger.Info("Mock Grafana Server running", "url", "http://127.0.0.1:3000")

	// 3. Initialize mcp-auth-helper
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	masterSecret := []byte("demo-master-secret-key-at-least-32-bytes-long!")
	sessionStore, err := store.NewRedisSessionStore(rdb, masterSecret)
	if err != nil {
		logger.Error("Failed to init store", "error", err)
		os.Exit(1)
	}

	oauthCfg := oauth.Config{
		BaseURL:         "http://127.0.0.1:8080",
		GrafanaURL:      "http://127.0.0.1:3000",
		CallbackBaseURL: "http://127.0.0.1:8080/mcp/auth/callback",
		SessionTTL:      2 * time.Hour,
		RefreshTTL:      30 * 24 * time.Hour,
		Logger:          logger,
	}
	oauthHandler := oauth.NewHandler(oauthCfg, sessionStore)
	extAuthServer := extauthz.NewServer(sessionStore, "http://127.0.0.1:8080", logger)

	// Start gRPC ext_authz on :9001
	grpcListener, err := net.Listen("tcp", "127.0.0.1:9001")
	if err != nil {
		logger.Error("Failed to listen on gRPC :9001", "error", err)
		os.Exit(1)
	}
	defer grpcListener.Close()
	grpcServer := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcServer, extAuthServer)
	go func() { _ = grpcServer.Serve(grpcListener) }()
	logger.Info("gRPC ext_authz Server running", "addr", "127.0.0.1:9001")

	// 4. Start Stock mcp-grafana Simulation Server on port :8000
	mcpListener, err := net.Listen("tcp", "127.0.0.1:8000")
	if err != nil {
		logger.Error("Failed to listen on :8000 for mcp-grafana", "error", err)
		os.Exit(1)
	}
	defer mcpListener.Close()

	var sessionsMu sync.Mutex
	sseClients := make(map[string]chan string)

	mcpMux := http.NewServeMux()

	// SSE Transport endpoint
	mcpMux.HandleFunc("GET /mcp/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		sessionID := fmt.Sprintf("sess_%d", time.Now().UnixNano())
		msgChan := make(chan string, 16)

		sessionsMu.Lock()
		sseClients[sessionID] = msgChan
		sessionsMu.Unlock()

		defer func() {
			sessionsMu.Lock()
			delete(sseClients, sessionID)
			sessionsMu.Unlock()
		}()

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Initial SSE event announcing endpoint
		endpointEvent := fmt.Sprintf("event: endpoint\ndata: /mcp/messages?sessionId=%s\n\n", sessionID)
		_, _ = w.Write([]byte(endpointEvent))
		flusher.Flush()

		notify := r.Context().Done()
		for {
			select {
			case <-notify:
				return
			case msg := <-msgChan:
				_, _ = w.Write([]byte(msg))
				flusher.Flush()
			}
		}
	})

	// JSON-RPC Message POST handler
	mcpMux.HandleFunc("POST /mcp/messages", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("sessionId")
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var req map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		method, _ := req["method"].(string)
		id := req["id"]

		sessionsMu.Lock()
		clientChan, hasClient := sseClients[sessionID]
		sessionsMu.Unlock()

		var respData map[string]interface{}
		switch method {
		case "initialize":
			respData = map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"protocolVersion": "2024-11-05",
					"capabilities": map[string]interface{}{
						"tools": map[string]interface{}{},
					},
					"serverInfo": map[string]interface{}{
						"name":    "grafana-mcp-oauth",
						"version": "1.0.0",
					},
				},
			}
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
			return
		case "tools/list":
			respData = map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"tools": []map[string]interface{}{
						{
							"name":        "query_prometheus",
							"description": "Execute Prometheus PromQL query via Grafana Datasource with user OAuth claims",
							"inputSchema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"query": map[string]interface{}{
										"type":        "string",
										"description": "The PromQL query string",
									},
								},
								"required": []string{"query"},
							},
						},
					},
				},
			}
		case "tools/call":
			// Forward request to Grafana API with Cookie header (verifies GRAFANA_FORWARD_HEADERS=Cookie)
			grafanaReq, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:3000/api/ds/query", nil)
			if c := r.Header.Get("Cookie"); c != "" {
				grafanaReq.Header.Set("Cookie", c)
			}
			grafanaResp, err := http.DefaultClient.Do(grafanaReq)
			if err != nil || grafanaResp.StatusCode != http.StatusOK {
				respData = map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      id,
					"error": map[string]interface{}{
						"code":    -32000,
						"message": fmt.Sprintf("Grafana API query rejected: status %v", grafanaResp.StatusCode),
					},
				}
			} else {
				respBody, _ := io.ReadAll(grafanaResp.Body)
				grafanaResp.Body.Close()
				respData = map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      id,
					"result": map[string]interface{}{
						"content": []map[string]interface{}{
							{
								"type": "text",
								"text": string(respBody),
							},
						},
					},
				}
			}
		default:
			respData = map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"error": map[string]interface{}{
					"code":    -32601,
					"message": "Method not found",
				},
			}
		}

		if hasClient && respData != nil {
			respJSON, _ := json.Marshal(respData)
			clientChan <- fmt.Sprintf("event: message\ndata: %s\n\n", string(respJSON))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	})

	mcpServer := &http.Server{Handler: mcpMux}
	go func() { _ = mcpServer.Serve(mcpListener) }()
	logger.Info("Upstream mcp-grafana Simulation Server running", "url", "http://127.0.0.1:8000")

	// 5. Start Envoy Gateway Simulation on port :8080
	gatewayListener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		logger.Error("Failed to listen on Gateway port :8080", "error", err)
		os.Exit(1)
	}
	defer gatewayListener.Close()

	gatewayMux := http.NewServeMux()

	// Route 1: RFC 9728 Discovery & OAuth Endpoints
	oauthMux := http.NewServeMux()
	oauthHandler.RegisterRoutes(oauthMux)

	gatewayMux.HandleFunc("/.well-known/", oauthMux.ServeHTTP)
	gatewayMux.HandleFunc("/mcp/auth/", oauthMux.ServeHTTP)
	gatewayMux.HandleFunc("/mcp/auth", oauthMux.ServeHTTP)

	// Route 2: Remote MCP Endpoint protected by ext_authz -> mcp-grafana:8000
	gatewayMux.HandleFunc("/mcp/", func(w http.ResponseWriter, r *http.Request) {
		headersMap := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				headersMap[strings.ToLower(k)] = v[0]
			}
		}

		checkReq := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method:  r.Method,
						Path:    r.URL.Path,
						Headers: headersMap,
					},
				},
			},
		}

		checkResp, err := extAuthServer.Check(r.Context(), checkReq)
		if err != nil || checkResp.GetStatus().GetCode() != int32(codes.OK) {
			denied := checkResp.GetDeniedResponse()
			if denied != nil {
				for _, h := range denied.GetHeaders() {
					w.Header().Set(h.GetHeader().GetKey(), h.GetHeader().GetValue())
				}
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("401 Unauthorized: MCP authentication required\n"))
			return
		}

		// Mutate headers as requested by ext_authz
		okResp := checkResp.GetOkResponse()
		forwardReq, _ := http.NewRequestWithContext(r.Context(), r.Method, "http://127.0.0.1:8000"+r.URL.RequestURI(), r.Body)
		for k, v := range r.Header {
			forwardReq.Header[k] = v
		}
		for _, rm := range okResp.GetHeadersToRemove() {
			forwardReq.Header.Del(rm)
		}
		for _, add := range okResp.GetHeaders() {
			forwardReq.Header.Set(add.GetHeader().GetKey(), add.GetHeader().GetValue())
		}

		// Forward to upstream mcp-grafana
		if r.Header.Get("Accept") == "text/event-stream" || strings.HasSuffix(r.URL.Path, "/sse") {
			// Streaming SSE forwarder
			client := &http.Client{}
			resp, err := client.Do(forwardReq)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			for k, v := range resp.Header {
				w.Header()[k] = v
			}
			w.WriteHeader(resp.StatusCode)
			flusher, _ := w.(http.Flusher)
			buf := make([]byte, 1024)
			for {
				n, err := resp.Body.Read(buf)
				if n > 0 {
					_, _ = w.Write(buf[:n])
					if flusher != nil {
						flusher.Flush()
					}
				}
				if err != nil {
					break
				}
			}
			return
		}

		resp, err := http.DefaultClient.Do(forwardReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	// Route 3: Transparent Pass-through to Grafana Web UI
	gatewayMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		forwardReq, _ := http.NewRequestWithContext(r.Context(), r.Method, "http://127.0.0.1:3000"+r.URL.RequestURI(), r.Body)
		for k, v := range r.Header {
			forwardReq.Header[k] = v
		}
		resp, err := http.DefaultClient.Do(forwardReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	gatewayServer := &http.Server{Handler: gatewayMux}
	go func() { _ = gatewayServer.Serve(gatewayListener) }()
	logger.Info("Envoy Gateway Unified Entrypoint running", "url", "http://127.0.0.1:8080")

	logger.Info("=================================================================")
	logger.Info("LIVE ECOSYSTEM READY! Press Ctrl+C to stop.")
	logger.Info("1. Web UI:        http://127.0.0.1:8080/")
	logger.Info("2. MCP SSE:       http://127.0.0.1:8080/mcp/sse")
	logger.Info("3. OAuth Login:   http://127.0.0.1:8080/mcp/auth/login")
	logger.Info("4. RFC 9728 Meta: http://127.0.0.1:8080/.well-known/oauth-protected-resource")
	logger.Info("=================================================================")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down demo servers...")
}
