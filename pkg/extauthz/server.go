package extauthz

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"grafana-mcp-oauth/pkg/store"
)

// Server implements Envoy external authorization for both gRPC and HTTP protocols.
type Server struct {
	authv3.UnimplementedAuthorizationServer
	store   store.SessionStore
	baseURL string
	logger  *slog.Logger
}

// NewServer creates a new Envoy external authorization server.
func NewServer(s store.SessionStore, baseURL string, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	return &Server{
		store:   s,
		baseURL: strings.TrimRight(baseURL, "/"),
		logger:  logger,
	}
}

// Check handles Envoy gRPC external authorization checks (envoy.service.auth.v3.Authorization/Check).
func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	if httpReq == nil {
		return s.buildDeniedResponse("Missing HTTP request attributes", http.StatusBadRequest), nil
	}

	headers := httpReq.GetHeaders()
	authHeader := getHeader(headers, "authorization")
	token := extractBearerToken(authHeader)

	if token == "" {
		s.logger.Warn("ext_authz rejected: missing or invalid Authorization header",
			"path", httpReq.GetPath(),
			"method", httpReq.GetMethod(),
		)
		return s.buildDeniedResponse("Unauthorized: Missing or invalid Bearer token", http.StatusUnauthorized), nil
	}

	// Validate token against encrypted session store
	session, err := s.store.GetSession(ctx, token)
	if err != nil {
		s.logger.Warn("ext_authz rejected: invalid or expired session",
			"error", err,
			"path", httpReq.GetPath(),
		)
		return s.buildDeniedResponse("Unauthorized: Session invalid or expired", http.StatusUnauthorized), nil
	}

	s.logger.Debug("ext_authz approved: injecting grafana_session",
		"username", session.Username,
		"path", httpReq.GetPath(),
	)

	// Combine with existing cookies if any, ensuring grafana_session is injected
	existingCookie := getHeader(headers, "cookie")
	injectedCookie := buildCookieHeader(existingCookie, session.GrafanaSession)

	// Build success response with header mutation
	okResponse := &authv3.OkHttpResponse{
		Headers: []*corev3.HeaderValueOption{
			{
				Header: &corev3.HeaderValue{
					Key:   "Cookie",
					Value: injectedCookie,
				},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			},
			{
				Header: &corev3.HeaderValue{
					Key:   "X-Forwarded-User",
					Value: session.Username,
				},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			},
		},
		// Remove incoming Bearer Authorization credential so it cannot leak upstream
		HeadersToRemove: []string{"authorization"},
	}

	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(codes.OK),
		},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: okResponse,
		},
	}, nil
}

// HandleHTTPCheck implements an HTTP endpoint for Envoy's HTTP ext_authz filter.
func (s *Server) HandleHTTPCheck(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	token := extractBearerToken(authHeader)

	if token == "" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, s.baseURL))
		http.Error(w, "Unauthorized: Missing Bearer token", http.StatusUnauthorized)
		return
	}

	session, err := s.store.GetSession(r.Context(), token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="invalid_token", resource_metadata="%s/.well-known/oauth-protected-resource"`, s.baseURL))
		http.Error(w, "Unauthorized: Session invalid or expired", http.StatusUnauthorized)
		return
	}

	// For Envoy HTTP ext_authz, NGINX auth_request & Kong forward-auth:
	cookieVal := buildCookieHeader(r.Header.Get("Cookie"), session.GrafanaSession)
	w.Header().Set("Cookie", cookieVal)
	w.Header().Set("X-Grafana-Session", session.GrafanaSession)
	w.Header().Set("X-Forwarded-User", session.Username)
	w.Header().Set("x-envoy-auth-headers-to-remove", "authorization")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) buildDeniedResponse(message string, httpStatus int) *authv3.CheckResponse {
	statusCode := typev3.StatusCode_Unauthorized
	if httpStatus == http.StatusBadRequest {
		statusCode = typev3.StatusCode_BadRequest
	} else if httpStatus == http.StatusForbidden {
		statusCode = typev3.StatusCode_Forbidden
	}

	// RFC 9728 MCP OAuth protected resource challenge
	challenge := fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, s.baseURL)
	if httpStatus == http.StatusUnauthorized && strings.Contains(message, "invalid or expired") {
		challenge = fmt.Sprintf(`Bearer error="invalid_token", resource_metadata="%s/.well-known/oauth-protected-resource"`, s.baseURL)
	}

	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(codes.PermissionDenied),
		},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{
					Code: statusCode,
				},
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   "WWW-Authenticate",
							Value: challenge,
						},
						AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
					},
					{
						Header: &corev3.HeaderValue{
							Key:   "Content-Type",
							Value: "text/plain; charset=utf-8",
						},
						AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
					},
				},
				Body: message + "\n",
			},
		},
	}
}

func extractBearerToken(h string) string {
	const prefix = "bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

func getHeader(headers map[string]string, key string) string {
	keyLower := strings.ToLower(key)
	for k, v := range headers {
		if strings.ToLower(k) == keyLower {
			return v
		}
	}
	return ""
}

func buildCookieHeader(existingCookie, session string) string {
	grafanaCookie := fmt.Sprintf("grafana_session=%s", session)
	if existingCookie == "" {
		return grafanaCookie
	}

	// Remove any existing stale grafana_session case-insensitively and append fresh one
	var parts []string
	for _, c := range strings.Split(existingCookie, ";") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		kv := strings.SplitN(c, "=", 2)
		cookieName := strings.TrimSpace(kv[0])
		if !strings.EqualFold(cookieName, "grafana_session") {
			parts = append(parts, c)
		}
	}
	parts = append(parts, grafanaCookie)
	return strings.Join(parts, "; ")
}
