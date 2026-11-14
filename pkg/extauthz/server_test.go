package extauthz_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"grafana-mcp-oauth/pkg/extauthz"
	"grafana-mcp-oauth/pkg/store"
)

func setupExtAuthzTest(t *testing.T) (*extauthz.Server, *store.RedisSessionStore) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	st, err := store.NewRedisSessionStore(rdb, []byte("ext-authz-test-secret-salt-32-bytes"))
	require.NoError(t, err)

	srv := extauthz.NewServer(st, "http://localhost:8080", nil)
	return srv, st
}

func TestExtAuthz_Check_Success(t *testing.T) {
	ctx := context.Background()
	srv, st := setupExtAuthzTest(t)

	token := "mcp_at_valid_test_token"
	sess := &store.SessionData{
		UserID:         "100",
		Username:       "charlie",
		GrafanaSession: "grafana_sess_charlie_12345",
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}
	err := st.SaveSession(ctx, token, sess, 1*time.Hour)
	require.NoError(t, err)

	// Simulate Envoy gRPC CheckRequest
	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "POST",
					Path:   "/mcp/v1/tools/call",
					Headers: map[string]string{
						"authorization": "Bearer " + token,
						"content-type":  "application/json",
						"cookie":        "other_cookie=xyz",
					},
				},
			},
		},
	}

	resp, err := srv.Check(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())

	okResp := resp.GetOkResponse()
	require.NotNil(t, okResp)

	// Verify Cookie header was injected
	var foundCookie, foundUser bool
	for _, h := range okResp.GetHeaders() {
		if h.GetHeader().GetKey() == "Cookie" {
			foundCookie = true
			val := h.GetHeader().GetValue()
			assert.Contains(t, val, "grafana_session=grafana_sess_charlie_12345")
			assert.Contains(t, val, "other_cookie=xyz")
		}
		if h.GetHeader().GetKey() == "X-Forwarded-User" {
			foundUser = true
			assert.Equal(t, "charlie", h.GetHeader().GetValue())
		}
	}
	assert.True(t, foundCookie, "Cookie header must be injected")
	assert.True(t, foundUser, "X-Forwarded-User header must be present")

	// Verify authorization header is stripped
	assert.Contains(t, okResp.GetHeadersToRemove(), "authorization")
}

func TestExtAuthz_Check_MissingOrInvalidToken(t *testing.T) {
	ctx := context.Background()
	srv, _ := setupExtAuthzTest(t)

	// Missing authorization header
	reqMissing := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  "GET",
					Path:    "/mcp/sse",
					Headers: map[string]string{},
				},
			},
		},
	}

	resp, err := srv.Check(ctx, reqMissing)
	require.NoError(t, err)
	assert.Equal(t, int32(codes.PermissionDenied), resp.GetStatus().GetCode())
	deniedResp := resp.GetDeniedResponse()
	require.NotNil(t, deniedResp)
	assert.Equal(t, typev3.StatusCode_Unauthorized, deniedResp.GetStatus().GetCode())

	// Verify RFC 9728 discovery challenge header
	var foundAuthHeader bool
	for _, h := range deniedResp.GetHeaders() {
		if h.GetHeader().GetKey() == "WWW-Authenticate" {
			foundAuthHeader = true
			assert.Contains(t, h.GetHeader().GetValue(), `resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource"`)
		}
	}
	assert.True(t, foundAuthHeader, "WWW-Authenticate header must contain resource_metadata pointer")

	// Nonexistent token
	reqInvalid := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "POST",
					Path:   "/mcp/v1/tools/list",
					Headers: map[string]string{
						"authorization": "Bearer mcp_at_fake_token",
					},
				},
			},
		},
	}

	resp, err = srv.Check(ctx, reqInvalid)
	require.NoError(t, err)
	assert.Equal(t, int32(codes.PermissionDenied), resp.GetStatus().GetCode())
	assert.Equal(t, typev3.StatusCode_Unauthorized, resp.GetDeniedResponse().GetStatus().GetCode())
}

func TestExtAuthz_HTTPCheck(t *testing.T) {
	ctx := context.Background()
	srv, st := setupExtAuthzTest(t)

	token := "mcp_at_http_token"
	sess := &store.SessionData{
		UserID:         "200",
		Username:       "dave",
		GrafanaSession: "grafana_sess_dave_67890",
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}
	err := st.SaveSession(ctx, token, sess, 1*time.Hour)
	require.NoError(t, err)

	// Valid HTTP request
	req := httptest.NewRequest(http.MethodGet, "/extauthz/check", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.HandleHTTPCheck(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "grafana_session=grafana_sess_dave_67890", w.Header().Get("Cookie"))
	assert.Equal(t, "dave", w.Header().Get("X-Forwarded-User"))
	assert.Equal(t, "authorization", w.Header().Get("x-envoy-auth-headers-to-remove"))
	assert.Empty(t, w.Header().Get("X-Grafana-Session"), "X-Grafana-Session must not be exposed in HTTP check response")

	// Unauthorized HTTP request
	reqUnauth := httptest.NewRequest(http.MethodGet, "/extauthz/check", nil)
	wUnauth := httptest.NewRecorder()
	srv.HandleHTTPCheck(wUnauth, reqUnauth)
	assert.Equal(t, http.StatusUnauthorized, wUnauth.Code)
	assert.Contains(t, wUnauth.Header().Get("WWW-Authenticate"), "resource_metadata=")
}
