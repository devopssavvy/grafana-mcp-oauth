package oauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grafana-mcp-oauth/pkg/oauth"
)

func TestRotateGrafanaSession_SuccessWithNewCookie(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/user/auth-tokens/rotate", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		cookie, err := r.Cookie("grafana_session")
		require.NoError(t, err)
		assert.Equal(t, "sess_old_123", cookie.Value)

		http.SetCookie(w, &http.Cookie{
			Name:     "grafana_session",
			Value:    "sess_new_456",
			Path:     "/",
			HttpOnly: true,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer mockServer.Close()

	ctx := context.Background()
	newSess, err := oauth.RotateGrafanaSession(ctx, mockServer.URL, "sess_old_123", nil)
	require.NoError(t, err)
	assert.Equal(t, "sess_new_456", newSess)
}

func TestRotateGrafanaSession_SuccessNoCookie_RetainsCurrent(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/user/auth-tokens/rotate", r.URL.Path)
		// Return 200 OK without Set-Cookie (e.g. SkipRotationTime threshold)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer mockServer.Close()

	ctx := context.Background()
	newSess, err := oauth.RotateGrafanaSession(ctx, mockServer.URL, "sess_current_789", nil)
	require.NoError(t, err)
	assert.Equal(t, "sess_current_789", newSess)
}

func TestRotateGrafanaSession_InvalidSession(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Unauthorized"}`))
	}))
	defer mockServer.Close()

	ctx := context.Background()
	_, err := oauth.RotateGrafanaSession(ctx, mockServer.URL, "sess_expired", nil)
	assert.ErrorIs(t, err, oauth.ErrGrafanaSessionInvalid)
}

func TestRotateGrafanaSession_RedirectTreatedAsInvalidSession(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/user/auth-tokens/rotate" {
			// Simulate Grafana redirecting unauthenticated / expired browser session to /login
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if r.URL.Path == "/login" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>login page</html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockServer.Close()

	ctx := context.Background()
	_, err := oauth.RotateGrafanaSession(ctx, mockServer.URL, "sess_redirected", nil)
	assert.ErrorIs(t, err, oauth.ErrGrafanaSessionInvalid, "HTTP 302 redirect to /login must be treated as invalid session, not followed")
}

func TestRotateGrafanaSession_DeletedCookie(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:   "grafana_session",
			Value:  "",
			MaxAge: -1,
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	ctx := context.Background()
	_, err := oauth.RotateGrafanaSession(ctx, mockServer.URL, "sess_deleted", nil)
	assert.ErrorIs(t, err, oauth.ErrGrafanaSessionInvalid)
}

func TestRotateGrafanaSession_ServerError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mockServer.Close()

	ctx := context.Background()
	_, err := oauth.RotateGrafanaSession(ctx, mockServer.URL, "sess_error", nil)
	assert.Error(t, err)
	assert.NotErrorIs(t, err, oauth.ErrGrafanaSessionInvalid)
}

func TestRotateGrafanaSession_InvalidArguments(t *testing.T) {
	ctx := context.Background()
	_, err := oauth.RotateGrafanaSession(ctx, "", "sess_123", nil)
	assert.Error(t, err)

	_, err = oauth.RotateGrafanaSession(ctx, "http://localhost:3000", "", nil)
	assert.Error(t, err)

	// Context cancellation
	timeoutCtx, cancel := context.WithTimeout(ctx, 1*time.Millisecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond)
	_, err = oauth.RotateGrafanaSession(timeoutCtx, "http://127.0.0.1:54321", "sess_123", nil)
	assert.Error(t, err)
}

func TestRevokeGrafanaSession_Success(t *testing.T) {
	var receivedCookie string
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/logout", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		if c, err := r.Cookie("grafana_session"); err == nil {
			receivedCookie = c.Value
		}
		// Grafana redirects to /login on logout
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer mockServer.Close()

	ctx := context.Background()
	err := oauth.RevokeGrafanaSession(ctx, mockServer.URL, "sess_to_revoke_123", nil)
	require.NoError(t, err)
	assert.Equal(t, "sess_to_revoke_123", receivedCookie)
}

func TestRevokeGrafanaSession_EmptyArgs(t *testing.T) {
	ctx := context.Background()

	// Empty grafanaURL returns error
	err := oauth.RevokeGrafanaSession(ctx, "", "sess_123", nil)
	assert.Error(t, err)

	// Empty currentSession is a no-op
	err = oauth.RevokeGrafanaSession(ctx, "http://localhost:3000", "", nil)
	assert.NoError(t, err)
}
