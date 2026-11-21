package oauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	// ErrGrafanaSessionInvalid is returned when Grafana explicitly rejects the session token (401, 403, or 3xx redirect to login).
	ErrGrafanaSessionInvalid = errors.New("grafana session expired or revoked")
)

// RotateGrafanaSession calls Grafana's POST /api/user/auth-tokens/rotate endpoint
// with the existing grafana_session cookie and returns the newly rotated session cookie value.
// If Grafana returns 200 OK without a Set-Cookie (e.g. SkipRotationTime threshold),
// it returns (currentSession, nil).
// It strictly rejects HTTP redirects (e.g. 302 to /login) to prevent session validation bypass
// and credential leakage.
func RotateGrafanaSession(ctx context.Context, grafanaURL string, currentSession string, client *http.Client) (string, error) {
	if grafanaURL == "" {
		return "", errors.New("grafanaURL must not be empty")
	}
	if currentSession == "" {
		return "", errors.New("currentSession must not be empty")
	}

	reqURL := fmt.Sprintf("%s/api/user/auth-tokens/rotate", strings.TrimRight(grafanaURL, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create rotation request: %w", err)
	}

	req.Header.Set("Cookie", fmt.Sprintf("grafana_session=%s", currentSession))
	req.Header.Set("Accept", "application/json")

	// Disallow HTTP redirects to prevent credential leakage and false-positive 200 OK responses from /login
	rotClient := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if client != nil {
		if client.Timeout > 0 {
			rotClient.Timeout = client.Timeout
		}
		if client.Transport != nil {
			rotClient.Transport = client.Transport
		}
	}

	resp, err := rotClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute rotation request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()

	// 3xx redirects (e.g. 302 to /login) indicate an unauthenticated/expired session in Grafana
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || (resp.StatusCode >= 300 && resp.StatusCode < 400) {
		return "", ErrGrafanaSessionInvalid
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("grafana rotation returned unexpected status %d", resp.StatusCode)
	}

	for _, c := range resp.Cookies() {
		if strings.EqualFold(c.Name, "grafana_session") {
			if c.MaxAge < 0 || c.Value == "" {
				return "", ErrGrafanaSessionInvalid
			}
			return c.Value, nil
		}
	}

	// Grafana returns 200 OK without Set-Cookie if SkipRotationTime was triggered; session is still valid.
	return currentSession, nil
}
