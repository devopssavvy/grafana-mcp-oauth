package store_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grafana-mcp-oauth/pkg/store"
)

func setupTestStore(t *testing.T) (*store.RedisSessionStore, *miniredis.Miniredis) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	secret := []byte("master-secret-key-at-least-32-bytes-long!")
	st, err := store.NewRedisSessionStore(rdb, secret)
	require.NoError(t, err)
	return st, mr
}

func TestStore_SaveAndGetSession(t *testing.T) {
	ctx := context.Background()
	st, mr := setupTestStore(t)

	token := "mcp_at_1234567890abcdef"
	sessionData := &store.SessionData{
		UserID:         "user_01",
		Username:       "alice",
		Email:          "alice@example.com",
		GrafanaSession: "grafana_sess_xyz987654321",
		RefreshToken:   "idp_rt_0001",
		UserClaims: map[string]interface{}{
			"role":   "admin",
			"org_id": float64(1),
		},
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	err := st.SaveSession(ctx, token, sessionData, 1*time.Hour)
	require.NoError(t, err)

	// Verify Zero-Knowledge in raw Redis
	keys := mr.Keys()
	require.Len(t, keys, 1)
	redisKey := keys[0]

	// Key should be prefixed with "mcp:session:" followed by 128-char hex (HMAC-SHA3-512)
	assert.True(t, strings.HasPrefix(redisKey, "mcp:session:"))
	assert.False(t, strings.Contains(redisKey, token), "Raw token must not appear in Redis key")

	// Raw value in Redis must be ciphertext (not containing plaintext session)
	rawBytes, err := mr.Get(redisKey)
	require.NoError(t, err)
	assert.False(t, strings.Contains(rawBytes, "grafana_sess_xyz987654321"), "Raw session must be encrypted in Redis")
	assert.False(t, strings.Contains(rawBytes, "alice@example.com"), "User PII must be encrypted in Redis")

	// Decrypt and retrieve via store
	retrieved, err := st.GetSession(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, sessionData.UserID, retrieved.UserID)
	assert.Equal(t, sessionData.Username, retrieved.Username)
	assert.Equal(t, sessionData.GrafanaSession, retrieved.GrafanaSession)
	assert.Equal(t, sessionData.RefreshToken, retrieved.RefreshToken)
	assert.Equal(t, "admin", retrieved.UserClaims["role"])
}

func TestStore_SessionExpired(t *testing.T) {
	ctx := context.Background()
	st, _ := setupTestStore(t)

	token := "mcp_at_expired_token"
	sessionData := &store.SessionData{
		UserID:         "user_02",
		GrafanaSession: "sess_expired",
		ExpiresAt:      time.Now().Add(-10 * time.Minute), // Already expired
	}

	err := st.SaveSession(ctx, token, sessionData, 1*time.Hour)
	require.NoError(t, err)

	_, err = st.GetSession(ctx, token)
	assert.ErrorIs(t, err, store.ErrSessionExpired)
}

func TestStore_SessionNotFoundAndDelete(t *testing.T) {
	ctx := context.Background()
	st, _ := setupTestStore(t)

	token := "mcp_at_nonexistent"
	_, err := st.GetSession(ctx, token)
	assert.ErrorIs(t, err, store.ErrSessionNotFound)

	// Save and then delete
	sessionData := &store.SessionData{
		UserID:         "user_03",
		GrafanaSession: "sess_to_delete",
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}
	err = st.SaveSession(ctx, token, sessionData, 1*time.Hour)
	require.NoError(t, err)

	err = st.DeleteSession(ctx, token)
	require.NoError(t, err)

	_, err = st.GetSession(ctx, token)
	assert.ErrorIs(t, err, store.ErrSessionNotFound)
}

func TestStore_UpdateGrafanaSession(t *testing.T) {
	ctx := context.Background()
	st, _ := setupTestStore(t)

	token := "mcp_at_updatable"
	sessionData := &store.SessionData{
		UserID:         "user_04",
		GrafanaSession: "old_session_1",
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}
	err := st.SaveSession(ctx, token, sessionData, 1*time.Hour)
	require.NoError(t, err)

	// Update Grafana session cookie
	err = st.UpdateGrafanaSession(ctx, token, "new_session_refreshed_2", 2*time.Hour)
	require.NoError(t, err)

	updated, err := st.GetSession(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, "new_session_refreshed_2", updated.GrafanaSession)
}

func TestStore_RefreshTokenMapping(t *testing.T) {
	ctx := context.Background()
	st, _ := setupTestStore(t)

	refreshToken := "mcp_rt_refresh_token_123"
	accessToken := "mcp_at_access_token_456"

	err := st.SaveRefreshToken(ctx, refreshToken, accessToken, 30*24*time.Hour)
	require.NoError(t, err)

	retrievedAccessToken, err := st.GetTokenByRefreshToken(ctx, refreshToken)
	require.NoError(t, err)
	assert.Equal(t, accessToken, retrievedAccessToken)

	// Delete refresh token
	err = st.DeleteRefreshToken(ctx, refreshToken)
	require.NoError(t, err)

	_, err = st.GetTokenByRefreshToken(ctx, refreshToken)
	assert.ErrorIs(t, err, store.ErrInvalidRefreshToken)
}


func TestStore_PendingAuthFlow(t *testing.T) {
	ctx := context.Background()
	st, mr := setupTestStore(t)

	state := "mcp_st_sample_oauth_state_12345"
	req := &store.PendingAuthRequest{
		ClientID:            "cursor-client-1",
		RedirectURI:         "http://127.0.0.1:54321/callback",
		ClientState:         "client_custom_state_abc",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		CreatedAt:           time.Now(),
	}

	err := st.SavePendingAuth(ctx, state, req, 15*time.Minute)
	require.NoError(t, err)

	// Verify key has prefix and raw state is not leaked
	keys := mr.Keys()
	var foundKey string
	for _, k := range keys {
		if strings.HasPrefix(k, "mcp:pending_auth:") {
			foundKey = k
			break
		}
	}
	require.NotEmpty(t, foundKey)
	assert.False(t, strings.Contains(foundKey, state))

	// Get pending auth
	retrieved, err := st.GetPendingAuth(ctx, state)
	require.NoError(t, err)
	assert.Equal(t, req.ClientID, retrieved.ClientID)
	assert.Equal(t, req.RedirectURI, retrieved.RedirectURI)
	assert.Equal(t, req.CodeChallenge, retrieved.CodeChallenge)
	assert.Equal(t, req.CodeChallengeMethod, retrieved.CodeChallengeMethod)

	// Delete pending auth
	err = st.DeletePendingAuth(ctx, state)
	require.NoError(t, err)

	_, err = st.GetPendingAuth(ctx, state)
	assert.ErrorIs(t, err, store.ErrPendingAuthNotFound)
}

func TestStore_AuthCodeFlow(t *testing.T) {
	ctx := context.Background()
	st, _ := setupTestStore(t)

	code := "mcp_code_authorization_code_abcdef"
	authCtx := &store.AuthCodeContext{
		GrafanaSession: "grafana_session_verified_cookie",
		UserInfo: &store.GrafanaUser{
			ID:    99,
			Email: "admin@company.com",
			Name:  "Admin User",
			Login: "admin",
			OrgID: 1,
		},
		ClientID:            "claude-desktop",
		RedirectURI:         "http://127.0.0.1:4321/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}

	err := st.SaveAuthCode(ctx, code, authCtx, 5*time.Minute)
	require.NoError(t, err)

	retrieved, err := st.GetAuthCode(ctx, code)
	require.NoError(t, err)
	assert.Equal(t, authCtx.GrafanaSession, retrieved.GrafanaSession)
	assert.Equal(t, authCtx.UserInfo.Login, retrieved.UserInfo.Login)
	assert.Equal(t, authCtx.RedirectURI, retrieved.RedirectURI)
	assert.Equal(t, authCtx.CodeChallenge, retrieved.CodeChallenge)

	err = st.DeleteAuthCode(ctx, code)
	require.NoError(t, err)

	_, err = st.GetAuthCode(ctx, code)
	assert.ErrorIs(t, err, store.ErrAuthCodeNotFound)
}


func TestStore_RefreshTokenSessionFlow(t *testing.T) {
	ctx := context.Background()
	st, _ := setupTestStore(t)

	refreshToken := "mcp_rt_session_holder_999"
	sess := &store.SessionData{
		UserID:         "user_999",
		Username:       "dave",
		Email:          "dave@example.com",
		GrafanaSession: "grafana_sess_dave_secret",
		ExpiresAt:      time.Now().Add(2 * time.Hour),
	}

	err := st.SaveRefreshTokenSession(ctx, refreshToken, sess, 30*24*time.Hour)
	require.NoError(t, err)

	// Atomic Get and Delete
	retrieved, err := st.GetAndDeleteRefreshSession(ctx, refreshToken)
	require.NoError(t, err)
	assert.Equal(t, sess.Username, retrieved.Username)
	assert.Equal(t, sess.GrafanaSession, retrieved.GrafanaSession)

	// Second attempt must fail (single-use rotation)
	_, err = st.GetAndDeleteRefreshSession(ctx, refreshToken)
	assert.ErrorIs(t, err, store.ErrInvalidRefreshToken)
}

func TestStore_AtomicAuthCodeSingleUse_And_RaceProtection(t *testing.T) {
	ctx := context.Background()
	st, _ := setupTestStore(t)

	code := "mcp_code_atomic_test_single_use"
	authCtx := &store.AuthCodeContext{
		GrafanaSession:      "grafana_session_secret_atomic",
		ClientID:            "cursor-ide",
		RedirectURI:         "http://127.0.0.1:54321/callback",
		CodeChallenge:       "challenge_abc",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}

	err := st.SaveAuthCode(ctx, code, authCtx, 5*time.Minute)
	require.NoError(t, err)

	// Atomic retrieval: first call succeeds
	res, err := st.GetAndDeleteAuthCode(ctx, code)
	require.NoError(t, err)
	assert.Equal(t, authCtx.GrafanaSession, res.GrafanaSession)

	// Second call must fail immediately (ErrAuthCodeNotFound)
	_, err = st.GetAndDeleteAuthCode(ctx, code)
	assert.ErrorIs(t, err, store.ErrAuthCodeNotFound)

	// Test concurrent race condition: save another code and execute 10 concurrent calls
	raceCode := "mcp_code_race_test"
	err = st.SaveAuthCode(ctx, raceCode, authCtx, 5*time.Minute)
	require.NoError(t, err)

	successCount := 0
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := st.GetAndDeleteAuthCode(ctx, raceCode)
			if err == nil {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, successCount, "Exactly ONE concurrent request must succeed in consuming the authorization code")
}

func TestStore_GetAndDeletePendingAuth(t *testing.T) {
	ctx := context.Background()
	st, _ := setupTestStore(t)

	state := "mcp_st_pending_atomic_test"
	req := &store.PendingAuthRequest{
		ClientID:    "agent-x",
		RedirectURI: "http://127.0.0.1:9090/cb",
		ClientState: "state123",
	}

	err := st.SavePendingAuth(ctx, state, req, 10*time.Minute)
	require.NoError(t, err)

	retrieved, err := st.GetAndDeletePendingAuth(ctx, state)
	require.NoError(t, err)
	assert.Equal(t, req.ClientID, retrieved.ClientID)

	// Second attempt fails
	_, err = st.GetAndDeletePendingAuth(ctx, state)
	assert.ErrorIs(t, err, store.ErrPendingAuthNotFound)
}

func TestStore_ZeroConfig_MultiPodSync(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	// Simulate Pod 1 (no MCP_MASTER_SECRET configured)
	pod1Store, err := store.NewRedisSessionStore(rdb, nil)
	require.NoError(t, err)

	// Simulate Pod 2 (no MCP_MASTER_SECRET configured)
	pod2Store, err := store.NewRedisSessionStore(rdb, nil)
	require.NoError(t, err)

	token := "mcp_at_zero_config_test_token_123456"
	sessionData := &store.SessionData{
		UserID:         "user_sync",
		Username:       "multipod_user",
		GrafanaSession: "grafana_sess_synced",
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}

	// Pod 1 saves session
	err = pod1Store.SaveSession(ctx, token, sessionData, 1*time.Hour)
	require.NoError(t, err)

	// Pod 2 reads and decrypts session seamlessly
	retrieved, err := pod2Store.GetSession(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, sessionData.Username, retrieved.Username)
	assert.Equal(t, sessionData.GrafanaSession, retrieved.GrafanaSession)

	// Zero-Knowledge check in Redis
	keys := mr.Keys()
	require.Len(t, keys, 1)
	rawBytes, err := mr.Get(keys[0])
	require.NoError(t, err)
	assert.False(t, strings.Contains(rawBytes, "grafana_sess_synced"))
}
