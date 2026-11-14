package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"grafana-mcp-oauth/pkg/crypto"
)

var (
	// ErrSessionNotFound is returned when a session does not exist in the store.
	ErrSessionNotFound = errors.New("session not found")
	// ErrSessionExpired is returned when a session has expired.
	ErrSessionExpired = errors.New("session has expired")
	// ErrInvalidRefreshToken is returned when a refresh token is invalid or expired.
	ErrInvalidRefreshToken = errors.New("invalid or expired refresh token")
	// ErrPendingAuthNotFound is returned when a pending auth request is missing or expired.
	ErrPendingAuthNotFound = errors.New("pending auth request not found or expired")
	// ErrAuthCodeNotFound is returned when an authorization code is invalid or expired.
	ErrAuthCodeNotFound = errors.New("authorization code not found or expired")
)

const (
	sessionKeyPrefix     = "mcp:session:"
	refreshKeyPrefix     = "mcp:refresh:"
	pendingAuthKeyPrefix = "mcp:pending_auth:"
	authCodeKeyPrefix    = "mcp:auth_code:"

	hkdfInfoSession     = "mcp-session-encryption"
	hkdfInfoRefresh     = "mcp-refresh-encryption"
	hkdfInfoPendingAuth = "mcp-pending-auth-encryption"
	hkdfInfoAuthCode    = "mcp-auth-code-encryption"
)

// SessionData represents the user identity and Grafana session credentials.
type SessionData struct {
	UserID         string                 `json:"user_id"`
	Username       string                 `json:"username"`
	Email          string                 `json:"email"`
	GrafanaSession string                 `json:"grafana_session"`
	RefreshToken   string                 `json:"refresh_token,omitempty"`
	IDToken        string                 `json:"id_token,omitempty"`
	UserClaims     map[string]interface{} `json:"user_claims,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	ExpiresAt      time.Time              `json:"expires_at"`
}

// GrafanaUser represents user info returned by Grafana /api/user.
type GrafanaUser struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Login string `json:"login"`
	OrgID int64  `json:"orgId"`
}

// PendingAuthRequest tracks an ongoing OAuth login authorization flow.
type PendingAuthRequest struct {
	ClientID            string    `json:"client_id"`
	RedirectURI         string    `json:"redirect_uri"`
	ClientState         string    `json:"client_state"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	CreatedAt           time.Time `json:"created_at"`
}

// AuthCodeContext holds state associated with an issued authorization code.
type AuthCodeContext struct {
	GrafanaSession      string       `json:"grafana_session"`
	UserInfo            *GrafanaUser `json:"user_info"`
	ClientID            string       `json:"client_id"`
	RedirectURI         string       `json:"redirect_uri"`
	CodeChallenge       string       `json:"code_challenge"`
	CodeChallengeMethod string       `json:"code_challenge_method"`
	ExpiresAt           time.Time    `json:"expires_at"`
}

// SessionStore defines the interface for secure distributed session and OAuth state storage.
type SessionStore interface {
	SaveSession(ctx context.Context, token string, session *SessionData, ttl time.Duration) error
	GetSession(ctx context.Context, token string) (*SessionData, error)
	DeleteSession(ctx context.Context, token string) error
	UpdateGrafanaSession(ctx context.Context, token string, newGrafanaSession string, ttl time.Duration) error
	SaveRefreshTokenSession(ctx context.Context, refreshToken string, session *SessionData, ttl time.Duration) error
	GetAndDeleteRefreshSession(ctx context.Context, refreshToken string) (*SessionData, error)
	SaveRefreshToken(ctx context.Context, refreshToken string, token string, ttl time.Duration) error
	GetTokenByRefreshToken(ctx context.Context, refreshToken string) (string, error)
	DeleteRefreshToken(ctx context.Context, refreshToken string) error

	// Distributed pending auth flows (login -> callback)
	SavePendingAuth(ctx context.Context, state string, req *PendingAuthRequest, ttl time.Duration) error
	GetPendingAuth(ctx context.Context, state string) (*PendingAuthRequest, error)
	DeletePendingAuth(ctx context.Context, state string) error

	// Distributed authorization codes (callback -> token exchange)
	SaveAuthCode(ctx context.Context, code string, authCode *AuthCodeContext, ttl time.Duration) error
	GetAuthCode(ctx context.Context, code string) (*AuthCodeContext, error)
	DeleteAuthCode(ctx context.Context, code string) error
}

// RedisSessionStore implements SessionStore with Zero-Knowledge encryption in Redis.
type RedisSessionStore struct {
	client       redis.UniversalClient
	masterSecret []byte
}

// NewRedisSessionStore creates a new RedisSessionStore with the given master secret.
func NewRedisSessionStore(client redis.UniversalClient, masterSecret []byte) (*RedisSessionStore, error) {
	if len(masterSecret) < 16 {
		return nil, errors.New("master secret must be at least 16 bytes")
	}
	return &RedisSessionStore{
		client:       client,
		masterSecret: masterSecret,
	}, nil
}

// SaveSession encrypts and stores the session in Redis under an HMAC-SHA3-512 hashed key.
func (s *RedisSessionStore) SaveSession(ctx context.Context, token string, session *SessionData, ttl time.Duration) error {
	redisKey := sessionKeyPrefix + crypto.HashTokenKey(token, s.masterSecret)

	encKey, err := crypto.DeriveKeyHKDF(token, s.masterSecret, []byte(hkdfInfoSession))
	if err != nil {
		return fmt.Errorf("failed to derive encryption key: %w", err)
	}

	// #nosec G117 -- session payload is encrypted with AES-256-GCM before storage
	payload, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	encrypted, err := crypto.Encrypt(payload, encKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt session: %w", err)
	}

	if err := s.client.Set(ctx, redisKey, encrypted, ttl).Err(); err != nil {
		return fmt.Errorf("redis set failed: %w", err)
	}

	return nil
}

// GetSession retrieves and decrypts the session from Redis.
func (s *RedisSessionStore) GetSession(ctx context.Context, token string) (*SessionData, error) {
	redisKey := sessionKeyPrefix + crypto.HashTokenKey(token, s.masterSecret)

	encrypted, err := s.client.Get(ctx, redisKey).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrSessionNotFound
	} else if err != nil {
		return nil, fmt.Errorf("redis get failed: %w", err)
	}

	encKey, err := crypto.DeriveKeyHKDF(token, s.masterSecret, []byte(hkdfInfoSession))
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	decrypted, err := crypto.Decrypt(encrypted, encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt session: %w", err)
	}

	var session SessionData
	if err := json.Unmarshal(decrypted, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	if !session.ExpiresAt.IsZero() && time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	return &session, nil
}

// DeleteSession removes a session from Redis.
func (s *RedisSessionStore) DeleteSession(ctx context.Context, token string) error {
	redisKey := sessionKeyPrefix + crypto.HashTokenKey(token, s.masterSecret)
	return s.client.Del(ctx, redisKey).Err()
}

// UpdateGrafanaSession updates the Grafana session cookie inside an existing encrypted session.
func (s *RedisSessionStore) UpdateGrafanaSession(ctx context.Context, token string, newGrafanaSession string, ttl time.Duration) error {
	session, err := s.GetSession(ctx, token)
	if err != nil {
		return err
	}
	session.GrafanaSession = newGrafanaSession
	if ttl <= 0 {
		ttl = s.client.TTL(ctx, sessionKeyPrefix+crypto.HashTokenKey(token, s.masterSecret)).Val()
		if ttl <= 0 {
			ttl = 2 * time.Hour
		}
	}
	session.ExpiresAt = time.Now().Add(ttl)
	return s.SaveSession(ctx, token, session, ttl)
}

// SaveRefreshTokenSession stores the full session encrypted under the refresh token with RefreshTTL (e.g. 30 days).
// This completely decouples the refresh token lifecycle from ephemeral access token expiration.
func (s *RedisSessionStore) SaveRefreshTokenSession(ctx context.Context, refreshToken string, session *SessionData, ttl time.Duration) error {
	redisKey := refreshKeyPrefix + crypto.HashTokenKey(refreshToken, s.masterSecret)

	encKey, err := crypto.DeriveKeyHKDF(refreshToken, s.masterSecret, []byte(hkdfInfoRefresh))
	if err != nil {
		return fmt.Errorf("failed to derive refresh encryption key: %w", err)
	}

	// #nosec G117 -- session payload is encrypted with AES-256-GCM before storage
	payload, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal refresh session: %w", err)
	}

	encrypted, err := crypto.Encrypt(payload, encKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt refresh session: %w", err)
	}

	if err := s.client.Set(ctx, redisKey, encrypted, ttl).Err(); err != nil {
		return fmt.Errorf("redis set refresh session failed: %w", err)
	}

	return nil
}

// GetAndDeleteRefreshSession atomically retrieves and deletes a refresh token session using a Lua script.
// This enforces single-use refresh token rotation and eliminates race conditions.
func (s *RedisSessionStore) GetAndDeleteRefreshSession(ctx context.Context, refreshToken string) (*SessionData, error) {
	redisKey := refreshKeyPrefix + crypto.HashTokenKey(refreshToken, s.masterSecret)

	// Atomic GETDEL Lua script compatible with all Redis & Miniredis versions
	luaScript := redis.NewScript(`
		local val = redis.call('GET', KEYS[1])
		if val then
			redis.call('DEL', KEYS[1])
		end
		return val
	`)

	res, err := luaScript.Run(ctx, s.client, []string{redisKey}).Text()
	if errors.Is(err, redis.Nil) || res == "" {
		return nil, ErrInvalidRefreshToken
	} else if err != nil {
		return nil, fmt.Errorf("redis getdel refresh session failed: %w", err)
	}

	encKey, err := crypto.DeriveKeyHKDF(refreshToken, s.masterSecret, []byte(hkdfInfoRefresh))
	if err != nil {
		return nil, fmt.Errorf("failed to derive refresh encryption key: %w", err)
	}

	decrypted, err := crypto.Decrypt([]byte(res), encKey)
	if err != nil {
		return nil, ErrInvalidRefreshToken
	}

	var session SessionData
	if err := json.Unmarshal(decrypted, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal refresh session: %w", err)
	}

	return &session, nil
}

// SaveRefreshToken stores a mapping from refresh_token to access_token.
func (s *RedisSessionStore) SaveRefreshToken(ctx context.Context, refreshToken string, token string, ttl time.Duration) error {
	redisKey := refreshKeyPrefix + crypto.HashTokenKey(refreshToken, s.masterSecret)

	encKey, err := crypto.DeriveKeyHKDF(refreshToken, s.masterSecret, []byte(hkdfInfoRefresh))
	if err != nil {
		return fmt.Errorf("failed to derive refresh encryption key: %w", err)
	}

	encrypted, err := crypto.Encrypt([]byte(token), encKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt refresh token payload: %w", err)
	}

	if err := s.client.Set(ctx, redisKey, encrypted, ttl).Err(); err != nil {
		return fmt.Errorf("redis set refresh failed: %w", err)
	}

	return nil
}

// GetTokenByRefreshToken retrieves the access token associated with a refresh token.
func (s *RedisSessionStore) GetTokenByRefreshToken(ctx context.Context, refreshToken string) (string, error) {
	redisKey := refreshKeyPrefix + crypto.HashTokenKey(refreshToken, s.masterSecret)

	encrypted, err := s.client.Get(ctx, redisKey).Bytes()
	if errors.Is(err, redis.Nil) {
		return "", ErrInvalidRefreshToken
	} else if err != nil {
		return "", fmt.Errorf("redis get refresh failed: %w", err)
	}

	encKey, err := crypto.DeriveKeyHKDF(refreshToken, s.masterSecret, []byte(hkdfInfoRefresh))
	if err != nil {
		return "", fmt.Errorf("failed to derive refresh encryption key: %w", err)
	}

	token, err := crypto.Decrypt(encrypted, encKey)
	if err != nil {
		return "", ErrInvalidRefreshToken
	}

	return string(token), nil
}

// DeleteRefreshToken removes a refresh token mapping from Redis.
func (s *RedisSessionStore) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	redisKey := refreshKeyPrefix + crypto.HashTokenKey(refreshToken, s.masterSecret)
	return s.client.Del(ctx, redisKey).Err()
}

// SavePendingAuth encrypts and stores an ongoing OAuth authorization flow state with TTL.
func (s *RedisSessionStore) SavePendingAuth(ctx context.Context, state string, req *PendingAuthRequest, ttl time.Duration) error {
	redisKey := pendingAuthKeyPrefix + crypto.HashTokenKey(state, s.masterSecret)

	encKey, err := crypto.DeriveKeyHKDF(state, s.masterSecret, []byte(hkdfInfoPendingAuth))
	if err != nil {
		return fmt.Errorf("failed to derive pending auth encryption key: %w", err)
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal pending auth: %w", err)
	}

	encrypted, err := crypto.Encrypt(payload, encKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt pending auth payload: %w", err)
	}

	if err := s.client.Set(ctx, redisKey, encrypted, ttl).Err(); err != nil {
		return fmt.Errorf("redis set pending auth failed: %w", err)
	}

	return nil
}

// GetPendingAuth retrieves and decrypts a pending auth request.
func (s *RedisSessionStore) GetPendingAuth(ctx context.Context, state string) (*PendingAuthRequest, error) {
	redisKey := pendingAuthKeyPrefix + crypto.HashTokenKey(state, s.masterSecret)

	encrypted, err := s.client.Get(ctx, redisKey).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrPendingAuthNotFound
	} else if err != nil {
		return nil, fmt.Errorf("redis get pending auth failed: %w", err)
	}

	encKey, err := crypto.DeriveKeyHKDF(state, s.masterSecret, []byte(hkdfInfoPendingAuth))
	if err != nil {
		return nil, fmt.Errorf("failed to derive pending auth encryption key: %w", err)
	}

	decrypted, err := crypto.Decrypt(encrypted, encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt pending auth: %w", err)
	}

	var req PendingAuthRequest
	if err := json.Unmarshal(decrypted, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pending auth: %w", err)
	}

	return &req, nil
}

// DeletePendingAuth removes a pending auth flow from Redis.
func (s *RedisSessionStore) DeletePendingAuth(ctx context.Context, state string) error {
	redisKey := pendingAuthKeyPrefix + crypto.HashTokenKey(state, s.masterSecret)
	return s.client.Del(ctx, redisKey).Err()
}

// SaveAuthCode encrypts and stores an issued authorization code with TTL.
func (s *RedisSessionStore) SaveAuthCode(ctx context.Context, code string, authCode *AuthCodeContext, ttl time.Duration) error {
	redisKey := authCodeKeyPrefix + crypto.HashTokenKey(code, s.masterSecret)

	encKey, err := crypto.DeriveKeyHKDF(code, s.masterSecret, []byte(hkdfInfoAuthCode))
	if err != nil {
		return fmt.Errorf("failed to derive auth code encryption key: %w", err)
	}

	payload, err := json.Marshal(authCode)
	if err != nil {
		return fmt.Errorf("failed to marshal auth code context: %w", err)
	}

	encrypted, err := crypto.Encrypt(payload, encKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt auth code context: %w", err)
	}

	if err := s.client.Set(ctx, redisKey, encrypted, ttl).Err(); err != nil {
		return fmt.Errorf("redis set auth code failed: %w", err)
	}

	return nil
}

// GetAuthCode retrieves and decrypts an authorization code context.
func (s *RedisSessionStore) GetAuthCode(ctx context.Context, code string) (*AuthCodeContext, error) {
	redisKey := authCodeKeyPrefix + crypto.HashTokenKey(code, s.masterSecret)

	encrypted, err := s.client.Get(ctx, redisKey).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrAuthCodeNotFound
	} else if err != nil {
		return nil, fmt.Errorf("redis get auth code failed: %w", err)
	}

	encKey, err := crypto.DeriveKeyHKDF(code, s.masterSecret, []byte(hkdfInfoAuthCode))
	if err != nil {
		return nil, fmt.Errorf("failed to derive auth code encryption key: %w", err)
	}

	decrypted, err := crypto.Decrypt(encrypted, encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt auth code context: %w", err)
	}

	var authCtx AuthCodeContext
	if err := json.Unmarshal(decrypted, &authCtx); err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth code context: %w", err)
	}

	return &authCtx, nil
}

// DeleteAuthCode removes an authorization code from Redis.
func (s *RedisSessionStore) DeleteAuthCode(ctx context.Context, code string) error {
	redisKey := authCodeKeyPrefix + crypto.HashTokenKey(code, s.masterSecret)
	return s.client.Del(ctx, redisKey).Err()
}
