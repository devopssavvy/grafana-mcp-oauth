package crypto_test

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grafana-mcp-oauth/pkg/crypto"
)

func TestHashTokenKey(t *testing.T) {
	secret := []byte("master-secret-salt-for-testing-1234567890")
	token1 := "mcp_at_abc123"
	token2 := "mcp_at_abc124"

	h1 := crypto.HashTokenKey(token1, secret)
	h1Again := crypto.HashTokenKey(token1, secret)
	h2 := crypto.HashTokenKey(token2, secret)

	assert.Equal(t, h1, h1Again, "HMAC-SHA3-512 must be deterministic")
	assert.NotEqual(t, h1, h2, "Different tokens must produce distinct hashes")
	assert.Len(t, h1, 128, "SHA3-512 hex string must be 128 characters long")
}

func TestDeriveKeyHKDF(t *testing.T) {
	token := "mcp_at_sample_token_for_test"
	salt := []byte("32-byte-random-master-salt-12345")
	info := []byte("mcp-session-test")

	key1, err := crypto.DeriveKeyHKDF(token, salt, info)
	require.NoError(t, err)
	assert.Len(t, key1, 32, "Derived key must be exactly 32 bytes")

	key2, err := crypto.DeriveKeyHKDF(token, salt, info)
	require.NoError(t, err)
	assert.Equal(t, key1, key2, "HKDF must produce reproducible keys for identical inputs")

	// Empty salt should return error
	_, err = crypto.DeriveKeyHKDF(token, nil, info)
	assert.Error(t, err)
}

func TestDeriveKeyArgon2id(t *testing.T) {
	token := "mcp_rt_refresh_token_test"
	salt := []byte("16-byte-salt-1234")

	key := crypto.DeriveKeyArgon2id(token, salt)
	assert.Len(t, key, 32, "Argon2id must produce 32-byte key")
}

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	originalData := []byte(`{"grafana_session":"sess_abcdef123456","user":"alice"}`)

	encrypted, err := crypto.Encrypt(originalData, key)
	require.NoError(t, err)
	assert.NotEqual(t, originalData, encrypted)
	// Nonce (24 bytes) + ciphertext + tag (16 bytes)
	assert.True(t, len(encrypted) >= len(originalData)+24+16)

	decrypted, err := crypto.Decrypt(encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, originalData, decrypted)
}

func TestEncrypt_UniqueNonces(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	data := []byte("constant payload")

	c1, err := crypto.Encrypt(data, key)
	require.NoError(t, err)

	c2, err := crypto.Encrypt(data, key)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(c1, c2), "Different encryptions of same data must have distinct 24-byte nonces")
}

func TestDecrypt_TamperResistance(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	original := []byte("important session data")
	encrypted, err := crypto.Encrypt(original, key)
	require.NoError(t, err)

	// Tamper with the last byte (authentication tag)
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[len(tampered)-1] ^= 0xFF

	_, err = crypto.Decrypt(tampered, key)
	assert.ErrorIs(t, err, crypto.ErrDecryptionFailed)

	// Wrong key
	wrongKey := make([]byte, 32)
	_, _ = rand.Read(wrongKey)
	_, err = crypto.Decrypt(encrypted, wrongKey)
	assert.ErrorIs(t, err, crypto.ErrDecryptionFailed)

	// Truncated data
	_, err = crypto.Decrypt([]byte("short"), key)
	assert.ErrorIs(t, err, crypto.ErrInvalidCiphertext)
}

func TestGenerateRandomToken(t *testing.T) {
	t1, err := crypto.GenerateRandomToken("mcp_at_", 32)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(t1, "mcp_at_"))
	assert.Len(t, t1, len("mcp_at_")+64) // 32 bytes = 64 hex chars

	t2, err := crypto.GenerateRandomToken("mcp_rt_", 32)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(t2, "mcp_rt_"))
	assert.NotEqual(t, t1, t2)
}
