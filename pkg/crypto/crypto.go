package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

var (
	// ErrInvalidCiphertext is returned when ciphertext is malformed or too short.
	ErrInvalidCiphertext = errors.New("invalid or truncated ciphertext")
	// ErrDecryptionFailed is returned when authentication tag verification fails.
	ErrDecryptionFailed = errors.New("decryption failed: authentication tag mismatch or corrupted data")
	// ErrInvalidKeySize is returned when an invalid key size is provided.
	ErrInvalidKeySize = errors.New("invalid key size: must be 32 bytes")
)

// HashTokenKey computes an HMAC-SHA3-512 over the token using the provided server secret.
// This produces a 128-character hex string suitable for use as a deterministic, collision-resistant
// Redis key without revealing the token or allowing offline rainbow table attacks.
func HashTokenKey(token string, secret []byte) string {
	mac := hmac.New(sha3.New512, secret)
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

// DeriveKeyHKDF derives a 32-byte symmetric key from the token using HKDF-SHA3-512.
// It is designed for low-latency (< 0.1ms), high-throughput cryptographic operations.
func DeriveKeyHKDF(token string, salt []byte, info []byte) ([]byte, error) {
	if len(salt) == 0 {
		return nil, errors.New("salt cannot be empty")
	}
	kdf := hkdf.New(sha3.New512, []byte(token), salt, info)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("hkdf key derivation failed: %w", err)
	}
	return key, nil
}

// DeriveKeyArgon2id derives a 32-byte key using Argon2id (RFC 9106) for memory-hard operations.
// Note: In high-throughput runtime session lookups, DeriveKeyHKDF is preferred for sub-millisecond
// latency; Argon2id is provided for high-entropy master key or password derivation.
func DeriveKeyArgon2id(token string, salt []byte) []byte {
	// Standard recommended parameters: 1 iteration, 64MB memory, 4 threads, 32-byte key
	return argon2.IDKey([]byte(token), salt, 1, 64*1024, 4, chacha20poly1305.KeySize)
}

// Encrypt encrypts plaintext using XChaCha20-Poly1305 (24-byte nonce, 16-byte Poly1305 MAC).
// The returned slice is [24-byte Nonce || Ciphertext || 16-byte Poly1305 Tag].
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, ErrInvalidKeySize
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create xchacha20poly1305 cipher: %w", err)
	}

	// 24-byte random nonce for XChaCha20-Poly1305 eliminates nonce reuse risk
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	// aead.Seal appends the ciphertext and tag to the nonce slice
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using XChaCha20-Poly1305 and verifies the authentication tag.
// It expects ciphertext in the format: [24-byte Nonce || Ciphertext || 16-byte Poly1305 Tag].
func Decrypt(data []byte, key []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, ErrInvalidKeySize
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create xchacha20poly1305 cipher: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(data) < nonceSize+aead.Overhead() {
		return nil, ErrInvalidCiphertext
	}

	nonce := data[:nonceSize]
	ciphertextWithTag := data[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertextWithTag, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// GenerateRandomToken generates a cryptographically secure random token string with a given prefix.
func GenerateRandomToken(prefix string, byteLength int) (string, error) {
	if byteLength < 16 {
		byteLength = 32
	}
	b := make([]byte, byteLength)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return prefix + hex.EncodeToString(b), nil
}
