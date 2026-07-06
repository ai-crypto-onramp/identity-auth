// Package crypto provides column-level envelope encryption helpers used to
// protect secrets at rest (TOTP secrets, API key material, recovery code
// material). AES-256-GCM is used with a 32-byte data key (DEK) that may be
// either supplied directly or derived from a passphrase via HKDF-SHA256.
//
// The DEK itself should be wrapped by a KMS-managed master key in production
// (envelope encryption); the wrapping step is out of scope for Stage 1.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const (
	// KeyLen is the AES-256 key length in bytes.
	KeyLen = 32
	// NonceLen is the GCM nonce length in bytes.
	NonceLen = 12
)

// ErrEmptyKey is returned when a zero-length key is supplied.
var ErrEmptyKey = errors.New("crypto: key must not be empty")

// Envelope wraps AES-256-GCM encryption with a per-message random nonce and
// a fixed data key. The same plaintext encrypted twice yields different
// ciphertexts; the DEK is never embedded in the output.
type Envelope struct {
	aead cipher.AEAD
}

// NewEnvelope constructs an Envelope from a raw 32-byte data key.
func NewEnvelope(key []byte) (*Envelope, error) {
	if len(key) == 0 {
		return nil, ErrEmptyKey
	}
	if len(key) != KeyLen {
		return nil, fmt.Errorf("crypto: key must be %d bytes, got %d", KeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	return &Envelope{aead: gcm}, nil
}

// DeriveKey derives a 32-byte DEK from a passphrase using HKDF-SHA256 with a
// fixed application salt and an info label, suitable for local/dev usage.
// Production callers should instead source the DEK from a KMS unwrap call.
func DeriveKey(passphrase, salt []byte, info string) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrEmptyKey
	}
	key, err := hkdf.Key(sha256.New, passphrase, salt, info, KeyLen)
	if err != nil {
		return nil, fmt.Errorf("crypto: hkdf: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext and returns nonce || ciphertext.
func (e *Envelope) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, NonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: read nonce: %w", err)
	}
	ciphertext := e.aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(ciphertext))
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// Decrypt decrypts a nonce || ciphertext blob produced by Encrypt.
func (e *Envelope) Decrypt(blob []byte) ([]byte, error) {
	if len(blob) < NonceLen {
		return nil, fmt.Errorf("crypto: ciphertext too short (%d bytes)", len(blob))
	}
	nonce, ciphertext := blob[:NonceLen], blob[NonceLen:]
	plaintext, err := e.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcm open: %w", err)
	}
	return plaintext, nil
}

// EncryptString is a string convenience wrapper around Encrypt that returns
// a base64 (std) encoded string.
func (e *Envelope) EncryptString(plaintext string) (string, error) {
	b, err := e.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// DecryptString is the inverse of EncryptString.
func (e *Envelope) DecryptString(ciphertext string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("crypto: base64 decode: %w", err)
	}
	plain, err := e.Decrypt(b)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// GenerateKey returns a fresh random 32-byte DEK suitable for NewEnvelope.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("crypto: generate key: %w", err)
	}
	return key, nil
}