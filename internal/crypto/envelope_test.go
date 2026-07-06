package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewEnvelopeRejectsBadKey(t *testing.T) {
	if _, err := NewEnvelope(nil); err != ErrEmptyKey {
		t.Fatalf("nil key: want ErrEmptyKey, got %v", err)
	}
	short := make([]byte, 16)
	if _, err := NewEnvelope(short); err == nil {
		t.Fatalf("short key: expected error, got nil")
	}
}

func TestGenerateKeyLength(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(key) != KeyLen {
		t.Fatalf("key length: want %d, got %d", KeyLen, len(key))
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	env, err := NewEnvelope(key)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}

	plaintexts := [][]byte{
		[]byte(""),
		[]byte("a"),
		[]byte("JBSWY3DPEHPK3PXP"),
		bytes.Repeat([]byte{0xAB}, 4096),
	}
	for _, pt := range plaintexts {
		ct, err := env.Encrypt(pt)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", pt, err)
		}
		if len(ct) < NonceLen {
			t.Fatalf("ciphertext too short: %d", len(ct))
		}
		if bytes.Equal(ct[:NonceLen], make([]byte, NonceLen)) {
			t.Fatalf("nonce is all zeros for %q", pt)
		}
		dec, err := env.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if !bytes.Equal(dec, pt) {
			t.Fatalf("round trip mismatch: want %q, got %q", pt, dec)
		}
	}
}

func TestEnvelopeProducesDifferentCiphertexts(t *testing.T) {
	env, err := NewEnvelope(mustGenKey(t))
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	pt := []byte("totp-secret-123")
	a, err := env.Encrypt(pt)
	if err != nil {
		t.Fatalf("Encrypt a: %v", err)
	}
	b, err := env.Encrypt(pt)
	if err != nil {
		t.Fatalf("Encrypt b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatalf("expected distinct ciphertexts for repeated plaintext; got identical")
	}
}

func TestEnvelopeRejectsTamperedCiphertext(t *testing.T) {
	env, err := NewEnvelope(mustGenKey(t))
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	ct, err := env.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := append([]byte{}, ct...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := env.Decrypt(tampered); err == nil {
		t.Fatalf("Decrypt: expected error for tampered ciphertext, got nil")
	}
}

func TestEnvelopeRejectsShortBlob(t *testing.T) {
	env, err := NewEnvelope(mustGenKey(t))
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if _, err := env.Decrypt([]byte{0x01, 0x02}); err == nil {
		t.Fatalf("Decrypt: expected error for short blob, got nil")
	}
}

func TestEnvelopeStringRoundTrip(t *testing.T) {
	env, err := NewEnvelope(mustGenKey(t))
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	want := "hello-encryption-world"
	ct, err := env.EncryptString(want)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	got, err := env.DecryptString(ct)
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if got != want {
		t.Fatalf("string round trip: want %q, got %q", want, got)
	}
	if !strings.HasSuffix(ct, "=") && strings.Contains(ct, want) {
		t.Fatalf("ciphertext leaked plaintext")
	}
}

func TestDeriveKeyRoundTrip(t *testing.T) {
	salt := []byte("identity-auth-salt")
	info := "totp-envelope"
	keyA, err := DeriveKey([]byte("passphrase"), salt, info)
	if err != nil {
		t.Fatalf("DeriveKey A: %v", err)
	}
	keyB, err := DeriveKey([]byte("passphrase"), salt, info)
	if err != nil {
		t.Fatalf("DeriveKey B: %v", err)
	}
	if !bytes.Equal(keyA, keyB) {
		t.Fatalf("DeriveKey not deterministic for same inputs")
	}
	keyC, err := DeriveKey([]byte("passphrase2"), salt, info)
	if err != nil {
		t.Fatalf("DeriveKey C: %v", err)
	}
	if bytes.Equal(keyA, keyC) {
		t.Fatalf("DeriveKey produced same key for different passphrase")
	}
	if len(keyA) != KeyLen {
		t.Fatalf("DeriveKey length: want %d, got %d", KeyLen, len(keyA))
	}

	env, err := NewEnvelope(keyA)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	ct, err := env.Encrypt([]byte("round-trip"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	dec, err := env.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(dec) != "round-trip" {
		t.Fatalf("decrypt mismatch: %q", dec)
	}
}

func TestDeriveKeyRejectsEmptyPassphrase(t *testing.T) {
	if _, err := DeriveKey(nil, []byte("salt"), "info"); err != ErrEmptyKey {
		t.Fatalf("expected ErrEmptyKey, got %v", err)
	}
}

func mustGenKey(t *testing.T) []byte {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}