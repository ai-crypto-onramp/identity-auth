package internal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Crypto primitives: random tokens, salted SHA-256 password hashing,
// HMAC-SHA256 JWT, RFC 6238 TOTP.
// ---------------------------------------------------------------------------

// randID generates a new app-side UUIDv7 primary key.
func randID() string {
	id, _ := uuid.NewV7()
	return id.String()
}

// randomToken returns a URL-safe base64 random string of nbytes entropy.
func randomToken(nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// sha256Hex returns hex-encoded SHA-256 of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// hashPassword is a simple salted SHA-256 hasher (NOT production-safe; for this impl only).
func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return hashPasswordWithSalt(password, salt), nil
}

// hashPasswordWithSalt concatenates salt+password and hashes.
func hashPasswordWithSalt(password string, salt []byte) string {
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(password))
	sum := mac.Sum(nil)
	return "sha256$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(sum)
}

// verifyPassword parses a "sha256$salt$sum" hash and compares.
func verifyPassword(hashed, password string) bool {
	parts := splitOn(hashed, '$', 3)
	if len(parts) != 3 || parts[0] != "sha256" {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	expected := hashPasswordWithSalt(password, salt)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(hashed)) == 1
}

// splitOn splits s on sep into at most n segments.
func splitOn(s string, sep byte, n int) []string {
	out := make([]string, 0, n)
	for len(out) < n-1 {
		i := -1
		for j := 0; j < len(s); j++ {
			if s[j] == sep {
				i = j
				break
			}
		}
		if i < 0 {
			break
		}
		out = append(out, s[:i])
		s = s[i+1:]
	}
	out = append(out, s)
	return out
}

// ---------------------------------------------------------------------------
// JWT (HMAC-SHA256) — header, payload, signature, base64url-encoded.
// ---------------------------------------------------------------------------

// JWTClaims are the standard claims we encode.
type JWTClaims struct {
	Sub string `json:"sub"`
	Sid string `json:"sid"`
	Iat int64 `json:"iat"`
	Exp int64 `json:"exp"`
	Iss string `json:"iss"`
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signJWT produces an HS256 JWT for the given claims and secret.
func signJWT(claims JWTClaims, secret string) (string, error) {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64url(hb) + "." + b64url(pb)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signing))
	sig := b64url(mac.Sum(nil))
	return signing + "." + sig, nil
}

// verifyJWT validates an HS256 JWT and returns claims.
func verifyJWT(token, secret string) (JWTClaims, error) {
	var c JWTClaims
	// Token has 3 parts separated by '.'.
	a, b, tail := split3(token)
	if a == "" || b == "" || tail == "" {
		return c, errors.New("malformed token")
	}
	signing := a + "." + b
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signing))
	expected := b64url(mac.Sum(nil))
	if !hmac.Equal([]byte(tail), []byte(expected)) {
		return c, errors.New("signature mismatch")
	}
	payload, err := base64.RawURLEncoding.DecodeString(b)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, err
	}
	if c.Exp > 0 && time.Now().Unix() > c.Exp {
		return c, errors.New("token expired")
	}
	return c, nil
}

// split3 returns the two dots' substrings or "".
func split3(s string) (string, string, string) {
	dot1 := -1
	dot2 := -1
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			if dot1 < 0 {
				dot1 = i
			} else if dot2 < 0 {
				dot2 = i
			} else {
				return "", "", ""
			}
		}
	}
	if dot1 < 0 || dot2 < 0 {
		return "", "", ""
	}
	return s[:dot1], s[dot1+1 : dot2], s[dot2+1:]
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238) — 30s window, 6 digits, SHA-256.
// ---------------------------------------------------------------------------

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// randomTOTPSecret returns a base32-encoded 20-byte secret.
func randomTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return totpEncoding.EncodeToString(b), nil
}

// totp computes the RFC 6238 6-digit code for the given time and secret.
func totp(secret string, t time.Time) (string, error) {
	key, err := totpEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}
	counter := t.Unix() / 30
	buf := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		buf[i] = byte(counter & 0xff)
		counter >>= 8
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0xf
	bin := ((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1]) & 0xff) << 16) |
		((int(sum[offset+2]) & 0xff) << 8) |
		(int(sum[offset+3]) & 0xff)
	code := bin % 1_000_000
	return fmt.Sprintf("%06d", code), nil
}

// totpWindowValid checks whether code is a valid OTP for secret at time t
// allowing ±window steps (default 1).
func totpWindowValid(secret, code string, t time.Time, window int) bool {
	if window < 0 {
		window = 0
	}
	for i := -window; i <= window; i++ {
		ts := t.Add(time.Duration(i) * 30 * time.Second)
		want, err := totp(secret, ts)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// otpURI builds the otpauth:// URI shown as the "QR" target.
func otpURI(issuer, account, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA256&digits=6&period=30",
		issuer, account, secret, issuer)
}