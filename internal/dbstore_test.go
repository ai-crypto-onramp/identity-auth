package internal

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/identity-auth/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ---------------------------------------------------------------------------
// Hermetic tests for the PostgreSQL-backed dbstore. Rather than spin up a
// real Postgres, these tests drive *dbstore against a scripted fake pool that
// implements the dbPool interface (and pgx.Tx) and returns canned results
// keyed by SQL substring. This exercises every branch in dbstore.go without any
// external dependency.
// ---------------------------------------------------------------------------

// fakeRow implements pgx.Row for scripted Scan results.
type fakeRow struct {
	scanErr error
	values  []any
}

func (r *fakeRow) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	return assignScan(dest, r.values)
}

// fakeRows implements pgx.Rows for scripted multi-row results.
type fakeRows struct {
	rows    [][]any
	idx    int
	closed bool
}

func (r *fakeRows) Close()                                       { r.closed = true }
func (r *fakeRows) Err() error                                   { return nil }
func (r *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeRows) Next() bool {
	if r.closed {
		return false
	}
	r.idx++
	return r.idx <= len(r.rows)
}
func (r *fakeRows) Scan(dest ...any) error {
	return assignScan(dest, r.rows[r.idx-1])
}
func (r *fakeRows) Values() ([]any, error) { return r.rows[r.idx-1], nil }
func (r *fakeRows) RawValues() [][]byte    { return nil }
func (r *fakeRows) Conn() *pgx.Conn         { return nil }

// scanResult is one scripted response matched by SQL substring.
type scanResult struct {
	sqlSub string
	rowErr error     // for QueryRow Scan error
	row    []any     // for QueryRow Scan values (if rowErr == nil)
	rows   [][]any   // for Query (multi-row)
	rowsErr error    // for Query error
}

// execResult is one scripted Exec response matched by SQL substring.
type execResult struct {
	sqlSub     string
	rowsAff    int64
	err        error
}

// fakePool implements both dbPool and pgx.Tx. dbstore calls pool.Begin() to get
// a pgx.Tx; we return the fake itself (Commit/Rollback are no-ops). All
// Exec/QueryRow/Query calls are matched against configured scripts by SQL
// substring (first match wins; ordered queues allow multiple sequential
// responses to the same substring).
type fakePool struct {
	mu       sync.Mutex
	execQ    []execResult
	queryQ   []scanResult
	beginErr error
	committed bool
	rolledBack bool
}

func newFake() *fakePool { return &fakePool{} }

// addExec appends a scripted Exec result matched by SQL substring.
func (f *fakePool) addExec(sqlSub string, rowsAff int64, err error) *fakePool {
	f.execQ = append(f.execQ, execResult{sqlSub: sqlSub, rowsAff: rowsAff, err: err})
	return f
}

// addQuery appends a scripted Query/QueryRow result matched by SQL substring.
func (f *fakePool) addQuery(sqlSub string, row []any) *fakePool {
	f.queryQ = append(f.queryQ, scanResult{sqlSub: sqlSub, row: row})
	return f
}
func (f *fakePool) addQueryErr(sqlSub string, err error) *fakePool {
	f.queryQ = append(f.queryQ, scanResult{sqlSub: sqlSub, rowErr: err})
	return f
}
func (f *fakePool) addRows(sqlSub string, rows [][]any) *fakePool {
	f.queryQ = append(f.queryQ, scanResult{sqlSub: sqlSub, rows: rows})
	return f
}
func (f *fakePool) addRowsErr(sqlSub string, err error) *fakePool {
	f.queryQ = append(f.queryQ, scanResult{sqlSub: sqlSub, rowsErr: err})
	return f
}

func (f *fakePool) findExec(sql string) (execResult, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, e := range f.execQ {
		if strings.Contains(sql, e.sqlSub) {
			if i+1 < len(f.execQ) {
				f.execQ = append(f.execQ[:i], f.execQ[i+1:]...)
			} else {
				f.execQ = f.execQ[:i]
			}
			return e, true
		}
	}
	return execResult{}, false
}

func (f *fakePool) findQuery(sql string) (scanResult, bool, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, q := range f.queryQ {
		if strings.Contains(sql, q.sqlSub) {
			isRows := len(q.rows) > 0 || q.rowsErr != nil
			if i+1 < len(f.queryQ) {
				f.queryQ = append(f.queryQ[:i], f.queryQ[i+1:]...)
			} else {
				f.queryQ = f.queryQ[:i]
			}
			return q, true, isRows
		}
	}
	return scanResult{}, false, false
}

func (f *fakePool) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	e, ok := f.findExec(sql)
	if !ok {
		return pgconn.NewCommandTag("UPDATE 0"), nil
	}
	return pgconn.NewCommandTag(commandTagFor(e.rowsAff)), e.err
}

func (f *fakePool) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	q, ok, _ := f.findQuery(sql)
	if !ok {
		return &fakeRows{}, nil
	}
	if q.rowsErr != nil {
		return nil, q.rowsErr
	}
	return &fakeRows{rows: q.rows}, nil
}

func (f *fakePool) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	q, ok, isRows := f.findQuery(sql)
	if isRows {
		// QueryRow used but script provided rows; take first row.
		if len(q.rows) > 0 {
			return &fakeRow{values: q.rows[0]}
		}
		return &fakeRow{}
	}
	if !ok {
		return &fakeRow{}
	}
	if q.rowErr != nil {
		return &fakeRow{scanErr: q.rowErr}
	}
	return &fakeRow{values: q.row}
}

func (f *fakePool) Begin(ctx context.Context) (pgx.Tx, error) {
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	return f, nil
}

func (f *fakePool) Commit(ctx context.Context) error   { f.committed = true; return nil }
func (f *fakePool) Rollback(ctx context.Context) error { f.rolledBack = true; return nil }

// pgx.Tx also has Begin (nested), Conn, CopyFrom, Prepare etc. We stub the rest.
func (f *fakePool) Conn() *pgx.Conn { return nil }
func (f *fakePool) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	return 0, nil
}
func (f *fakePool) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults { return nil }
func (f *fakePool) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }
func (f *fakePool) Prepare(ctx context.Context, name, sql string) (*pgconn.StatementDescription, error) {
	return nil, nil
}

// commandTagFor builds a CommandTag string whose RowsAffected() returns n.
func commandTagFor(n int64) string {
	if n == 0 {
		return "UPDATE 0"
	}
	return "UPDATE " + intToStr(int(n))
}

// assignScan assigns scripted source values into destination pointers, like
// pgx Scan does for common types used by dbstore (string, *time.Time, []byte,
// int, bool, and pointer-to-pointer for nullable columns).
func assignScan(dest []any, src []any) error {
	for i, d := range dest {
		if i >= len(src) {
			break
		}
		s := src[i]
		switch d := d.(type) {
		case *string:
			if s != nil {
				switch v := s.(type) {
				case string:
					*d = v
				case []byte:
					*d = string(v)
				}
			}
		case **string:
			switch v := s.(type) {
			case *string:
				*d = v
			case string:
				str := v
				*d = &str
			case nil:
				*d = nil
			}
		case *[]byte:
			switch v := s.(type) {
			case []byte:
				*d = v
			case string:
				*d = []byte(v)
			}
		case *time.Time:
			if v, ok := s.(time.Time); ok {
				*d = v
			}
		case **time.Time:
			switch v := s.(type) {
			case *time.Time:
				*d = v
			case time.Time:
				t := v
				*d = &t
			case nil:
				*d = nil
			}
		case *bool:
			if v, ok := s.(bool); ok {
				*d = v
			}
		case *int:
			if v, ok := s.(int); ok {
				*d = v
			}
		case *int64:
			if v, ok := s.(int64); ok {
				*d = v
			}
		case *UserStatus:
			if v, ok := s.(string); ok {
				*d = UserStatus(v)
			}
		}
		_ = d
	}
	return nil
}

// newDBStoreWithFake builds a dbstore backed by the scripted fake pool and a
// deterministic Encryptor (fixed key) so test fixtures can encrypt/decrypt
// with the same key. Returns the store and the fake for further scripting.
func newDBStoreWithFake(t *testing.T) (*dbstore, *fakePool) {
	t.Helper()
	enc, err := db.NewEncryptor(testEncKey[:])
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	f := newFake()
	return &dbstore{pool: f, enc: enc}, f
}

// testEncKey is the 32-byte key shared between newDBStoreWithFake and tests
// that need to pre-encrypt MFA secrets.
var testEncKey = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

// testEncryptor returns the canonical encryptor used by newDBStoreWithFake.
func testEncryptor(t *testing.T) *db.Encryptor {
	t.Helper()
	enc, err := db.NewEncryptor(testEncKey[:])
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	return enc
}

// ===========================================================================
// Users.
// ===========================================================================

func TestDBCreateUserSuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("INSERT INTO users", 1, nil).
		addExec("INSERT INTO verification_tokens", 1, nil)
	u, token, err := s.CreateUser("alice@example.com", "S3cretPass!")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.ID == "" || token == "" {
		t.Fatalf("missing id/token: %+v %q", u, token)
	}
	if u.Status != StatusPending {
		t.Errorf("status: want PENDING got %q", u.Status)
	}
}

func TestDBCreateUserEmptyEmail(t *testing.T) {
	s, _ := newDBStoreWithFake(t)
	if _, _, err := s.CreateUser("", "S3cretPass!"); err != ErrBadRequest {
		t.Errorf("want ErrBadRequest got %v", err)
	}
}

func TestDBCreateUserWeakPassword(t *testing.T) {
	s, _ := newDBStoreWithFake(t)
	if _, _, err := s.CreateUser("weak@example.com", "short"); err != ErrWeakPassword {
		t.Errorf("want ErrWeakPassword got %v", err)
	}
}

func TestDBCreateUserInsertFails(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("INSERT INTO users", 0, errors.New("unique violation"))
	if _, _, err := s.CreateUser("dup@example.com", "S3cretPass!"); err != ErrEmailTaken {
		t.Errorf("want ErrEmailTaken got %v", err)
	}
}

func TestDBCreateUserVerificationInsertFails(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("INSERT INTO users", 1, nil).
		addExec("INSERT INTO verification_tokens", 0, errors.New("boom"))
	if _, _, err := s.CreateUser("v2@example.com", "S3cretPass!"); err == nil {
		t.Fatal("expected error from verification token insert")
	}
}

func TestDBVerifyUserTokenInvalid(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQueryErr("DELETE FROM verification_tokens", pgx.ErrNoRows)
	if _, err := s.VerifyUserToken("bogus"); err != ErrInvalidToken {
		t.Errorf("want ErrInvalidToken got %v", err)
	}
}

func TestDBVerifyUserTokenSuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQuery("DELETE FROM verification_tokens", []any{"u-1"}).
		addExec("UPDATE users SET status", 1, nil).
		addQuery("SELECT id, email, password_hash", []any{"u-1", "x@y.z", "hash", "ACTIVE", time.Now(), time.Now(), (*time.Time)(nil)})
	u, err := s.VerifyUserToken("good")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if u.ID != "u-1" {
		t.Errorf("id: want u-1 got %q", u.ID)
	}
}

func TestDBVerifyUserTokenAlreadyActive(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQuery("DELETE FROM verification_tokens", []any{"u-1"}).
		addExec("UPDATE users SET status", 0, nil) // no rows affected
	if _, err := s.VerifyUserToken("good"); err != ErrInvalidToken {
		t.Errorf("want ErrInvalidToken got %v", err)
	}
}

func TestDBVerifyUserUpdatesZeroUnknownUser(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("UPDATE users SET status", 0, nil).
		addQuery("SELECT id, email, password_hash", []any{"u-1", "e", "h", "PENDING", time.Now(), time.Now(), (*time.Time)(nil)})
	if err := s.VerifyUser("u-1"); err != ErrInvalidToken {
		t.Errorf("want ErrInvalidToken got %v", err)
	}
}

func TestDBVerifyUserSuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("UPDATE users SET status", 1, nil)
	if err := s.VerifyUser("u-1"); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestDBUserByIDFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addQuery("SELECT id, email, password_hash", []any{"u1", "a@b.c", "h", "ACTIVE", now, now, (*time.Time)(nil)})
	u := s.UserByID("u1")
	if u == nil || u.ID != "u1" {
		t.Fatalf("user: %+v", u)
	}
}

func TestDBUserByIDNotFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQueryErr("SELECT id, email, password_hash", errors.New("no rows"))
	if s.UserByID("nope") != nil {
		t.Error("expected nil")
	}
}

func TestDBUserByEmailFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addQuery("SELECT id, email, password_hash", []any{"u1", "a@b.c", "h", "ACTIVE", now, now, (*time.Time)(nil)})
	if s.UserByEmail("A@B.C") == nil {
		t.Error("expected user (normalized)")
	}
}

func TestDBUpdateUserEmailEmpty(t *testing.T) {
	s, _ := newDBStoreWithFake(t)
	if _, err := s.UpdateUserEmail("u1", ""); err != ErrBadRequest {
		t.Errorf("want ErrBadRequest got %v", err)
	}
}

func TestDBUpdateUserEmailUnknown(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQueryErr("SELECT status FROM users", pgx.ErrNoRows)
	if _, err := s.UpdateUserEmail("u1", "x@y.z"); err != ErrUserNotFound {
		t.Errorf("want ErrUserNotFound got %v", err)
	}
}

func TestDBUpdateUserEmailClosed(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQuery("SELECT status FROM users", []any{"CLOSED"})
	if _, err := s.UpdateUserEmail("u1", "x@y.z"); err != ErrAccountClosed {
		t.Errorf("want ErrAccountClosed got %v", err)
	}
}

func TestDBUpdateUserEmailTaken(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQuery("SELECT status FROM users", []any{"ACTIVE"}).
		addExec("UPDATE users SET email", 0, errors.New("unique violation"))
	if _, err := s.UpdateUserEmail("u1", "taken@x.y"); err != ErrEmailTaken {
		t.Errorf("want ErrEmailTaken got %v", err)
	}
}

func TestDBUpdateUserEmailSuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addQuery("SELECT status FROM users", []any{"ACTIVE"}).
		addExec("UPDATE users SET email", 1, nil).
		addQuery("SELECT id, email, password_hash", []any{"u1", "new@x.y", "h", "ACTIVE", now, now, (*time.Time)(nil)})
	u, err := s.UpdateUserEmail("u1", "new@x.y")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if u.Email != "new@x.y" {
		t.Errorf("email: %q", u.Email)
	}
}

func TestDBSoftDeleteUserNotFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("UPDATE users SET status='CLOSED'", 0, nil)
	if err := s.SoftDeleteUser("nope"); err != ErrUserNotFound {
		t.Errorf("want ErrUserNotFound got %v", err)
	}
}

func TestDBSoftDeleteUserSuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("UPDATE users SET status='CLOSED'", 1, nil).
		addExec("UPDATE sessions SET revoked_at", 1, nil)
	if err := s.SoftDeleteUser("u1"); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
}

func TestDBSetUserPasswordWeak(t *testing.T) {
	s, _ := newDBStoreWithFake(t)
	if err := s.SetUserPassword("u1", "short"); err != ErrWeakPassword {
		t.Errorf("want ErrWeakPassword got %v", err)
	}
}

func TestDBSetUserPasswordNotFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("UPDATE users SET password_hash", 0, nil)
	if err := s.SetUserPassword("nope", "S3cretPass!"); err != ErrUserNotFound {
		t.Errorf("want ErrUserNotFound got %v", err)
	}
}

func TestDBSetUserPasswordSuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("UPDATE users SET password_hash", 1, nil)
	if err := s.SetUserPassword("u1", "S3cretPass!"); err != nil {
		t.Fatalf("set pw: %v", err)
	}
}

func TestDBRevokeAllSessionsForUser(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("UPDATE sessions SET revoked_at", 2, nil)
	s.RevokeAllSessionsForUser("u1") // no error returned; just exercise
}

// ===========================================================================
// Sessions + lockouts.
// ===========================================================================

func TestDBLoginUnknownEmail(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQueryErr("SELECT id, email, password_hash", errors.New("no rows"))
	if _, _, err := s.Login("nobody@x.y", "pw", "", DefaultConfig()); err != ErrInvalidCredentials {
		t.Errorf("want ErrInvalidCredentials got %v", err)
	}
}

func TestDBLoginClosedAccount(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addQuery("SELECT id, email, password_hash", []any{"u1", "c@x.y", "h", "CLOSED", now, now, (*time.Time)(nil)})
	if _, _, err := s.Login("c@x.y", "pw", "", DefaultConfig()); err != ErrAccountClosed {
		t.Errorf("want ErrAccountClosed got %v", err)
	}
}

func TestDBLoginPendingAccount(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addQuery("SELECT id, email, password_hash", []any{"u1", "p@x.y", "h", "PENDING", now, now, (*time.Time)(nil)})
	if _, _, err := s.Login("p@x.y", "pw", "", DefaultConfig()); err != ErrAccountPending {
		t.Errorf("want ErrAccountPending got %v", err)
	}
}

func TestDBLoginWrongPassword(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.		addQuery("SELECT id, email, password_hash", []any{"u1", "a@b.c", hashPasswordWithSalt("S3cretPass!", []byte("salt")), "ACTIVE", now, now, (*time.Time)(nil)}).
		addQuery("SELECT locked_until FROM lockouts", []any{(*time.Time)(nil)}). // isLocked false
		addExec("INSERT INTO lockouts", 1, nil).                                  // recordFailure
		addQuery("SELECT fail_count FROM lockouts", []any{1}).                    // below threshold
		addQuery("SELECT locked_until FROM lockouts", []any{(*time.Time)(nil)})    // isLocked false after failure
	if _, _, err := s.Login("a@b.c", "wrong", "", DefaultConfig()); err != ErrInvalidCredentials {
		t.Errorf("want ErrInvalidCredentials got %v", err)
	}
}

func TestDBLoginLockedOut(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	until := now.Add(5 * time.Minute)
	f.addQuery("SELECT id, email, password_hash", []any{"u1", "a@b.c", "h", "ACTIVE", now, now, (*time.Time)(nil)}).
		addQuery("SELECT locked_until FROM lockouts", []any{until}) // isLocked true
	if _, _, err := s.Login("a@b.c", "pw", "", DefaultConfig()); err != ErrAccountLocked {
		t.Errorf("want ErrAccountLocked got %v", err)
	}
}

func TestDBLoginSuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	hashed := hashPasswordWithSalt("S3cretPass!", []byte("salt"))
	f.addQuery("SELECT id, email, password_hash", []any{"u1", "a@b.c", hashed, "ACTIVE", now, now, (*time.Time)(nil)}).
		addQuery("SELECT locked_until FROM lockouts", []any{(*time.Time)(nil)}). // not locked
		addExec("DELETE FROM lockouts", 1, nil).                                  // resetLockout
		addRows("SELECT id, user_id, type, secret_encrypted, confirmed, created_at, disabled_at FROM mfa_factors WHERE user_id=$1 AND confirmed=true", nil). // no confirmed factors
		addExec("INSERT INTO sessions", 1, nil)
	res, _, err := s.Login("a@b.c", "S3cretPass!", "", DefaultConfig())
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Errorf("missing tokens: %+v", res)
	}
}

func TestDBLoginMFARequired(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	hashed := hashPasswordWithSalt("S3cretPass!", []byte("salt"))
	// confirmedFactors returns 1 factor with a valid secret.
	enc := testEncryptor(t)
	encSecret, _ := enc.EncryptString("GEZDGNBVGY3TQOJQ")
	f.addQuery("SELECT id, email, password_hash", []any{"u1", "a@b.c", hashed, "ACTIVE", now, now, (*time.Time)(nil)}).
		addQuery("SELECT locked_until FROM lockouts", []any{(*time.Time)(nil)}).
		addExec("DELETE FROM lockouts", 1, nil).
		addRows("SELECT id, user_id, type, secret_encrypted, confirmed, created_at, disabled_at FROM mfa_factors WHERE user_id=$1 AND confirmed=true", [][]any{
			{"f1", "u1", "TOTP", []byte(encSecret), true, now, (*time.Time)(nil)},
		})
	if _, _, err := s.Login("a@b.c", "S3cretPass!", "", DefaultConfig()); err != ErrMFARequired {
		t.Errorf("want ErrMFARequired got %v", err)
	}
}

func TestDBIssueSessionInsertFails(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("INSERT INTO sessions", 0, errors.New("db down"))
	if _, _, err := s.issueSession("u1", DefaultConfig()); err == nil {
		t.Fatal("expected error from issueSession")
	}
}

func TestDBRefreshInvalidToken(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQueryErr("SELECT id, user_id, revoked_at, expires_at FROM sessions", pgx.ErrNoRows).
		addQueryErr("SELECT session_id FROM used_refresh_tokens", pgx.ErrNoRows)
	if _, _, err := s.Refresh("bogus", DefaultConfig()); err != ErrRefreshTokenInvalid {
		t.Errorf("want ErrRefreshTokenInvalid got %v", err)
	}
}

func TestDBRefreshReuseDetected(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQueryErr("SELECT id, user_id, revoked_at, expires_at FROM sessions", pgx.ErrNoRows).
		addQuery("SELECT session_id FROM used_refresh_tokens", []any{"sid-1"}).
		addExec("UPDATE sessions SET revoked_at", 1, nil) // RevokeSession called
	if _, _, err := s.Refresh("reused", DefaultConfig()); err != ErrRefreshTokenInvalid {
		t.Errorf("want ErrRefreshTokenInvalid got %v", err)
	}
}

func TestDBRefreshRevokedSession(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addQuery("SELECT id, user_id, revoked_at, expires_at FROM sessions", []any{"sid", "u1", now, now.Add(time.Hour)})
	if _, _, err := s.Refresh("r", DefaultConfig()); err != ErrRefreshTokenInvalid {
		t.Errorf("want ErrRefreshTokenInvalid got %v", err)
	}
}

func TestDBRefreshExpired(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	past := time.Now().Add(-time.Hour)
	f.addQuery("SELECT id, user_id, revoked_at, expires_at FROM sessions", []any{"sid", "u1", (*time.Time)(nil), past})
	if _, _, err := s.Refresh("r", DefaultConfig()); err != ErrRefreshTokenInvalid {
		t.Errorf("want ErrRefreshTokenInvalid got %v", err)
	}
}

func TestDBRefreshSuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	future := time.Now().Add(time.Hour)
	f.addQuery("SELECT id, user_id, revoked_at, expires_at FROM sessions", []any{"sid", "u1", (*time.Time)(nil), future}).
		addExec("UPDATE sessions SET refresh_token_hash", 1, nil).
		addExec("INSERT INTO used_refresh_tokens", 1, nil)
	res, _, err := s.Refresh("r", DefaultConfig())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Errorf("missing tokens")
	}
}

func TestDBLogoutNotFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQueryErr("SELECT user_id, revoked_at FROM sessions", pgx.ErrNoRows)
	if _, err := s.Logout("bogus"); err != ErrSessionNotFound {
		t.Errorf("want ErrSessionNotFound got %v", err)
	}
}

func TestDBLogoutAlreadyRevoked(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addQuery("SELECT user_id, revoked_at FROM sessions", []any{"u1", now})
	ev, err := s.Logout("sid")
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	if ev != nil {
		t.Errorf("expected nil audit event for already-revoked, got %+v", ev)
	}
}

func TestDBLogoutSuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQuery("SELECT user_id, revoked_at FROM sessions", []any{"u1", (*time.Time)(nil)}).
		addExec("UPDATE sessions SET revoked_at=$1", 1, nil)
	ev, err := s.Logout("sid")
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	if ev == nil || ev.Type != "auth.logout" {
		t.Errorf("expected auth.logout event, got %+v", ev)
	}
}

func TestDBRevokeSessionNotFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("UPDATE sessions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL", 0, nil).
		addQuery("SELECT EXISTS(SELECT 1 FROM sessions WHERE id=$1)", []any{false})
	if err := s.RevokeSession("bogus"); err != ErrSessionNotFound {
		t.Errorf("want ErrSessionNotFound got %v", err)
	}
}

func TestRevokeSessionAlreadyRevoked(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("UPDATE sessions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL", 0, nil).
		addQuery("SELECT EXISTS(SELECT 1 FROM sessions WHERE id=$1)", []any{true})
	if err := s.RevokeSession("sid"); err != nil {
		t.Errorf("already-revoked revoke should be idempotent, got %v", err)
	}
}

func TestDBRevokeSessionSuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("UPDATE sessions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL", 1, nil)
	if err := s.RevokeSession("sid"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

func TestDBListSessionsQueryErr(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addRowsErr("SELECT id, user_id, refresh_token_hash, issuer", errors.New("db err"))
	if got := s.ListSessions("u1"); got != nil {
		t.Errorf("expected nil on query error, got %v", got)
	}
}

func TestDBListSessionsFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addRows("SELECT id, user_id, refresh_token_hash, issuer", [][]any{
		{"s1", "u1", "rh", "iss", now, now, now.Add(time.Hour), (*time.Time)(nil)},
	})
	got := s.ListSessions("u1")
	if len(got) != 1 || got[0].ID != "s1" {
		t.Fatalf("list: %+v", got)
	}
}

func TestDBSessionByIDFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addQuery("SELECT id, user_id, refresh_token_hash, issuer", []any{"s1", "u1", "rh", "iss", now, now, now.Add(time.Hour), (*time.Time)(nil)})
	sess, ok := s.SessionByID("s1")
	if !ok || sess == nil || sess.ID != "s1" {
		t.Fatalf("expected found session, got %v %v", sess, ok)
	}
}

func TestDBSessionByIDRevoked(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	revoked := now.Add(-time.Minute)
	f.addQuery("SELECT id, user_id, refresh_token_hash, issuer", []any{"s1", "u1", "rh", "iss", now, now, now.Add(time.Hour), &revoked})
	if _, ok := s.SessionByID("s1"); ok {
		t.Error("revoked session should not be found")
	}
}

func TestDBUnlockUserNotFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQuery("SELECT EXISTS(SELECT 1 FROM users", []any{false})
	if err := s.UnlockUser("nope"); err != ErrUserNotFound {
		t.Errorf("want ErrUserNotFound got %v", err)
	}
}

func TestDBUnlockUserSuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQuery("SELECT EXISTS(SELECT 1 FROM users", []any{true}).
		addExec("DELETE FROM lockouts", 1, nil)
	if err := s.UnlockUser("u1"); err != nil {
		t.Fatalf("unlock: %v", err)
	}
}

func TestDBIsLockedFalse(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQuery("SELECT locked_until FROM lockouts", []any{(*time.Time)(nil)})
	if s.isLocked("u1") {
		t.Error("expected not locked")
	}
}

func TestDBIsLockedTrue(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	until := time.Now().Add(10 * time.Minute)
	f.addQuery("SELECT locked_until FROM lockouts", []any{until})
	if !s.isLocked("u1") {
		t.Error("expected locked")
	}
}

func TestDBResetLockout(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("DELETE FROM lockouts", 1, nil)
	s.resetLockout("u1")
}

// ===========================================================================
// MFA.
// ===========================================================================

func TestDBEnrollMFAUnknownUser(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQueryErr("SELECT status FROM users WHERE id=$1", pgx.ErrNoRows)
	if _, _, err := s.EnrollMFA("nope", DefaultConfig()); err != ErrUserNotFound {
		t.Errorf("want ErrUserNotFound got %v", err)
	}
}

func TestDBEnrollMFAClosed(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQuery("SELECT status FROM users WHERE id=$1", []any{"CLOSED"})
	if _, _, err := s.EnrollMFA("u1", DefaultConfig()); err != ErrAccountClosed {
		t.Errorf("want ErrAccountClosed got %v", err)
	}
}

func TestDBEnrollMFASuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addQuery("SELECT status FROM users WHERE id=$1", []any{"ACTIVE"}).
		addExec("INSERT INTO mfa_factors", 1, nil).
		addQuery("SELECT id, email, password_hash", []any{"u1", "a@b.c", "h", "ACTIVE", now, now, (*time.Time)(nil)})
	res, ev, err := s.EnrollMFA("u1", DefaultConfig())
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if res.FactorID == "" || res.Secret == "" {
		t.Errorf("missing enroll result: %+v", res)
	}
	if ev == nil || ev.Type != "auth.mfa.enroll" {
		t.Errorf("audit: %+v", ev)
	}
}

func TestDBEnrollMFAInsertFails(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQuery("SELECT status FROM users WHERE id=$1", []any{"ACTIVE"}).
		addExec("INSERT INTO mfa_factors", 0, errors.New("boom"))
	if _, _, err := s.EnrollMFA("u1", DefaultConfig()); err == nil {
		t.Fatal("expected insert error")
	}
}

func TestDBVerifyMFANoUnconfirmed(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQueryErr("SELECT id, secret_encrypted FROM mfa_factors", pgx.ErrNoRows)
	if _, err := s.VerifyMFA("u1", "000000", "000000"); err != ErrFactorNotConfirmed {
		t.Errorf("want ErrFactorNotConfirmed got %v", err)
	}
}

func TestDBVerifyMFAInvalidCode(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	enc := testEncryptor(t)
	encSecret, _ := enc.EncryptString("GEZDGNBVGY3TQOJQ")
	f.addQuery("SELECT id, secret_encrypted FROM mfa_factors", []any{"f1", []byte(encSecret)})
	if _, err := s.VerifyMFA("u1", "000000", "000000"); err != ErrMFAInvalid {
		t.Errorf("want ErrMFAInvalid got %v", err)
	}
}

func TestDBVerifyMFASameCodes(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	enc := testEncryptor(t)
	secret := "GEZDGNBVGY3TQOJQ"
	encSecret, _ := enc.EncryptString(secret)
	code, _ := totp(secret, time.Now())
	f.addQuery("SELECT id, secret_encrypted FROM mfa_factors", []any{"f1", []byte(encSecret)})
	if _, err := s.VerifyMFA("u1", code, code); err != ErrMFAInvalid {
		t.Errorf("same codes want ErrMFAInvalid got %v", err)
	}
}

func TestDBVerifyMFASuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	enc := testEncryptor(t)
	secret := "GEZDGNBVGY3TQOJQ"
	encSecret, _ := enc.EncryptString(secret)
	now := time.Now()
	code1, _ := totp(secret, now)
	code2, _ := totp(secret, now.Add(30*time.Second))
	f.addQuery("SELECT id, secret_encrypted FROM mfa_factors", []any{"f1", []byte(encSecret)}).
		addExec("UPDATE mfa_factors SET confirmed=true", 1, nil)
	ev, err := s.VerifyMFA("u1", code1, code2)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ev == nil || ev.Type != "auth.mfa.verify" {
		t.Errorf("audit: %+v", ev)
	}
}

func TestDBConfirmedFactorsQueryErr(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addRowsErr("SELECT id, user_id, type, secret_encrypted, confirmed, created_at, disabled_at FROM mfa_factors WHERE user_id=$1 AND confirmed=true", errors.New("db"))
	if got := s.confirmedFactors("u1"); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestDBConfirmedFactorsFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	enc := testEncryptor(t)
	encSecret, _ := enc.EncryptString("GEZDGNBVGY3TQOJQ")
	now := time.Now()
	f.addRows("SELECT id, user_id, type, secret_encrypted, confirmed, created_at, disabled_at FROM mfa_factors WHERE user_id=$1 AND confirmed=true", [][]any{
		{"f1", "u1", "TOTP", []byte(encSecret), true, now, (*time.Time)(nil)},
	})
	got := s.confirmedFactors("u1")
	if len(got) != 1 || got[0].Secret != "GEZDGNBVGY3TQOJQ" {
		t.Fatalf("factors: %+v", got)
	}
}

func TestDBValidateMFAEmptyCode(t *testing.T) {
	s, _ := newDBStoreWithFake(t)
	if s.validateMFA("u1", "") {
		t.Error("empty code should not validate")
	}
}

func TestDBValidateMFARecoveryCode(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	// confirmedFactors returns none (empty rows); then recovery-code path hits.
	f.addRows("SELECT id, user_id, type, secret_encrypted, confirmed, created_at, disabled_at FROM mfa_factors WHERE user_id=$1 AND confirmed=true", nil).
		addExec("UPDATE mfa_recovery_codes SET used_at", 1, nil) // recovery code matches
	if !s.validateMFA("u1", "some-recovery") {
		t.Error("expected recovery code to validate")
	}
}

func TestDBValidateMFARecoveryCodeNoMatch(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addRows("SELECT id, user_id, type, secret_encrypted, confirmed, created_at, disabled_at FROM mfa_factors WHERE user_id=$1 AND confirmed=true", nil).
		addExec("UPDATE mfa_recovery_codes SET used_at", 0, nil) // no match
	if s.validateMFA("u1", "bogus-recovery") {
		t.Error("expected no validation for bogus recovery code")
	}
}

func TestDBGenerateRecoveryCodesUnknownUser(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQuery("SELECT EXISTS(SELECT 1 FROM users", []any{false})
	if _, _, err := s.GenerateRecoveryCodes("nope"); err != ErrUserNotFound {
		t.Errorf("want ErrUserNotFound got %v", err)
	}
}

func TestDBGenerateRecoveryCodesSuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQuery("SELECT EXISTS(SELECT 1 FROM users", []any{true}).
		addExec("DELETE FROM mfa_recovery_codes WHERE user_id=$1", 1, nil)
	for i := 0; i < 10; i++ {
		f.addExec("INSERT INTO mfa_recovery_codes", 1, nil)
	}
	codes, ev, err := s.GenerateRecoveryCodes("u1")
	if err != nil {
		t.Fatalf("gen codes: %v", err)
	}
	if len(codes) != 10 {
		t.Errorf("want 10 codes got %d", len(codes))
	}
	if ev == nil || ev.Type != "auth.mfa.recovery" {
		t.Errorf("audit: %+v", ev)
	}
}

func TestDBDisableFactorNotFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQueryErr("SELECT user_id FROM mfa_factors WHERE id=$1", pgx.ErrNoRows)
	if _, err := s.DisableFactor("u1", "nope"); err != ErrFactorNotFound {
		t.Errorf("want ErrFactorNotFound got %v", err)
	}
}

func TestDBDisableFactorUserMismatch(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQuery("SELECT user_id FROM mfa_factors WHERE id=$1", []any{"other-user"})
	if _, err := s.DisableFactor("u1", "f1"); err != ErrFactorNotFound {
		t.Errorf("want ErrFactorNotFound got %v", err)
	}
}

func TestDBDisableFactorSuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQuery("SELECT user_id FROM mfa_factors WHERE id=$1", []any{"u1"}).
		addExec("UPDATE mfa_factors SET disabled_at", 1, nil)
	ev, err := s.DisableFactor("u1", "f1")
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if ev == nil || ev.Type != "auth.mfa.disable" {
		t.Errorf("audit: %+v", ev)
	}
}

// ===========================================================================
// API keys.
// ===========================================================================

func TestDBCreateAPIKeyEmptyPartner(t *testing.T) {
	s, _ := newDBStoreWithFake(t)
	if _, _, err := s.CreateAPIKey("", nil, nil, nil); err != ErrBadRequest {
		t.Errorf("want ErrBadRequest got %v", err)
	}
}

func TestDBCreateAPIKeySuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("INSERT INTO api_keys", 1, nil)
	res, ev, err := s.CreateAPIKey("partner-1", []string{"read"}, []string{"10.0.0.1"}, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Key == "" || res.Prefix == "" {
		t.Errorf("missing key material: %+v", res)
	}
	if ev == nil || ev.Type != "auth.key.create" {
		t.Errorf("audit: %+v", ev)
	}
}

func TestDBCreateAPIKeyInsertFails(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("INSERT INTO api_keys", 0, errors.New("db err"))
	if _, _, err := s.CreateAPIKey("p1", nil, nil, nil); err == nil {
		t.Fatal("expected insert error")
	}
}

func TestDBListAPIKeysQueryErr(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addRowsErr("SELECT id, partner_id, prefix, key_hash, scopes, ip_allowlist", errors.New("db"))
	if got := s.ListAPIKeys("p1"); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestDBListAPIKeysFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addRows("SELECT id, partner_id, prefix, key_hash, scopes, ip_allowlist", [][]any{
		{"k1", "p1", "iko_abcd", "hash", []byte(`["read"]`), []byte(`["10.0.0.1"]`), (*time.Time)(nil), now, (*time.Time)(nil), (*string)(nil), (*string)(nil), (*time.Time)(nil)},
	})
	got := s.ListAPIKeys("p1")
	if len(got) != 1 || got[0].ID != "k1" || got[0].Scopes[0] != "read" {
		t.Fatalf("list: %+v", got)
	}
}

func TestDBRotateAPIKeyNotFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQueryErr("SELECT partner_id, scopes, ip_allowlist, expires_at, key_hash, prefix, revoked_at FROM api_keys WHERE id=$1", pgx.ErrNoRows)
	if _, _, err := s.RotateAPIKey("nope"); err != ErrAPIKeyNotFound {
		t.Errorf("want ErrAPIKeyNotFound got %v", err)
	}
}

func TestDBRotateAPIKeyRevoked(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addQuery("SELECT partner_id, scopes, ip_allowlist, expires_at, key_hash, prefix, revoked_at FROM api_keys WHERE id=$1", []any{"p1", []byte(`[]`), []byte(`[]`), (*time.Time)(nil), "oldhash", "iko_old", now})
	if _, _, err := s.RotateAPIKey("k1"); err != ErrAPIKeyNotFound {
		t.Errorf("want ErrAPIKeyNotFound got %v", err)
	}
}

func TestDBRotateAPIKeySuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQuery("SELECT partner_id, scopes, ip_allowlist, expires_at, key_hash, prefix, revoked_at FROM api_keys WHERE id=$1", []any{"p1", []byte(`["read"]`), []byte(`["10.0.0.1"]`), (*time.Time)(nil), "oldhash", "iko_old", (*time.Time)(nil)}).
		addExec("UPDATE api_keys SET previous_key_hash", 1, nil)
	res, ev, err := s.RotateAPIKey("k1")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if res.Key == "" {
		t.Errorf("missing new key: %+v", res)
	}
	if ev == nil || ev.Type != "auth.key.rotate" {
		t.Errorf("audit: %+v", ev)
	}
}

func TestDBRevokeAPIKeyNotFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQueryErr("SELECT partner_id, revoked_at FROM api_keys WHERE id=$1", pgx.ErrNoRows)
	if _, err := s.RevokeAPIKey("nope"); err != ErrAPIKeyNotFound {
		t.Errorf("want ErrAPIKeyNotFound got %v", err)
	}
}

func TestDBRevokeAPIKeyAlreadyRevoked(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addQuery("SELECT partner_id, revoked_at FROM api_keys WHERE id=$1", []any{"p1", now})
	ev, err := s.RevokeAPIKey("k1")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if ev != nil {
		t.Errorf("already-revoked revoke should return nil event, got %+v", ev)
	}
}

func TestDBRevokeAPIKeySuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQuery("SELECT partner_id, revoked_at FROM api_keys WHERE id=$1", []any{"p1", (*time.Time)(nil)}).
		addExec("UPDATE api_keys SET revoked_at=$1", 1, nil)
	ev, err := s.RevokeAPIKey("k1")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if ev == nil || ev.Type != "auth.key.revoke" {
		t.Errorf("audit: %+v", ev)
	}
}

func TestDBResolveAPIKeyFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addQuery("SELECT id, partner_id, prefix, key_hash, scopes, ip_allowlist", []any{"k1", "p1", "iko_abcd", "hash", []byte(`["read"]`), []byte(`[]`), (*time.Time)(nil), now, (*time.Time)(nil), (*string)(nil), (*string)(nil), (*time.Time)(nil)})
	if k := s.ResolveAPIKey("iko_full"); k == nil || k.ID != "k1" {
		t.Fatalf("expected k1, got %+v", k)
	}
}

func TestDBResolveAPIKeyRevoked(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	revoked := now
	f.addQuery("SELECT id, partner_id, prefix, key_hash, scopes, ip_allowlist", []any{"k1", "p1", "iko_abcd", "hash", []byte(`["read"]`), []byte(`[]`), (*time.Time)(nil), now, &revoked, (*string)(nil), (*string)(nil), (*time.Time)(nil)})
	if s.ResolveAPIKey("iko_full") != nil {
		t.Error("revoked key should not resolve")
	}
}

// ===========================================================================
// RBAC.
// ===========================================================================

func TestDBAddBindingInvalidRole(t *testing.T) {
	s, _ := newDBStoreWithFake(t)
	if _, err := s.AddBinding("USER", "x", "nope", "", ""); err != ErrBadRequest {
		t.Errorf("want ErrBadRequest got %v", err)
	}
}

func TestDBAddBindingEmptySubject(t *testing.T) {
	s, _ := newDBStoreWithFake(t)
	if _, err := s.AddBinding("USER", "", "admin", "", ""); err != ErrBadRequest {
		t.Errorf("want ErrBadRequest got %v", err)
	}
}

func TestDBAddBindingSuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("INSERT INTO role_bindings", 1, nil)
	b, err := s.AddBinding("USER", "u1", "admin", "partner", "p1")
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if b.ID == "" || b.Role != "admin" {
		t.Errorf("binding: %+v", b)
	}
}

func TestDBListBindingsWithFilters(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addRows("SELECT id, subject_type, subject_id, role, scope_type, scope_id, created_at FROM role_bindings", [][]any{
		{"b1", "USER", "u1", "admin", "partner", "p1", now},
	})
	got := s.ListBindings("USER", "u1")
	if len(got) != 1 || got[0].ID != "b1" {
		t.Fatalf("list: %+v", got)
	}
}

func TestDBListBindingsNoFilters(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addRows("SELECT id, subject_type, subject_id, role, scope_type, scope_id, created_at FROM role_bindings", nil)
	if got := s.ListBindings("", ""); len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestDBListBindingsQueryErr(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addRowsErr("SELECT id, subject_type, subject_id, role, scope_type, scope_id, created_at FROM role_bindings", errors.New("db"))
	if got := s.ListBindings("", ""); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestDBDeleteBindingNotFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("DELETE FROM role_bindings WHERE id=$1", 0, nil)
	if err := s.DeleteBinding("nope"); err != ErrBindingNotFound {
		t.Errorf("want ErrBindingNotFound got %v", err)
	}
}

func TestDBDeleteBindingSuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("DELETE FROM role_bindings WHERE id=$1", 1, nil)
	if err := s.DeleteBinding("b1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestDBBindingsForSubject(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addRows("SELECT id, subject_type, subject_id, role, scope_type, scope_id, created_at FROM role_bindings", [][]any{
		{"b1", "USER", "u1", "admin", "", "", now},
	})
	if got := s.BindingsForSubject("u1"); len(got) != 1 {
		t.Errorf("expected 1, got %v", got)
	}
}

func TestDBAuthorizeAllow(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addRows("SELECT id, subject_type, subject_id, role, scope_type, scope_id, created_at FROM role_bindings", [][]any{
		{"b1", "USER", "u1", "admin", "", "", now},
	})
	res, ev := s.Authorize("u1", "users.read", "res")
	if !res.Allow {
		t.Errorf("expected allow, got %+v", res)
	}
	if ev != nil {
		t.Errorf("allow should not produce audit event, got %+v", ev)
	}
}

func TestDBAuthorizeDeny(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addRows("SELECT id, subject_type, subject_id, role, scope_type, scope_id, created_at FROM role_bindings", nil)
	res, ev := s.Authorize("u1", "nonexistent.action", "res")
	if res.Allow {
		t.Error("expected deny")
	}
	if ev == nil || ev.Type != "auth.authz.deny" {
		t.Errorf("expected deny audit event, got %+v", ev)
	}
}

// ===========================================================================
// Password reset.
// ===========================================================================

func TestDBPasswordResetInitUnknownEmail(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQueryErr("SELECT id, email, password_hash", errors.New("no rows"))
	if _, _, err := s.PasswordResetInit("nobody@x.y"); err != ErrUserNotFound {
		t.Errorf("want ErrUserNotFound got %v", err)
	}
}

func TestDBPasswordResetInitClosed(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addQuery("SELECT id, email, password_hash", []any{"u1", "c@x.y", "h", "CLOSED", now, now, (*time.Time)(nil)})
	if _, _, err := s.PasswordResetInit("c@x.y"); err != ErrAccountClosed {
		t.Errorf("want ErrAccountClosed got %v", err)
	}
}

func TestDBPasswordResetInitSuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addQuery("SELECT id, email, password_hash", []any{"u1", "a@b.c", "h", "ACTIVE", now, now, (*time.Time)(nil)}).
		addExec("INSERT INTO password_resets", 1, nil)
	token, ev, err := s.PasswordResetInit("a@b.c")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if token == "" || ev == nil {
		t.Errorf("missing token/audit: %q %+v", token, ev)
	}
}

func TestDBPasswordResetConfirmInvalidToken(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addQueryErr("SELECT id, user_id, used_at, expires_at FROM password_resets", pgx.ErrNoRows)
	if _, err := s.PasswordResetConfirm("bogus", "NewS3cretPass!", ""); err != ErrInvalidToken {
		t.Errorf("want ErrInvalidToken got %v", err)
	}
}

func TestDBPasswordResetConfirmExpired(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	past := time.Now().Add(-time.Hour)
	f.addQuery("SELECT id, user_id, used_at, expires_at FROM password_resets", []any{"r1", "u1", (*time.Time)(nil), past})
	if _, err := s.PasswordResetConfirm("t", "NewS3cretPass!", ""); err != ErrInvalidToken {
		t.Errorf("want ErrInvalidToken got %v", err)
	}
}

func TestDBPasswordResetConfirmUsed(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	used := now.Add(-time.Minute)
	f.addQuery("SELECT id, user_id, used_at, expires_at FROM password_resets", []any{"r1", "u1", &used, now.Add(time.Hour)})
	if _, err := s.PasswordResetConfirm("t", "NewS3cretPass!", ""); err != ErrInvalidToken {
		t.Errorf("want ErrInvalidToken got %v", err)
	}
}

func TestDBPasswordResetConfirmWeakPassword(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	future := time.Now().Add(time.Hour)
	f.addQuery("SELECT id, user_id, used_at, expires_at FROM password_resets", []any{"r1", "u1", (*time.Time)(nil), future}).
		addRows("SELECT id, user_id, type, secret_encrypted, confirmed, created_at, disabled_at FROM mfa_factors WHERE user_id=$1 AND confirmed=true", nil).
		addExec("UPDATE users SET password_hash", 0, nil) // SetUserPassword fails on weak? Actually weak returns before db call.
	if _, err := s.PasswordResetConfirm("t", "short", ""); err != ErrWeakPassword {
		t.Errorf("want ErrWeakPassword got %v", err)
	}
}

func TestDBPasswordResetConfirmSuccess(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	future := time.Now().Add(time.Hour)
	f.addQuery("SELECT id, user_id, used_at, expires_at FROM password_resets", []any{"r1", "u1", (*time.Time)(nil), future}).
		addRows("SELECT id, user_id, type, secret_encrypted, confirmed, created_at, disabled_at FROM mfa_factors WHERE user_id=$1 AND confirmed=true", nil). // no MFA
		addExec("UPDATE users SET password_hash", 1, nil). // SetUserPassword
		addExec("UPDATE password_resets SET used_at", 1, nil).
		addExec("UPDATE sessions SET revoked_at", 1, nil). // RevokeAllSessionsForUser
		addExec("DELETE FROM lockouts", 1, nil)            // resetLockout
	ev, err := s.PasswordResetConfirm("t", "NewS3cretPass!", "")
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if ev == nil || ev.Type != "auth.password.reset.confirm" {
		t.Errorf("audit: %+v", ev)
	}
}

func TestDBPasswordResetConfirmMFARequired(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	future := time.Now().Add(time.Hour)
	enc := testEncryptor(t)
	encSecret, _ := enc.EncryptString("GEZDGNBVGY3TQOJQ")
	now := time.Now()
	f.addQuery("SELECT id, user_id, used_at, expires_at FROM password_resets", []any{"r1", "u1", (*time.Time)(nil), future}).
		addRows("SELECT id, user_id, type, secret_encrypted, confirmed, created_at, disabled_at FROM mfa_factors WHERE user_id=$1 AND confirmed=true", [][]any{
			{"f1", "u1", "TOTP", []byte(encSecret), true, now, (*time.Time)(nil)},
		})
	if _, err := s.PasswordResetConfirm("t", "NewS3cretPass!", ""); err != ErrMFARequired {
		t.Errorf("want ErrMFARequired got %v", err)
	}
}

// ===========================================================================
// Audit.
// ===========================================================================

func TestDBRecordAudit(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addExec("INSERT INTO audit_events", 1, nil)
	// nil events should be skipped.
	s.RecordAudit(nil, &AuditEvent{Type: "test.event"}, &AuditEvent{ID: "pre", Type: "test.event2"})
}

func TestDBListAuditFound(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	now := time.Now()
	f.addRows("SELECT id, type, subject_id, session_id, request_id, metadata, created_at FROM audit_events", [][]any{
		{"a1", "auth.login", "u1", "s1", "rid", []byte(`{"k":"v"}`), now},
	})
	got := s.ListAudit()
	if len(got) != 1 || got[0].ID != "a1" {
		t.Fatalf("audit: %+v", got)
	}
	if got[0].Metadata == nil || got[0].Metadata["k"] != "v" {
		t.Errorf("metadata not decoded: %+v", got[0].Metadata)
	}
}

func TestDBListAuditQueryErr(t *testing.T) {
	s, f := newDBStoreWithFake(t)
	f.addRowsErr("SELECT id, type, subject_id, session_id, request_id, metadata, created_at FROM audit_events", errors.New("db"))
	if got := s.ListAudit(); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

// ===========================================================================
// Scan helpers + pure utilities.
// ===========================================================================

type errScanner struct{ err error }

func (e errScanner) Scan(dest ...any) error { return e.err }

func TestScanUserError(t *testing.T) {
	if _, err := scanUser(errScanner{errors.New("scan fail")}); err == nil {
		t.Fatal("expected scan error")
	}
}

func TestScanSessionError(t *testing.T) {
	if _, err := scanSession(errScanner{errors.New("scan fail")}); err == nil {
		t.Fatal("expected scan error")
	}
}

func TestScanAPIKeyError(t *testing.T) {
	if _, err := scanAPIKey(errScanner{errors.New("scan fail")}); err == nil {
		t.Fatal("expected scan error")
	}
}

func TestScanBindingError(t *testing.T) {
	if _, err := scanBinding(errScanner{errors.New("scan fail")}); err == nil {
		t.Fatal("expected scan error")
	}
}

func TestScanFactorDecryptError(t *testing.T) {
	enc := testEncryptor(t)
	// Provide encSecret that won't decrypt to the stored plaintext.
	if _, err := scanFactor(&fakeRow{values: []any{"f1", "u1", "TOTP", []byte("not-valid-b64"), true, time.Now(), (*time.Time)(nil)}}, enc); err == nil {
		t.Fatal("expected decrypt error for invalid ciphertext")
	}
}

func TestScanFactorError(t *testing.T) {
	enc := testEncryptor(t)
	if _, err := scanFactor(errScanner{errors.New("scan fail")}, enc); err == nil {
		t.Fatal("expected scan error")
	}
}

func TestScanUserSuccess(t *testing.T) {
	now := time.Now()
	u, err := scanUser(&fakeRow{values: []any{"u1", "a@b.c", "h", "ACTIVE", now, now, (*time.Time)(nil)}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if u.ID != "u1" || u.Status != StatusActive {
		t.Errorf("user: %+v", u)
	}
}

func TestScanSessionSuccess(t *testing.T) {
	now := time.Now()
	s, err := scanSession(&fakeRow{values: []any{"s1", "u1", "rh", "iss", now, now, now.Add(time.Hour), (*time.Time)(nil)}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if s.ID != "s1" {
		t.Errorf("session: %+v", s)
	}
}

func TestScanBindingSuccess(t *testing.T) {
	now := time.Now()
	b, err := scanBinding(&fakeRow{values: []any{"b1", "USER", "u1", "admin", "partner", "p1", now}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if b.ID != "b1" || b.Role != "admin" {
		t.Errorf("binding: %+v", b)
	}
}

func TestScanAPIKeySuccess(t *testing.T) {
	now := time.Now()
	hash := "hash"
	prefix := "iko_old"
	k, err := scanAPIKey(&fakeRow{values: []any{"k1", "p1", "iko_abcd", "kh", []byte(`["read"]`), []byte(`["1.1.1.1"]`), (*time.Time)(nil), now, (*time.Time)(nil), &hash, &prefix, (*time.Time)(nil)}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if k.ID != "k1" || k.PreviousKeyHash != "hash" || k.PreviousPrefix != "iko_old" {
		t.Errorf("apikey: %+v", k)
	}
}

func TestScanAPIKeyNoPrevious(t *testing.T) {
	now := time.Now()
	k, err := scanAPIKey(&fakeRow{values: []any{"k1", "p1", "iko_abcd", "kh", []byte(`[]`), []byte(`[]`), (*time.Time)(nil), now, (*time.Time)(nil), (*string)(nil), (*string)(nil), (*time.Time)(nil)}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if k.PreviousKeyHash != "" || k.PreviousPrefix != "" {
		t.Errorf("expected empty previous, got %+v", k)
	}
}

func TestScanFactorSuccess(t *testing.T) {
	enc := testEncryptor(t)
	encSecret, _ := enc.EncryptString("GEZDGNBVGY3TQOJQ")
	now := time.Now()
	f, err := scanFactor(&fakeRow{values: []any{"f1", "u1", "TOTP", []byte(encSecret), true, now, (*time.Time)(nil)}}, enc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if f.ID != "f1" || f.Secret != "GEZDGNBVGY3TQOJQ" {
		t.Errorf("factor: %+v", f)
	}
}

func TestJsonScopesNil(t *testing.T) {
	if got := jsonScopes(nil); string(got) != "[]" {
		t.Errorf("nil scopes: want [] got %s", got)
	}
	if got := jsonAllowlist(nil); string(got) != "[]" {
		t.Errorf("nil allowlist: want [] got %s", got)
	}
}

func TestJsonScopesNonNil(t *testing.T) {
	if got := jsonScopes([]string{"read", "write"}); string(got) != `["read","write"]` {
		t.Errorf("scopes: got %s", got)
	}
	if got := jsonAllowlist([]string{"1.1.1.1"}); string(got) != `["1.1.1.1"]` {
		t.Errorf("allowlist: got %s", got)
	}
}

func TestParseStringsEmpty(t *testing.T) {
	if parseStrings(nil) != nil {
		t.Error("expected nil for empty")
	}
	if parseStrings([]byte("not-json")) != nil {
		t.Error("expected nil for invalid json")
	}
}

func TestParseStringsValid(t *testing.T) {
	got := parseStrings([]byte(`["a","b"]`))
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("got %v", got)
	}
}

func TestJoinStrings(t *testing.T) {
	if got := joinStrings([]string{"a", "b", "c"}, ", "); got != "a, b, c" {
		t.Errorf("got %q", got)
	}
	if got := joinStrings(nil, ", "); got != "" {
		t.Errorf("nil got %q", got)
	}
}

// ===========================================================================
// dbDSN / newStoreFromEnv edge cases.
// ===========================================================================

func TestDBDSNFromEnv(t *testing.T) {
	t.Setenv("DB_URL", "postgres://localhost/test")
	if got := dbDSN(); got != "postgres://localhost/test" {
		t.Errorf("got %q", got)
	}
}

func TestNewStoreFromEnvNoDB(t *testing.T) {
	t.Setenv("DB_URL", "")
	st, err := newStoreFromEnv()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if st == nil {
		t.Error("expected in-memory store")
	}
}