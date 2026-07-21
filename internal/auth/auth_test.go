package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// testIters keeps derivation fast; the protocol carries the real value in HELLO_OK.
const testIters = 4096

// TestHMACSHA256KAT verifies HMAC-SHA256 against RFC 4231 test case 1.
func TestHMACSHA256KAT(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 20)
	m := hmac.New(sha256.New, key)
	m.Write([]byte("Hi There"))
	got := hex.EncodeToString(m.Sum(nil))
	want := "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
	if got != want {
		t.Fatalf("HMAC-SHA256 KAT = %s, want %s", got, want)
	}
}

// TestPBKDF2SHA256KAT verifies PBKDF2-HMAC-SHA256 against a published vector
// (P="password", S="salt", c=1, dkLen=32).
func TestPBKDF2SHA256KAT(t *testing.T) {
	dk, err := pbkdf2.Key(sha256.New, "password", []byte("salt"), 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(dk)
	want := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	if got != want {
		t.Fatalf("PBKDF2-HMAC-SHA256 KAT = %s, want %s", got, want)
	}
}

func TestProofVerifyRoundTrip(t *testing.T) {
	const login, pw = "vit", "correct horse battery staple"
	stored := StoredKey(pw, login, testIters)
	challenge := []byte("0123456789abcdef") // 16 bytes

	proof := Proof(pw, login, testIters, challenge)
	if !Verify(stored, challenge, login, proof) {
		t.Fatal("valid proof rejected")
	}
}

func TestVerifyRejectsWrongPassword(t *testing.T) {
	const login = "vit"
	stored := StoredKey("right", login, testIters)
	challenge := []byte("0123456789abcdef")
	proof := Proof("wrong", login, testIters, challenge)
	if Verify(stored, challenge, login, proof) {
		t.Fatal("proof from wrong password accepted")
	}
}

func TestVerifyRejectsReplayOnNewChallenge(t *testing.T) {
	const login, pw = "vit", "hunter2"
	stored := StoredKey(pw, login, testIters)

	c1 := []byte("aaaaaaaaaaaaaaaa")
	proof := Proof(pw, login, testIters, c1) // captured proof for challenge c1

	// The server issues a fresh challenge; the replayed proof must not verify.
	c2 := []byte("bbbbbbbbbbbbbbbb")
	if Verify(stored, c2, login, proof) {
		t.Fatal("replayed proof accepted against a new challenge")
	}
}

func TestVerifyRejectsWrongLogin(t *testing.T) {
	stored := StoredKey("pw", "alice", testIters)
	challenge := []byte("0123456789abcdef")
	// Proof derived for a different login must not verify against alice's key.
	proof := Proof("pw", "bob", testIters, challenge)
	if Verify(stored, challenge, "alice", proof) {
		t.Fatal("proof for a different login accepted")
	}
}

func TestUserDBNoAuthBootstrap(t *testing.T) {
	db, err := Load(filepath.Join(t.TempDir(), "users.json")) // missing file
	if err != nil {
		t.Fatal(err)
	}
	if !db.Empty() {
		t.Fatal("missing users.json should yield an empty DB")
	}
}

func TestUserDBSetLookupSaveReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	db, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetUser("admin", proto.RoleAdmin, "s3cret", testIters)
	db.SetUser("guest", proto.RoleUser, "guestpw", testIters)
	if db.Empty() {
		t.Fatal("DB should not be empty after SetUser")
	}
	if err := db.Save(); err != nil {
		t.Fatal(err)
	}

	db2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	sk, role, enabled, ok := db2.Lookup("admin")
	if !ok || !enabled || role != proto.RoleAdmin {
		t.Fatalf("admin lookup: ok=%v enabled=%v role=%v", ok, enabled, role)
	}
	// The reloaded StoredKey must authenticate the same password.
	challenge := []byte("0123456789abcdef")
	if !Verify(sk, challenge, "admin", Proof("s3cret", "admin", testIters, challenge)) {
		t.Fatal("reloaded StoredKey failed to verify correct password")
	}

	if _, _, _, ok := db2.Lookup("nobody"); ok {
		t.Fatal("unexpected lookup hit for absent user")
	}
}

func TestUserDBSetPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	db, _ := Load(path)
	if err := db.SetPassword("ghost", "x", testIters); err != ErrNoSuchUser {
		t.Fatalf("SetPassword on absent user: err=%v, want ErrNoSuchUser", err)
	}
	db.SetUser("vit", proto.RoleUser, "old", testIters)
	if err := db.SetPassword("vit", "new", testIters); err != nil {
		t.Fatal(err)
	}
	sk, _, _, _ := db.Lookup("vit")
	challenge := []byte("0123456789abcdef")
	if Verify(sk, challenge, "vit", Proof("old", "vit", testIters, challenge)) {
		t.Fatal("old password still verifies after reset")
	}
	if !Verify(sk, challenge, "vit", Proof("new", "vit", testIters, challenge)) {
		t.Fatal("new password does not verify after reset")
	}
}

func TestGuardBanAfterMaxFails(t *testing.T) {
	g := NewGuard(3)
	ip := "10.0.0.5"
	now := time.Unix(1_000_000, 0)
	ban := 60 * time.Second

	if g.Banned(ip, now) {
		t.Fatal("fresh ip should not be banned")
	}
	if g.Fail(ip, now, ban) {
		t.Fatal("first failure should not ban")
	}
	if g.Fail(ip, now, ban) {
		t.Fatal("second failure should not ban")
	}
	if !g.Fail(ip, now, ban) {
		t.Fatal("third failure should ban")
	}
	if !g.Banned(ip, now) {
		t.Fatal("ip should be banned right after the third failure")
	}
	// Ban expires.
	if g.Banned(ip, now.Add(61*time.Second)) {
		t.Fatal("ban should expire after banDur")
	}
}

func TestGuardSuccessClears(t *testing.T) {
	g := NewGuard(3)
	ip := "10.0.0.6"
	now := time.Unix(1_000_000, 0)
	g.Fail(ip, now, time.Minute)
	g.Fail(ip, now, time.Minute)
	g.Success(ip)
	// After success, two fresh failures must not ban (counter was reset).
	if g.Fail(ip, now, time.Minute) || g.Fail(ip, now, time.Minute) {
		t.Fatal("counter not cleared after Success")
	}
}
