// Package auth implements the SCRAM-like challenge/response used by fileshare
// v2. The password never crosses the wire, and theft of users.json (which holds
// only StoredKey) does not let an attacker authenticate
// (docs/tz/09-go-port.md §5.3, docs/tz/06-security.md §3).
package auth

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// DefaultIters is the default PBKDF2 iteration count for new users. The server
// announces the effective value in HELLO_OK so the client derives with the same
// parameter. Set to the security floor per docs/tz/06-security.md §2.
const DefaultIters = 600_000

const clientKeyLabel = "Client Key"

// saltFor returns the deterministic per-login salt.
func saltFor(login string) []byte {
	return []byte("fileshare-v2:" + login)
}

// saltedPassword = PBKDF2-HMAC-SHA256(password, salt, iters, dkLen=32).
func saltedPassword(password, login string, iters int) [32]byte {
	dk, err := pbkdf2.Key(sha256.New, password, saltFor(login), iters, 32)
	if err != nil {
		// pbkdf2.Key only errors on an out-of-range keyLength, which is fixed
		// at 32 here, so this is unreachable.
		panic("auth: pbkdf2: " + err.Error())
	}
	var out [32]byte
	copy(out[:], dk)
	return out
}

// ClientKey = HMAC-SHA256(SaltedPassword, "Client Key").
func ClientKey(password, login string, iters int) [32]byte {
	sp := saltedPassword(password, login, iters)
	m := hmac.New(sha256.New, sp[:])
	m.Write([]byte(clientKeyLabel))
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

// storedKeyFrom returns SHA256(ClientKey).
func storedKeyFrom(clientKey [32]byte) [32]byte {
	return sha256.Sum256(clientKey[:])
}

// StoredKey = SHA256(ClientKey) — the verifier persisted in users.json.
func StoredKey(password, login string, iters int) [32]byte {
	return storedKeyFrom(ClientKey(password, login, iters))
}

// authMessage = challenge || login.
func authMessage(challenge []byte, login string) []byte {
	msg := make([]byte, 0, len(challenge)+len(login))
	msg = append(msg, challenge...)
	msg = append(msg, login...)
	return msg
}

// hmacStored = HMAC-SHA256(StoredKey, AuthMessage).
func hmacStored(storedKey [32]byte, challenge []byte, login string) [32]byte {
	m := hmac.New(sha256.New, storedKey[:])
	m.Write(authMessage(challenge, login))
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

func xor32(a, b [32]byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// Proof computes ClientProof = ClientKey XOR HMAC-SHA256(StoredKey, challenge||login).
// This is what the client places in AUTH_REQUEST.
func Proof(password, login string, iters int, challenge []byte) [proto.ProofLen]byte {
	ck := ClientKey(password, login, iters)
	sk := storedKeyFrom(ck)
	return xor32(ck, hmacStored(sk, challenge, login))
}

// Verify reports whether proof authenticates against storedKey for the given
// challenge and login. The final comparison is constant-time.
func Verify(storedKey [proto.ChecksumLen]byte, challenge []byte, login string, proof [proto.ProofLen]byte) bool {
	recovered := xor32(proof, hmacStored(storedKey, challenge, login))
	check := storedKeyFrom(recovered)
	return subtle.ConstantTimeCompare(check[:], storedKey[:]) == 1
}
