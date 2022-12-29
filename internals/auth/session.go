package auth

import (
	"github.com/tjfoc/gmsm/sm3"
	"github.com/wangchao475/secretone/internals/api/uuid"
	"github.com/wangchao475/secretone/internals/crypto"
)

// NewSessionSigner returns a new SessionSigner.
func NewSessionSigner(sessionID uuid.UUID, secretKey string) *SessionSigner {
	return &SessionSigner{
		sessionID: sessionID,
		secretKey: secretKey,
	}
}

// SessionSigner is an implementation of the Signer interface that uses an HMAC session to authenticate a request.
type SessionSigner struct {
	sessionID uuid.UUID
	secretKey string
}

// ID returns the session id of this signer.
func (s SessionSigner) ID() (string, error) {
	return s.sessionID.String(), nil
}

// SignMethod returns the signature method of this signer.
func (s SessionSigner) SignMethod() string {
	return "Session-HMAC"
}

// Sign the payload with an HMAC signature.
func (s SessionSigner) Sign(msg []byte) ([]byte, error) {
	signKey := crypto.NewSymmetricKey(sm3.Sm3Sum([]byte(s.secretKey)))
	return signKey.HMAC(msg)
}
