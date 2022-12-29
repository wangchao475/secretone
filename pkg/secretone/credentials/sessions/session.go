// Package sessions provides session authentication to the secretone API for the HTTP client.
package sessions

import (
	"time"

	"github.com/wangchao475/secretone/internals/api/uuid"
	"github.com/wangchao475/secretone/internals/auth"
	"github.com/wangchao475/secretone/pkg/secretone/internals/http"
)

const expirationMargin = time.Second * 30

// SessionCreator can create a new secretone session with a http.Client.
type SessionCreator interface {
	Create(httpClient *http.Client) (Session, error)
}

// Session provides a auth.Authenticator than can be temporarily used to temporarily authenticate to the secretone API.
type Session interface {
	NeedsRefresh() bool
	Authenticator() auth.Authenticator
}

type hmacSession struct {
	sessionID  uuid.UUID
	sessionKey string

	expireTime
}

// Authenticator returns an auth.Authenticator that can be used to authenticate a request with an HMAC session.
func (h hmacSession) Authenticator() auth.Authenticator {
	return auth.NewHTTPSigner(auth.NewSessionSigner(h.sessionID, h.sessionKey))
}

type expireTime int64

// NeedsRefresh returns true when the session is about to expire and should be refreshed.
func (t expireTime) NeedsRefresh() bool {
	//由服务端来校验是否过期，客户端不进行校验了
	//return time.Now().After(time.Time(t).Add(-expirationMargin))
	//return time.Now().After(time.Time(t).Add(-expirationMargin))
	return false
}
