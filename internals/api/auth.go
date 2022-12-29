package api

import (
	"encoding/json"
	"net/http"
	"github.com/wangchao475/secretone/internals/api/uuid"
)

// AuthMethod options
const (
	AuthMethodAWSSTS            = "aws-sts"
	AuthMethodGCPServiceAccount = "gcp-service-account"
)

// SessionType options
const (
	SessionTypeHMAC SessionType = "hmac"
)

// Errors
var (
	ErrInvalidSessionType = errAPI.Code("invalid_session_type").StatusError("invalid session type provided for authentication request", http.StatusBadRequest)
	ErrInvalidPayload     = errAPI.Code("invalid_payload").StatusError("invalid payload provided for authentication request", http.StatusBadRequest)
	ErrInvalidAuthMethod  = errAPI.Code("invalid_auth_method").StatusError("invalid auth method", http.StatusBadRequest)
	ErrMissingField       = errAPI.Code("missing_field").StatusErrorPref("request is missing field %s", http.StatusBadRequest)
	ErrSessionNotFound    = errAPI.Code("session_not_found").StatusError("session could not be found, it might have expired", http.StatusForbidden)
	ErrSessionExpired     = errAPI.Code("session_expired").StatusError("session has expired", http.StatusForbidden)
	ErrAuthFailed         = errAPI.Code("auth_failed").StatusError("authentication failed", http.StatusForbidden)
)

// SessionType defines how a session can be used.
type SessionType string

// AuthRequest is a request to authenticate and request a session.
type AuthRequest struct {
	Method      string      `json:"method"`
	SessionType SessionType `json:"session_type"`
	Payload     interface{} `json:"payload"`
}

// UnmarshalJSON converts a JSON representation into a AuthRequest with the correct Payload.
func (r *AuthRequest) UnmarshalJSON(b []byte) error {
	// Declare a private type to avoid recursion into this function.
	type authRequest AuthRequest

	var rawMessage json.RawMessage
	dec := authRequest{
		Payload: &rawMessage,
	}

	err := json.Unmarshal(b, &dec)
	if err != nil {
		return err
	}

	if dec.Method == "" {
		return ErrMissingField("method")
	}

	switch dec.Method {
	case AuthMethodAWSSTS:
		dec.Payload = &AuthPayloadAWSSTS{}
	case AuthMethodGCPServiceAccount:
		dec.Payload = &AuthPayloadGCPServiceAccount{}
	default:
		return ErrInvalidAuthMethod
	}

	if rawMessage != nil {
		err = json.Unmarshal(rawMessage, dec.Payload)
		if err != nil {
			return err
		}
	}
	*r = AuthRequest(dec)
	return nil
}

// Validate whether an AuthRequest is a valid request.
func (r *AuthRequest) Validate() error {
	if r.SessionType == "" {
		return ErrMissingField("session_type")
	}
	if r.SessionType != SessionTypeHMAC {
		return ErrInvalidSessionType
	}
	if r.Method == "" {
		return ErrMissingField("method")
	}
	switch r.Method {
	case AuthMethodAWSSTS:
		authPayload, ok := r.Payload.(*AuthPayloadAWSSTS)
		if !ok {
			return ErrInvalidPayload
		}
		if err := authPayload.Validate(); err != nil {
			return err
		}
	case AuthMethodGCPServiceAccount:
		authPayload, ok := r.Payload.(*AuthPayloadGCPServiceAccount)
		if !ok {
			return ErrInvalidPayload
		}
		if err := authPayload.Validate(); err != nil {
			return err
		}
	default:
		return ErrInvalidAuthMethod
	}
	return nil
}

// NewSessionHMAC returns a HMAC type api.Session.
//func NewSessionHMAC(sessionID uuid.UUID, expiration time.Time, secretKey string) *Session {
//	return &Session{
//		SessionID: sessionID,
//		ExpiresAt: expiration,
//		Type:      SessionTypeHMAC,
//		Payload: &SessionPayloadHMAC{
//			SessionKey: secretKey,
//		},
//	}
//}

// Session represents a session that can be used for authentication to the server.
type Session struct {
	SessionID uuid.UUID   `json:"session_id"`
	ExpiresAt int64       `json:"expires_at"`
	Type      SessionType `json:"type"`
	Payload   interface{} `json:"payload"`
}

// SessionPayloadHMAC is the payload of a HMAC typed session.
type SessionPayloadHMAC struct {
	SessionKey string `json:"session_key"`
}

// Validate whether the SessionPayloadHMAC is valid.
func (pl *SessionPayloadHMAC) Validate() error {
	if pl.SessionKey == "" {
		return ErrMissingField("session_key")
	}
	return nil
}

// SessionHMAC is a session that uses the HMAC algorithm to verify the authentication.
type SessionHMAC struct {
	SessionID uuid.UUID
	Expires   int64
	//Expires   time.Time
	Payload SessionPayloadHMAC
}

// UnmarshalJSON converts a JSON representation into a Session with the correct Payload.
func (s *Session) UnmarshalJSON(b []byte) error {
	// Declare a private type to avoid recursion into this function.
	type session Session

	var rawMessage json.RawMessage
	dec := session{
		Payload: &rawMessage,
	}

	err := json.Unmarshal(b, &dec)
	if err != nil {
		return err
	}

	if dec.Type == "" {
		return ErrMissingField("type")
	}

	switch dec.Type {
	case SessionTypeHMAC:
		dec.Payload = &SessionPayloadHMAC{}
	default:
		return ErrInvalidSessionType
	}

	if rawMessage != nil {
		err = json.Unmarshal(rawMessage, dec.Payload)
		if err != nil {
			return err
		}
	}
	*s = Session(dec)
	return nil
}

type validator interface {
	Validate() error
}

// Validate whether the Session is valid.
func (s *Session) Validate() error {
	//if s.ExpiresAt.IsZero() {
	//	return ErrMissingField("expires_at")
	//}
	if s.ExpiresAt == 0 {
		return ErrMissingField("expires_at")
	}
	if s.Type == "" {
		return ErrMissingField("type")
	}
	if s.Type != SessionTypeHMAC {
		return ErrInvalidSessionType
	}
	if s.Payload == nil {
		return ErrMissingField("payload")
	}
	payload := s.Payload.(validator)
	if err := payload.Validate(); err != nil {
		return err
	}
	return nil
}

// HMAC returns the HMAC specific representation of this session.
func (s *Session) HMAC() *SessionHMAC {
	payload := s.Payload.(*SessionPayloadHMAC)
	return &SessionHMAC{
		SessionID: s.SessionID,
		Expires:   s.ExpiresAt,
		Payload:   *payload,
	}
}
