package api

import (
	"net/http"
)

// Errors
var (
	ErrAccountNotKeyed    = errAPI.Code("account_not_keyed").StatusError("User has not yet keyed their account", http.StatusBadRequest)
	ErrAccountKeyNotFound = errAPI.Code("account_key_not_found").StatusError("User has not yet keyed their account", http.StatusNotFound)
	ErrIllegalKeyVersion  = errHub.Code("illegal_key_version").StatusError("key_version should be either v1 or v2", http.StatusBadRequest)
)

// EncryptedAccountKey represents an account key encrypted with a credential.
type EncryptedAccountKey struct {
	Account             *Account       `json:"account"`
	PublicKey           []byte         `json:"public_key"`
	EncryptedPrivateKey *EncryptedData `json:"encrypted_private_key"`
	Credential          *Credential    `json:"credential"`
}
type GMEncryptedAccountKey struct {
	Account             *Account         `json:"account"`
	PublicKey           []byte           `json:"public_key"`
	EncryptedPrivateKey *GMEncryptedData `json:"encrypted_private_key"`
	Credential          *Credential      `json:"credential"`
}

// CreateAccountKeyRequest contains the fields to add an account_key encrypted for a credential.
type CreateAccountKeyRequest struct {
	EncryptedPrivateKey *EncryptedData `json:"encrypted_private_key"`
	PublicKey           []byte         `json:"public_key"`
}

// Validate checks whether the request is valid.
func (req CreateAccountKeyRequest) Validate() error {
	if len(req.PublicKey) == 0 {
		return ErrInvalidPublicKey
	}
	if req.EncryptedPrivateKey == nil {
		return ErrMissingField("encrypted_private_key")
	}
	if err := req.EncryptedPrivateKey.Validate(); err != nil {
		return err
	}
	return nil
}
