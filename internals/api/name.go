package api

import (
	"github.com/wangchao475/secretone/internals/api/uuid"
)

// EncryptedNameRequest contains an EncryptedName for an Account.
type EncryptedNameRequest struct {
	AccountID uuid.UUID `json:"account_id"`
	//EncryptedName crypto.CiphertextSM2 `json:"encrypted_name"`
	Name string `json:"name"` //此name有多个用途，有时填充secret名称，有时填充dirname
}

// Validate validates the EncryptedNameRequest to be valid.
func (enr *EncryptedNameRequest) Validate() error {
	if enr.AccountID.IsZero() {
		return ErrInvalidAccountID
	}
	//if enr.AccountID == "" {
	//	return ErrInvalidAccountID
	//}
	return nil
}

// EncryptedNameForNodeRequest contains an EncryptedName for an Account and the corresponding NodeID.
type EncryptedNameForNodeRequest struct {
	EncryptedNameRequest
	NodeID uuid.UUID `json:"node_id"`
}

// Validate validates the EncryptedNameForNodeRequest.
func (nnr EncryptedNameForNodeRequest) Validate() error {
	if nnr.NodeID.IsZero() {
		return ErrInvalidNodeID
	}

	err := nnr.EncryptedNameRequest.Validate()
	if err != nil {
		return err
	}

	return nil
}
