// Package credentials provides utilities for managing secretone API credentials.
package credentials

import "github.com/wangchao475/secretone/internals/api"

// Verifier exports verification bytes that can be used to verify signed data is processed by the owner of a signer.
type Verifier interface {
	// Export returns the data to be stored server side to verify an http request authenticated with this credential.
	Export() (verifierBytes []byte, fingerprint string, err error)
	// Type returns what type of credential this is.
	Type() api.CredentialType
	// AddProof adds the proof of this credential's possession to a CreateCredentialRequest.
	AddProof(req *api.CreateCredentialRequest) error
}

// Decrypter decrypts data, typically an account key.
type Decrypter interface {
	// Unwrap decrypts data, typically an account key.
	Unwrap(ciphertext *api.EncryptedData) ([]byte, error)
}

// Encrypter encrypts data, typically an account key.
type Encrypter interface {
	// Wrap encrypts data, typically an account key.
	Wrap(plaintext []byte) (*api.EncryptedData, error)
}

// CreatorProvider is both a credential creator and provider.
type CreatorProvider interface {
	Creator
	Provider
}
