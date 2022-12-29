package secretone

import (
	"github.com/wangchao475/secretone/internals/api"
	"github.com/wangchao475/secretone/internals/crypto"
	"github.com/wangchao475/secretone/pkg/secretone/credentials"
)

// DefaultAccountKeyLength defines the default bit size for account keys.
const DefaultAccountKeyLength = 4096

//func generateAccountKey() (crypto.RSAPrivateKey, error) {
//	return crypto.GenerateRSAPrivateKey(DefaultAccountKeyLength)
//}
func generateAccountKey() (crypto.SM2PrivateKey, error) {
	return crypto.GenerateSM2PrivateKey()
}

// AccountKeyService handles operations on secretone account keys.
type AccountKeyService interface {
	// Create creates an account key for the client's credential.
	Create(verifier credentials.Verifier, encrypter credentials.Encrypter) (*api.EncryptedAccountKey, error)
	// Exists returns whether an account key exists for the client's credential.
	Exists() (bool, error)
}

type accountKeyService struct {
	client *Client
}

// newAccountKeyService creates a new accountKeyService
func newAccountKeyService(client *Client) accountKeyService {
	return accountKeyService{
		client: client,
	}
}

// Create creates an account key for the clients credential.
func (s accountKeyService) Create(verifier credentials.Verifier, encrypter credentials.Encrypter) (*api.EncryptedAccountKey, error) {
	_, fingerprint, err := verifier.Export()
	if err != nil {
		return nil, err
	}

	key, err := generateAccountKey()
	if err != nil {
		return nil, err
	}
	return s.client.createAccountKey(fingerprint, key, encrypter)
}

// Exists returns whether an account key exists for the client's credential.
func (s accountKeyService) Exists() (bool, error) {
	_, err := s.client.getAccountKey()
	if api.IsErrNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
