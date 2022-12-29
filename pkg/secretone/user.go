package secretone

import (
	"github.com/wangchao475/secretone/internals/api"
	"github.com/wangchao475/secretone/internals/crypto"
	"github.com/wangchao475/secretone/internals/errio"
	"github.com/wangchao475/secretone/pkg/secretone/credentials"
)

// UserService handles operations on users from secretone.
type UserService interface {
	// Me gets the account's user if it exists.
	Me() (*api.User, error)
	// Get a user by their username.
	Get(username string) (*api.User, error)
}

func newUserService(client *Client) UserService {
	return userService{
		client: client,
	}
}

type userService struct {
	client *Client
}

// Me gets the account's user if it exists.
func (s userService) Me() (*api.User, error) {
	return s.client.httpClient.GetMyUser()
}

// Get retrieves the user with the given username from secretone.
func (s userService) Get(username string) (*api.User, error) {
	err := api.ValidateUsername(username)
	if err != nil {
		return nil, errio.Error(err)
	}

	user, err := s.client.httpClient.GetUser(username)
	if err != nil {
		return nil, errio.Error(err)
	}

	return user, nil
}

// createAccountKey adds the account key for the clients credential.
func (c *Client) createAccountKey(credentialFingerprint string, accountKey crypto.SM2PrivateKey, encrypter credentials.Encrypter) (*api.EncryptedAccountKey, error) {
	accountKeyRequest, err := c.createAccountKeyRequest(encrypter, accountKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = accountKeyRequest.Validate()
	if err != nil {
		return nil, err
	}

	result, err := c.httpClient.CreateAccountKey(accountKeyRequest, credentialFingerprint)
	if err != nil {
		return nil, errio.Error(err)
	}
	return result, nil
}
