package secretone

import (
	"fmt"

	"github.com/wangchao475/secretone/internals/api"
	"github.com/wangchao475/secretone/internals/api/uuid"
	"github.com/wangchao475/secretone/internals/crypto"
	"github.com/wangchao475/secretone/internals/errio"
)

// getSecretKey gets the current key for a given secret.
func (c *Client) getSecretKey(secretPath api.SecretPath) (*api.SecretKey, error) {
	//blindName, err := c.convertPathToBlindName(secretPath)
	blindName := secretPath
	//if err != nil {
	//	return nil, errio.Error(err)
	//}

	encKey, err := c.httpClient.GetCurrentSecretKey(blindName.String())
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := c.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	return encKey.Decrypt(accountKey)
}

// createSecretKey creates a new secret key for a given secret.
func (c *Client) createSecretKey(secretPath api.SecretPath) (*api.SecretKey, error) {
	secretKey, err := crypto.GenerateSymmetricKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	parentPath, err := secretPath.GetParentPath()
	if err != nil {
		return nil, errio.Error(err)
	}

	blindName := secretPath
	encryptedKeysMap := make(map[uuid.UUID]api.EncryptedKeyRequest)

	tries := 0
	for {
		// Get all accounts that have permission to read the secret.
		accounts, err := c.listDirAccounts(parentPath.String())
		if err != nil {
			return nil, errio.Error(err)
		}

		for _, account := range accounts {
			_, ok := encryptedKeysMap[account.AccountID]
			if !ok {
				//publicKey, err := crypto.ImportSM2PublicKey(account.PublicKey)
				//if err != nil {
				//	return nil, errio.Error(err)
				//}
				//
				//encryptedSecretKey, err := publicKey.Wrap(secretKey.Export())
				//if err != nil {
				//	return nil, errio.Error(err)
				//}
				//
				//encryptedKeysMap[account.AccountID] = api.EncryptedKeyRequest{
				//	AccountID:    account.AccountID,
				//	EncryptedKey: encryptedSecretKey,
				//}
				_, ok = encryptedKeysMap[account.AccountID]
				if !ok {
					encryptedKey, err := encryptKeyForAccount(secretKey, account)
					if err != nil {
						return nil, err
					}
					encryptedKeysMap[account.AccountID] = encryptedKey
				}
			}
		}

		encryptedFor := make([]api.EncryptedKeyRequest, len(encryptedKeysMap))
		i := 0
		for _, encryptedKey := range encryptedKeysMap {
			encryptedFor[i] = encryptedKey
			i++
		}

		in := &api.CreateSecretKeyRequest{
			EncryptedFor: encryptedFor,
		}

		resp, err := c.httpClient.CreateSecretKey(blindName.String(), in)
		if err == nil {
			accountKey, err := c.getAccountKey()
			if err != nil {
				return nil, err
			}

			return resp.Decrypt(accountKey)
		}
		if !errio.EqualsAPIError(api.ErrNotEncryptedForAccounts, err) {
			return nil, err
		}
		if tries >= missingMemberRetries {
			return nil, fmt.Errorf("cannot create secret key: access rules giving access to the secret (key) are simultaneously being created; you may try again")
		}
		tries++
	}
}

// createSecretKey creates a new secret key for a given secret.
func (c *Client) appendSecretKey(secretPath api.SecretPath, secretKey *crypto.SymmetricKey) (*api.SecretKey, error) {
	secretKey, err := crypto.GenerateSymmetricKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	parentPath, err := secretPath.GetParentPath()
	if err != nil {
		return nil, errio.Error(err)
	}

	//blindName, err := c.convertPathToBlindName(secretPath)
	//if err != nil {
	//	return nil, errio.Error(err)
	//}
	blindName := secretPath
	encryptedKeysMap := make(map[uuid.UUID]api.EncryptedKeyRequest)

	tries := 0
	for {
		// Get all accounts that have permission to read the secret.
		accounts, err := c.listDirAccounts(parentPath.String())
		if err != nil {
			return nil, errio.Error(err)
		}

		for _, account := range accounts {
			_, ok := encryptedKeysMap[account.AccountID]
			if !ok {
				publicKey, err := crypto.ImportSM2PublicKey(account.PublicKey)
				if err != nil {
					return nil, errio.Error(err)
				}

				encryptedSecretKey, err := publicKey.Wrap(secretKey.Export())
				if err != nil {
					return nil, errio.Error(err)
				}

				encryptedKeysMap[account.AccountID] = api.EncryptedKeyRequest{
					AccountID:    account.AccountID,
					EncryptedKey: encryptedSecretKey,
				}
			}
		}

		encryptedFor := make([]api.EncryptedKeyRequest, len(encryptedKeysMap))
		i := 0
		for _, encryptedKey := range encryptedKeysMap {
			encryptedFor[i] = encryptedKey
			i++
		}

		in := &api.CreateSecretKeyRequest{
			EncryptedFor: encryptedFor,
		}

		resp, err := c.httpClient.CreateSecretKey(blindName.String(), in)
		if err == nil {
			accountKey, err := c.getAccountKey()
			if err != nil {
				return nil, err
			}

			return resp.Decrypt(accountKey)
		}
		if !errio.EqualsAPIError(api.ErrNotEncryptedForAccounts, err) {
			return nil, err
		}
		if tries >= missingMemberRetries {
			return nil, fmt.Errorf("cannot create secret key: access rules giving access to the secret (key) are simultaneously being created; you may try again")
		}
		tries++
	}
}
