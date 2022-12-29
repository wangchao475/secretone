package secretone

import (
	"github.com/wangchao475/secretone/internals/api"
	"github.com/wangchao475/secretone/internals/errio"
	"github.com/wangchao475/secretone/pkg/secretone/internals/http"
)

// SecretService handles operations on secrets from secretone.
type SecretService interface {
	// Write encrypts and writes any secret data to secretone, always creating
	// a new secret version for the written data. This ensures secret data is
	// never overwritten.
	//
	// To ensure forward secrecy, a new secret key is used whenever the previously
	// used key has been flagged.
	//
	// Write accepts any non-empty byte data that is within the size limit of MaxSecretSize.
	// Note that data is encrypted as is. Sanitizing data is the responsibility of the
	// function caller.
	Write(path string, data []byte) (*api.SecretVersion, error)
	//将原有秘钥再次写入（写入对象为没有secretkey的用户，因为他们无法解密秘钥）
	ReWrite(path string, data []byte) error
	// Read is an alias of `Versions().GetWithData` and gets a secret version, with sensitive data decrypted.
	Read(path string) (*api.SecretVersion, error)
	// ReadString is a convenience function to get the secret data as a string.
	//
	// See .Versions() for more elaborate use.
	ReadString(path string) (string, error)
	// Exists returns whether a secret exists on the given path.
	Exists(path string) (bool, error)
	// Get retrieves a Secret.
	Get(path string) (*api.Secret, error)
	// Delete removes the secret at the given path.
	Delete(path string) error
	// EventIterator returns an iterator that retrieves all audit events for a given secret.
	//
	// Usage:
	//  iter := client.Repos().EventIterator(path, &secretone.AuditEventIteratorParams{})
	//  for {
	//  	event, err := iter.Next()
	//  	if err == iterator.Done {
	//  		break
	//  	} else if err != nil {
	//  		// Handle error
	//  	}
	//
	//  	// Use event
	//  }
	EventIterator(path string, _ *AuditEventIteratorParams) AuditEventIterator
	// ListEvents retrieves all audit events for a given secret.
	ListEvents(path string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error)
	// Versions returns a SecretVersionService.
	Versions() SecretVersionService
}

func newSecretService(client *Client) SecretService {
	return secretService{
		client: client,
	}
}

type secretService struct {
	client *Client
}

// Delete removes the secret at the given path.
func (s secretService) Delete(path string) error {
	secretPath, err := api.NewSecretPath(path)
	if err != nil {
		return errio.Error(err)
	}

	//secretBlindName, err := s.client.convertPathToBlindName(secretPath)
	//if err != nil {
	//	return errio.Error(err)
	//}

	err = s.client.httpClient.DeleteSecret(secretPath.String())
	if err != nil {
		return errio.Error(err)
	}

	return nil
}

// Exists returns whether a secret exists on the given path.
func (s secretService) Exists(path string) (bool, error) {
	secretPath, err := api.NewSecretPath(path)
	if err != nil {
		return false, errio.Error(err)
	}

	//blindName, err := s.client.convertPathToBlindName(secretPath)
	//if err != nil {
	//	return false, errio.Error(err)
	//}

	_, err = s.client.httpClient.GetSecret(secretPath.String())
	if api.IsErrNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// Get retrieves a Secret.
func (s secretService) Get(path string) (*api.Secret, error) {
	secretPath, err := api.NewSecretPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	//blindName, err := s.client.convertPathToBlindName(secretPath)
	//if api.IsErrNotFound(err) {
	//	return nil, &errSecretNotFound{path: secretPath, err: err}
	//} else if err != nil {
	//	return nil, errio.Error(err)
	//}

	encSecret, err := s.client.httpClient.GetSecret(secretPath.String())
	if api.IsErrNotFound(err) {
		return nil, &errSecretNotFound{path: secretPath, err: err}
	} else if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := s.client.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	return encSecret.Decrypt(accountKey)
}

// Read gets a secret version, with sensitive data decrypted.
func (s secretService) Read(path string) (*api.SecretVersion, error) {
	return s.Versions().GetWithData(path)
}

// ReadString gets the secret data as a string.
func (s secretService) ReadString(path string) (string, error) {
	secret, err := s.Read(path)
	if err != nil {
		return "", err
	}
	return string(secret.Data), nil
}

// Write encrypts and writes any secret data to secretone, always creating
// a new secret version for the written data. This ensures secret data is
// never overwritten.
//
// To ensure forward secrecy, a new secret key is used whenever the previously
// used key has been flagged.
//
// Write accepts any non-empty byte data that is within the size limit of MaxSecretSize.
// Note that data is encrypted as is. Sanitizing data is the responsibility of the
// function caller.
func (s secretService) Write(path string, data []byte) (*api.SecretVersion, error) {
	secretPath, err := api.NewSecretPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	if secretPath.HasVersion() {
		return nil, ErrCannotWriteToVersion
	}

	if len(data) == 0 {
		return nil, ErrEmptySecret
	}

	if len(data) > MaxSecretSize {
		return nil, ErrSecretTooBig
	}
	//s.client.createSecretKey(secretPath)
	//return  nil,nil

	key, err := s.client.getSecretKey(secretPath)
	if api.IsErrNotFound(err) {
		return s.client.createSecret(secretPath, data)
	} else if api.IsErrNotStatusOK(err) { //todo 什么时候会出现secretkey全部失效的情况？？？
		key, err = s.client.createSecretKey(secretPath)
		if err != nil {
			return nil, errio.Error(err)
		}
	} else if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.createSecretVersion(secretPath, data, key)
}
func (s secretService) ReWrite(path string, data []byte) error {
	secretPath, err := api.NewSecretPath(path)
	if err != nil {
		return errio.Error(err)
	}
	if !secretPath.HasVersion() {
		return ErrCannotWriteToVersion
	}
	if len(data) == 0 {
		return ErrEmptySecret
	}

	if len(data) > MaxSecretSize {
		return ErrSecretTooBig
	}
	key, err := s.client.getSecretKey(secretPath)
	if api.IsErrNotFound(err) {
		return ErrCannotReWriteToVersion
	} else {
		//将没有secretkey的用户添加进来，使得这些用户可以解密秘钥
		key, err = s.client.appendSecretKey(secretPath, key.Key)
		if err != nil {
			return errio.Error(err)
		}
	}
	return nil
	//return s.client.createSecretVersion(secretPath, data, key)
}

// ListEvents retrieves all audit events for a given secret.
// If subjectTypes is left empty, the server's default is used.
func (s secretService) ListEvents(path string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	secretPath, err := api.NewSecretPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	blindName, err := s.client.convertPathToBlindName(secretPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	events, err := s.client.httpClient.AuditSecret(blindName, subjectTypes)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = s.client.decryptAuditEvents(events...)
	if err != nil {
		return nil, errio.Error(err)
	}

	return events, nil
}

// EventIterator returns an iterator that retrieves all audit events for a given secret.
//
// Usage:
//  iter := client.Repos().EventIterator(path, &secretone.AuditEventIteratorParams{})
//  for {
//  	event, err := iter.Next()
//  	if err == iterator.Done {
//  		break
//  	} else if err != nil {
//  		// Handle error
//  	}
//
//  	// Use event
//  }
func (s secretService) EventIterator(path string, _ *AuditEventIteratorParams) AuditEventIterator {
	return newAuditEventIterator(
		func() (*http.AuditPaginator, error) {
			secretPath, err := api.NewSecretPath(path)
			if err != nil {
				return nil, err
			}

			//blindName, err := s.client.convertPathToBlindName(secretPath)
			//if err != nil {
			//	return nil, err
			//}

			return s.client.httpClient.AuditSecretPaginator(secretPath.String()), nil
		},
		s.client,
	)
}

// Versions returns a SecretVersionService.
func (s secretService) Versions() SecretVersionService {
	return newSecretVersionService(s.client)
}

// convertsToBlindName will convert a path to a blindname.
func (c *Client) convertPathToBlindName(path api.BlindNamePath) (string, error) {
	repoIndexKey, err := c.getRepoIndexKey(path.GetRepoPath())
	if err != nil {
		return "", errio.Error(err)
	}

	blindName, err := path.BlindName(repoIndexKey)
	if err != nil {
		return "", errio.Error(err)
	}
	return blindName, nil
}
