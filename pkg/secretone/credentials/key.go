package credentials

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/wangchao475/secretone/internals/auth"
	"github.com/wangchao475/secretone/internals/crypto"
	"github.com/wangchao475/secretone/pkg/secretone/internals/http"
)

type ErrLoadingCredential struct {
	Location string
	Err      error
}

func (e ErrLoadingCredential) Error() string {
	return "load credential " + e.Location + ": " + e.Err.Error()
}

// Key is a credential that uses a local key for all its operations.
type Key struct {
	key              *SM2Credential
	exportPassphrase Reader
	tenantId         string //租户id，跟凭据一起保存
}

// Verifier returns a Verifier that can be used for creating a new credential from this Key.
func (k Key) Verifier() Verifier {
	return k.key
}

// Encrypter returns a Encrypter that can be used to encrypt data with this Key.
func (k Key) Encrypter() Encrypter {
	return k.key
}
func (k Key) SetTenantId(tenantId string) {
	k.tenantId = tenantId
}

// Provide implements the Provider interface for a Key.
func (k Key) Provide(httpClient *http.Client) (auth.Authenticator, Decrypter, string, error) {
	return k.key, k.key, k.tenantId, nil
}

// Passphrase returns a new Key that uses the provided passphraseReader to obtain a passphrase that is used for
// encryption when Export() is called.
func (k Key) Passphrase(passphraseReader Reader) Key {
	k.exportPassphrase = passphraseReader
	return k
}

// Export the key of this credential to string format to save for later use.
// If a passphrase was set with Passphrase(), this passphrase is used for encrypting the key.
func (k Key) Export() ([]byte, error) {
	if k.key == nil {
		return nil, errors.New("key has not yet been generated created. Use KeyCreator before calling Export()")
	}
	if k.exportPassphrase != nil {
		passphrase, err := k.exportPassphrase.Read()
		if err != nil {
			return nil, err
		}
		passBasedKey, err := NewPassBasedKey(passphrase)
		if err != nil {
			return nil, err
		}
		return EncodeEncryptedCredential(k.key, passBasedKey)
	}
	return EncodeCredential(k.key)
}

// ImportKey returns a Key by loading it from the provided credentialReader.
// If the key is encrypted with a passphrase, passphraseReader should be provided. This is used to read a passphrase
// from that is used for decryption. If the passphrase is incorrect, a new passphrase will be read up to 3 times.
func ImportKey(credentialReader, passphraseReader Reader) (Key, error) {
	bytes, err := credentialReader.Read()
	if err != nil {
		return Key{}, err
	}
	//bytes:= []byte("fa928768-49b6-4754-8ef8-03e2ed3b5308:eyJ0eXBlIjoic20yIn0.MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgDU6ST-bgUesC7cfbsVgYx8mrQ7ngfUGJC5x0AGRM8HmgCgYIKoEcz1UBgi2hRANCAAShRW5ZiWG9-_sq_lus4pQJf5AtiyHLB6Da_a3cF0nCInr4ZzPz9nzcaBC3uYdjmlTfeA4AGtlSbwrJ5Q_B2LLn")
	dataStr := string(bytes)
	var tenantId string
	index := strings.Index(dataStr, ":")
	var credentialBytes []byte
	if index > 0 {
		tenantId = dataStr[:index]
		credentialBytes = []byte(dataStr[index+1:])
	} else {
		credentialBytes = bytes
	}
	//encoded, err := defaultParser.parse(bytes)
	encoded, err := defaultParser.parse(credentialBytes)
	if err != nil {
		return Key{}, err
	}
	if encoded.IsEncrypted() {
		const credentialPassphraseEnvVar = "SECRETONE_CREDENTIAL_PASSPHRASE"
		envPassphrase := os.Getenv(credentialPassphraseEnvVar)
		if envPassphrase != "" {
			credential, err := decryptKey([]byte(envPassphrase), encoded)
			if err != nil {
				if crypto.IsWrongKey(err) {
					err = ErrCannotDecryptCredential
				}
				return Key{}, fmt.Errorf("decrypting credential with passphrase read from $%s: %v", credentialPassphraseEnvVar, err)
			}
			return Key{key: credential, tenantId: tenantId}, nil
		}
		if passphraseReader == nil {
			return Key{}, ErrNeedPassphrase
		}

		// Try up to three times to get the correct passphrase.
		for i := 0; i < 3; i++ {
			passphrase, err := passphraseReader.Read()
			if err != nil {
				return Key{}, err
			}
			if len(passphrase) == 0 {
				continue
			}

			credential, err := decryptKey(passphrase, encoded)
			if crypto.IsWrongKey(err) {
				continue
			} else if err != nil {
				return Key{}, err
			}

			return Key{key: credential, tenantId: tenantId}, nil
		}

		return Key{}, ErrCannotDecryptCredential
	}
	credential, err := encoded.Decode()
	if err != nil {
		return Key{}, err
	}
	return Key{key: credential, tenantId: tenantId}, nil
}

func decryptKey(passphrase []byte, encoded *encodedCredential) (*SM2Credential, error) {
	key, err := NewPassBasedKey(passphrase)
	if err != nil {
		return nil, err
	}
	return encoded.DecodeEncrypted(key)
}
//校验credential此刻是否需要输入pin码,true需要pin，false不需要
func CheckKey(credentialReader, passphraseReader Reader) (bool, error) {
	bytes, err := credentialReader.Read()
	if err != nil {
		return false, err
	}
	dataStr := string(bytes)
	index := strings.Index(dataStr, ":")
	var credentialBytes []byte
	if index > 0 {
		credentialBytes = []byte(dataStr[index+1:])
	} else {
		credentialBytes = bytes
	}
	//encoded, err := defaultParser.parse(bytes)
	encoded, err := defaultParser.parse(credentialBytes)
	if err != nil {
		return false, err
	}
	if encoded.IsEncrypted() {
		const credentialPassphraseEnvVar = "SECRETONE_CREDENTIAL_PASSPHRASE"
		envPassphrase := os.Getenv(credentialPassphraseEnvVar)
		if envPassphrase != "" {
			_, err := decryptKey([]byte(envPassphrase), encoded)
			if err != nil {
				if crypto.IsWrongKey(err) {
					err = ErrCannotDecryptCredential
				}
				return false, fmt.Errorf("decrypting credential with passphrase read from $%s: %v", credentialPassphraseEnvVar, err)
			}
			return false, nil  //随便被pin加密了，但此刻通过环境变量得到了pin码，能够解密
		}
		if passphraseReader == nil {
			return false, ErrNeedPassphrase
		}

		// Try up to three times to get the correct passphrase.
		for i := 0; i < 3; i++ {
			needPin, err := passphraseReader.Check()
			if err != nil {
				return false, err
			}
			return needPin, nil
		}
		return false, ErrCannotDecryptCredential
	}
	_, err = encoded.Decode()
	if err != nil {
		return false, err
	}
	return false, nil
}