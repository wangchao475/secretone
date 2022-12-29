package credentials

import (
	"net/http"
	"github.com/wangchao475/secretone/internals/api"
	"github.com/wangchao475/secretone/internals/auth"
	"github.com/wangchao475/secretone/internals/crypto"
	"github.com/wangchao475/secretone/internals/errio"
	httpclient "github.com/wangchao475/secretone/pkg/secretone/internals/http"
)

// RSACredential implements a Credential for an RSA key.
type SM2Credential struct {
	crypto.SM2PrivateKey
}

//创建sm2公私钥
func GenerateSM2Credential() (*SM2Credential, error) {
	pri, err := crypto.GenerateSM2PrivateKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	return &SM2Credential{
		pri,
	}, nil
}

// Fingerprint returns the key identifier by which the server can identify the credential.
//返回参数说明：公钥hex，指纹，error
func (c SM2Credential) Export() ([]byte, string, error) {
	verifier, err := c.SM2PrivateKey.Public().Encode()
	if err != nil {
		return nil, "", err
	}
	//averifier := []byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE5bhGS5s3jNpsU4rJGUt2kgPhdc/d\nW4FotxXOGkR7aoI8cXGI4aFtcIqTHI6SEdExCdEn4OtTphWmf9qA14m/NA==\n-----END PUBLIC KEY-----\n")
	//verifier = averifier
	fingerprint := api.GetFingerprint(c.Type(), verifier)
	return verifier, fingerprint, nil
}

// ID returns a string by which the credential can be identified.
func (c SM2Credential) ID() (string, error) {
	_, fingerprint, err := c.Export()
	return fingerprint, err
}

// Sign provides proof the given bytes are processed by the owner of the credential.
//使用sm2签名
func (c SM2Credential) Sign(data []byte) ([]byte, error) {
	//pri,_:=c.SM2PrivateKey.ExportPEM()
	//pub,_:=c.SM2PrivateKey.Public().Encode()
	//fmt.Printf("公钥：%s\n",pub)
	//fmt.Printf("私钥：%s\n",pri)
	//fmt.Printf("公钥hex：%s\n",hex.EncodeToString(c.SM2PrivateKey.Public().GetRawBytes()))
	//fmt.Printf("私钥hex：%s\n",hex.EncodeToString(c.SM2PrivateKey.GetRawBytes()))
	signed, err := c.SM2PrivateKey.Sign(data)
	//fmt.Println("signed:",signed)
	return signed, err
}

// SignMethod returns a string by which the signing method can be identified.
func (c SM2Credential) SignMethod() string {
	return "sm2"
}

// Decoder returns the Decoder for the rsa private key.
func (c SM2Credential) Decoder() Decoder {
	return sm2PrivateKeyDecoder{}
}

// Wrap encrypts data, typically an account key.加密
func (c SM2Credential) Wrap(plaintext []byte) (*api.EncryptedData, error) {
	CiphertextData, err := c.SM2PrivateKey.Public().Encrypt(plaintext)
	if err != nil {
		return nil, errio.Error(err)
	}
	return &api.EncryptedData{
		Algorithm:  api.EncryptionAlgorithmGM,
		Key:        CiphertextData.EncKey,       //这里是随机key的密文结构体
		Ciphertext: CiphertextData.EncData.Data, //这里是数据的密文
	}, nil
}

// Unwrap decrypts data, typically an account key.
func (c SM2Credential) Unwrap(ciphertext *api.EncryptedData) ([]byte, error) {
	if ciphertext.Algorithm != api.EncryptionAlgorithmGM {
		return nil, api.ErrInvalidCiphertext
	}
	//key的类型为string
	key, ok := ciphertext.Key.(string)
	if !ok {
		return nil, api.ErrInvalidKeyType
	}
	return c.SM2PrivateKey.Decrypt(crypto.CiphertextGM{
		EncKey: crypto.CiphertextSM2{
			Data: []byte(key),
		},
		EncData: crypto.CiphertextSM4{
			Data: ciphertext.Ciphertext,
		},
	})
}

// Type returns what type of credential this is.
func (c SM2Credential) Type() api.CredentialType {
	return api.CredentialTypeKey
}

// AddProof add the proof for possession of this credential to a CreateCredentialRequest .
func (c SM2Credential) AddProof(_ *api.CreateCredentialRequest) error {
	// Currently not implemented for RSA credentials
	return nil
}

// Authenticate implements the auth.Authenticator interface.
func (c SM2Credential) Authenticate(r *http.Request) error {
	return auth.NewHTTPSigner(c).Authenticate(r)
}

// Provide implements the credentials.Provider interface.
func (c SM2Credential) Provide(_ *httpclient.Client) (auth.Authenticator, Decrypter, string, error) {
	return c, c, "", nil
}
