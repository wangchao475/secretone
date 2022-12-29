package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/x509"
	"github.com/wangchao475/secretone/internals/errio"
)

type SM2PublicKey struct {
	publicKey *sm2.PublicKey
}

func (pub SM2PublicKey) GetUnCompressBytes() []byte {
	xBytes := pub.publicKey.X.Bytes()
	yBytes := pub.publicKey.Y.Bytes()
	xl := len(xBytes)
	yl := len(yBytes)

	raw := make([]byte, 1+KeyBytes*2)
	raw[0] = UnCompress
	if xl > KeyBytes {
		copy(raw[1:1+KeyBytes], xBytes[xl-KeyBytes:])
	} else if xl < KeyBytes {
		copy(raw[1+(KeyBytes-xl):1+KeyBytes], xBytes)
	} else {
		copy(raw[1:1+KeyBytes], xBytes)
	}

	if yl > KeyBytes {
		copy(raw[1+KeyBytes:], yBytes[yl-KeyBytes:])
	} else if yl < KeyBytes {
		copy(raw[1+KeyBytes+(KeyBytes-yl):], yBytes)
	} else {
		copy(raw[1+KeyBytes:], yBytes)
	}
	return raw
}
func (pub SM2PublicKey) Encrypt(data []byte) (CiphertextGM, error) {
	randKey, err := GenerateSymmetricKey()
	if err != nil {
		return CiphertextGM{}, errio.Error(err)
	}
	randKeyContent := randKey.Export() //导出key的内容
	encData, err := Sm4Encrypt(randKeyContent, data)
	if err != nil {
		return CiphertextGM{}, errio.Error(err)
	}
	encKey, err := pub.wrap(randKeyContent)
	if err != nil {
		return CiphertextGM{}, err
	}
	hexEncKey := hex.EncodeToString(encKey)

	return CiphertextGM{
		EncKey:  CiphertextSM2{[]byte(hexEncKey)},
		EncData: CiphertextSM4{[]byte(encData)},
	}, nil

}
func (pub SM2PublicKey) Wrap(data []byte) (CiphertextSM2, error) {
	encrypted, err := pub.wrap(data)
	if err != nil {
		return CiphertextSM2{}, err
	}

	return CiphertextSM2{
		Data: encrypted,
	}, nil
}
func (pub SM2PublicKey) wrap(data []byte) ([]byte, error) {
	//使用凭据公钥来保护中间随机key
	encrypted, err := sm2.Encrypt(pub.publicKey, data, rand.Reader, sm2.C1C3C2)
	if err != nil {
		return nil, ErrSM2Encrypt(err)
	}
	return encrypted, nil
}
func (pub SM2PublicKey) WrapBytes(data []byte) ([]byte, error) {
	return pub.wrap(data)
}
func (pub SM2PublicKey) Verify(message, signature []byte) error {
	result := pub.publicKey.Verify(message, signature)
	if result {
		return nil
	} else {
		return errors.New("verify failed")
	}
}

// Fingerprint returns the SHA256 hash of the public key, encoded as a hexadecimal string.
func (pub SM2PublicKey) Fingerprint() (string, error) {
	exported, err := pub.Encode()
	if err != nil {
		return "", errio.Error(err)
	}

	sum := sha256.Sum256(exported)
	return hex.EncodeToString(sum[:]), nil
}

// Encode uses PEM encoding to encode the public key as bytes so it
// can be easily stored and transferred between systems.
func (pub SM2PublicKey) Encode() ([]byte, error) {
	der, err := x509.MarshalSm2PublicKey(pub.publicKey) //Convert publick key to DER format
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	certPem := pem.EncodeToMemory(block)
	return certPem, nil
}
func (pub SM2PublicKey) GetRawBytes() []byte {
	raw := pub.GetUnCompressBytes()
	return raw[1:]
}

// ImportSM2PublicKey decodes a PEM encoded sm2 public key into a public key that can be
// used for encryption and signature verification.
func ImportSM2PublicKey(encodedPublicKey []byte) (SM2PublicKey, error) {
	if len(encodedPublicKey) == 0 {
		return SM2PublicKey{}, ErrEmptyPublicKey
	}
	publicKey, err := x509.ReadPublicKeyFromPem(encodedPublicKey)
	if err != nil {
		return SM2PublicKey{}, ErrNotPKCS1Format
	}

	return SM2PublicKey{
		publicKey: publicKey,
	}, nil
}

//私钥
type SM2PrivateKey struct {
	private *sm2.PrivateKey
}

const (
	BitSize    = 256
	KeyBytes   = (BitSize + 7) / 8
	UnCompress = 0x04
)

func (pri SM2PrivateKey) GetRawBytes() []byte {
	dBytes := pri.private.D.Bytes()
	dl := len(dBytes)
	if dl > KeyBytes {
		raw := make([]byte, KeyBytes)
		copy(raw, dBytes[dl-KeyBytes:])
		return raw
	} else if dl < KeyBytes {
		raw := make([]byte, KeyBytes)
		copy(raw[KeyBytes-dl:], dBytes)
		return raw
	} else {
		return dBytes
	}
}
func (prv SM2PrivateKey) Public() SM2PublicKey {
	return SM2PublicKey{
		publicKey: &prv.private.PublicKey,
	}
}
func (prv SM2PrivateKey) Sign(message []byte) ([]byte, error) {
	//hashedMessage := sha256.Sum256(message)
	//message = []byte("GET\n\nFri, 23 Dec 2022 16:57:57 +0800\nv1/secrets/tina/repo/mysql/pass?encrypted=true;")
	//fmt.Println("message:",message)
	//fmt.Println("message string:",string(message))
	hashedMessage := sm3.Sm3Sum(message)
	//fmt.Println("hash message:",hex.EncodeToString(hashedMessage))
	return prv.private.Sign(rand.Reader, hashedMessage[:], nil)
}
func (prv SM2PrivateKey) ExportPEM() ([]byte, error) {
	return x509.WritePrivateKeyToPem(prv.private, nil)
}

func (prv SM2PrivateKey) Decrypt(ciphertext CiphertextGM) ([]byte, error) {
	//先解密中间key
	encKey, err := DecodeCiphertextSM2FromString(string(ciphertext.EncKey.Data))
	encKeyData, err := hex.DecodeString(string(encKey.Data))
	if err != nil {
		return nil, err
	}
	keyData, err := prv.Unwrap(CiphertextSM2{
		Data: encKeyData,
	})
	if err != nil {
		return nil, err
	}
	//使用中间key解密原始数据
	encCiphertextData, err := DecodeCiphertextSM4FromString(string(ciphertext.EncData.Data))
	if err != nil {
		return nil, err
	}
	data, err := Sm4Decrypt(keyData, encCiphertextData.Data)
	return data, err
}
func (prv SM2PrivateKey) Unwrap(ciphertext CiphertextSM2) ([]byte, error) {
	if len(ciphertext.Data) == 0 {
		return []byte{}, nil
	}
	return prv.unwrap(ciphertext.Data)
}

func (prv SM2PrivateKey) unwrap(encryptedData []byte) ([]byte, error) {
	output, err := sm2.Decrypt(prv.private, encryptedData, sm2.C1C3C2)
	if err != nil {
		return nil, ErrSM2Encrypt(err)
	}
	return output, nil
}

func GenerateSM2PrivateKey() (SM2PrivateKey, error) {
	privateKey, err := sm2.GenerateKey(nil)
	if err != nil {
		return SM2PrivateKey{}, ErrGenerateSM2Key
	}
	return NewSM2PrivateKey(privateKey), nil
}

func NewSM2PrivateKey(privateKey *sm2.PrivateKey) SM2PrivateKey {
	return SM2PrivateKey{
		private: privateKey,
	}
}

// Export returns the private key in der encoded format.
func (prv SM2PrivateKey) Encode() []byte {
	data, err := x509.MarshalSm2UnecryptedPrivateKey(prv.private)
	if err != nil {
		return nil
	}
	return data
}

// ReWrapBytes uses the private key to re-encrypt a small number of encrypted bytes for
// the given public key. Note that this function will be deprecated. Directly use
// Unwrap and Wrap when possible.
func (prv SM2PrivateKey) ReWrapBytes(pub SM2PublicKey, encData []byte) ([]byte, error) {

	decData, err := prv.UnwrapBytes(encData)
	if err != nil {
		return nil, errio.Error(err)
	}

	return pub.WrapBytes(decData)
}

//  decodes a given PEM encoded private key into an sm2 private key.
func ImportSM2PrivateKeyPEM(privateKey []byte) (SM2PrivateKey, error) {
	privateSM2Key, err := x509.ReadPrivateKeyFromPem(privateKey, nil)
	if err != nil {
		return SM2PrivateKey{}, ErrNotSM2Format
	}
	return NewSM2PrivateKey(privateSM2Key), nil
}

//国密算法
type CiphertextGM struct {
	EncData CiphertextSM4 //加密数据 sm4加密  对应原来的AES
	EncKey  CiphertextSM2 //加密中间key sm2加密  对应原来的RSA
}

//存放sm4加密密文，对应原来的AES
type CiphertextSM4 struct {
	Data []byte `json:"data"`
}

// EncodeToString encodes the ciphertext in a string.
func (ct CiphertextSM4) EncodeToString() string {
	data := base64.StdEncoding.EncodeToString(ct.Data)
	return data
}

// DecodeCiphertextAESFromString decodes an encoded ciphertext string to an CiphertextAES.
func DecodeCiphertextSM4FromString(s string) (CiphertextSM4, error) {
	encryptedData, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return CiphertextSM4{}, errio.Error(err)
	}
	return CiphertextSM4{
		Data: encryptedData,
	}, nil
}

// CiphertextSM2 represents data encrypted with sm2. 对应原来的RSA
type CiphertextSM2 struct {
	Data []byte `json:"data"`
}

// EncodeToString encodes the ciphertext in a string.
func (ct CiphertextSM2) EncodeToString() string {
	encodedKey := base64.StdEncoding.EncodeToString(ct.Data)
	return fmt.Sprintf("%s$%s$", algorithmSM2, encodedKey)
}

// MarshalJSON encodes the ciphertext in JSON.
func (ct CiphertextSM2) MarshalJSON() ([]byte, error) {
	return json.Marshal(ct.EncodeToString())
}

// UnmarshalJSON decodes JSON into a ciphertext.
func (ct *CiphertextSM2) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}

	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	ciphertext, err := DecodeCiphertextSM2FromString(s)
	if err != nil {
		return err
	}

	*ct = ciphertext
	return nil
}

// DecodeCiphertextSM2FromString decodes an encoded ciphertext string to an CiphertextSM2.
func DecodeCiphertextSM2FromString(s string) (CiphertextSM2, error) {
	encoded, err := newEncodedCiphertext(s)
	if err != nil {
		return CiphertextSM2{}, err
	}

	algorithm, err := encoded.algorithm()
	if err != nil {
		return CiphertextSM2{}, errio.Error(err)
	}

	if algorithm != algorithmSM2 {
		return CiphertextSM2{}, ErrWrongAlgorithm
	}

	encryptedData, err := encoded.data()
	if err != nil {
		return CiphertextSM2{}, errio.Error(err)
	}

	return CiphertextSM2{
		Data: encryptedData,
	}, nil
}
