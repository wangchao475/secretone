package api

import (
	"fmt"
	units "github.com/docker/go-units"
	"github.com/wangchao475/secretone/internals/api/uuid"
	"github.com/wangchao475/secretone/internals/crypto"
	"github.com/wangchao475/secretone/internals/errio"
	"strconv"
)

const (
	// MaxEncryptedSecretSize is the maximum size of EncryptedSecretVersion.EncryptedData.
	MaxEncryptedSecretSize = (512*4/3 + 5) * units.KiB // 512 KiB corrected for base64 overhead (4/3) and metadata
)

// Status Constants
const (
	// StatusOK signals everything is in order.
	StatusOK = "ok"
	// StatusFlagged signals that a resource should be considered compromised and should be rotated/no longer used.
	StatusFlagged = "flagged"
	// StatusFailed signals that revocation cannot complete.
	StatusFailed = "failed"
)

// Errors
var (
	ErrEncryptedDataTooBig = errAPI.Code("encrypted_data_too_big").Error(fmt.Sprintf("maximum size of encrypted data is %s", units.BytesSize(MaxEncryptedSecretSize)))
)

// EncryptedSecretVersion represents a version of an encrypted Secret.
// It contains the encrypted data and the corresponding key.
type EncryptedSecretVersion struct {
	SecretVersionID uuid.UUID `json:"secret_version_id"`
	//	Secret          *EncryptedSecret      `json:"secret"`
	Secret        *Secret               `json:"secret"` //名字不需要加密，之前只是针对name进行了加密
	Version       int                   `json:"version"`
	SecretKey     *EncryptedSecretKey   `json:"secret_key,omitempty"`
	EncryptedData *crypto.CiphertextSM4 `json:"encrypted_data,omitempty"`
	CreatedAt     string                `json:"created_at"`
	Status        string                `json:"status"`
}

// Decrypt decrypts an EncryptedSecretVersion into a SecretVersion.
func (esv *EncryptedSecretVersion) Decrypt(accountKey *crypto.SM2PrivateKey) (*SecretVersion, error) {
	//secret, err := esv.Secret.Decrypt(accountKey)
	//if err != nil {
	//	return nil, errio.Error(err)
	//}
	var secretKey *SecretKey
	var err error
	var data []byte
	if esv.SecretKey != nil && esv.EncryptedData != nil {
		secretKey, err = esv.SecretKey.Decrypt(accountKey)
		if err != nil {
			return nil, errio.Error(err)
		}

		data, err = secretKey.Key.Decrypt(*esv.EncryptedData)
		if err != nil {
			return nil, err
		}
	}

	return &SecretVersion{
		SecretVersionID: esv.SecretVersionID,
		Secret:          esv.Secret,
		Version:         esv.Version,
		SecretKey:       secretKey,
		Data:            data,
		CreatedAt:       esv.CreatedAt,
		Status:          esv.Status,
	}, nil
}

// SecretVersion represents a version of a Secret without any encrypted data.
type SecretVersion struct {
	SecretVersionID uuid.UUID  `json:"secret_version_id"`
	Secret          *Secret    `json:"secret"`
	Version         int        `json:"version"`
	SecretKey       *SecretKey `json:"secret_key,omitempty"`
	Data            []byte     `json:"data,omitempty"`
	CreatedAt       string     `json:"created_at"`
	Status          string     `json:"status"`
}

// IsLatest returns true when the secret version is the latest version of the secret.
func (sv *SecretVersion) IsLatest() bool {
	if sv.Secret == nil {
		return false
	}

	return sv.Secret.LatestVersion == sv.Version
}

// Name returns the secret name:version
func (sv *SecretVersion) Name() string {
	if sv.Secret == nil {
		return strconv.Itoa(sv.Version)
	}
	return fmt.Sprintf("%s:%d", sv.Secret.Name, sv.Version)
}

// ToAuditSubject converts an EncryptedSecret to an AuditSubject
func (es *EncryptedSecret) ToAuditSubject() *AuditSubject {
	return &AuditSubject{
		SubjectID:       es.SecretID,
		Type:            AuditSubjectSecret,
		EncryptedSecret: es,
	}
}

// ToAuditSubject converts a SecretVersion to an AuditSubject
func (esv *EncryptedSecretVersion) ToAuditSubject() *AuditSubject {
	return &AuditSubject{
		SubjectID:              esv.SecretVersionID,
		Type:                   AuditSubjectSecretVersion,
		EncryptedSecretVersion: esv,
	}
}

// CreateSecretVersionRequest contains the request fields for creating a
// secret version with a secret key.
type CreateSecretVersionRequest struct {
	EncryptedData crypto.CiphertextSM4 `json:"encrypted_data"`
	SecretKeyID   uuid.UUID            `json:"secret_key_id"`
}

// Validate validates the request fields.
func (csvr *CreateSecretVersionRequest) Validate() error {
	if csvr.SecretKeyID.IsZero() {
		return ErrInvalidSecretKeyID
	}
	// 这个地方原来是校验是否能转化成json的，这里面修改一下，感觉没有必要
	//encoded, err := csvr.EncryptedData.MarshalJSON()
	//if err != nil {
	//	return err
	//}
	encoded := csvr.EncryptedData.EncodeToString()
	if len(encoded) > MaxEncryptedSecretSize {
		return ErrEncryptedDataTooBig
	}

	return nil
}
