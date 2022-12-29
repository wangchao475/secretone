package api

import (
	"encoding/json"
	"testing"

	"github.com/wangchao475/secretone/internals/api/uuid"

	"github.com/wangchao475/secretone/internals/assert"
)

func TestEncryptedData_MarshalUnmarshalValidate(t *testing.T) {
	encryptedDataRSAAccountKey := NewEncryptedDataRSAOAEP([]byte("rsa-ciphertext"), HashingAlgorithmSHA256, NewEncryptionKeyAccountKey(4096, uuid.New()))

	cases := map[string]struct {
		in          *EncryptedData
		expectedErr error
		validateErr error
	}{
		"aes with rsa account key": {
			in: NewEncryptedDataAESGCM([]byte("ciphertext"), []byte("nonce"), 96, NewEncryptionKeyEncrypted(256, encryptedDataRSAAccountKey)),
		},
		"aes with rsa local key": {
			in: NewEncryptedDataAESGCM([]byte("ciphertext"), []byte("nonce"), 96, NewEncryptionKeyLocal(256)),
		},
		"aes with secret key": {
			in: NewEncryptedDataAESGCM([]byte("ciphertext"), []byte("nonce"), 96, NewEncryptionKeySecretKey(256, uuid.New())),
		},
		"rsa account key": {
			in: encryptedDataRSAAccountKey,
		},
		"aws kms": {
			in: NewEncryptedDataAWSKMS([]byte("ciphertext"), NewEncryptionKeyAWS("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")),
		},
		"gcp kms": {
			in: NewEncryptedDataGCPKMS([]byte("ciphertext"), NewEncryptionKeyGCP("projects/secretone-test-1234567890.iam/locations/global/keyRings/test/cryptoKeys/test")),
		},
		"aes with scrypt": {
			in: NewEncryptedDataAESGCM([]byte("ciphertext"), []byte("nonce"), 96, NewEncryptionKeyDerivedScrypt(256, 1, 2, 3, []byte("just-a-salt"))),
		},
		"aes with bootstrap code": {
			in: NewEncryptedDataAESGCM([]byte("ciphertext"), []byte("nonce"), 96, NewEncryptionKeyBootstrapCode(256)),
		},
		"rsa with missing key": {
			in:          NewEncryptedDataAESGCM([]byte("ciphertext"), []byte("nonce"), 96, nil),
			expectedErr: ErrInvalidKeyType,
		},
		"rsa with empty local key": {
			in:          NewEncryptedDataAESGCM([]byte("ciphertext"), []byte("nonce"), 96, &EncryptionKey{KeyTypeLocal}),
			validateErr: ErrMissingField("length"),
		},
		"empty encrypted data": {
			in:          &EncryptedData{Key: &EncryptionKey{KeyTypeLocal}},
			expectedErr: ErrInvalidEncryptionAlgorithm,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			bytes, err := json.Marshal(tc.in)
			assert.OK(t, err)

			var res EncryptedData
			err = json.Unmarshal(bytes, &res)

			assert.Equal(t, err, tc.expectedErr)
			if tc.expectedErr == nil {
				assert.Equal(t, res.Validate(), tc.validateErr)
				if tc.validateErr == nil {
					assert.Equal(t, res, tc.in)
				}
			}
		})
	}
}
