package gcp

import (
	"errors"
	"testing"

	"google.golang.org/genproto/googleapis/cloud/kms/v1"

	"github.com/wangchao475/secretone/internals/assert"

	"github.com/wangchao475/secretone/internals/api"
)

var errTest = errors.New("test-error")

func TestGCPDecrypter_Unwrap(t *testing.T) {
	defaultCiphertext := []byte("ciphertext")
	defaultKMSKey := "projects/secretone-test-1234567890.iam/locations/global/keyRings/test/cryptoKeys/test"
	defaultPlaintext := "plaintext"

	cases := map[string]struct {
		input       *api.EncryptedData
		plaintext   string
		decryptErr  error
		expected    []byte
		expectedErr error
	}{
		"success": {
			input:     api.NewEncryptedDataGCPKMS(defaultCiphertext, api.NewEncryptionKeyGCP(defaultKMSKey)),
			plaintext: defaultPlaintext,
			expected:  []byte(defaultPlaintext),
		},
		"invalid EncryptedData": {
			input:       api.NewEncryptedDataAESGCM(defaultCiphertext, []byte("nonce"), 10, api.NewEncryptionKeyLocal(256)),
			expectedErr: api.ErrInvalidKeyType,
		},
		"decryption error": {
			input:       api.NewEncryptedDataGCPKMS(defaultCiphertext, api.NewEncryptionKeyGCP(defaultKMSKey)),
			decryptErr:  errTest,
			expectedErr: errTest,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			decrypter := KMSDecrypter{
				decryptFunc: func(name string, ciphertext []byte) (*kms.DecryptResponse, error) {
					assert.Equal(t, ciphertext, defaultCiphertext)
					return &kms.DecryptResponse{
						Plaintext: []byte(tc.plaintext),
					}, tc.decryptErr
				},
			}

			res, err := decrypter.Unwrap(tc.input)
			assert.Equal(t, err, tc.expectedErr)
			if tc.expectedErr == nil {
				assert.Equal(t, res, tc.expected)
			}
		})
	}
}
