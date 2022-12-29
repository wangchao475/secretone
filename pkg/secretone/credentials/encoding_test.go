package credentials

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/tjfoc/gmsm/sm3"
	"net/http"
	"reflect"
	"github.com/wangchao475/secretone/internals/api"
	"github.com/wangchao475/secretone/internals/crypto"
	"testing"
	"time"

	"github.com/wangchao475/secretone/internals/assert"
)

var (
	foo                  = "foo"
	fooEncoded           = "Zm9v"
	exampleHeader        = map[string]interface{}{"type": "test"}
	exampleHeaderEncoded = "eyJ0eXBlIjoidGVzdCJ9"
)

func TestPassBasedKey(t *testing.T) {

	pass := []byte("Password123")
	key, err := NewPassBasedKey(pass)
	assert.OK(t, err)

	expected := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	encrypted, header, err := key.Encrypt(expected)
	assert.OK(t, err)

	if reflect.DeepEqual(encrypted, expected) {
		t.Errorf(
			"unexpected encrypted payload: %v (encrypted) == %v (expected)",
			encrypted,
			expected,
		)
	}

	headerBytes, err := json.Marshal(header)
	assert.OK(t, err)

	actual, err := key.Decrypt(encrypted, headerBytes)
	assert.OK(t, err)

	assert.Equal(t, actual, expected)
}
func TestAAAJson(t *testing.T) {
	out := &api.HttpResponse{}
	text := "{\"msg\":\"执行成功\",\"code\":0,\"data\":{\"account\":{\"name\":\"vincent\",\"account_id\":\"fa627b77556add2ed0795074801292fd\",\"public_key\":\"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb0VjejFVQmdpMERRZ0FFV2hjT2E3Q2JwMmFIUW1lcG9zOStmRm0wdFV0RwpScDcxbVJFUlIzMDd6MTRzSnR1MjI4NEM4VTVRV3ZtQkJ0cDNPU1VKam1Zc3I2dGpCQ0Q4YXBiVHZnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==\",\"account_type\":\"user\",\"created_at\":\"2022-06-14 16:20:51\"},\"credential\":{\"description\":\"tina\",\"fingerprint\":\"2e5eaba717c7a47b9f15820ac18e83c59c297c0aa70b23c4324248d118fcdc18\",\"verifier\":\"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb0VjejFVQmdpMERRZ0FFVjhoWFUwMmNqWU84K0U1aTdzRWthVUNweW1aNQpYWXJVR0FRZ0VxZlFoRUVmZG5uT3g1cWQwUG9kY09aUlVGSU1QY291N0Vjdk5NMnBqY2lTQzhtY2tBPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==\",\"enabled\":true,\"account_id\":\"fa627b77556add2ed0795074801292fd\",\"type\":\"key\",\"created_at\":\"2022-07-05 11:02:49\"},\"public_key\":\"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb0VjejFVQmdpMERRZ0FFV2hjT2E3Q2JwMmFIUW1lcG9zOStmRm0wdFV0RwpScDcxbVJFUlIzMDd6MTRzSnR1MjI4NEM4VTVRV3ZtQkJ0cDNPU1VKam1Zc3I2dGpCQ0Q4YXBiVHZnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==\",\"encrypted_private_key\":{\"algorithm\":\"SM2\",\"key\":\"SM2$MDQ1NDZkYWI3OWE0NmQ5OWQ5ZWY0YWYwOGE2M2U2ZDM1Y2RmYjQ2OWExYjM2MjMzZjY3MDM3ZDcyOGFiMTMxNWYzYjE1YmU2OWY2Y2M2OTlhNDE5YjBjNDU5ZDBiYmY4MGQ2YTU2NzNlMmI1ZGJjY2Y5N2VhZmRjYWM3MDkxMTIwZjk2NmIwMzEzMGY0MGNjMGE3MTE0ZmUzNmM1ODNiODcyMjBhZDkyNDQ2NGFmNzU2OWZkNzkyMDMyZjZmZDAyZTc4OTA3MzU2OWFiZmYxMjkzMTBlNDcyNDE1ZTNhYzBhMA==$\",\"ciphertext\":\"N2E2MTA3N2YzN2QyNzk0NTQxYWQ3NWFkMGY3Y2Y5OWI2Mjk5NmE2NjQ3NDU3ZWI0M2JhNzRlMTQ2NGU5NjI4YWRjYjllNzU3ODAzMmFlNTUzNDg1YTg0MjFkYjM1N2JkZjI0YzhlNmJiZTM1OGFmZDJmYzE3NmJkNGFiM2QwMTk4NjFmYmNjNjlmMWEzNmEzOGU1NDYyMmVhZmRlY2FjMmFmOGI0OWQ1NmRlZTYzNjY3MDkwNjRiYjQ3YjA0NzhlYzRmM2U0ZTczMzMxNTA2NjVjNzZhODA5N2IyYWVmZmRkODgwMDAxMzQ2MjRmZDNjYzBlYjA0YjMyNmExZTY4YzAxN2Q3ZDg0NTE2MjFhMjdhODMyY2EzMGIwOTA0YjVhNTRlOGVjMmNjOTdiNGEyM2UzYmFiZmVhZTM0OTUxZGM4MzNkZDBjZDFkN2RlNTJmZGQyYWJkNWFlZDY2NGJkYTY4MmQxZTdmODBkMDFlODNmNjg5OTNmNTI1M2FlYjgwNzE5YzQ1YjI4MDhlNDg1MDNmZmJhY2I3NWNhNTlhODVjNzNkN2U1YjM2ZWE3NTc2ZmIzYjQyYzMxYmM0YjhkMDU1NmMzMjIzYmU3MWVhYTFiNDJjMTMzZDljNjU5NGM3YmRmYWU4OWFjMzVhZWQwNTE3Y2VkZjE3OGI5NDhjMTMxOTdiYjZiN2Q3MWY0ZDFiNWVlNDg0ZTg0ZjkzNDc2MQ==\"}}}"
	err := json.Unmarshal([]byte(text), out)
	respData := &api.EncryptedAccountKey{}
	if out.Code != 0 {
		assert.OK(t, err)
	}
	vars, ok := out.Data.(map[string]interface{})
	if !ok {

	}
	for key, value := range vars {
		switch key {
		case "account":
			arr, _ := json.Marshal(value)
			var account api.Account
			err = json.Unmarshal(arr, &account)
			respData.Account = &account
			break
		case "credential":
			arr, _ := json.Marshal(value)
			var credential api.Credential
			err = json.Unmarshal(arr, &credential)
			respData.Credential = &credential
			break
		case "public_key":
			tmp, ok := value.(string)
			if !ok {
				return
			}
			respData.PublicKey = []byte(tmp)
			break
		case "encrypted_private_key":
			keyVars, ok := value.(map[string]interface{})
			if !ok {
				return
			}
			var encPriKey api.EncryptedData
			for kkey, kvalue := range keyVars {
				switch kkey {
				case "algorithm":
					encPriKey.Algorithm = kvalue.(string)
				case "ciphertext":
					encPriKey.Ciphertext = []byte(kvalue.(string))
				case "key":
					encPriKey.Key = kvalue
				}
			}
			respData.EncryptedPrivateKey = &encPriKey
		}
	}

	assert.OK(t, err)
}
func TestSM2sign(t *testing.T) {
	formattedTime := time.Now().Format(time.RFC1123Z)
	fmt.Println(formattedTime)
	req, err := http.NewRequest("GET", "http://10.11.100.229", nil)
	req.Header.Set("Date", formattedTime)
	//priv, err := sm2.GenerateKey(nil) // 生成密钥对
	//if err != nil {
	//	t.Fatal(err)
	//}
	//
	//pubKey, _ := priv.Public().(*sm2.PublicKey)
	//pubkeyPem, err := x509.WritePublicKeyToPem(pubKey)       // 生成公钥文件
	//
	//pubKey, err = x509.ReadPublicKeyFromPem(pubkeyPem) // 读取公钥
	//if err != nil {
	//	t.Fatal(err)
	//}
	//msg := []byte("123456")
	//enc,err:=priv.Sign(rand.Reader,msg,nil)
	//result:=pubKey.Verify(msg,enc)
	//fmt.Println(result)
	accountKey, err := crypto.ImportSM2PrivateKeyPEM([]byte("-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgbQiAphvXlUI2G+D4\nPZN6UFSodOXnfdF8Oe++27Zz6bagCgYIKoEcz1UBgi2hRANCAATpBL3t4fUnHo7v\nezzRJXreDiKp96gqM8WwyVhfqndcRqSm5yGOSu5gHkKRtKxU16ew5rRl3zoU6xH+\nC1zXyfFL\n-----END PRIVATE KEY-----\n"))
	if err != nil {
		assert.OK(t, err)
	}
	msg := "GET\n\n2022-07-05 01:35:16 +0000 UTC\n/v1/me/user;"
	text := sm3.Sm3Sum([]byte(msg))
	fmt.Println("hex:", hex.EncodeToString(text))
	data, err := accountKey.Sign([]byte(msg))
	if err != nil {
		assert.OK(t, err)
	}
	fmt.Printf("签名:%s\n", base64.StdEncoding.EncodeToString(data))

	pubkey, err := crypto.ImportSM2PublicKey([]byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEKeQnUQBcayBamRG7IgkH9fQAHmXA\nX8+bBA228rTlipcEvGreNGzabwWvdsPUbK0BVEWA4BdIluvOre3h3W+9jA==\n-----END PUBLIC KEY-----\n"))
	if err != nil {
		assert.OK(t, err)
	}
	decodedata, err := base64.StdEncoding.DecodeString("MEYCIQCgCvZadVktd0cLgp82SGPSFg9GORrzsK9lSxU8PoOHzgIhAOfzic3KjjIOFYhTdfUOKuAx/T/DBosAzIY+AM/1/DpL")
	if err != nil {
		assert.OK(t, err)
	}
	err = pubkey.Verify(text, decodedata)
	if err != nil {
		assert.OK(t, err)
	}
}
func TestSM2Credential(t *testing.T) {

	credential, err := GenerateSM2Credential()
	assert.OK(t, err)

	t.Run("encoding", func(t *testing.T) {
		exported := credential.Encode()

		decoder := credential.Decoder()
		actual, err := decoder.Decode(exported)
		assert.OK(t, err)

		assert.Equal(t, actual, credential)
	})

	t.Run("encryption", func(t *testing.T) {
		expected := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

		ciphertext, err := credential.Wrap(expected)
		assert.OK(t, err)

		if reflect.DeepEqual(ciphertext, expected) {
			t.Errorf(
				"unexpected ciphertext: %v (ciphertext) == %v (plaintext)",
				ciphertext,
				expected,
			)
		}

		actual, err := credential.Unwrap(ciphertext)
		assert.OK(t, err)

		assert.Equal(t, actual, expected)
	})
}

//func TestParser(t *testing.T) {
//
//	// Arrange
//	credential, err := GenerateRSACredential(1024)
//	assert.OK(t, err)
//
//	payload := credential.Encode()
//
//	header := map[string]interface{}{
//		"type": credential.Decoder().Name(),
//	}
//	headerBytes, err := json.Marshal(header)
//	assert.OK(t, err)
//	raw := fmt.Sprintf(
//		"%s.%s",
//		defaultEncoding.EncodeToString(headerBytes),
//		defaultEncoding.EncodeToString(payload),
//	)
//
//	headerEncrypted := map[string]interface{}{
//		"type": credential.Decoder().Name(),
//		"enc":  "scrypt",
//	}
//	headerEncryptedBytes, err := json.Marshal(headerEncrypted)
//	assert.OK(t, err)
//	rawEncrypted := fmt.Sprintf(
//		"%s.%s",
//		defaultEncoding.EncodeToString(headerEncryptedBytes),
//		defaultEncoding.EncodeToString(payload), // payload isn't actually encrypted but that does not matter for the parser.
//	)
//
//	headerTypeNotSet, err := json.Marshal(map[string]interface{}{"foo": "bar"})
//	assert.OK(t, err)
//
//	headerUnsupportedType, err := json.Marshal(map[string]interface{}{"type": "unsupported"})
//	assert.OK(t, err)
//
//	cases := map[string]struct {
//		raw      string
//		expected *encodedCredential
//		err      error
//	}{
//		"valid_rsa": {
//			raw: raw,
//			expected: &encodedCredential{
//				Raw:                 []byte(raw),
//				Header:              header,
//				RawHeader:           headerBytes,
//				Payload:             payload,
//				EncryptionAlgorithm: "",
//				Decoder:             credential.Decoder(),
//			},
//			err: nil,
//		},
//		"valid_rsa_encrypted": {
//			raw: rawEncrypted,
//			expected: &encodedCredential{
//				Raw:                 []byte(rawEncrypted),
//				Header:              headerEncrypted,
//				RawHeader:           headerEncryptedBytes,
//				Payload:             payload,
//				EncryptionAlgorithm: "scrypt",
//				Decoder:             credential.Decoder(),
//			},
//			err: nil,
//		},
//		"header_one_segment": {
//			raw:      defaultEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5}),
//			expected: nil,
//			err:      ErrInvalidNumberOfCredentialSegments(1),
//		},
//		"header_three_segments": {
//			raw: fmt.Sprintf(
//				"%s.%s.%s",
//				defaultEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5}),
//				defaultEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5}),
//				defaultEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5}),
//			),
//			expected: nil,
//			err:      ErrInvalidNumberOfCredentialSegments(3),
//		},
//		"header_not_base64": {
//			raw:      fmt.Sprintf("#not_base64.%s", defaultEncoding.EncodeToString(payload)),
//			expected: nil,
//			err:      ErrCannotDecodeCredentialHeader("illegal base64 data at input byte 0"),
//		},
//		"header_not_json": {
//			raw: fmt.Sprintf(
//				"%s.%s",
//				defaultEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5}),
//				defaultEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5}),
//			),
//			expected: nil,
//			err:      ErrCannotDecodeCredentialHeader("cannot unmarshal json: invalid character '\\x00' looking for beginning of value"),
//		},
//		"header_type_not_set": {
//			raw: fmt.Sprintf(
//				"%s.%s",
//				defaultEncoding.EncodeToString(headerTypeNotSet),
//				defaultEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5}),
//			),
//			expected: nil,
//			err:      ErrInvalidCredentialHeaderField("type"),
//		},
//		"header_unsupported_type": {
//			raw: fmt.Sprintf(
//				"%s.%s",
//				defaultEncoding.EncodeToString(headerUnsupportedType),
//				defaultEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5}),
//			),
//			expected: nil,
//			err:      ErrUnsupportedCredentialType("unsupported"),
//		},
//		"payload_not_base64": {
//			raw: fmt.Sprintf(
//				"%s.#not_base64",
//				defaultEncoding.EncodeToString(headerBytes),
//			),
//			expected: nil,
//			err:      ErrCannotDecodeCredentialPayload("illegal base64 data at input byte 0"),
//		},
//	}
//
//	parser := newParser(DefaultDecoders)
//
//	for name, tc := range cases {
//		t.Run(name, func(t *testing.T) {
//			// Act
//			actual, err := parser.parse([]byte(tc.raw))
//
//			// Assert
//			assert.Equal(t, err, tc.err)
//			if tc.err == nil {
//				assert.Equal(t, actual, tc.expected)
//			}
//		})
//	}
//}

func TestEncodeCredential(t *testing.T) {

	// Arrange
	cred, err := GenerateSM2Credential()
	assert.OK(t, err)

	parser := newParser(DefaultDecoders)

	// Act
	raw, err := EncodeCredential(cred)
	assert.OK(t, err)

	parsed, err := parser.parse(raw)
	assert.OK(t, err)

	decoded, err := parsed.Decode()
	assert.OK(t, err)

	// Assert
	assert.Equal(t, cred, decoded)
}

func TestEncodeEncryptedCredential(t *testing.T) {

	// Arrange
	cred, err := GenerateSM2Credential()
	assert.OK(t, err)

	parser := newParser(DefaultDecoders)

	pass := []byte("Password123")
	key, err := NewPassBasedKey(pass)
	assert.OK(t, err)

	// Act
	raw, err := EncodeEncryptedCredential(cred, key)
	assert.OK(t, err)

	parsed, err := parser.parse(raw)
	assert.OK(t, err)

	decoded, err := parsed.DecodeEncrypted(key)
	assert.OK(t, err)

	// Assert
	assert.Equal(t, cred, decoded)
}

func TestEncodeCredentialParts(t *testing.T) {

	// Arrange
	cases := map[string]struct {
		header   map[string]interface{}
		payload  []byte
		expected []byte
		err      error
	}{
		"success": {
			header:   exampleHeader,
			payload:  []byte(foo),
			expected: []byte(fmt.Sprintf("%s.%s", exampleHeaderEncoded, fooEncoded)),
		},
		"nil_header": {
			header:  nil,
			payload: []byte(foo),
			err:     ErrEmptyCredentialHeader,
		},
		"empty_header": {
			header:  make(map[string]interface{}),
			payload: []byte(foo),
			err:     ErrEmptyCredentialHeader,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			actual, err := encodeCredentialParts(tc.header, tc.payload)
			assert.Equal(t, err, tc.err)

			// Assert
			assert.Equal(t, actual, tc.expected)
		})
	}
}

func TestCredentialIsEncrypted(t *testing.T) {

	// Arrange
	cases := map[string]struct {
		algorithm string
		expected  bool
	}{
		"empty": {
			algorithm: "",
			expected:  false,
		},
		"scrypt": {
			algorithm: "scrypt",
			expected:  true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cred := &encodedCredential{
				EncryptionAlgorithm: tc.algorithm,
			}

			// Act
			actual := cred.IsEncrypted()

			// Assert
			assert.Equal(t, actual, tc.expected)
		})
	}
}

// TestBase64NoPadding tests the assumption that base64 works fine
// if you consistently disable padding and don't concatenate strings.
func TestBase64NoPaddingAssumption(t *testing.T) {

	// Arrange
	cases := map[string]struct {
		input    string
		expected string
	}{
		"empty": {
			input:    "",
			expected: "",
		},
		"one_byte": {
			input:    "f",
			expected: "Zg",
		},
		"two_byte": {
			input:    "fo",
			expected: "Zm8",
		},
		"three_byte": {
			input:    "foo",
			expected: "Zm9v",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(tc.input))

			decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(encoded)
			assert.OK(t, err)

			// Assert
			assert.Equal(t, encoded, tc.expected)
			assert.Equal(t, string(decoded), tc.input)
		})
	}
}
