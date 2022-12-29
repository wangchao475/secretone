package auth_test

import (
	"net/http"
	"testing"

	"github.com/wangchao475/secretone/pkg/secretone/credentials"

	"github.com/wangchao475/secretone/internals/assert"
	"github.com/wangchao475/secretone/internals/auth"
	"github.com/wangchao475/secretone/internals/crypto"
)

func TestSignRequest_CheckHeadersAreSet(t *testing.T) {
	// Arrange
	clientKey, err := crypto.GenerateRSAPrivateKey(1024)
	if err != nil {
		panic(err)
	}

	signer := auth.NewHTTPSigner(credentials.RSACredential{RSAPrivateKey: clientKey})

	req, err := http.NewRequest("GET", "https://api.secretone.io/repos/jdoe/catpictures", nil)
	assert.OK(t, err)

	// Act
	err = signer.Authenticate(req)
	assert.OK(t, err)

	// Assert
	if req.Header.Get("Date") == "" {
		t.Error("Date header not set.")
	}

	if req.Header.Get("Authorization") == "" {
		t.Error("Authorization header not set.")
	}
}
