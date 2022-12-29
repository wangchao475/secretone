package credentials

import (
	"google.golang.org/api/option"

	"github.com/wangchao475/secretone/internals/auth"
	"github.com/wangchao475/secretone/internals/gcp"
	"github.com/wangchao475/secretone/pkg/secretone/credentials/sessions"
	"github.com/wangchao475/secretone/pkg/secretone/internals/http"
)

// UseGCPServiceAccount returns a Provider that can be used to use a GCP Service Account as a credential for secretone.
// The provided gcpOptions is used to configure the GCP client.
// If used on GCP (e.g. from a Compute Engine instance), this extra configuration is not required and the correct
// configuration should be auto-detected by the GCP client.
//
// Access to the GCP metadata server is required for this function to work. In practice, this means that it can
// only be run on GCP.
//
// Usage:
//		credentials.UseGCPServiceAccount()
func UseGCPServiceAccount(gcpOptions ...option.ClientOption) Provider {
	return providerFunc(func(httpClient *http.Client) (auth.Authenticator, Decrypter, string, error) {
		decrypter, err := gcp.NewKMSDecrypter(gcpOptions...)
		if err != nil {
			return nil, nil, "", err
		}
		authenticator := sessions.NewSessionRefresher(httpClient, sessions.NewGCPSessionCreator(gcpOptions...))
		return authenticator, decrypter, "", nil
	})
}

// CreateGCPServiceAccount returns a Creator that creates a credential for a GCP Service Account.
// The serviceAccountEmail is the email of the GCP Service Account that can use this secretone service account.
// The kmsResourceID is the Resource ID of the key in KMS that is used to encrypt the account key.
// The service account should have decryption permission on the provided KMS key.
// gcpOptions can be used to optionally configure the used GCP client. For example to set a custom API key.
// The KMS key id and service account email are returned in the credentials metadata.
func CreateGCPServiceAccount(serviceAccountEmail string, keyResourceID string, gcpOptions ...option.ClientOption) Creator {
	return &gcpServiceAccountCreator{
		keyResourceID:       keyResourceID,
		serviceAccountEmail: serviceAccountEmail,
		gcpOptions:          gcpOptions,
	}
}

type gcpServiceAccountCreator struct {
	keyResourceID       string
	serviceAccountEmail string

	gcpOptions []option.ClientOption

	credentialCreator *gcp.CredentialCreator
	metadata          map[string]string
}

func (gc *gcpServiceAccountCreator) Create() error {
	creator, metadata, err := gcp.NewCredentialCreator(gc.serviceAccountEmail, gc.keyResourceID, gc.gcpOptions...)
	if err != nil {
		return err
	}
	gc.metadata = metadata
	gc.credentialCreator = creator
	return nil
}

func (gc *gcpServiceAccountCreator) Verifier() Verifier {
	return gc.credentialCreator
}

func (gc *gcpServiceAccountCreator) Encrypter() Encrypter {
	return gc.credentialCreator
}

func (gc *gcpServiceAccountCreator) Metadata() map[string]string {
	return gc.metadata
}
