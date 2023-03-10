package fakeclient

import (
	"github.com/wangchao475/secretone/internals/api"
	"github.com/wangchao475/secretone/internals/oauthorizer"
	"github.com/wangchao475/secretone/pkg/secretone"
	"github.com/wangchao475/secretone/pkg/secretone/iterator"
)

type IDPLinkService struct {
	GCPService secretone.IDPLinkGCPService
}

func (i IDPLinkService) GCP() secretone.IDPLinkGCPService {
	return i.GCPService
}

type IDPLinkGCPService struct {
	CreateFunc                    func(namespace string, projectID string, authorizationCode string, redirectURI string) (*api.IdentityProviderLink, error)
	ListFunc                      func(namespace string, params *secretone.IdpLinkIteratorParams) secretone.IdpLinkIterator
	GetFunc                       func(namespace string, projectID string) (*api.IdentityProviderLink, error)
	ExistsFunc                    func(namespace string, projectID string) (bool, error)
	DeleteFunc                    func(namespace string, projectID string) error
	AuthorizationCodeListenerFunc func(namespace string, projectID string) (oauthorizer.CallbackHandler, error)
}

func (i IDPLinkGCPService) Create(namespace string, projectID string, authorizationCode, redirectURI string) (*api.IdentityProviderLink, error) {
	return i.CreateFunc(namespace, projectID, authorizationCode, redirectURI)
}

func (i IDPLinkGCPService) List(namespace string, params *secretone.IdpLinkIteratorParams) secretone.IdpLinkIterator {
	return i.ListFunc(namespace, params)
}

func (i IDPLinkGCPService) Get(namespace string, projectID string) (*api.IdentityProviderLink, error) {
	return i.GetFunc(namespace, projectID)
}

func (i IDPLinkGCPService) Exists(namespace string, projectID string) (bool, error) {
	return i.ExistsFunc(namespace, projectID)
}

func (i IDPLinkGCPService) Delete(namespace string, projectID string) error {
	return i.DeleteFunc(namespace, projectID)
}

func (i IDPLinkGCPService) AuthorizationCodeListener(namespace string, projectID string) (oauthorizer.CallbackHandler, error) {
	return i.AuthorizationCodeListenerFunc(namespace, projectID)
}

type IDPLinkIterator struct {
	IDPLinks     []*api.IdentityProviderLink
	CurrentIndex int
	Err          error
}

func (c *IDPLinkIterator) Next() (api.IdentityProviderLink, error) {
	if c.Err != nil {
		return api.IdentityProviderLink{}, c.Err
	}

	currentIndex := c.CurrentIndex
	if currentIndex >= len(c.IDPLinks) {
		return api.IdentityProviderLink{}, iterator.Done
	}
	c.CurrentIndex++
	return *c.IDPLinks[currentIndex], nil
}
