package secretone

import (
	"github.com/wangchao475/secretone/internals/api"
	"github.com/wangchao475/secretone/internals/errio"
	"github.com/wangchao475/secretone/pkg/secretone/iterator"
)

// OrgService handles operations on organisations on secretone.
type OrgService interface {
	// Create creates an organization.
	Create(name string, description string) (*api.Org, error)
	// Get retrieves an organization.
	Get(name string) (*api.Org, error)
	// Members returns an OrgMemberService.
	Members() OrgMemberService
	// Delete removes an organization.
	Delete(name string) error
	// ListMine returns the organizations of the current user.
	// Deprecated: Use iterator function instead.
	ListMine() ([]*api.Org, error)
	// Iterator returns an iterator that lists all organizations of the current user.
	Iterator(params *OrgIteratorParams) OrgIterator
}

func newOrgService(client *Client) OrgService {
	return orgService{
		client: client,
	}
}

type orgService struct {
	client *Client
}

// Create creates an organization and adds the current account as an admin member.
func (s orgService) Create(name string, description string) (*api.Org, error) {
	in := &api.CreateOrgRequest{
		Name:        name,
		Description: description,
	}

	err := in.Validate()
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.httpClient.CreateOrg(in)
}

// Delete permanently deletes an organization and all of its resources.
func (s orgService) Delete(name string) error {
	err := api.ValidateOrgName(name)
	if err != nil {
		return errio.Error(err)
	}

	return s.client.httpClient.DeleteOrg(name)
}

// Get retrieves an organization.
func (s orgService) Get(name string) (*api.Org, error) {
	err := api.ValidateOrgName(name)
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.httpClient.GetOrg(name)
}

// Members returns an OrgMemberService.
func (s orgService) Members() OrgMemberService {
	return newOrgMemberService(s.client)
}

// ListMine returns the organizations of the current user.
func (s orgService) ListMine() ([]*api.Org, error) {
	return s.client.httpClient.ListMyOrgs()
}

// Iterator returns an iterator that lists all organizations of the current user.
func (s orgService) Iterator(params *OrgIteratorParams) OrgIterator {
	return &orgIterator{
		iterator: iterator.New(
			iterator.PaginatorFactory(
				func() ([]interface{}, error) {
					orgs, err := s.client.httpClient.ListMyOrgs()
					if err != nil {
						return nil, err
					}

					res := make([]interface{}, len(orgs))
					for i, element := range orgs {
						res[i] = element
					}
					return res, nil
				},
			),
		),
	}
}

type OrgIteratorParams struct{}

// OrgIterator iterates over organizations.
type OrgIterator interface {
	Next() (api.Org, error)
}

type orgIterator struct {
	iterator iterator.Iterator
}

// Next returns the next organization or iterator.Done as an error if all of them have been returned.
func (it *orgIterator) Next() (api.Org, error) {
	item, err := it.iterator.Next()
	if err != nil {
		return api.Org{}, err
	}

	return *item.(*api.Org), nil
}
