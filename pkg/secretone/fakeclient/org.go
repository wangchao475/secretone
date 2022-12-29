// +build !production

package fakeclient

import (
	"github.com/wangchao475/secretone/internals/api"
	"github.com/wangchao475/secretone/pkg/secretone"
)

// OrgService is a mock of the RepoService interface.
type OrgService struct {
	CreateFunc     func(name string, description string) (*api.Org, error)
	DeleteFunc     func(name string) error
	GetFunc        func(name string) (*api.Org, error)
	MembersService secretone.OrgMemberService
	ListMineFunc   func() ([]*api.Org, error)
	IteratorFunc   func(params *secretone.OrgIteratorParams) secretone.OrgIterator
}

func (s *OrgService) Iterator(params *secretone.OrgIteratorParams) secretone.OrgIterator {
	return s.IteratorFunc(params)
}

// Create implements the RepoService interface Create function.
func (s *OrgService) Create(name string, description string) (*api.Org, error) {
	return s.CreateFunc(name, description)
}

// Delete implements the RepoService interface Delete function.
func (s *OrgService) Delete(name string) error {
	return s.DeleteFunc(name)
}

// Get implements the RepoService interface Get function.
func (s *OrgService) Get(name string) (*api.Org, error) {
	return s.GetFunc(name)
}

// Members returns a mock of the OrgMemberService interface.
func (s *OrgService) Members() secretone.OrgMemberService {
	return s.MembersService
}

// ListMine implements the RepoService interface ListMine function.
func (s *OrgService) ListMine() ([]*api.Org, error) {
	return s.ListMineFunc()
}
