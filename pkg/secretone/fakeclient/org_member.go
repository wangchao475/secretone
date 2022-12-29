// +build !production

package fakeclient

import (
	"github.com/wangchao475/secretone/internals/api"
	"github.com/wangchao475/secretone/pkg/secretone"
)

// OrgMemberService is a mock of the OrgMemberService interface.
type OrgMemberService struct {
	InviteFunc   func(org string, username string, role string) (*api.OrgMember, error)
	GetFunc      func(org string, username string) (*api.OrgMember, error)
	UpdateFunc   func(org string, username string, role string) (*api.OrgMember, error)
	RevokeFunc   func(org string, username string, opts *api.RevokeOpts) (*api.RevokeOrgResponse, error)
	ListFunc     func(org string) ([]*api.OrgMember, error)
	IteratorFunc func(org string, params *secretone.OrgMemberIteratorParams) secretone.OrgMemberIterator
}

func (s *OrgMemberService) Invite(org string, username string, role string) (*api.OrgMember, error) {
	return s.InviteFunc(org, username, role)
}

func (s *OrgMemberService) Get(org string, username string) (*api.OrgMember, error) {
	return s.GetFunc(org, username)
}

func (s *OrgMemberService) Update(org string, username string, role string) (*api.OrgMember, error) {
	return s.UpdateFunc(org, username, role)
}

func (s *OrgMemberService) Revoke(org string, username string, opts *api.RevokeOpts) (*api.RevokeOrgResponse, error) {
	return s.RevokeFunc(org, username, opts)
}

func (s *OrgMemberService) List(org string) ([]*api.OrgMember, error) {
	return s.ListFunc(org)
}

func (s *OrgMemberService) Iterator(org string, params *secretone.OrgMemberIteratorParams) secretone.OrgMemberIterator {
	return s.IteratorFunc(org, params)
}
