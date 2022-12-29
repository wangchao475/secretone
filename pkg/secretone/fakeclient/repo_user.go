// +build !production

package fakeclient

import (
	"github.com/wangchao475/secretone/internals/api"
	"github.com/wangchao475/secretone/pkg/secretone"
)

// RepoUserService is a mock of the RepoUserService interface.
type RepoUserService struct {
	InviteFunc   func(path string, username string) (*api.RepoMember, error)
	ListFunc     func(path string) ([]*api.User, error)
	RevokeFunc   func(path string, username string) (*api.RevokeRepoResponse, error)
	IteratorFunc func() secretone.UserIterator
}

func (s *RepoUserService) Iterator(path string, params *secretone.UserIteratorParams) secretone.UserIterator {
	return s.IteratorFunc()
}

// Invite implements the RepoUserService interface Invite function.
func (s *RepoUserService) Invite(path string, username string) (*api.RepoMember, error) {
	return s.InviteFunc(path, username)
}

// List implements the RepoUserService interface List function.
func (s *RepoUserService) List(path string) ([]*api.User, error) {
	return s.ListFunc(path)
}

// Revoke implements the RepoUserService interface Revoke function.
func (s *RepoUserService) Revoke(path string, username string) (*api.RevokeRepoResponse, error) {
	return s.RevokeFunc(path, username)
}
