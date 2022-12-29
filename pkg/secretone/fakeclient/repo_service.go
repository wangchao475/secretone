// +build !production

package fakeclient

import (
	"github.com/wangchao475/secretone/internals/api"
	"github.com/wangchao475/secretone/pkg/secretone"
)

// RepoServiceService is a mock of the RepoServiceService interface.
type RepoServiceService struct {
	ListFunc     func(path string) ([]*api.Service, error)
	IteratorFunc func() secretone.ServiceIterator
}

func (s *RepoServiceService) Iterator(path string, _ *secretone.RepoServiceIteratorParams) secretone.ServiceIterator {
	return s.IteratorFunc()
}

// List implements the RepoServiceService interface List function.
func (s *RepoServiceService) List(path string) ([]*api.Service, error) {
	return s.ListFunc(path)
}
