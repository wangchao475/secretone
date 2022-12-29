package fakeclient

import (
	"github.com/wangchao475/secretone/internals/api"
	"github.com/wangchao475/secretone/pkg/secretone"
)

type MeService struct {
	GetUserFunc               func() (*api.User, error)
	SendVerificationEmailFunc func() error
	ListReposFunc             func() ([]*api.Repo, error)
	RepoIteratorFunc          func(_ *secretone.RepoIteratorParams) secretone.RepoIterator
}

func (m *MeService) GetUser() (*api.User, error) {
	return m.GetUserFunc()
}

func (m *MeService) SendVerificationEmail() error {
	return m.SendVerificationEmailFunc()
}

func (m *MeService) ListRepos() ([]*api.Repo, error) {
	return m.ListReposFunc()
}

func (m *MeService) RepoIterator(repoIteratorParams *secretone.RepoIteratorParams) secretone.RepoIterator {
	return m.RepoIteratorFunc(repoIteratorParams)
}
