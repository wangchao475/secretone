// +build !production

package fakeclient

import (
	"github.com/wangchao475/secretone/internals/api"
	"github.com/wangchao475/secretone/pkg/secretone"
)

// DirService is a mock of the DirService interface.
type DirService struct {
	CreateFunc  func(path string) (*api.Dir, error)
	ExistsFunc  func(path string) (bool, error)
	DeleteFunc  func(path string) error
	GetTreeFunc func(path string, depth int, ancestors bool) (*api.Tree, error)
	secretone.DirService
}

// Create implements the DirService interface Create function.
func (s *DirService) Create(path string) (*api.Dir, error) {
	return s.CreateFunc(path)
}

// Exists implements the DirService interface Exists function.
func (s *DirService) Exists(path string) (bool, error) {
	return s.ExistsFunc(path)
}

// Delete implements the DirService interface Delete function.
func (s *DirService) Delete(path string) error {
	return s.DeleteFunc(path)
}

// GetTree implements the DirService interface GetTree function.
func (s *DirService) GetTree(path string, depth int, ancestors bool) (*api.Tree, error) {
	return s.GetTreeFunc(path, depth, ancestors)
}
