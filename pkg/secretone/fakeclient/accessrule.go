// +build !production

package fakeclient

import (
	"github.com/wangchao475/secretone/internals/api"
	"github.com/wangchao475/secretone/pkg/secretone"
)

// AccessRuleService is a mock of the AccessRuleService interface.
type AccessRuleService struct {
	DeleteFunc        func(path string, accountName string) error
	GetFunc           func(path string, accountName string) (*api.AccessRule, error)
	ListLevelsFunc    func(path string) ([]*api.AccessLevel, error)
	ListFunc          func(path string, depth int, ancestors bool) ([]*api.AccessRule, error)
	SetFunc           func(path string, permission string, accountName string) (*api.AccessRule, error)
	IteratorFunc      func() secretone.AccessRuleIterator
	LevelIteratorFunc func() secretone.AccessLevelIterator
}

func (s *AccessRuleService) Iterator(path string, _ *secretone.AccessRuleIteratorParams) secretone.AccessRuleIterator {
	return s.IteratorFunc()
}

func (s *AccessRuleService) LevelIterator(path string, _ *secretone.AccessLevelIteratorParams) secretone.AccessLevelIterator {
	return s.LevelIteratorFunc()
}

// Delete implements the AccessRuleService interface Delete function.
func (s *AccessRuleService) Delete(path string, accountName string) error {
	return s.DeleteFunc(path, accountName)
}

// Get implements the AccessRuleService interface Get function.
func (s *AccessRuleService) Get(path string, accountName string) (*api.AccessRule, error) {
	return s.GetFunc(path, accountName)
}

// ListLevels implements the AccessRuleService interface ListLevels function.
func (s *AccessRuleService) ListLevels(path string) ([]*api.AccessLevel, error) {
	return s.ListLevelsFunc(path)
}

// List implements the AccessRuleService interface List function.
func (s *AccessRuleService) List(path string, depth int, ancestors bool) ([]*api.AccessRule, error) {
	return s.ListFunc(path, depth, ancestors)
}

// Set implements the AccessRuleService interface Set function.
func (s *AccessRuleService) Set(path string, permission string, accountName string) (*api.AccessRule, error) {
	return s.SetFunc(path, permission, accountName)
}
