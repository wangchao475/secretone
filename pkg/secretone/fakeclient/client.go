// +build !production

// Package fakeclient provides mock implementations of
// the client to be used for testing.
package fakeclient

import "github.com/wangchao475/secretone/pkg/secretone"

var _ secretone.ClientInterface = (*Client)(nil)

// Client implements the secretone.Client interface.
type Client struct {
	AccessRuleService *AccessRuleService
	AccountService    *AccountService
	CredentialService *CredentialService
	DirService        *DirService
	IDPLinkService    *IDPLinkService
	MeService         *MeService
	OrgService        *OrgService
	RepoService       *RepoService
	SecretService     *SecretService
	ServiceService    *ServiceService
	UserService       *UserService
}

// AccessRules implements the secretone.Client interface.
func (c Client) AccessRules() secretone.AccessRuleService {
	return c.AccessRuleService
}

// Accounts implements the secretone.Client interface.
func (c Client) Accounts() secretone.AccountService {
	return c.AccountService
}

// Dirs implements the secretone.Client interface.
func (c Client) Dirs() secretone.DirService {
	return c.DirService
}

// Me implements the secretone.Client interface.
func (c Client) Me() secretone.MeService {
	return c.MeService
}

// Orgs implements the secretone.Client interface.
func (c Client) Orgs() secretone.OrgService {
	return c.OrgService
}

// Repos implements the secretone.Client interface.
func (c Client) Repos() secretone.RepoService {
	return c.RepoService
}

// Secrets implements the secretone.Client interface.
func (c Client) Secrets() secretone.SecretService {
	return c.SecretService
}

// Services implements the secretone.Client interface.
func (c Client) Services() secretone.ServiceService {
	return c.ServiceService
}

// Users implements the secretone.Client interface.
func (c Client) Users() secretone.UserService {
	return c.UserService
}

func (c Client) IDPLinks() secretone.IDPLinkService {
	return c.IDPLinkService
}

func (c Client) Credentials() secretone.CredentialService {
	return c.CredentialService
}
