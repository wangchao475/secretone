package secretone

import (
	"github.com/wangchao475/secretone/internals/api"
	"github.com/wangchao475/secretone/internals/errio"
	"github.com/wangchao475/secretone/pkg/secretone/internals/http"
	"github.com/wangchao475/secretone/pkg/secretone/iterator"
)

func (c *Client) decryptAuditEvents(events ...*api.Audit) error {
	accountKey, err := c.getAccountKey()
	if err != nil {
		return errio.Error(err)
	}

	// Decrypt all Secret names
	for _, event := range events {
		if event.Subject.Deleted {
			continue
		}

		if event.Subject.Type == api.AuditSubjectSecret || event.Subject.Type == api.AuditSubjectSecretMember {
			event.Subject.Secret, err = event.Subject.EncryptedSecret.Decrypt(accountKey)
			if err != nil {
				return errio.Error(err)
			}
		} else if event.Subject.Type == api.AuditSubjectSecretVersion {
			event.Subject.SecretVersion, err = event.Subject.EncryptedSecretVersion.Decrypt(accountKey)
			if err != nil {
				return errio.Error(err)
			}
		}
	}

	return nil
}

func newAuditEventIterator(newPaginator func() (*http.AuditPaginator, error), client *Client) *auditEventIterator {
	return &auditEventIterator{
		iterator: iterator.New(func() (iterator.Paginator, error) {
			return newPaginator()
		}),
		decryptAuditEvents: client.decryptAuditEvents,
	}
}

type AuditEventIterator interface {
	Next() (api.Audit, error)
}

type auditEventIterator struct {
	iterator           iterator.Iterator
	decryptAuditEvents func(...*api.Audit) error
}

func (it *auditEventIterator) Next() (api.Audit, error) {
	item, err := it.iterator.Next()
	if err != nil {
		return api.Audit{}, err
	}
	audit := item.(api.Audit)
	err = it.decryptAuditEvents(&audit)
	if err != nil {
		return api.Audit{}, err
	}
	return audit, nil
}

// AuditEventIteratorParams can be used to configure iteration of audit events.
//
// For now, there's nothing to configure. We'll add filter options soon.
// The struct is already added, so that adding parameters is backwards compatible.
type AuditEventIteratorParams struct{}
