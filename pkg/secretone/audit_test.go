package secretone

import (
	"testing"

	"github.com/wangchao475/secretone/internals/api"
	"github.com/wangchao475/secretone/internals/api/uuid"
	"github.com/wangchao475/secretone/internals/assert"
	"github.com/wangchao475/secretone/pkg/secretone/iterator"
)

type fakeAuditPaginator struct {
	events   []api.Audit
	returned bool
}

func (pag *fakeAuditPaginator) Next() ([]interface{}, error) {
	if pag.returned {
		return []interface{}{}, nil
	}

	res := make([]interface{}, len(pag.events))
	for i, event := range pag.events {
		res[i] = event
	}
	pag.returned = true
	return res, nil
}

func TestAuditEventIterator_Next(t *testing.T) {
	events := []api.Audit{
		{
			EventID: uuid.New(),
			Action:  api.AuditActionRead,
		},
	}

	iter := auditEventIterator{
		iterator: iterator.New(func() (iterator.Paginator, error) {
			return &fakeAuditPaginator{events: events}, nil
		}),
		decryptAuditEvents: func(audit ...*api.Audit) error {
			return nil
		},
	}

	for _, event := range events {
		actual, err := iter.Next()

		assert.Equal(t, err, nil)
		assert.Equal(t, actual, event)
	}
	_, err := iter.Next()
	assert.Equal(t, err, iterator.Done)
}
