package iterator

import (
	"testing"

	"github.com/wangchao475/secretone/internals/assert"
)

func TestPaginatorConstructorWithFetch(t *testing.T) {
	it := New(PaginatorFactory(func() ([]interface{}, error) {
		return []interface{}{"this", "is", "a", "test"}, nil
	}))

	expected := []string{"this", "is", "a", "test"}
	i := 0

	for {
		str, err := it.Next()
		if err == Done {
			break
		} else if err != nil {
			t.Fail()
		} else {
			assert.Equal(t, str, expected[i])
			i++
		}
	}
}
