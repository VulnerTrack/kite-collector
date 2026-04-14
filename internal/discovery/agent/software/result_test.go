package software

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// ---------------------------------------------------------------------------
// Result.Merge
// ---------------------------------------------------------------------------

func TestResult_Merge_AppendsItems(t *testing.T) {
	r := &Result{
		Items: []model.InstalledSoftware{
			{ID: uuid.Must(uuid.NewV7()), SoftwareName: "a", Version: "1"},
		},
	}
	other := &Result{
		Items: []model.InstalledSoftware{
			{ID: uuid.Must(uuid.NewV7()), SoftwareName: "b", Version: "2"},
		},
	}

	r.Merge(other)
	require.Len(t, r.Items, 2)
	assert.Equal(t, "a", r.Items[0].SoftwareName)
	assert.Equal(t, "b", r.Items[1].SoftwareName)
}

func TestResult_Merge_AppendsErrors(t *testing.T) {
	r := &Result{
		Errs: []CollectError{
			{Collector: "a", Line: 1, Err: errors.New("err1")},
		},
	}
	other := &Result{
		Errs: []CollectError{
			{Collector: "b", Line: 2, Err: errors.New("err2")},
		},
	}

	r.Merge(other)
	require.Len(t, r.Errs, 2)
	assert.Equal(t, "a", r.Errs[0].Collector)
	assert.Equal(t, "b", r.Errs[1].Collector)
}

func TestResult_Merge_EmptyIntoEmpty(t *testing.T) {
	r := &Result{}
	other := &Result{}

	r.Merge(other)
	assert.Empty(t, r.Items)
	assert.Empty(t, r.Errs)
}

// ---------------------------------------------------------------------------
// Result.HasErrors / TotalErrors
// ---------------------------------------------------------------------------

func TestResult_HasErrors_True(t *testing.T) {
	r := &Result{
		Errs: []CollectError{{Collector: "test", Err: errors.New("fail")}},
	}
	assert.True(t, r.HasErrors())
	assert.Equal(t, 1, r.TotalErrors())
}

func TestResult_HasErrors_False(t *testing.T) {
	r := &Result{}
	assert.False(t, r.HasErrors())
	assert.Equal(t, 0, r.TotalErrors())
}

// ---------------------------------------------------------------------------
// CollectError
// ---------------------------------------------------------------------------

func TestCollectError_Error_FormatsMessage(t *testing.T) {
	e := &CollectError{
		Collector: "dpkg",
		Line:      42,
		RawLine:   "bad line",
		Err:       errors.New("parse failed"),
	}
	msg := e.Error()
	assert.Contains(t, msg, "dpkg")
	assert.Contains(t, msg, "42")
	assert.Contains(t, msg, "bad line")
	assert.Contains(t, msg, "parse failed")
}

func TestCollectError_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	e := &CollectError{Err: inner}
	assert.True(t, errors.Is(e, inner))
}
