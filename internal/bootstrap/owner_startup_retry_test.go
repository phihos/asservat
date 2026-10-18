package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/configuration"
)

func TestRetryChangedProvesAgainOnlyOnChange(t *testing.T) {
	calls := 0
	until, err := retryChanged(context.Background(), func() (time.Time, error) {
		calls++
		if calls == 1 {
			return time.Time{}, errors.Join(configuration.ErrChanged, errors.New("journal"))
		}
		return time.Unix(10, 0), nil
	})
	if err != nil || calls != 2 || !until.Equal(time.Unix(10, 0)) {
		t.Fatal("changed proof was not proved again", calls, err)
	}
	calls = 0
	if _, err = retryChanged(context.Background(), func() (time.Time, error) { calls++; return time.Time{}, configuration.ErrDenied }); !errors.Is(err, configuration.ErrDenied) || calls != 1 {
		t.Fatal("a denial was retried", calls)
	}
	calls = 0
	if _, err = retryChanged(context.Background(), func() (time.Time, error) { calls++; return time.Time{}, configuration.ErrChanged }); !errors.Is(err, configuration.ErrChanged) || calls != 3 {
		t.Fatal("retries are not bounded", calls)
	}
}
