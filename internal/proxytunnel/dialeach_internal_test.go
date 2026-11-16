package proxytunnel

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPartialDeadline(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		remaining time.Duration
		addrsLeft int
		want      time.Duration
	}{
		{name: "equal share", remaining: 10 * time.Second, addrsLeft: 2, want: 5 * time.Second},
		{name: "two-second floor", remaining: 3 * time.Second, addrsLeft: 2, want: 2 * time.Second},
		{name: "less than the floor left", remaining: time.Second, addrsLeft: 3, want: time.Second},
		{name: "last address gets the rest", remaining: 7 * time.Second, addrsLeft: 1, want: 7 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := partialDeadline(now, now.Add(tt.remaining), tt.addrsLeft)
			require.True(t, ok)
			require.Equal(t, tt.want, got.Sub(now))
		})
	}

	_, ok := partialDeadline(now, now, 1)
	require.False(t, ok, "a passed deadline leaves no time to dial")
}

func TestDialBudgetIsTheEarliestLimit(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	require.True(t, dialBudget(context.Background(), &net.Dialer{}, now).IsZero())
	require.Equal(t, now.Add(5*time.Second), dialBudget(context.Background(), &net.Dialer{Timeout: 5 * time.Second}, now))
	require.Equal(t, now.Add(time.Second), dialBudget(context.Background(), &net.Dialer{Timeout: 5 * time.Second, Deadline: now.Add(time.Second)}, now))

	ctx, cancel := context.WithDeadline(context.Background(), now.Add(2*time.Second))
	defer cancel()
	require.Equal(t, now.Add(2*time.Second), dialBudget(ctx, &net.Dialer{Timeout: 5 * time.Second}, now))
}

// blackholeThenConnect is an attempt whose first call waits for its context
// like a dial to an address that drops packets, and whose later calls connect.
func blackholeThenConnect(t *testing.T, firstLasted *time.Duration) func(context.Context, int) (net.Conn, error) {
	return func(ctx context.Context, i int) (net.Conn, error) {
		if i == 0 {
			start := time.Now()
			<-ctx.Done()
			*firstLasted = time.Since(start)
			return nil, ctx.Err()
		}
		client, server := net.Pipe()
		t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
		return client, nil
	}
}

func TestDialInTurnSplitsTheBudgetAcrossAddresses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var firstLasted time.Duration
		conn, err := dialInTurn(t.Context(), time.Now().Add(10*time.Second), 2, blackholeThenConnect(t, &firstLasted))
		require.NoError(t, err)
		require.NotNil(t, conn)
		require.Equal(t, 5*time.Second, firstLasted)
	})
}

func TestDialInTurnKeepsTheFloorForTheFirstAddress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var firstLasted time.Duration
		conn, err := dialInTurn(t.Context(), time.Now().Add(3*time.Second), 2, blackholeThenConnect(t, &firstLasted))
		require.NoError(t, err)
		require.NotNil(t, conn)
		require.Equal(t, 2*time.Second, firstLasted)
	})
}

func TestDialInTurnReportsEveryFailure(t *testing.T) {
	first, second := errors.New("refused one"), errors.New("refused two")
	conn, err := dialInTurn(t.Context(), time.Time{}, 2, func(_ context.Context, i int) (net.Conn, error) {
		return nil, []error{first, second}[i]
	})
	require.Nil(t, conn)
	require.ErrorIs(t, err, first)
	require.ErrorIs(t, err, second)
}

func TestDialInTurnStopsWhenTheBudgetIsSpent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		attempts := 0
		conn, err := dialInTurn(t.Context(), time.Now().Add(time.Second), 3, func(ctx context.Context, _ int) (net.Conn, error) {
			attempts++
			<-ctx.Done()
			return nil, ctx.Err()
		})
		require.Nil(t, conn)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Equal(t, 1, attempts)
	})
}

func TestDialInTurnRefusesAnEmptyList(t *testing.T) {
	_, err := dialInTurn(t.Context(), time.Time{}, 0, nil)
	require.ErrorContains(t, err, "no address to dial")
}
