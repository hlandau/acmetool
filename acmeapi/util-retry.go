package acmeapi

import (
	"github.com/hlandau/goutils/clock"
	"golang.org/x/net/context"
	"net/http"
	"strconv"
	"time"
)

var defaultClock = clock.Real

func parseRetryAfter(h http.Header) (t time.Time, ok bool) {
	v := h.Get("Retry-After")
	if v == "" {
		return time.Time{}, false
	}

	n, err := strconv.ParseUint(v, 10, 31)
	if err != nil {
		t, err = time.Parse(time.RFC1123, v)
		if err != nil {
			return time.Time{}, false
		}

		return t, true
	}

	return defaultClock.Now().Add(time.Duration(n) * time.Second), true
}

func retryAtDefault(h http.Header, d time.Duration) time.Time {
	t, ok := parseRetryAfter(h)
	if ok {
		return t
	}

	return defaultClock.Now().Add(d)
}

// Wait until time t. If t is before the current time, returns immediately.
// Cancellable via ctx, in which case err is passed through. Otherwise returns
// nil.
func waitUntil(t time.Time, ctx context.Context) error {
	var ch <-chan time.Time
	ch = closedChannel
	now := defaultClock.Now()
	if t.After(now) {
		ch = defaultClock.After(t.Sub(now))
	}

	// make sure ctx.Done() is checked here even when we are using closedChannel,
	// as select doesn't guarantee any particular priority.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
		}
	}

	return nil
}

var closedChannel = make(chan time.Time)

func init() {
	close(closedChannel)
}
