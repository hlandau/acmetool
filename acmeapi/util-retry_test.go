package acmeapi

import (
	"github.com/hlandau/goutils/clock"
	"golang.org/x/net/context"
	"net/http"
	"testing"
	"time"
)

func withClock(cl clock.Clock, f func()) {
	origClock := defaultClock
	defer func() {
		defaultClock = origClock
	}()

	defaultClock = cl
	f()
}

var clk clock.Fake
var slowClk clock.Fake

func init() {
	refTime, _ := time.Parse(time.RFC3339, "2009-10-11T11:09:06Z")
	clk = clock.NewFastAt(refTime)
	slowClk = clock.NewSlowAt(refTime)
}

func TestRetryAfter(t *testing.T) {
	withClock(clk, func() {
		h := http.Header{}
		t1, ok := parseRetryAfter(h)
		if ok {
			t.Fatal()
		}

		h.Set("Retry-After", "Mon, 02 Jan 2006 15:04:05 UTC")
		t1 = retryAtDefault(h, 1*time.Second)
		tref, _ := time.Parse("Mon, 02 Jan 2006 15:04:05 UTC", "Mon, 02 Jan 2006 15:04:05 UTC")
		if t1 != tref || tref.IsZero() {
			t.Fatal()
		}

		t2, _ := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
		if t1 != t2 {
			t.Fatalf("%v %v", t1, t2)
		}

		h.Set("Retry-After", "20")
		t1, ok = parseRetryAfter(h)
		now := defaultClock.Now()
		if !ok {
			t.Fatal()
		}
		d := now.Add(20 * time.Second).Sub(t1)
		if d != 0 {
			t.Fatalf("%v", d)
		}

		h.Set("Retry-After", "Mon 02 Jan 2006 15:04:05 UTC")
		t1, ok = parseRetryAfter(h)
		if ok || !t1.IsZero() {
			t.Fatal()
		}
	})
}

func TestRetryAfterDefault(t *testing.T) {
	withClock(clk, func() {
		h := http.Header{}
		t1 := retryAtDefault(h, 42*time.Second)
		now := defaultClock.Now()
		d := now.Add(42 * time.Second).Sub(t1)
		if d != 0 {
			t.Fatalf("%v", d)
		}
	})
}

func TestWaitUntil(t *testing.T) {
	withClock(clk, func() {
		tgt := defaultClock.Now().Add(49828 * time.Millisecond)
		waitUntil(tgt, context.TODO())
		if defaultClock.Now().Sub(tgt) != 0 {
			t.Fatalf("%v", defaultClock.Now().Sub(tgt))
		}
	})

	withClock(slowClk, func() {
		tgt := defaultClock.Now().Add(49828 * time.Millisecond)
		ctx, _ := context.WithTimeout(context.TODO(), 10*time.Millisecond)
		err := waitUntil(tgt, ctx)
		if err == nil {
			t.Fatal()
		}

		ctx, cancel := context.WithCancel(context.TODO())
		cancel()
		err = waitUntil(tgt, ctx)
		if err == nil {
			t.Fatal()
		}

		slowClk.Advance(49829 * time.Millisecond)
		err = waitUntil(tgt, context.TODO())
		if err != nil {
			t.Fatal()
		}
	})
}
