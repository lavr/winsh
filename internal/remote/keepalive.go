package remote

import (
	"context"
	"sync"
	"time"
)

// Windows HTTP.sys closes idle connections after 120 seconds by default, and
// an administrator may lower that. A lane idle for HeartbeatInterval gets an
// Identify at the next tick, so it is never idle much beyond twice that.
// heartbeatTimeout bounds how long a cleanup waits behind a heartbeat on its
// lane, within the five-second cleanup budget.
const (
	HeartbeatInterval = 30 * time.Second
	heartbeatTimeout  = 2 * time.Second
)

type keepAliver interface {
	KeepAlive(context.Context, time.Duration) error
}

// KeepAliveLanes sends one heartbeat round: each persistent lane idle for
// HeartbeatInterval gets an Identify. Lanes without a heartbeat are skipped.
func KeepAliveLanes(ctx context.Context, lanes ...Poster) error {
	for _, lane := range lanes {
		k, ok := lane.(keepAliver)
		if !ok {
			continue
		}
		laneCtx, cancel := context.WithTimeout(ctx, heartbeatTimeout)
		err := k.KeepAlive(laneCtx, HeartbeatInterval)
		cancel()
		if err != nil {
			return err
		}
	}
	return nil
}

// keepLanesAlive runs heartbeat rounds every interval until stop is called.
// A failed round ends the loop: the failed lane is already unusable and a
// later exchange on it reports that. stop waits for an in-flight round.
func keepLanesAlive(ctx context.Context, interval time.Duration, lanes ...Poster) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if ctx.Err() != nil || KeepAliveLanes(ctx, lanes...) != nil {
				return
			}
		}
	}()
	return func() { cancel(); wg.Wait() }
}
