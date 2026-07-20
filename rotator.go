package keyset

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Spec describes a keyset that Rotator.Ensure should create if missing.
type Spec struct {
	Algorithm Algorithm
	Policy    Policy
}

// Rotator rotates keysets in an AdminStore.
type Rotator struct {
	store    AdminStore
	interval time.Duration
	now      func() time.Time
	ensure   map[string]Spec
	logger   *slog.Logger

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// RotatorOption configures NewRotator.
type RotatorOption func(*Rotator) error

// WithInterval sets how often Run wakes up. Required for Run; ignored by Once.
func WithInterval(d time.Duration) RotatorOption {
	return func(r *Rotator) error {
		if d <= 0 {
			return errors.New("keyset: interval must be positive")
		}
		r.interval = d
		return nil
	}
}

// WithEnsure provisions named keysets when missing.
func WithEnsure(specs map[string]Spec) RotatorOption {
	return func(r *Rotator) error {
		for name, spec := range specs {
			if _, err := spec.Algorithm.purpose(); err != nil {
				return fmt.Errorf("keyset: ensure %q: %w", name, err)
			}
			if err := spec.Policy.validate(); err != nil {
				return fmt.Errorf("keyset: ensure %q: %w", name, err)
			}
			r.ensure[name] = spec
		}
		return nil
	}
}

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) RotatorOption {
	return func(r *Rotator) error {
		if l != nil {
			r.logger = l
		}
		return nil
	}
}

// WithClock overrides time for tests.
func WithClock(now func() time.Time) RotatorOption {
	return func(r *Rotator) error {
		if now != nil {
			r.now = now
		}
		return nil
	}
}

// NewRotator constructs a Rotator.
func NewRotator(store AdminStore, opts ...RotatorOption) (*Rotator, error) {
	if store == nil {
		return nil, errors.New("keyset: store is required")
	}
	r := &Rotator{
		store:  store,
		now:    time.Now,
		ensure: make(map[string]Spec),
		logger: slog.Default().With("component", "keyset.rotator"),
	}
	for _, opt := range opts {
		if err := opt(r); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Once runs a single rotation pass (and Ensure provisioning).
func (r *Rotator) Once(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	r.logger.Info("rotation pass starting")
	var first error
	seen := make(map[string]struct{})

	err := r.store.ForEach(ctx, func(name string) error {
		seen[name] = struct{}{}
		if err := r.process(ctx, name); err != nil {
			r.logger.Error("rotate failed", "name", name, "error", err)
			if first == nil {
				first = err
			}
		}
		return nil
	})
	if err != nil && first == nil {
		first = err
	}

	for name, spec := range r.ensure {
		if _, ok := seen[name]; ok {
			continue
		}
		_, _, err := r.store.Read(ctx, name)
		if err == nil {
			continue
		}
		if !errors.Is(err, ErrNotFound) {
			if first == nil {
				first = err
			}
			continue
		}
		if err := r.Ensure(ctx, name, spec.Algorithm, spec.Policy); err != nil {
			r.logger.Error("ensure failed", "name", name, "error", err)
			if first == nil {
				first = err
			}
		}
	}
	r.logger.Info("rotation pass finished")
	return first
}

func (r *Rotator) process(ctx context.Context, name string) error {
	ks, rev, err := r.store.Read(ctx, name)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	changed, err := ks.Rotate(r.now())
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	if err := r.store.Write(ctx, name, ks, rev); err != nil {
		if errors.Is(err, ErrConflict) {
			r.logger.Warn("conflict writing rotation", "name", name)
			return nil
		}
		return err
	}
	r.logger.Info("rotated", "name", name)
	return nil
}

// Ensure creates name if it does not exist.
func (r *Rotator) Ensure(ctx context.Context, name string, alg Algorithm, policy Policy) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalid)
	}
	if _, err := alg.purpose(); err != nil {
		return err
	}
	if err := policy.validate(); err != nil {
		return err
	}
	ks, _, err := r.store.Read(ctx, name)
	if err == nil {
		if ks.Algorithm() != alg || ks.Policy() != policy {
			return fmt.Errorf("%w: existing keyset %q does not match requested specification", ErrExist, name)
		}
		return nil
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	ks, err = newAt(name, alg, policy, r.now())
	if err != nil {
		return err
	}
	if err := r.store.Write(ctx, name, ks, nil); err != nil {
		if errors.Is(err, ErrConflict) {
			existing, _, readErr := r.store.Read(ctx, name)
			if readErr == nil && existing.Algorithm() == alg && existing.Policy() == policy {
				return nil
			}
		}
		return err
	}
	r.logger.Info("ensured", "name", name, "algorithm", alg)
	return nil
}

// Run starts periodic Once calls until ctx is cancelled or Stop is called.
// WithInterval must have been set.
func (r *Rotator) Run(ctx context.Context) error {
	if r.interval <= 0 {
		return errors.New("keyset: WithInterval is required for Run")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return errors.New("keyset: rotator already running")
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.running = true
	r.done = make(chan struct{})
	done := r.done
	r.mu.Unlock()

	go func() {
		defer func() {
			r.mu.Lock()
			r.running = false
			r.cancel = nil
			close(done)
			r.mu.Unlock()
		}()
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()
		if err := r.Once(runCtx); err != nil {
			r.logger.Error("initial pass", "error", err)
		}
		for {
			select {
			case <-ticker.C:
				if err := r.Once(runCtx); err != nil {
					r.logger.Error("periodic pass", "error", err)
				}
			case <-runCtx.Done():
				return
			}
		}
	}()
	return nil
}

// Stop ends Run and waits for the background goroutine.
func (r *Rotator) Stop() {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return
	}
	done := r.done
	if r.cancel != nil {
		r.cancel()
	}
	r.mu.Unlock()
	<-done
}
