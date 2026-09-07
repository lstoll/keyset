package keyset

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Client caches keysets from a Store. Get and Public reload an expired cache
// entry, but a previously returned Keyset or Public value never refreshes itself.
type Client struct {
	store Store
	ttl   time.Duration

	mu          sync.Mutex
	cache       map[string]*cacheEntry
	publicCache map[string]*publicCacheEntry
}

type cacheEntry struct {
	ks   *Keyset
	when time.Time
}

type publicCacheEntry struct {
	public Public
	when   time.Time
}

// ClientOption configures NewClient.
type ClientOption func(*Client) error

// WithTTL sets the handle cache lifetime. Default is 5 minutes.
func WithTTL(ttl time.Duration) ClientOption {
	return func(c *Client) error {
		if ttl < 0 {
			return fmt.Errorf("%w: client TTL cannot be negative", ErrInvalid)
		}
		c.ttl = ttl
		return nil
	}
}

// NewClient returns a caching client over store.
func NewClient(store Store, opts ...ClientOption) (*Client, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: client store is required", ErrInvalid)
	}
	c := &Client{
		store:       store,
		ttl:         5 * time.Minute,
		cache:       make(map[string]*cacheEntry),
		publicCache: make(map[string]*publicCacheEntry),
	}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Client) get(ctx context.Context, name string) (*Keyset, error) {
	c.mu.Lock()
	if e, ok := c.cache[name]; ok && c.ttl > 0 && time.Since(e.when) < c.ttl {
		c.mu.Unlock()
		return e.ks.clone(), nil
	}
	c.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	ks, err := c.store.Get(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("keyset: load %q: %w", name, err)
	}
	if ks == nil {
		return nil, fmt.Errorf("%w: store returned nil keyset for %q", ErrInvalid, name)
	}
	c.mu.Lock()
	c.cache[name] = &cacheEntry{ks: ks.clone(), when: time.Now()}
	c.mu.Unlock()
	return ks, nil
}

func (c *Client) getPublic(ctx context.Context, name string) (Public, error) {
	c.mu.Lock()
	if e, ok := c.publicCache[name]; ok && c.ttl > 0 && time.Since(e.when) < c.ttl {
		c.mu.Unlock()
		return clonePublic(e.public), nil
	}
	c.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	public, err := c.store.Public(ctx, name)
	if err != nil {
		return Public{}, fmt.Errorf("keyset: load public %q: %w", name, err)
	}
	c.mu.Lock()
	c.publicCache[name] = &publicCacheEntry{public: clonePublic(public), when: time.Now()}
	c.mu.Unlock()
	return clonePublic(public), nil
}

func clonePublic(in Public) Public {
	out := in
	out.Keys = make([]PublicKey, len(in.Keys))
	for i, key := range in.Keys {
		out.Keys[i] = key
		out.Keys[i].PublicKey = append([]byte(nil), key.PublicKey...)
	}
	return out
}

// Get loads name subject to the configured TTL and returns a snapshot keyset.
// Each call returns a separate copy, so callers may mutate it (e.g. Rotate)
// without affecting other callers or the cache.
func (c *Client) Get(ctx context.Context, name string) (*Keyset, error) {
	return c.get(ctx, name)
}

// Public returns the public view for name.
func (c *Client) Public(ctx context.Context, name string) (Public, error) {
	return c.getPublic(ctx, name)
}
