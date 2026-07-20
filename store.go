package keyset

import "context"

// Store loads keysets for crypto clients.
type Store interface {
	Get(ctx context.Context, name string) (*Keyset, error)
	Public(ctx context.Context, name string) (Public, error)
}

// AdminStore supports rotation writes with optimistic concurrency.
type AdminStore interface {
	Store
	// Read returns the keyset and an opaque revision for a later Write.
	Read(ctx context.Context, name string) (ks *Keyset, rev any, err error)
	// Write persists ks. rev nil means insert; otherwise it must match Read.
	Write(ctx context.Context, name string, ks *Keyset, rev any) error
	ForEach(ctx context.Context, fn func(name string) error) error
}
