// Package memstore is an in-memory keyset.AdminStore, mainly for tests and
// single-process use. Contents are lost when the process exits.
package memstore

import (
	"context"
	"fmt"
	"sync"

	"lds.li/keyset"
)

// Store is an in-memory AdminStore.
type Store struct {
	keeper keyset.Keeper

	mu      sync.Mutex
	entries map[string]entry
}

type entry struct {
	blob []byte
	rev  int64
}

// New returns a Store that seals keysets with keeper.
func New(keeper keyset.Keeper) *Store {
	if keeper == nil {
		panic("memstore: keeper is required")
	}
	return &Store{
		keeper:  keeper,
		entries: make(map[string]entry),
	}
}

func (s *Store) Get(ctx context.Context, name string) (*keyset.Keyset, error) {
	ks, _, err := s.Read(ctx, name)
	return ks, err
}

func (s *Store) Public(_ context.Context, name string) (keyset.Public, error) {
	s.mu.Lock()
	entry, ok := s.entries[name]
	s.mu.Unlock()
	if !ok {
		return keyset.Public{}, keyset.ErrNotFound
	}
	public, err := keyset.UnmarshalPublic(entry.blob)
	if err != nil {
		return keyset.Public{}, err
	}
	if public.Name != name {
		return keyset.Public{}, fmt.Errorf("%w: stored public name %q does not match %q", keyset.ErrInvalid, public.Name, name)
	}
	return public, nil
}

func (s *Store) Read(_ context.Context, name string) (*keyset.Keyset, any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[name]
	if !ok {
		return nil, nil, keyset.ErrNotFound
	}
	ks, err := keyset.Unmarshal(name, e.blob, s.keeper)
	if err != nil {
		return nil, nil, err
	}
	return ks, e.rev, nil
}

func (s *Store) Write(_ context.Context, name string, ks *keyset.Keyset, rev any) error {
	if ks == nil || ks.Name() != name {
		return keyset.ErrInvalid
	}
	blob, err := ks.Marshal(s.keeper)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cur, exists := s.entries[name]
	if rev == nil {
		if exists {
			return keyset.ErrConflict
		}
		s.entries[name] = entry{blob: blob, rev: 1}
		return nil
	}
	want, ok := rev.(int64)
	if !ok {
		return keyset.ErrInvalid
	}
	if !exists || cur.rev != want {
		return keyset.ErrConflict
	}
	s.entries[name] = entry{blob: blob, rev: cur.rev + 1}
	return nil
}

func (s *Store) ForEach(_ context.Context, fn func(name string) error) error {
	s.mu.Lock()
	names := make([]string, 0, len(s.entries))
	for n := range s.entries {
		names = append(names, n)
	}
	s.mu.Unlock()
	for _, n := range names {
		if err := fn(n); err != nil {
			return err
		}
	}
	return nil
}

var _ keyset.AdminStore = (*Store)(nil)
