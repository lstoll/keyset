package keyset

import (
	"context"
	"fmt"
)

// Registry maps type names to constructors and policies.
type Registry struct {
	types map[string]Type
}

// NewRegistry copies types. Type names must be non-empty, New required, Policy valid.
func NewRegistry(types map[string]Type) (*Registry, error) {
	r := &Registry{types: make(map[string]Type, len(types))}
	for name, t := range types {
		if name == "" {
			return nil, fmt.Errorf("%w: type name is required", ErrInvalid)
		}
		if err := t.validate(); err != nil {
			return nil, fmt.Errorf("keyset: type %q: %w", name, err)
		}
		r.types[name] = t
	}
	return r, nil
}

// Lookup returns the registered type.
func (r *Registry) Lookup(typ string) (Type, bool) {
	if r == nil {
		return Type{}, false
	}
	t, ok := r.types[typ]
	return t, ok
}

// New constructs a keyset of the registered type.
func (r *Registry) New(ctx context.Context, name, typ string) (*Keyset, error) {
	t, ok := r.Lookup(typ)
	if !ok {
		return nil, fmt.Errorf("%w: unknown type %q", ErrInvalid, typ)
	}
	return New(ctx, name, typ, t)
}
