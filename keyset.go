package keyset

import (
	"context"
	"fmt"
	"time"
)

// Keyset is a named collection of keys of one type.
// Not safe for concurrent mutation. Client.Get returns a private copy per call.
type Keyset struct {
	doc document
	// typ mints keys during Rotate. It is set by New and by Rotate with a
	// non-nil Type; keysets from Unmarshal have none until one is supplied.
	typ *Type
}

type document struct {
	Name      string
	Type      string
	Policy    Policy
	PrimaryID string
	Keys      []key
}

type key struct {
	ID          string
	State       KeyState
	CreatedAt   time.Time
	PromotedAt  *time.Time
	PhasedOutAt *time.Time
	DisabledAt  *time.Time
	DeleteAfter *time.Time
	PrivateKey  []byte
	PublicKey   []byte
}

// New creates an in-memory keyset with a primary key and a pending successor.
// It does not read from or write to a Store.
func New(ctx context.Context, name, typ string, t Type) (*Keyset, error) {
	return newAt(ctx, name, typ, t, time.Now().UTC())
}

func newAt(ctx context.Context, name, typ string, t Type, now time.Time) (*Keyset, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalid)
	}
	if typ == "" {
		return nil, fmt.Errorf("%w: type is required", ErrInvalid)
	}
	if err := t.validate(); err != nil {
		return nil, fmt.Errorf("keyset: type %q: %w", typ, err)
	}
	now = now.UTC()

	ks := &Keyset{
		doc: document{
			Name:   name,
			Type:   typ,
			Policy: t.Policy,
		},
		typ: &t,
	}
	if _, err := ks.addKey(ctx, StatePrimary, now, ks.typ); err != nil {
		return nil, fmt.Errorf("keyset: generate key: %w", err)
	}
	if _, err := ks.Rotate(ctx, now, nil); err != nil {
		return nil, err
	}
	return ks, nil
}

// Name returns the keyset name.
func (k *Keyset) Name() string { return k.doc.Name }

// Type returns the registry type name stored on this keyset.
func (k *Keyset) Type() string { return k.doc.Type }

// Policy returns the rotation policy.
func (k *Keyset) Policy() Policy { return k.doc.Policy }

// PrimaryID returns the current primary key id.
func (k *Keyset) PrimaryID() string { return k.doc.PrimaryID }

// Keys returns a copy of all keys, including private material.
func (k *Keyset) Keys() []Key {
	if k == nil {
		return nil
	}
	out := make([]Key, 0, len(k.doc.Keys))
	for i := range k.doc.Keys {
		out = append(out, k.doc.Keys[i].export())
	}
	return out
}

// Key returns a copy of the key with id.
func (k *Keyset) Key(id string) (Key, bool) {
	if k == nil {
		return Key{}, false
	}
	ky, ok := k.keyByID(id)
	if !ok {
		return Key{}, false
	}
	return ky.export(), true
}

// Primary returns a copy of the primary key.
func (k *Keyset) Primary() (Key, bool) {
	if k == nil {
		return Key{}, false
	}
	return k.Key(k.doc.PrimaryID)
}

// Public returns a secret-free view.
func (k *Keyset) Public() Public {
	out := Public{
		Name:      k.doc.Name,
		Type:      k.doc.Type,
		Policy:    k.doc.Policy,
		PrimaryID: k.doc.PrimaryID,
		Keys:      make([]PublicKey, 0, len(k.doc.Keys)),
	}
	for _, ky := range k.doc.Keys {
		pk := PublicKey{ID: ky.ID, State: ky.State}
		if len(ky.PublicKey) > 0 {
			pk.PublicKey = append([]byte(nil), ky.PublicKey...)
		}
		out.Keys = append(out.Keys, pk)
	}
	return out
}

func (k *Keyset) keyByID(id string) (*key, bool) {
	for i := range k.doc.Keys {
		if k.doc.Keys[i].ID == id {
			return &k.doc.Keys[i], true
		}
	}
	return nil, false
}

func (k *Keyset) existingIDs() []string {
	ids := make([]string, 0, len(k.doc.Keys))
	for _, ky := range k.doc.Keys {
		ids = append(ids, ky.ID)
	}
	return ids
}

func (k *Keyset) addKey(ctx context.Context, state KeyState, now time.Time, t *Type) (string, error) {
	if t == nil || t.New == nil {
		return "", fmt.Errorf("%w: key constructor is required", ErrInvalid)
	}
	m, err := t.New(ctx)
	if err != nil {
		return "", err
	}
	id, priv, pub, err := k.applyMaterial(m, t.NewID)
	if err != nil {
		return "", err
	}
	ky := key{
		ID:         id,
		State:      state,
		CreatedAt:  now.UTC(),
		PrivateKey: priv,
		PublicKey:  pub,
	}
	if state == StatePrimary {
		t := now.UTC()
		ky.PromotedAt = &t
		k.doc.PrimaryID = id
	}
	k.doc.Keys = append(k.doc.Keys, ky)
	return id, nil
}

func (ky key) export() Key {
	return Key{
		ID:          ky.ID,
		State:       ky.State,
		CreatedAt:   ky.CreatedAt,
		PromotedAt:  cloneTime(ky.PromotedAt),
		PhasedOutAt: cloneTime(ky.PhasedOutAt),
		DisabledAt:  cloneTime(ky.DisabledAt),
		DeleteAfter: cloneTime(ky.DeleteAfter),
		Private:     append([]byte(nil), ky.PrivateKey...),
		Public:      append([]byte(nil), ky.PublicKey...),
	}
}

// clone returns a deep copy that shares no mutable state with k.
func (k *Keyset) clone() *Keyset {
	c := &Keyset{doc: k.doc, typ: k.typ}
	c.doc.Keys = make([]key, len(k.doc.Keys))
	for i, ky := range k.doc.Keys {
		ky.PromotedAt = cloneTime(ky.PromotedAt)
		ky.PhasedOutAt = cloneTime(ky.PhasedOutAt)
		ky.DisabledAt = cloneTime(ky.DisabledAt)
		ky.DeleteAfter = cloneTime(ky.DeleteAfter)
		ky.PrivateKey = append([]byte(nil), ky.PrivateKey...)
		ky.PublicKey = append([]byte(nil), ky.PublicKey...)
		c.doc.Keys[i] = ky
	}
	return c
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	c := t.UTC()
	return &c
}

func (k *Keyset) validate() error {
	if k == nil {
		return fmt.Errorf("%w: nil keyset", ErrInvalid)
	}
	if err := validateDocumentMetadata(k.doc); err != nil {
		return err
	}
	for _, ky := range k.doc.Keys {
		if len(ky.PrivateKey) == 0 {
			return fmt.Errorf("%w: key %q missing private material", ErrInvalid, ky.ID)
		}
	}
	return nil
}

func validateDocumentMetadata(d document) error {
	if d.Name == "" {
		return fmt.Errorf("%w: empty name", ErrInvalid)
	}
	if d.Type == "" {
		return fmt.Errorf("%w: empty type", ErrInvalid)
	}
	if err := d.Policy.validate(); err != nil {
		return err
	}
	if len(d.Keys) == 0 {
		return fmt.Errorf("%w: no keys", ErrInvalid)
	}

	seen := make(map[string]struct{}, len(d.Keys))
	var primaryCount int
	var foundPrimary bool
	for _, ky := range d.Keys {
		if err := validateKeyID(ky.ID); err != nil {
			return err
		}
		if _, ok := seen[ky.ID]; ok {
			return fmt.Errorf("%w: duplicate key id %q", ErrInvalid, ky.ID)
		}
		seen[ky.ID] = struct{}{}
		switch ky.State {
		case StatePending, StatePrimary, StatePhasingOut, StateDisabled:
		default:
			return fmt.Errorf("%w: unknown state %q", ErrInvalid, ky.State)
		}
		if ky.CreatedAt.IsZero() {
			return fmt.Errorf("%w: key %q missing created_at", ErrInvalid, ky.ID)
		}
		if ky.State == StatePrimary && ky.PromotedAt == nil {
			return fmt.Errorf("%w: primary key %q missing promoted_at", ErrInvalid, ky.ID)
		}
		if ky.State == StatePhasingOut && ky.PhasedOutAt == nil {
			return fmt.Errorf("%w: phasing-out key %q missing phased_out_at", ErrInvalid, ky.ID)
		}
		if ky.State == StateDisabled && ky.DisabledAt == nil {
			return fmt.Errorf("%w: disabled key %q missing disabled_at", ErrInvalid, ky.ID)
		}
		if ky.PromotedAt != nil && ky.PromotedAt.Before(ky.CreatedAt) {
			return fmt.Errorf("%w: key %q promoted before creation", ErrInvalid, ky.ID)
		}
		if ky.PhasedOutAt != nil && (ky.PromotedAt == nil || ky.PhasedOutAt.Before(*ky.PromotedAt)) {
			return fmt.Errorf("%w: key %q has invalid phased_out_at", ErrInvalid, ky.ID)
		}
		if ky.DisabledAt != nil && (ky.PhasedOutAt == nil || ky.DisabledAt.Before(*ky.PhasedOutAt)) {
			return fmt.Errorf("%w: key %q has invalid disabled_at", ErrInvalid, ky.ID)
		}
		if ky.DeleteAfter != nil && (ky.DisabledAt == nil || ky.DeleteAfter.Before(*ky.DisabledAt)) {
			return fmt.Errorf("%w: key %q has invalid delete_after", ErrInvalid, ky.ID)
		}
		switch ky.State {
		case StatePending:
			if ky.PromotedAt != nil || ky.PhasedOutAt != nil || ky.DisabledAt != nil || ky.DeleteAfter != nil {
				return fmt.Errorf("%w: pending key %q has lifecycle timestamps", ErrInvalid, ky.ID)
			}
		case StatePrimary:
			if ky.PhasedOutAt != nil || ky.DisabledAt != nil || ky.DeleteAfter != nil {
				return fmt.Errorf("%w: primary key %q has post-primary timestamps", ErrInvalid, ky.ID)
			}
		case StatePhasingOut:
			if ky.DisabledAt != nil || ky.DeleteAfter != nil {
				return fmt.Errorf("%w: phasing-out key %q has disabled timestamps", ErrInvalid, ky.ID)
			}
		}
		if ky.State == StatePrimary {
			primaryCount++
			if ky.ID == d.PrimaryID {
				foundPrimary = true
			}
		}
	}
	if primaryCount != 1 {
		return fmt.Errorf("%w: want exactly one primary, found %d", ErrInvalid, primaryCount)
	}
	if !foundPrimary {
		return fmt.Errorf("%w: primary_id %q is not primary", ErrInvalid, d.PrimaryID)
	}
	return nil
}

// String redacts secrets.
func (k *Keyset) String() string {
	if k == nil {
		return "keyset.Keyset<nil>"
	}
	return fmt.Sprintf("keyset.Keyset{name=%q type=%s keys=%d primary=%s}",
		k.doc.Name, k.doc.Type, len(k.doc.Keys), k.doc.PrimaryID)
}

// GoString redacts secrets.
func (k *Keyset) GoString() string { return k.String() }
