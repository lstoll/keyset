package keyset

import (
	"fmt"
	"time"
)

// Keyset is an opaque, named collection of keys for one algorithm.
// Not safe for concurrent mutation; share only after construction if read-only.
type Keyset struct {
	doc document
}

type document struct {
	Version   int       `json:"version"`
	Name      string    `json:"name"`
	Purpose   purpose   `json:"purpose"`
	Algorithm Algorithm `json:"algorithm"`
	Policy    Policy    `json:"policy"`
	PrimaryID uint32    `json:"primary_id"`
	Keys      []key     `json:"keys"`
}

type key struct {
	ID          uint32     `json:"id"`
	State       keyState   `json:"state"`
	CreatedAt   time.Time  `json:"created_at"`
	PromotedAt  *time.Time `json:"promoted_at,omitempty"`
	PhasedOutAt *time.Time `json:"phased_out_at,omitempty"`
	DisabledAt  *time.Time `json:"disabled_at,omitempty"`
	DeleteAfter *time.Time `json:"delete_after,omitempty"`
	PrivateKey  []byte     `json:"private_key,omitempty"`
	PublicKey   []byte     `json:"public_key,omitempty"`
}

// New creates an in-memory keyset with a primary key and a pending successor.
// It does not read from or write to a Store.
func New(name string, alg Algorithm, policy Policy) (*Keyset, error) {
	return newAt(name, alg, policy, time.Now().UTC())
}

func newAt(name string, alg Algorithm, policy Policy, now time.Time) (*Keyset, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalid)
	}
	purp, err := alg.purpose()
	if err != nil {
		return nil, err
	}
	if err := policy.validate(); err != nil {
		return nil, err
	}
	now = now.UTC()

	priv, pub, err := generateMaterial(alg)
	if err != nil {
		return nil, fmt.Errorf("keyset: generate key: %w", err)
	}
	id, err := generateKeyID(nil)
	if err != nil {
		return nil, err
	}
	promoted := now
	ks := &Keyset{doc: document{
		Version:   documentVersion,
		Name:      name,
		Purpose:   purp,
		Algorithm: alg,
		Policy:    policy,
		PrimaryID: id,
		Keys: []key{{
			ID:         id,
			State:      statePrimary,
			CreatedAt:  now,
			PromotedAt: &promoted,
			PrivateKey: priv,
			PublicKey:  pub,
		}},
	}}
	if _, err := ks.Rotate(now); err != nil {
		return nil, err
	}
	return ks, nil
}

// Name returns the keyset name.
func (k *Keyset) Name() string { return k.doc.Name }

// Algorithm returns the frozen algorithm.
func (k *Keyset) Algorithm() Algorithm { return k.doc.Algorithm }

// Policy returns the rotation policy.
func (k *Keyset) Policy() Policy { return k.doc.Policy }

// PrimaryID returns the current primary key id.
func (k *Keyset) PrimaryID() uint32 { return k.doc.PrimaryID }

// Public returns a secret-free view.
func (k *Keyset) Public() Public {
	out := Public{
		Name:      k.doc.Name,
		Algorithm: k.doc.Algorithm,
		PrimaryID: k.doc.PrimaryID,
		Keys:      make([]PublicKey, 0, len(k.doc.Keys)),
	}
	for _, ky := range k.doc.Keys {
		pk := PublicKey{ID: ky.ID, State: string(ky.State)}
		if len(ky.PublicKey) > 0 {
			pk.PublicKey = append([]byte(nil), ky.PublicKey...)
		}
		out.Keys = append(out.Keys, pk)
	}
	return out
}

func (k *Keyset) keyByID(id uint32) (*key, bool) {
	for i := range k.doc.Keys {
		if k.doc.Keys[i].ID == id {
			return &k.doc.Keys[i], true
		}
	}
	return nil, false
}

func (k *Keyset) existingIDs() map[uint32]struct{} {
	m := make(map[uint32]struct{}, len(k.doc.Keys))
	for _, ky := range k.doc.Keys {
		m[ky.ID] = struct{}{}
	}
	return m
}

func (k *Keyset) addKey(state keyState, now time.Time) (uint32, error) {
	priv, pub, err := generateMaterial(k.doc.Algorithm)
	if err != nil {
		return 0, err
	}
	id, err := generateKeyID(k.existingIDs())
	if err != nil {
		return 0, err
	}
	ky := key{
		ID:         id,
		State:      state,
		CreatedAt:  now.UTC(),
		PrivateKey: priv,
		PublicKey:  pub,
	}
	if state == statePrimary {
		t := now.UTC()
		ky.PromotedAt = &t
		k.doc.PrimaryID = id
	}
	k.doc.Keys = append(k.doc.Keys, ky)
	return id, nil
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
			return fmt.Errorf("%w: key %d missing private material", ErrInvalid, ky.ID)
		}
		if _, err := parsePrivateKey(k.doc.Algorithm, ky.PrivateKey); err != nil {
			return fmt.Errorf("key %d: %w", ky.ID, err)
		}
		if k.doc.Purpose == purposeSign {
			if err := validateKeyPair(k.doc.Algorithm, ky.PrivateKey, ky.PublicKey); err != nil {
				return fmt.Errorf("key %d: %w", ky.ID, err)
			}
		}
	}
	return nil
}

func validateDocumentMetadata(d document) error {
	if d.Version != documentVersion {
		return fmt.Errorf("%w: unsupported version %d", ErrInvalid, d.Version)
	}
	if d.Name == "" {
		return fmt.Errorf("%w: empty name", ErrInvalid)
	}
	purp, err := d.Algorithm.purpose()
	if err != nil {
		return err
	}
	if d.Purpose != purp {
		return fmt.Errorf("%w: purpose mismatch", ErrInvalid)
	}
	if err := d.Policy.validate(); err != nil {
		return err
	}
	if len(d.Keys) == 0 {
		return fmt.Errorf("%w: no keys", ErrInvalid)
	}

	seen := make(map[uint32]struct{}, len(d.Keys))
	var primaryCount int
	var foundPrimary bool
	for _, ky := range d.Keys {
		if ky.ID == 0 {
			return fmt.Errorf("%w: key id 0 is reserved", ErrInvalid)
		}
		if _, ok := seen[ky.ID]; ok {
			return fmt.Errorf("%w: duplicate key id %d", ErrInvalid, ky.ID)
		}
		seen[ky.ID] = struct{}{}
		switch ky.State {
		case statePending, statePrimary, statePhasingOut, stateDisabled:
		default:
			return fmt.Errorf("%w: unknown state %q", ErrInvalid, ky.State)
		}
		if ky.CreatedAt.IsZero() {
			return fmt.Errorf("%w: key %d missing created_at", ErrInvalid, ky.ID)
		}
		if d.Purpose == purposeSign && len(ky.PublicKey) == 0 {
			return fmt.Errorf("%w: signing key %d missing public material", ErrInvalid, ky.ID)
		}
		if len(ky.PublicKey) > 0 {
			if _, err := parsePublicKey(d.Algorithm, ky.PublicKey); err != nil {
				return fmt.Errorf("key %d: %w", ky.ID, err)
			}
		}
		if ky.State == statePrimary && ky.PromotedAt == nil {
			return fmt.Errorf("%w: primary key %d missing promoted_at", ErrInvalid, ky.ID)
		}
		if ky.State == statePhasingOut && ky.PhasedOutAt == nil {
			return fmt.Errorf("%w: phasing-out key %d missing phased_out_at", ErrInvalid, ky.ID)
		}
		if ky.State == stateDisabled && ky.DisabledAt == nil {
			return fmt.Errorf("%w: disabled key %d missing disabled_at", ErrInvalid, ky.ID)
		}
		if ky.PromotedAt != nil && ky.PromotedAt.Before(ky.CreatedAt) {
			return fmt.Errorf("%w: key %d promoted before creation", ErrInvalid, ky.ID)
		}
		if ky.PhasedOutAt != nil && (ky.PromotedAt == nil || ky.PhasedOutAt.Before(*ky.PromotedAt)) {
			return fmt.Errorf("%w: key %d has invalid phased_out_at", ErrInvalid, ky.ID)
		}
		if ky.DisabledAt != nil && (ky.PhasedOutAt == nil || ky.DisabledAt.Before(*ky.PhasedOutAt)) {
			return fmt.Errorf("%w: key %d has invalid disabled_at", ErrInvalid, ky.ID)
		}
		if ky.DeleteAfter != nil && (ky.DisabledAt == nil || ky.DeleteAfter.Before(*ky.DisabledAt)) {
			return fmt.Errorf("%w: key %d has invalid delete_after", ErrInvalid, ky.ID)
		}
		switch ky.State {
		case statePending:
			if ky.PromotedAt != nil || ky.PhasedOutAt != nil || ky.DisabledAt != nil || ky.DeleteAfter != nil {
				return fmt.Errorf("%w: pending key %d has lifecycle timestamps", ErrInvalid, ky.ID)
			}
		case statePrimary:
			if ky.PhasedOutAt != nil || ky.DisabledAt != nil || ky.DeleteAfter != nil {
				return fmt.Errorf("%w: primary key %d has post-primary timestamps", ErrInvalid, ky.ID)
			}
		case statePhasingOut:
			if ky.DisabledAt != nil || ky.DeleteAfter != nil {
				return fmt.Errorf("%w: phasing-out key %d has disabled timestamps", ErrInvalid, ky.ID)
			}
		}
		if ky.State == statePrimary {
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
		return fmt.Errorf("%w: primary_id %d is not primary", ErrInvalid, d.PrimaryID)
	}
	return nil
}

// String redacts secrets.
func (k *Keyset) String() string {
	if k == nil {
		return "keyset.Keyset<nil>"
	}
	return fmt.Sprintf("keyset.Keyset{name=%q alg=%s keys=%d primary=%d}",
		k.doc.Name, k.doc.Algorithm, len(k.doc.Keys), k.doc.PrimaryID)
}

// GoString redacts secrets.
func (k *Keyset) GoString() string { return k.String() }
