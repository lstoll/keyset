package keyset

import (
	"context"
	"fmt"
	"time"
)

const envelopeVersion = 1

const maxKeyIDLen = 128

// Policy controls automated rotation.
type Policy struct {
	// Primary is how long a key stays primary before promotion is eligible.
	Primary time.Duration `json:"primary"`
	// Propagate is how long a pending key must exist before it may become primary.
	// Should exceed the longest client cache TTL plus deploy skew.
	Propagate time.Duration `json:"propagate"`
	// PhaseOut is how long a former primary remains usable for verify/decrypt.
	// Zero keeps former primaries usable indefinitely. This is normally the safe
	// choice for durable ciphertext unless old data is re-encrypted separately.
	PhaseOut time.Duration `json:"phase_out"`
	// Retention is how long a disabled key is kept before deletion. Zero keeps
	// disabled key material indefinitely.
	Retention time.Duration `json:"retention"`
}

// DefaultPolicy rotates weekly and prepublishes successors for an hour. It does
// not automatically disable or delete old keys, so durable ciphertext remains
// decryptable. Set PhaseOut and Retention explicitly for expiring data.
func DefaultPolicy() Policy {
	return Policy{
		Primary:   7 * 24 * time.Hour,
		Propagate: time.Hour,
		PhaseOut:  0,
		Retention: 0,
	}
}

func (p Policy) validate() error {
	if p.Primary <= 0 {
		return fmt.Errorf("%w: policy.Primary must be positive", ErrInvalid)
	}
	if p.Propagate < 0 || p.PhaseOut < 0 || p.Retention < 0 {
		return fmt.Errorf("%w: policy durations cannot be negative", ErrInvalid)
	}
	if p.Propagate > p.Primary {
		return fmt.Errorf("%w: policy.Propagate cannot exceed Primary", ErrInvalid)
	}
	return nil
}

// KeyState is a key's lifecycle state.
type KeyState string

const (
	StatePending    KeyState = "pending"
	StatePrimary    KeyState = "primary"
	StatePhasingOut KeyState = "phasing_out"
	StateDisabled   KeyState = "disabled"
)

// IsPrimary reports whether the key is the current primary (sign/encrypt).
func (s KeyState) IsPrimary() bool { return s == StatePrimary }

// IsUsable reports whether the key may be used to verify or decrypt.
// Pending, primary, and phasing-out keys are usable; disabled keys are not.
func (s KeyState) IsUsable() bool {
	return s == StatePrimary || s == StatePending || s == StatePhasingOut
}

// Material is opaque key bytes returned by a Type constructor.
type Material struct {
	// ID is an opaque key id, up to 128 bytes. Set it when the id derives from
	// the key itself (e.g. a JWK thumbprint). Empty defers to Type.NewID.
	ID string
	// Private is required secret material. Encoding is the type's contract.
	Private []byte
	// Public is optional public material. Encoding is the type's contract.
	Public []byte
}

// Type describes how to mint keys and how they rotate.
type Type struct {
	Policy Policy
	New    func(ctx context.Context) (Material, error)
	// NewID optionally assigns an id when New returns Material with an empty
	// ID. existing holds every id currently in the keyset, in keyset order,
	// so generators can count up or retry on collision. The result must be
	// non-empty, at most 128 bytes, and not in existing. Nil assigns a random
	// version 4 UUID.
	NewID func(existing []string) (string, error)
}

func (t Type) validate() error {
	if t.New == nil {
		return fmt.Errorf("%w: New is required", ErrInvalid)
	}
	return t.Policy.validate()
}

// Key is a copied view of one key, including secret material.
type Key struct {
	ID          string
	State       KeyState
	CreatedAt   time.Time
	PromotedAt  *time.Time
	PhasedOutAt *time.Time
	DisabledAt  *time.Time
	DeleteAfter *time.Time
	Private     []byte
	Public      []byte
}

// Public is a secret-free view of a keyset (safe to JSON-encode).
// UnmarshalPublic does not authenticate this metadata.
type Public struct {
	Name      string      `json:"name"`
	Type      string      `json:"type"`
	Policy    Policy      `json:"policy"`
	PrimaryID string      `json:"primary_id"`
	Keys      []PublicKey `json:"keys"`
}

// PublicKey is one public key in a Public view.
type PublicKey struct {
	ID        string   `json:"id"`
	State     KeyState `json:"state"`
	PublicKey []byte   `json:"public_key,omitempty"`
}
