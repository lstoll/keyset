package keyset

import (
	"fmt"
	"time"
)

const documentVersion = 1

// Algorithm is an allowlisted primitive. A keyset is frozen to one algorithm.
type Algorithm string

const (
	AES256GCM  Algorithm = "aes256-gcm"
	HMACSHA256 Algorithm = "hmac-sha256"

	Ed25519                 Algorithm = "ed25519"
	ECDSAP256SHA256         Algorithm = "ecdsa-p256-sha256"
	ECDSAP384SHA384         Algorithm = "ecdsa-p384-sha384"
	RSAPKCS1v15_2048_SHA256 Algorithm = "rsa-pkcs1v15-2048-sha256"
	RSAPKCS1v15_3072_SHA256 Algorithm = "rsa-pkcs1v15-3072-sha256"
	RSAPSS2048SHA256        Algorithm = "rsa-pss-2048-sha256"
	RSAPSS3072SHA256        Algorithm = "rsa-pss-3072-sha256"
)

type purpose string

const (
	purposeAEAD purpose = "aead"
	purposeMAC  purpose = "mac"
	purposeSign purpose = "sign"
)

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

func (a Algorithm) purpose() (purpose, error) {
	switch a {
	case AES256GCM:
		return purposeAEAD, nil
	case HMACSHA256:
		return purposeMAC, nil
	case Ed25519, ECDSAP256SHA256, ECDSAP384SHA384,
		RSAPKCS1v15_2048_SHA256, RSAPKCS1v15_3072_SHA256,
		RSAPSS2048SHA256, RSAPSS3072SHA256:
		return purposeSign, nil
	default:
		return "", fmt.Errorf("%w: unknown algorithm %q", ErrInvalid, a)
	}
}

type keyState string

const (
	statePending    keyState = "pending"
	statePrimary    keyState = "primary"
	statePhasingOut keyState = "phasing_out"
	stateDisabled   keyState = "disabled"
)

func (s keyState) canEncryptOrSign() bool { return s == statePrimary }
func (s keyState) canDecryptOrVerify() bool {
	return s == statePrimary || s == statePending || s == statePhasingOut
}

// Public is a secret-free view of a keyset (safe to JSON-encode).
type Public struct {
	Name      string      `json:"name"`
	Algorithm Algorithm   `json:"algorithm"`
	PrimaryID uint32      `json:"primary_id"`
	Keys      []PublicKey `json:"keys"`
}

// PublicKeyset is the preferred name for Public. Public remains as a compact
// compatibility name for persisted store interfaces.
type PublicKeyset = Public

// PublicKey is one public key in a Public view.
type PublicKey struct {
	ID        uint32 `json:"id"`
	State     string `json:"state"`
	PublicKey []byte `json:"public_key,omitempty"`
}
