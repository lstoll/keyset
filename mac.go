package keyset

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"hash"
)

// MAC is a snapshot-bound message authentication code.
type MAC struct {
	alg    Algorithm
	keyID  uint32
	sumKey []byte
	verify []keyedBytes
}

// MAC returns a snapshot-bound MAC for this in-memory keyset. It does not
// access a Store, and the returned MAC does not observe later rotations.
func (k *Keyset) MAC() (*MAC, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: nil keyset", ErrInvalid)
	}
	if k.doc.Purpose != purposeMAC {
		return nil, fmt.Errorf("%w: not a MAC keyset (%s)", ErrInvalid, k.doc.Algorithm)
	}
	primary, ok := k.keyByID(k.doc.PrimaryID)
	if !ok || !primary.State.canEncryptOrSign() {
		return nil, fmt.Errorf("%w: no usable primary key", ErrInvalid)
	}
	m := &MAC{
		alg:    k.doc.Algorithm,
		keyID:  primary.ID,
		sumKey: append([]byte(nil), primary.PrivateKey...),
	}
	for i := range k.doc.Keys {
		ky := &k.doc.Keys[i]
		if !ky.State.canDecryptOrVerify() {
			continue
		}
		m.verify = append(m.verify, keyedBytes{
			id:  ky.ID,
			key: append([]byte(nil), ky.PrivateKey...),
		})
	}
	return m, nil
}

// KeyID is the key used by Compute and Sum.
func (m *MAC) KeyID() uint32 { return m.keyID }

// Overhead returns the bytes added by Compute: framing plus the tag.
func (m *MAC) Overhead() int { return outputHeaderSize + sha256.Size }

// RawOverhead returns the tag size without framing.
func (m *MAC) RawOverhead() int { return sha256.Size }

// Compute returns version || key ID || tag. The prefix is authenticated.
func (m *MAC) Compute(msg []byte) ([]byte, error) {
	header := outputHeader(m.keyID)
	tag, err := macSum(m.alg, m.sumKey, framedAAD("keyset/mac/v1:", header[:], msg))
	if err != nil {
		return nil, err
	}
	return append(header[:], tag...), nil
}

// Sum is an alias for Compute.
func (m *MAC) Sum(msg []byte) ([]byte, error) { return m.Compute(msg) }

// Verify parses the framed key ID and verifies with that key.
func (m *MAC) Verify(mac, msg []byte) error {
	keyID, tag, err := parseOutputHeader(mac)
	if err != nil {
		return ErrVerificationFailed
	}
	header := outputHeader(keyID)
	for _, ky := range m.verify {
		if ky.id != keyID {
			continue
		}
		got, err := macSum(m.alg, ky.key, framedAAD("keyset/mac/v1:", header[:], msg))
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(got, tag) == 1 {
			return nil
		}
		return ErrVerificationFailed
	}
	return ErrUnknownKey
}

// VerifyKey verifies framed output and requires its key ID to match keyID.
func (m *MAC) VerifyKey(keyID uint32, mac, msg []byte) error {
	framedID, _, err := parseOutputHeader(mac)
	if err != nil {
		return ErrVerificationFailed
	}
	if framedID != keyID {
		return ErrUnknownKey
	}
	return m.Verify(mac, msg)
}

// ComputeRaw computes a protocol-compatible unframed HMAC.
func (m *MAC) ComputeRaw(msg []byte) ([]byte, error) {
	return macSum(m.alg, m.sumKey, msg)
}

// VerifyRaw checks an unframed HMAC against every verify-capable key.
func (m *MAC) VerifyRaw(mac, msg []byte) error {
	for _, ky := range m.verify {
		got, err := macSum(m.alg, ky.key, msg)
		if err == nil && subtle.ConstantTimeCompare(got, mac) == 1 {
			return nil
		}
	}
	return ErrVerificationFailed
}

// VerifyKeyRaw checks an unframed HMAC with a specific key ID.
func (m *MAC) VerifyKeyRaw(keyID uint32, mac, msg []byte) error {
	for _, ky := range m.verify {
		if ky.id != keyID {
			continue
		}
		got, err := macSum(m.alg, ky.key, msg)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(got, mac) != 1 {
			return ErrVerificationFailed
		}
		return nil
	}
	return ErrUnknownKey
}

func macSum(alg Algorithm, key, msg []byte) ([]byte, error) {
	var newHash func() hash.Hash
	switch alg {
	case HMACSHA256:
		newHash = sha256.New
	default:
		return nil, fmt.Errorf("%w: not a MAC algorithm", ErrInvalid)
	}
	h := hmac.New(newHash, key)
	h.Write(msg)
	return h.Sum(nil), nil
}
