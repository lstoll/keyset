package keyset

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
)

// Signer is a snapshot-bound crypto.MessageSigner for the primary key.
type Signer struct {
	alg   Algorithm
	keyID uint32
	priv  any
	pub   crypto.PublicKey
	opts  crypto.SignerOpts
}

// Verifier verifies signatures against the snapshot's verify-capable keys.
type Verifier struct {
	alg  Algorithm
	opts crypto.SignerOpts
	keys []keyedPublic
}

type keyedPublic struct {
	id  uint32
	pub []byte
}

// Signer returns a snapshot-bound MessageSigner for this in-memory keyset. It
// does not access a Store, and the returned signer does not observe rotations.
func (k *Keyset) Signer() (*Signer, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: nil keyset", ErrInvalid)
	}
	if k.doc.Purpose != purposeSign {
		return nil, fmt.Errorf("%w: not a signing keyset (%s)", ErrInvalid, k.doc.Algorithm)
	}
	primary, ok := k.keyByID(k.doc.PrimaryID)
	if !ok || !primary.State.canEncryptOrSign() {
		return nil, fmt.Errorf("%w: no usable primary key", ErrInvalid)
	}
	priv, err := parsePrivateKey(k.doc.Algorithm, primary.PrivateKey)
	if err != nil {
		return nil, err
	}
	pub, err := parsePublicKey(k.doc.Algorithm, primary.PublicKey)
	if err != nil {
		return nil, err
	}
	opts, err := pinnedOpts(k.doc.Algorithm)
	if err != nil {
		return nil, err
	}
	return &Signer{
		alg:   k.doc.Algorithm,
		keyID: primary.ID,
		priv:  priv,
		pub:   pub,
		opts:  opts,
	}, nil
}

// Verifier returns a snapshot-bound verifier for this in-memory keyset. It does
// not access a Store, and the returned verifier does not observe rotations.
func (k *Keyset) Verifier() (*Verifier, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: nil keyset", ErrInvalid)
	}
	if k.doc.Purpose != purposeSign {
		return nil, fmt.Errorf("%w: not a signing keyset (%s)", ErrInvalid, k.doc.Algorithm)
	}
	return k.Public().Verifier()
}

// Verifier returns a verifier containing public material only.
func (p Public) Verifier() (*Verifier, error) {
	if _, err := p.Algorithm.purpose(); err != nil {
		return nil, err
	}
	opts, err := pinnedOpts(p.Algorithm)
	if err != nil {
		return nil, err
	}
	v := &Verifier{alg: p.Algorithm, opts: opts}
	seen := make(map[uint32]struct{}, len(p.Keys))
	for _, ky := range p.Keys {
		if ky.ID == 0 {
			return nil, fmt.Errorf("%w: public key id 0 is reserved", ErrInvalid)
		}
		if _, ok := seen[ky.ID]; ok {
			return nil, fmt.Errorf("%w: duplicate public key id %d", ErrInvalid, ky.ID)
		}
		seen[ky.ID] = struct{}{}
		switch keyState(ky.State) {
		case stateDisabled:
			continue
		case statePending, statePrimary, statePhasingOut:
		default:
			return nil, fmt.Errorf("%w: unknown public key state %q", ErrInvalid, ky.State)
		}
		if _, err := parsePublicKey(p.Algorithm, ky.PublicKey); err != nil {
			return nil, fmt.Errorf("public key %d: %w", ky.ID, err)
		}
		v.keys = append(v.keys, keyedPublic{
			id:  ky.ID,
			pub: append([]byte(nil), ky.PublicKey...),
		})
	}
	return v, nil
}

// KeyID is the key used for signing.
func (s *Signer) KeyID() uint32 { return s.keyID }

// Algorithm returns the signer's pinned algorithm.
func (s *Signer) Algorithm() Algorithm { return s.alg }

// Public implements crypto.Signer.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// SignMsg signs msg with the algorithm's pinned options (convenience over MessageSigner).
func (s *Signer) SignMsg(msg []byte) ([]byte, error) {
	return s.SignMessage(rand.Reader, msg, s.opts)
}

// SignMessage implements crypto.MessageSigner.
func (s *Signer) SignMessage(random io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if err := checkOpts(s.alg, opts); err != nil {
		return nil, err
	}
	if random == nil {
		random = rand.Reader
	}
	return signMessage(s.alg, s.priv, random, msg, opts)
}

// Sign implements crypto.Signer. For Ed25519, digest is the unhashed message as
// required when opts.HashFunc() is zero.
func (s *Signer) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if err := checkOpts(s.alg, opts); err != nil {
		return nil, err
	}
	if random == nil {
		random = rand.Reader
	}
	if s.alg == Ed25519 {
		return signMessage(s.alg, s.priv, random, digest, opts)
	}
	if len(digest) != opts.HashFunc().Size() {
		return nil, fmt.Errorf("%w: want %d-byte digest, got %d", ErrInvalid, opts.HashFunc().Size(), len(digest))
	}
	return signDigest(s.alg, s.priv, random, digest, opts)
}

// Verify checks a signature against every key in the snapshot.
func (v *Verifier) Verify(msg, sig []byte) error {
	for _, ky := range v.keys {
		if err := verifyWith(v.alg, ky.pub, msg, sig, v.opts); err == nil {
			return nil
		}
	}
	return ErrVerificationFailed
}

// VerifyKey checks a signature with a specific key id.
func (v *Verifier) VerifyKey(keyID uint32, msg, sig []byte) error {
	for _, ky := range v.keys {
		if ky.id != keyID {
			continue
		}
		return verifyWith(v.alg, ky.pub, msg, sig, v.opts)
	}
	return ErrUnknownKey
}

func pinnedOpts(alg Algorithm) (crypto.SignerOpts, error) {
	h, err := signerHash(alg)
	if err != nil {
		return nil, err
	}
	return h, nil
}

func checkOpts(alg Algorithm, opts crypto.SignerOpts) error {
	want, err := signerHash(alg)
	if err != nil {
		return err
	}
	var got crypto.Hash
	if opts != nil {
		got = opts.HashFunc()
	}
	if got != want {
		return fmt.Errorf("%w: want hash %v, got %v", ErrInvalid, want, got)
	}
	return nil
}

func signMessage(alg Algorithm, key any, random io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch alg {
	case Ed25519:
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, ErrInvalid
		}
		return ed25519.Sign(priv, msg), nil

	case ECDSAP256SHA256, ECDSAP384SHA384:
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, ErrInvalid
		}
		h := opts.HashFunc().New()
		h.Write(msg)
		return ecdsa.SignASN1(random, priv, h.Sum(nil))

	case RSAPSS2048SHA256, RSAPSS3072SHA256:
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrInvalid
		}
		h := opts.HashFunc().New()
		h.Write(msg)
		return rsa.SignPSS(random, priv, opts.HashFunc(), h.Sum(nil), &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       opts.HashFunc(),
		})

	default:
		return nil, fmt.Errorf("%w: not a signing algorithm", ErrInvalid)
	}
}

func signDigest(alg Algorithm, key any, random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch alg {
	case ECDSAP256SHA256, ECDSAP384SHA384:
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, ErrInvalid
		}
		return ecdsa.SignASN1(random, priv, digest)

	case RSAPSS2048SHA256, RSAPSS3072SHA256:
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrInvalid
		}
		return rsa.SignPSS(random, priv, opts.HashFunc(), digest, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       opts.HashFunc(),
		})

	default:
		return nil, fmt.Errorf("%w: pre-hashed Sign not supported for %s", ErrInvalid, alg)
	}
}

func verifyWith(alg Algorithm, pubDER, msg, sig []byte, opts crypto.SignerOpts) error {
	pub, err := parsePublicKey(alg, pubDER)
	if err != nil {
		return err
	}
	switch alg {
	case Ed25519:
		pk, ok := pub.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(pk, msg, sig) {
			return ErrVerificationFailed
		}
		return nil

	case ECDSAP256SHA256, ECDSAP384SHA384:
		pk, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return ErrVerificationFailed
		}
		h := opts.HashFunc().New()
		h.Write(msg)
		if !ecdsa.VerifyASN1(pk, h.Sum(nil), sig) {
			return ErrVerificationFailed
		}
		return nil

	case RSAPSS2048SHA256, RSAPSS3072SHA256:
		pk, ok := pub.(*rsa.PublicKey)
		if !ok {
			return ErrVerificationFailed
		}
		h := opts.HashFunc().New()
		h.Write(msg)
		if err := rsa.VerifyPSS(pk, opts.HashFunc(), h.Sum(nil), sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       opts.HashFunc(),
		}); err != nil {
			return ErrVerificationFailed
		}
		return nil

	default:
		return fmt.Errorf("%w: not a signing algorithm", ErrInvalid)
	}
}

var (
	_ crypto.Signer        = (*Signer)(nil)
	_ crypto.MessageSigner = (*Signer)(nil)
)
