// Package jws adapts keyset signing primitives to JWS signature encoding.
// It does not construct or parse JWTs.
package jws

import (
	"encoding/asn1"
	"fmt"
	"math/big"
	"strconv"

	"lds.li/keyset"
)

// Signer signs JWS signing input and returns the wire-format signature.
type Signer struct {
	signer *keyset.Signer
	alg    string
}

// NewSigner wraps an asymmetric keyset signer.
func NewSigner(signer *keyset.Signer) (*Signer, error) {
	if signer == nil {
		return nil, fmt.Errorf("jws: signer is required")
	}
	if !isAsymmetric(signer.Algorithm()) {
		return nil, fmt.Errorf("jws: unsupported signing algorithm %s", signer.Algorithm())
	}
	alg, err := signer.Algorithm().JOSEAlgorithm()
	if err != nil {
		return nil, err
	}
	return &Signer{signer: signer, alg: alg}, nil
}

// KeyID returns the decimal JWS kid value.
func (s *Signer) KeyID() string { return strconv.FormatUint(uint64(s.signer.KeyID()), 10) }

// Algorithm returns the JWS alg value.
func (s *Signer) Algorithm() string { return s.alg }

// Sign signs a JWS signing input. ECDSA signatures are returned as fixed-width R || S.
func (s *Signer) Sign(signingInput []byte) ([]byte, error) {
	signature, err := s.signer.SignMsg(signingInput)
	if err != nil {
		return nil, err
	}
	return toJWS(s.signer.Algorithm(), signature)
}

// Verifier verifies JWS wire-format signatures using public key material only.
type Verifier struct {
	verifier *keyset.Verifier
	alg      keyset.Algorithm
	joseAlg  string
}

// NewVerifier constructs a public-only JWS verifier.
func NewVerifier(public keyset.PublicKeyset) (*Verifier, error) {
	if !isAsymmetric(public.Algorithm) {
		return nil, fmt.Errorf("jws: unsupported verification algorithm %s", public.Algorithm)
	}
	verifier, err := public.Verifier()
	if err != nil {
		return nil, err
	}
	alg, err := public.Algorithm.JOSEAlgorithm()
	if err != nil {
		return nil, err
	}
	return &Verifier{verifier: verifier, alg: public.Algorithm, joseAlg: alg}, nil
}

// Algorithm returns the expected JWS alg value.
func (v *Verifier) Algorithm() string { return v.joseAlg }

// Verify verifies a signature for the decimal kid.
func (v *Verifier) Verify(kid string, signingInput, signature []byte) error {
	id, err := strconv.ParseUint(kid, 10, 32)
	if err != nil || id == 0 {
		return fmt.Errorf("jws: invalid kid %q", kid)
	}
	encoded, err := fromJWS(v.alg, signature)
	if err != nil {
		return err
	}
	return v.verifier.VerifyKey(uint32(id), signingInput, encoded)
}

func isAsymmetric(alg keyset.Algorithm) bool {
	switch alg {
	case keyset.Ed25519, keyset.ECDSAP256SHA256, keyset.ECDSAP384SHA384,
		keyset.RSAPSS2048SHA256, keyset.RSAPSS3072SHA256:
		return true
	default:
		return false
	}
}

type ecdsaSignature struct {
	R, S *big.Int
}

func toJWS(alg keyset.Algorithm, signature []byte) ([]byte, error) {
	size := ecdsaSize(alg)
	if size == 0 {
		return signature, nil
	}
	var parsed ecdsaSignature
	rest, err := asn1.Unmarshal(signature, &parsed)
	if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil || parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
		return nil, fmt.Errorf("jws: invalid ASN.1 ECDSA signature")
	}
	if parsed.R.BitLen() > size*8 || parsed.S.BitLen() > size*8 {
		return nil, fmt.Errorf("jws: ECDSA signature component is too large")
	}
	out := make([]byte, size*2)
	parsed.R.FillBytes(out[:size])
	parsed.S.FillBytes(out[size:])
	return out, nil
}

func fromJWS(alg keyset.Algorithm, signature []byte) ([]byte, error) {
	size := ecdsaSize(alg)
	if size == 0 {
		return signature, nil
	}
	if len(signature) != size*2 {
		return nil, fmt.Errorf("jws: want %d-byte ECDSA signature, got %d", size*2, len(signature))
	}
	r := new(big.Int).SetBytes(signature[:size])
	s := new(big.Int).SetBytes(signature[size:])
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return nil, fmt.Errorf("jws: invalid ECDSA signature")
	}
	return asn1.Marshal(ecdsaSignature{R: r, S: s})
}

func ecdsaSize(alg keyset.Algorithm) int {
	switch alg {
	case keyset.ECDSAP256SHA256:
		return 32
	case keyset.ECDSAP384SHA384:
		return 48
	default:
		return 0
	}
}
