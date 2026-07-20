// Package jwk converts public keysets to JSON Web Key Sets.
package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"strconv"

	"lds.li/keyset"
)

// Set is a JSON Web Key Set.
type Set struct {
	Keys []Key `json:"keys"`
}

// Key is the public portion of a JSON Web Key.
type Key struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// FromPublic converts all verify-capable keys to a JWKS. Disabled keys are omitted.
func FromPublic(public keyset.PublicKeyset) (Set, error) {
	if _, err := public.Verifier(); err != nil {
		return Set{}, fmt.Errorf("jwk: invalid public keyset: %w", err)
	}
	alg, err := public.Algorithm.JOSEAlgorithm()
	if err != nil {
		return Set{}, err
	}
	set := Set{Keys: make([]Key, 0, len(public.Keys))}
	for _, source := range public.Keys {
		switch source.State {
		case "disabled":
			continue
		case "pending", "primary", "phasing_out":
		default:
			return Set{}, fmt.Errorf("jwk: key %d has invalid state %q", source.ID, source.State)
		}
		parsed, err := x509.ParsePKIXPublicKey(source.PublicKey)
		if err != nil {
			return Set{}, fmt.Errorf("jwk: parse key %d: %w", source.ID, err)
		}
		key := Key{Use: "sig", Alg: alg, Kid: strconv.FormatUint(uint64(source.ID), 10)}
		switch parsed := parsed.(type) {
		case ed25519.PublicKey:
			key.Kty, key.Crv = "OKP", "Ed25519"
			key.X = encode(parsed)
		case *ecdsa.PublicKey:
			bits := parsed.Curve.Params().BitSize
			switch bits {
			case 256:
				key.Crv = "P-256"
			case 384:
				key.Crv = "P-384"
			default:
				return Set{}, fmt.Errorf("jwk: key %d uses unsupported curve", source.ID)
			}
			key.Kty = "EC"
			size := (bits + 7) / 8
			key.X = encode(parsed.X.FillBytes(make([]byte, size)))
			key.Y = encode(parsed.Y.FillBytes(make([]byte, size)))
		case *rsa.PublicKey:
			key.Kty = "RSA"
			key.N = encode(parsed.N.Bytes())
			key.E = encode(big.NewInt(int64(parsed.E)).Bytes())
		default:
			return Set{}, fmt.Errorf("jwk: key %d has unsupported public key type %T", source.ID, parsed)
		}
		set.Keys = append(set.Keys, key)
	}
	return set, nil
}

func encode(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
