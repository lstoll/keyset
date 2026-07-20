package keyset

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	aes256KeySize  = 32
	hmacSHA256Size = 32
	rsaPSS2048Bits = 2048
	rsaPSS3072Bits = 3072
)

func generateKeyID(existing map[uint32]struct{}) (uint32, error) {
	var b [4]byte
	for range 64 {
		if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
			return 0, fmt.Errorf("keyset: generate key id: %w", err)
		}
		id := binary.BigEndian.Uint32(b[:])
		if id == 0 {
			continue
		}
		if _, taken := existing[id]; taken {
			continue
		}
		return id, nil
	}
	return 0, fmt.Errorf("keyset: failed to allocate unique key id")
}

func generateMaterial(alg Algorithm) (privateKey, publicKey []byte, err error) {
	switch alg {
	case AES256GCM:
		key := make([]byte, aes256KeySize)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, nil, err
		}
		return key, nil, nil

	case HMACSHA256:
		key := make([]byte, hmacSHA256Size)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, nil, err
		}
		return key, nil, nil

	case Ed25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, nil, err
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, nil, err
		}
		return privBytes, pubBytes, nil

	case ECDSAP256SHA256:
		return generateECDSA(elliptic.P256())
	case ECDSAP384SHA384:
		return generateECDSA(elliptic.P384())

	case RSAPSS2048SHA256:
		return generateRSAPSS(rsaPSS2048Bits)
	case RSAPSS3072SHA256:
		return generateRSAPSS(rsaPSS3072Bits)

	default:
		return nil, nil, fmt.Errorf("%w: unsupported algorithm %q", ErrInvalid, alg)
	}
}

func generateECDSA(curve elliptic.Curve) (privateKey, publicKey []byte, err error) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return privBytes, pubBytes, nil
}

func generateRSAPSS(bits int) (privateKey, publicKey []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return privBytes, pubBytes, nil
}

func parsePrivateKey(alg Algorithm, der []byte) (any, error) {
	switch alg {
	case AES256GCM:
		if len(der) != aes256KeySize {
			return nil, fmt.Errorf("%w: AES-256 key must be %d bytes", ErrInvalid, aes256KeySize)
		}
		out := make([]byte, len(der))
		copy(out, der)
		return out, nil
	case HMACSHA256:
		if len(der) != hmacSHA256Size {
			return nil, fmt.Errorf("%w: HMAC-SHA-256 key must be %d bytes", ErrInvalid, hmacSHA256Size)
		}
		out := make([]byte, len(der))
		copy(out, der)
		return out, nil
	case Ed25519, ECDSAP256SHA256, ECDSAP384SHA384, RSAPSS2048SHA256, RSAPSS3072SHA256:
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("%w: parse private key: %v", ErrInvalid, err)
		}
		if err := checkPrivateKeyType(alg, key); err != nil {
			return nil, err
		}
		return key, nil
	default:
		return nil, fmt.Errorf("%w: unsupported algorithm %q", ErrInvalid, alg)
	}
}

func validateKeyPair(alg Algorithm, privateDER, publicDER []byte) error {
	if alg == AES256GCM || alg == HMACSHA256 {
		return nil
	}
	privateKey, err := parsePrivateKey(alg, privateDER)
	if err != nil {
		return err
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("%w: private key does not expose a public key", ErrInvalid)
	}
	derived, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("%w: marshal derived public key: %v", ErrInvalid, err)
	}
	if !bytes.Equal(derived, publicDER) {
		return fmt.Errorf("%w: private and public keys do not match", ErrInvalid)
	}
	return nil
}

func parsePublicKey(alg Algorithm, der []byte) (crypto.PublicKey, error) {
	switch alg {
	case Ed25519, ECDSAP256SHA256, ECDSAP384SHA384, RSAPSS2048SHA256, RSAPSS3072SHA256:
		key, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("%w: parse public key: %v", ErrInvalid, err)
		}
		if err := checkPublicKeyType(alg, key); err != nil {
			return nil, err
		}
		return key, nil
	default:
		return nil, fmt.Errorf("%w: algorithm %q has no public key", ErrInvalid, alg)
	}
}

func checkPrivateKeyType(alg Algorithm, key any) error {
	switch alg {
	case Ed25519:
		if _, ok := key.(ed25519.PrivateKey); !ok {
			return fmt.Errorf("%w: expected ed25519 private key", ErrInvalid)
		}
	case ECDSAP256SHA256:
		k, ok := key.(*ecdsa.PrivateKey)
		if !ok || k.Curve != elliptic.P256() {
			return fmt.Errorf("%w: expected P-256 ECDSA private key", ErrInvalid)
		}
	case ECDSAP384SHA384:
		k, ok := key.(*ecdsa.PrivateKey)
		if !ok || k.Curve != elliptic.P384() {
			return fmt.Errorf("%w: expected P-384 ECDSA private key", ErrInvalid)
		}
	case RSAPSS2048SHA256:
		k, ok := key.(*rsa.PrivateKey)
		if !ok || k.N.BitLen() != rsaPSS2048Bits {
			return fmt.Errorf("%w: expected RSA-2048 private key", ErrInvalid)
		}
	case RSAPSS3072SHA256:
		k, ok := key.(*rsa.PrivateKey)
		if !ok || k.N.BitLen() != rsaPSS3072Bits {
			return fmt.Errorf("%w: expected RSA-3072 private key", ErrInvalid)
		}
	}
	return nil
}

func checkPublicKeyType(alg Algorithm, key crypto.PublicKey) error {
	switch alg {
	case Ed25519:
		if _, ok := key.(ed25519.PublicKey); !ok {
			return fmt.Errorf("%w: expected ed25519 public key", ErrInvalid)
		}
	case ECDSAP256SHA256:
		k, ok := key.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() {
			return fmt.Errorf("%w: expected P-256 ECDSA public key", ErrInvalid)
		}
	case ECDSAP384SHA384:
		k, ok := key.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P384() {
			return fmt.Errorf("%w: expected P-384 ECDSA public key", ErrInvalid)
		}
	case RSAPSS2048SHA256:
		k, ok := key.(*rsa.PublicKey)
		if !ok || k.N.BitLen() != rsaPSS2048Bits {
			return fmt.Errorf("%w: expected RSA-2048 public key", ErrInvalid)
		}
	case RSAPSS3072SHA256:
		k, ok := key.(*rsa.PublicKey)
		if !ok || k.N.BitLen() != rsaPSS3072Bits {
			return fmt.Errorf("%w: expected RSA-3072 public key", ErrInvalid)
		}
	}
	return nil
}

func signerHash(alg Algorithm) (crypto.Hash, error) {
	switch alg {
	case Ed25519:
		return 0, nil
	case ECDSAP256SHA256, RSAPSS2048SHA256, RSAPSS3072SHA256:
		return crypto.SHA256, nil
	case ECDSAP384SHA384:
		return crypto.SHA384, nil
	default:
		return 0, fmt.Errorf("%w: not a signing algorithm", ErrInvalid)
	}
}
