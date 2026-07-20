package keyset

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Keeper protects keyset blobs at rest. Implementations own nonces.
// Use FromCipher or AES256GCMKeeper; cleartext only via insecurecleartext.Keeper.
type Keeper interface {
	Seal(plaintext, additionalData []byte) ([]byte, error)
	Open(ciphertext, additionalData []byte) ([]byte, error)
}

const keeperVersion byte = 1

type cipherKeeper struct {
	aead cipher.AEAD
}

// FromCipher adapts a cipher.AEAD as a Keeper.
// Format: version (1) || nonce || seal(...).
func FromCipher(aead cipher.AEAD) Keeper {
	if aead == nil {
		panic("keyset: nil cipher.AEAD")
	}
	return &cipherKeeper{aead: aead}
}

func (k *cipherKeeper) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("keyset: keeper nonce: %w", err)
	}
	out := make([]byte, 1+len(nonce), 1+len(nonce)+len(plaintext)+k.aead.Overhead())
	out[0] = keeperVersion
	copy(out[1:], nonce)
	return k.aead.Seal(out, nonce, plaintext, aad), nil
}

func (k *cipherKeeper) Open(ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < 1+k.aead.NonceSize() {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrAuthenticationFailed)
	}
	if ciphertext[0] != keeperVersion {
		return nil, fmt.Errorf("%w: unsupported keeper version %d", ErrAuthenticationFailed, ciphertext[0])
	}
	nonce := ciphertext[1 : 1+k.aead.NonceSize()]
	ct := ciphertext[1+k.aead.NonceSize():]
	pt, err := k.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	return pt, nil
}
