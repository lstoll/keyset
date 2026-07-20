package keyset

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// AEAD is a snapshot-bound authenticated cipher. Nonces are generated internally.
// Seal emits version || key ID || nonce || ciphertext and always uses KeyID().
// Later Rotate on the parent Keyset does not affect it.
type AEAD struct {
	alg     Algorithm
	keyID   uint32
	sealKey []byte
	open    []keyedBytes
}

type keyedBytes struct {
	id  uint32
	key []byte
}

// AEAD returns a snapshot-bound AEAD for this in-memory keyset. It does not
// access a Store, and the returned AEAD does not observe later rotations.
func (k *Keyset) AEAD() (*AEAD, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: nil keyset", ErrInvalid)
	}
	if k.doc.Purpose != purposeAEAD {
		return nil, fmt.Errorf("%w: not an AEAD keyset (%s)", ErrInvalid, k.doc.Algorithm)
	}
	primary, ok := k.keyByID(k.doc.PrimaryID)
	if !ok || !primary.State.canEncryptOrSign() {
		return nil, fmt.Errorf("%w: no usable primary key", ErrInvalid)
	}
	a := &AEAD{
		alg:     k.doc.Algorithm,
		keyID:   primary.ID,
		sealKey: append([]byte(nil), primary.PrivateKey...),
	}
	for i := range k.doc.Keys {
		ky := &k.doc.Keys[i]
		if !ky.State.canDecryptOrVerify() {
			continue
		}
		a.open = append(a.open, keyedBytes{
			id:  ky.ID,
			key: append([]byte(nil), ky.PrivateKey...),
		})
	}
	return a, nil
}

// KeyID is the key used by Seal.
func (a *AEAD) KeyID() uint32 { return a.keyID }

// NonceSize returns the size of the internally generated nonce.
func (a *AEAD) NonceSize() int {
	c, _ := cipherAEAD(a.alg, a.sealKey)
	return c.NonceSize()
}

// RawOverhead returns the nonce and authentication-tag expansion without framing.
func (a *AEAD) RawOverhead() int {
	c, _ := cipherAEAD(a.alg, a.sealKey)
	return c.NonceSize() + c.Overhead()
}

// Overhead returns the total expansion added by Seal, including the key ID frame.
func (a *AEAD) Overhead() int { return outputHeaderSize + a.RawOverhead() }

// Seal encrypts plaintext with the bound key.
func (a *AEAD) Seal(plaintext, additionalData []byte) ([]byte, error) {
	c, err := cipherAEAD(a.alg, a.sealKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, c.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("keyset: nonce: %w", err)
	}
	header := outputHeader(a.keyID)
	out := make([]byte, 0, outputHeaderSize+len(nonce)+len(plaintext)+c.Overhead())
	out = append(out, header[:]...)
	out = append(out, nonce...)
	return c.Seal(out, nonce, plaintext, framedAAD("keyset/aead/v1:", header[:], additionalData)), nil
}

// Open parses the framed key ID and decrypts with that key.
func (a *AEAD) Open(ciphertext, additionalData []byte) ([]byte, error) {
	keyID, raw, err := parseOutputHeader(ciphertext)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	header := outputHeader(keyID)
	for _, ky := range a.open {
		if ky.id == keyID {
			return openWith(a.alg, ky.key, raw, framedAAD("keyset/aead/v1:", header[:], additionalData))
		}
	}
	return nil, ErrUnknownKey
}

// OpenKey decrypts framed ciphertext and requires its key ID to match keyID.
func (a *AEAD) OpenKey(keyID uint32, ciphertext, additionalData []byte) ([]byte, error) {
	framedID, _, err := parseOutputHeader(ciphertext)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	if framedID != keyID {
		return nil, ErrUnknownKey
	}
	return a.Open(ciphertext, additionalData)
}

// SealRaw encrypts without a version or key ID prefix.
func (a *AEAD) SealRaw(plaintext, additionalData []byte) ([]byte, error) {
	c, err := cipherAEAD(a.alg, a.sealKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, c.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("keyset: nonce: %w", err)
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+c.Overhead())
	out = append(out, nonce...)
	return c.Seal(out, nonce, plaintext, additionalData), nil
}

// OpenRaw tries every decrypt-capable key against unframed ciphertext.
func (a *AEAD) OpenRaw(ciphertext, additionalData []byte) ([]byte, error) {
	for _, ky := range a.open {
		if pt, err := openWith(a.alg, ky.key, ciphertext, additionalData); err == nil {
			return pt, nil
		}
	}
	return nil, ErrAuthenticationFailed
}

// OpenKeyRaw decrypts unframed ciphertext using a specific key ID.
func (a *AEAD) OpenKeyRaw(keyID uint32, ciphertext, additionalData []byte) ([]byte, error) {
	for _, ky := range a.open {
		if ky.id != keyID {
			continue
		}
		return openWith(a.alg, ky.key, ciphertext, additionalData)
	}
	return nil, ErrUnknownKey
}

func cipherAEAD(alg Algorithm, key []byte) (cipher.AEAD, error) {
	switch alg {
	case AES256GCM:
		if len(key) != aes256KeySize {
			return nil, fmt.Errorf("%w: bad AES key size", ErrInvalid)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, fmt.Errorf("%w: not an AEAD algorithm", ErrInvalid)
	}
}

func openWith(alg Algorithm, key, ciphertext, aad []byte) ([]byte, error) {
	c, err := cipherAEAD(alg, key)
	if err != nil {
		return nil, err
	}
	ns := c.NonceSize()
	if len(ciphertext) < ns {
		return nil, ErrAuthenticationFailed
	}
	nonce, ct := ciphertext[:ns], ciphertext[ns:]
	pt, err := c.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	return pt, nil
}
