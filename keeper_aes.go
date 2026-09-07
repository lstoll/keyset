package keyset

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

const aes256KeySize = 32

// AES256GCMKeeper returns a Keeper from a 32-byte AES key.
func AES256GCMKeeper(key []byte) (Keeper, error) {
	if len(key) != aes256KeySize {
		return nil, fmt.Errorf("%w: AES-256-GCM keeper requires 32-byte key", ErrInvalid)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return FromCipher(aead), nil
}
