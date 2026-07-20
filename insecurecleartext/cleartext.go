package insecurecleartext

import "lds.li/keyset"

// Keeper is a pass-through keyset.Keeper for Marshal/Unmarshal.
// Importing this package is an explicit choice to handle cleartext key material.
var Keeper keyset.Keeper = plaintext{}

type plaintext struct{}

func (plaintext) Seal(plaintext, _ []byte) ([]byte, error) {
	out := make([]byte, len(plaintext))
	copy(out, plaintext)
	return out, nil
}

func (plaintext) Open(ciphertext, _ []byte) ([]byte, error) {
	out := make([]byte, len(ciphertext))
	copy(out, ciphertext)
	return out, nil
}
