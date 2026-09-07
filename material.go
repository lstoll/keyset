package keyset

import (
	"fmt"
	"slices"
	"uuid"
)

func validateKeyID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: key id is required", ErrInvalid)
	}
	if len(id) > maxKeyIDLen {
		return fmt.Errorf("%w: key id too long", ErrInvalid)
	}
	return nil
}

// applyMaterial picks the key id (Material.ID, then newID, then a random UUID),
// checks it, and copies the key bytes.
func (k *Keyset) applyMaterial(m Material, newID func(existing []string) (string, error)) (id string, priv, pub []byte, err error) {
	if len(m.Private) == 0 {
		return "", nil, nil, fmt.Errorf("%w: private material is required", ErrInvalid)
	}
	existing := k.existingIDs()
	switch {
	case m.ID != "":
		id = m.ID
	case newID != nil:
		id, err = newID(slices.Clone(existing))
		if err != nil {
			return "", nil, nil, fmt.Errorf("keyset: generate key id: %w", err)
		}
	default:
		id = uuid.NewV4().String()
	}
	if err := validateKeyID(id); err != nil {
		return "", nil, nil, err
	}
	if slices.Contains(existing, id) {
		return "", nil, nil, fmt.Errorf("%w: duplicate key id %q", ErrInvalid, id)
	}
	priv = append([]byte(nil), m.Private...)
	if len(m.Public) > 0 {
		pub = append([]byte(nil), m.Public...)
	}
	return id, priv, pub, nil
}
