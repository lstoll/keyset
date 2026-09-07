package keyset

import "errors"

var (
	ErrNotFound             = errors.New("keyset: not found")
	ErrExist                = errors.New("keyset: already exists")
	ErrConflict             = errors.New("keyset: concurrent modification")
	ErrInvalid              = errors.New("keyset: invalid")
	ErrAuthenticationFailed = errors.New("keyset: authentication failed")
)
