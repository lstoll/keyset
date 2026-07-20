package jwk_test

import (
	"encoding/json"
	"testing"

	"lds.li/keyset"
	"lds.li/keyset/jwk"
)

func TestFromPublic(t *testing.T) {
	ks, err := keyset.New("jwt", keyset.Ed25519, keyset.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	set, err := jwk.FromPublic(ks.Public())
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("keys=%d, want primary and pending", len(set.Keys))
	}
	for _, key := range set.Keys {
		if key.Kty != "OKP" || key.Crv != "Ed25519" || key.Alg != "EdDSA" || key.Kid == "" || key.X == "" {
			t.Fatalf("unexpected JWK: %#v", key)
		}
	}
	if _, err := json.Marshal(set); err != nil {
		t.Fatal(err)
	}
}
