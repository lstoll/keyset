package jws_test

import (
	"testing"

	"lds.li/keyset"
	"lds.li/keyset/jws"
)

func TestECDSAWireEncoding(t *testing.T) {
	ks, err := keyset.New("jwt", keyset.ECDSAP256SHA256, keyset.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	coreSigner, err := ks.Signer()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jws.NewSigner(coreSigner)
	if err != nil {
		t.Fatal(err)
	}
	if signer.Algorithm() != "ES256" {
		t.Fatalf("alg=%q", signer.Algorithm())
	}
	signature, err := signer.Sign([]byte("header.payload"))
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != 64 {
		t.Fatalf("ECDSA JWS signature size=%d", len(signature))
	}
	verifier, err := jws.NewVerifier(ks.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(signer.KeyID(), []byte("header.payload"), signature); err != nil {
		t.Fatal(err)
	}
}

func TestEd25519WireEncoding(t *testing.T) {
	ks, err := keyset.New("jwt", keyset.Ed25519, keyset.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	coreSigner, err := ks.Signer()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jws.NewSigner(coreSigner)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign([]byte("header.payload"))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := jws.NewVerifier(ks.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(signer.KeyID(), []byte("header.payload"), signature); err != nil {
		t.Fatal(err)
	}
}
