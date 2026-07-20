package keyset_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"lds.li/keyset"
	"lds.li/keyset/insecurecleartext"
	"lds.li/keyset/memstore"
)

func testKeeper(t *testing.T) keyset.Keeper {
	t.Helper()
	key := bytes.Repeat([]byte{0x42}, 32)
	k, err := keyset.AES256GCMKeeper(key)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAEADLifecycle(t *testing.T) {
	policy := keyset.Policy{
		Primary:   10 * time.Second,
		Propagate: 2 * time.Second,
		PhaseOut:  5 * time.Second,
		Retention: 3 * time.Second,
	}
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	ks, err := newAtForTest(t, "sessions", keyset.AES256GCM, policy, now)
	if err != nil {
		t.Fatal(err)
	}

	aead, err := ks.AEAD()
	if err != nil {
		t.Fatal(err)
	}
	kid := aead.KeyID()
	ct, err := aead.Seal([]byte("hello"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := aead.OpenKey(kid, ct, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello" {
		t.Fatal(string(pt))
	}
	pt, err = aead.Open(ct, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello" {
		t.Fatal(string(pt))
	}

	type rec struct {
		ct  []byte
		kid uint32
	}
	history := []rec{{ct, kid}}
	end := now.Add(60 * time.Second)
	for now = now.Add(time.Second); now.Before(end); now = now.Add(time.Second) {
		if _, err := ks.Rotate(now); err != nil {
			t.Fatal(err)
		}
		aead, err = ks.AEAD()
		if err != nil {
			t.Fatal(err)
		}
		ct, err = aead.Seal([]byte("ping"), []byte("aad"))
		if err != nil {
			t.Fatal(err)
		}
		history = append(history, rec{ct, aead.KeyID()})
		for _, r := range history {
			if _, err := aead.OpenKey(r.kid, r.ct, []byte("aad")); err != nil {
				if !errors.Is(err, keyset.ErrUnknownKey) && !errors.Is(err, keyset.ErrAuthenticationFailed) {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestAEADFramingAndSizes(t *testing.T) {
	ks, err := keyset.New("data", keyset.AES256GCM, keyset.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	aead, err := ks.AEAD()
	if err != nil {
		t.Fatal(err)
	}
	if aead.NonceSize() != 12 || aead.RawOverhead() != 28 || aead.Overhead() != 33 {
		t.Fatalf("sizes: nonce=%d raw=%d framed=%d", aead.NonceSize(), aead.RawOverhead(), aead.Overhead())
	}
	plaintext := []byte("hello")
	ct, err := aead.Seal(plaintext, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != len(plaintext)+aead.Overhead() {
		t.Fatalf("ciphertext size=%d", len(ct))
	}
	if got := binary.BigEndian.Uint32(ct[1:5]); got != aead.KeyID() {
		t.Fatalf("framed key id=%d, want %d", got, aead.KeyID())
	}
	tampered := append([]byte(nil), ct...)
	tampered[4] ^= 1
	if _, err := aead.Open(tampered, []byte("aad")); err == nil {
		t.Fatal("tampered key ID was accepted")
	}
	raw, err := aead.SealRaw(plaintext, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != len(plaintext)+aead.RawOverhead() {
		t.Fatalf("raw ciphertext size=%d", len(raw))
	}
	if _, err := aead.OpenRaw(raw, []byte("aad")); err != nil {
		t.Fatal(err)
	}
	if _, err := aead.Open(raw, []byte("aad")); err == nil {
		t.Fatal("unframed ciphertext accepted by Open")
	}
}

func newAtForTest(t *testing.T, name string, alg keyset.Algorithm, policy keyset.Policy, now time.Time) (*keyset.Keyset, error) {
	t.Helper()
	store := memstore.New(testKeeper(t))
	rot, err := keyset.NewRotator(store, keyset.WithClock(func() time.Time { return now }))
	if err != nil {
		return nil, err
	}
	if err := rot.Ensure(t.Context(), name, alg, policy); err != nil {
		return nil, err
	}
	return store.Get(t.Context(), name)
}

func TestBoundSnapshot(t *testing.T) {
	policy := keyset.Policy{
		Primary:   time.Second,
		Propagate: 0,
		PhaseOut:  time.Hour,
		Retention: time.Hour,
	}
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	ks, err := newAtForTest(t, "s", keyset.AES256GCM, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := ks.AEAD()
	if err != nil {
		t.Fatal(err)
	}
	kid := aead.KeyID()
	ct, err := aead.Seal([]byte("a"), nil)
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(2 * time.Second)
	if _, err := ks.Rotate(now); err != nil {
		t.Fatal(err)
	}
	if ks.PrimaryID() == kid {
		t.Fatal("expected primary change")
	}
	ct2, err := aead.Seal([]byte("b"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if aead.KeyID() != kid {
		t.Fatal("kid drifted")
	}
	if _, err := aead.OpenKey(kid, ct, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := aead.OpenKey(kid, ct2, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRefuseJSONAndKeeper(t *testing.T) {
	ks, err := keyset.New("a", keyset.AES256GCM, keyset.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(ks); err == nil {
		t.Fatal("expected refuse")
	}
	pub, err := json.Marshal(ks.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(pub, []byte(`"name":"a"`)) {
		t.Fatalf("%s", pub)
	}

	keeper := testKeeper(t)
	blob, err := ks.Marshal(keeper)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyset.Unmarshal("b", blob, keeper); err == nil {
		t.Fatal("expected name mismatch")
	}
	got, err := keyset.Unmarshal("a", blob, keeper)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name() != "a" {
		t.Fatal(got.Name())
	}

	clear, err := ks.Marshal(insecurecleartext.Keeper)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(clear, []byte(`"name":"a"`)) {
		t.Fatalf("%s", clear)
	}
	withUnknownField := bytes.Replace(clear, []byte(`{"version":1`), []byte(`{"unknown":true,"version":1`), 1)
	if _, err := keyset.Unmarshal("a", withUnknownField, insecurecleartext.Keeper); err == nil {
		t.Fatal("unknown document field was accepted")
	}
}

func TestInspectableAuthenticatedEnvelope(t *testing.T) {
	ks, err := keyset.New("inspect", keyset.Ed25519, keyset.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	keeper := testKeeper(t)
	encrypted, err := ks.Marshal(keeper)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encrypted, []byte(`"name":"inspect"`)) ||
		!bytes.Contains(encrypted, []byte(`"state":"primary"`)) ||
		!bytes.Contains(encrypted, []byte(`"public_key"`)) {
		t.Fatalf("public metadata is not inspectable: %s", encrypted)
	}

	public, err := keyset.UnmarshalPublic(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if public.Name != "inspect" || len(public.Keys) != 2 || len(public.Keys[0].PublicKey) == 0 {
		t.Fatalf("unexpected public envelope: %#v", public)
	}

	clear, err := ks.Marshal(insecurecleartext.Keeper)
	if err != nil {
		t.Fatal(err)
	}
	var clearEnvelope struct {
		PrivateMaterial []byte `json:"private_material"`
	}
	if err := json.Unmarshal(clear, &clearEnvelope); err != nil {
		t.Fatal(err)
	}
	if len(clearEnvelope.PrivateMaterial) == 0 {
		t.Fatal("cleartext envelope did not contain private material")
	}
	if bytes.Contains(encrypted, clearEnvelope.PrivateMaterial) {
		t.Fatal("encrypted envelope exposed clear private material")
	}

	tampered := bytes.Replace(encrypted, []byte(`"name":"inspect"`), []byte(`"name":"xnspect"`), 1)
	tamperedPublic, err := keyset.UnmarshalPublic(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if tamperedPublic.Name != "xnspect" {
		t.Fatalf("public parse did not expose clear metadata change: %q", tamperedPublic.Name)
	}
	if _, err := keyset.Unmarshal("inspect", tampered, keeper); !errors.Is(err, keyset.ErrAuthenticationFailed) {
		t.Fatalf("tampered metadata error=%v", err)
	}
}

func TestSignVerify(t *testing.T) {
	ks, err := keyset.New("jwt", keyset.Ed25519, keyset.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ks.Signer()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.SignMsg([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	ver, err := ks.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	if err := ver.VerifyKey(signer.KeyID(), []byte("payload"), sig); err != nil {
		t.Fatal(err)
	}
	if err := ver.Verify([]byte("payload"), sig); err != nil {
		t.Fatal(err)
	}
	publicVerifier, err := ks.Public().Verifier()
	if err != nil {
		t.Fatal(err)
	}
	if err := publicVerifier.VerifyKey(signer.KeyID(), []byte("payload"), sig); err != nil {
		t.Fatal(err)
	}
	var cryptoSigner crypto.Signer = signer
	sig, err = cryptoSigner.Sign(rand.Reader, []byte("crypto.Signer message"), crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := publicVerifier.VerifyKey(signer.KeyID(), []byte("crypto.Signer message"), sig); err != nil {
		t.Fatal(err)
	}
}

func TestMAC(t *testing.T) {
	ks, err := keyset.New("hooks", keyset.HMACSHA256, keyset.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	mac, err := ks.MAC()
	if err != nil {
		t.Fatal(err)
	}
	tag, err := mac.Sum([]byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	if err := mac.VerifyKey(mac.KeyID(), tag, []byte("body")); err != nil {
		t.Fatal(err)
	}
	if err := mac.Verify(tag, []byte("body")); err != nil {
		t.Fatal(err)
	}
	if len(tag) != mac.Overhead() || len(tag) != 37 {
		t.Fatalf("framed MAC size=%d", len(tag))
	}
	if got := binary.BigEndian.Uint32(tag[1:5]); got != mac.KeyID() {
		t.Fatalf("framed key id=%d, want %d", got, mac.KeyID())
	}
	tampered := append([]byte(nil), tag...)
	tampered[4] ^= 1
	if err := mac.Verify(tampered, []byte("body")); err == nil {
		t.Fatal("tampered key ID was accepted")
	}
	raw, err := mac.ComputeRaw([]byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != mac.RawOverhead() || len(raw) != 32 {
		t.Fatalf("raw MAC size=%d", len(raw))
	}
	if err := mac.VerifyKeyRaw(mac.KeyID(), raw, []byte("body")); err != nil {
		t.Fatal(err)
	}
}

func TestClientRotator(t *testing.T) {
	store := memstore.New(testKeeper(t))
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	rot, err := keyset.NewRotator(store,
		keyset.WithClock(func() time.Time { return now }),
		keyset.WithEnsure(map[string]keyset.Spec{
			"sessions": {Algorithm: keyset.AES256GCM, Policy: keyset.DefaultPolicy()},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := rot.Once(t.Context()); err != nil {
		t.Fatal(err)
	}

	client, err := keyset.NewClient(store, keyset.WithTTL(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := client.AEAD(t.Context(), "sessions")
	if err != nil {
		t.Fatal(err)
	}
	ct, err := aead.Seal([]byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := aead.OpenKey(aead.KeyID(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "x" {
		t.Fatal(string(pt))
	}
}

type observedStore struct {
	public keyset.Public
	mu     sync.Mutex
	gets   int
	pubs   int
}

func (s *observedStore) Get(context.Context, string) (*keyset.Keyset, error) {
	s.mu.Lock()
	s.gets++
	s.mu.Unlock()
	return nil, fmt.Errorf("private load should not be called")
}

func (s *observedStore) Public(context.Context, string) (keyset.Public, error) {
	s.mu.Lock()
	s.pubs++
	s.mu.Unlock()
	return s.public, nil
}

func TestClientVerifierLoadsOnlyPublicMaterial(t *testing.T) {
	ks, err := keyset.New("jwt", keyset.Ed25519, keyset.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	store := &observedStore{public: ks.Public()}
	client, err := keyset.NewClient(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Verifier(t.Context(), "jwt"); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.gets != 0 || store.pubs != 1 {
		t.Fatalf("private gets=%d public gets=%d", store.gets, store.pubs)
	}
}

func TestClientOptions(t *testing.T) {
	store := memstore.New(testKeeper(t))
	if _, err := keyset.NewClient(nil); err == nil {
		t.Fatal("nil store was accepted")
	}
	if _, err := keyset.NewClient(store, keyset.WithTTL(-time.Second)); err == nil {
		t.Fatal("negative TTL was accepted")
	}
	if _, err := keyset.NewClient(store, keyset.WithTTL(0)); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureIsIdempotent(t *testing.T) {
	store := memstore.New(testKeeper(t))
	rotator, err := keyset.NewRotator(store)
	if err != nil {
		t.Fatal(err)
	}
	policy := keyset.DefaultPolicy()
	if err := rotator.Ensure(t.Context(), "jwt", keyset.Ed25519, policy); err != nil {
		t.Fatal(err)
	}
	if err := rotator.Ensure(t.Context(), "jwt", keyset.Ed25519, policy); err != nil {
		t.Fatal(err)
	}
	if err := rotator.Ensure(t.Context(), "jwt", keyset.ECDSAP256SHA256, policy); !errors.Is(err, keyset.ErrExist) {
		t.Fatalf("mismatched ensure error=%v", err)
	}
}

func TestConcurrentRotatorStop(t *testing.T) {
	store := memstore.New(testKeeper(t))
	rotator, err := keyset.NewRotator(store, keyset.WithInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := rotator.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	var stopped sync.WaitGroup
	stopped.Add(2)
	for range 2 {
		go func() {
			defer stopped.Done()
			rotator.Stop()
		}()
	}
	stopped.Wait()
}
