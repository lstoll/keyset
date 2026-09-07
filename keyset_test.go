package keyset_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

func testType(policy keyset.Policy) keyset.Type {
	var n atomic.Int64
	return keyset.Type{
		Policy: policy,
		New: func(context.Context) (keyset.Material, error) {
			priv := make([]byte, 32)
			if _, err := rand.Read(priv); err != nil {
				return keyset.Material{}, err
			}
			id := n.Add(1)
			return keyset.Material{
				Private: priv,
				Public:  []byte(fmt.Sprintf("pub-%d", id)),
			}, nil
		},
	}
}

func typedIDs(policy keyset.Policy) keyset.Type {
	var n atomic.Int64
	return keyset.Type{
		Policy: policy,
		New: func(context.Context) (keyset.Material, error) {
			id := n.Add(1)
			return keyset.Material{
				ID:      fmt.Sprintf("%d", id),
				Private: []byte(fmt.Sprintf("priv-%d", id)),
				Public:  []byte(fmt.Sprintf("pub-%d", id)),
			}, nil
		},
	}
}

func newRegistry(t *testing.T, types map[string]keyset.Type) *keyset.Registry {
	t.Helper()
	reg, err := keyset.NewRegistry(types)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestLifecycleAndMaterial(t *testing.T) {
	policy := keyset.Policy{
		Primary:   10 * time.Second,
		Propagate: 2 * time.Second,
		PhaseOut:  5 * time.Second,
		Retention: 3 * time.Second,
	}
	typ := testType(policy)
	ks, err := keyset.New(t.Context(), "sessions", "sessions", typ)
	if err != nil {
		t.Fatal(err)
	}
	if ks.Type() != "sessions" || ks.Name() != "sessions" {
		t.Fatalf("name=%q type=%q", ks.Name(), ks.Type())
	}
	primary, ok := ks.Primary()
	if !ok || !primary.State.IsPrimary() || len(primary.Private) == 0 {
		t.Fatalf("primary=%#v ok=%v", primary, ok)
	}
	keys := ks.Keys()
	if len(keys) != 2 {
		t.Fatalf("keys=%d", len(keys))
	}
	var pending bool
	for _, k := range keys {
		if k.State == keyset.StatePending && k.State.IsUsable() && !k.State.IsPrimary() {
			pending = true
		}
	}
	if !pending {
		t.Fatal("expected a pending successor")
	}

	end := time.Now().UTC().Add(60 * time.Second)
	now := time.Now().UTC()
	seen := map[string]bool{ks.PrimaryID(): true}
	for now = now.Add(time.Second); now.Before(end); now = now.Add(time.Second) {
		if _, err := ks.Rotate(t.Context(), now, &typ); err != nil {
			t.Fatal(err)
		}
		seen[ks.PrimaryID()] = true
	}
	if len(seen) < 2 {
		t.Fatalf("expected rotations, primaries=%d", len(seen))
	}
}

func TestConstructorIDs(t *testing.T) {
	ks, err := keyset.New(t.Context(), "jwt", "jwt", typedIDs(keyset.DefaultPolicy()))
	if err != nil {
		t.Fatal(err)
	}
	if ks.PrimaryID() != "1" {
		t.Fatalf("primary id=%s", ks.PrimaryID())
	}
	got, ok := ks.Key("2")
	if !ok || got.State != keyset.StatePending {
		t.Fatalf("pending=%#v ok=%v", got, ok)
	}

	dup := keyset.Type{
		Policy: keyset.DefaultPolicy(),
		New: func(context.Context) (keyset.Material, error) {
			return keyset.Material{ID: "same", Private: []byte("x")}, nil
		},
	}
	if _, err := keyset.New(t.Context(), "x", "x", dup); err == nil {
		t.Fatal("duplicate constructor id accepted")
	}
}

// sequentialIDs numbers keys max+1 from the ids already in the keyset, so it
// keeps working after a reload, unlike a counter held in memory.
func sequentialIDs(existing []string) (string, error) {
	highest := 0
	for _, id := range existing {
		n, err := strconv.Atoi(id)
		if err != nil {
			return "", fmt.Errorf("non-numeric id %q", id)
		}
		highest = max(highest, n)
	}
	return strconv.Itoa(highest + 1), nil
}

func TestNewIDSequentialSurvivesReload(t *testing.T) {
	typ := testType(keyset.Policy{Primary: time.Second})
	typ.NewID = sequentialIDs
	start := time.Now().UTC()
	ks, err := keyset.New(t.Context(), "s", "s", typ)
	if err != nil {
		t.Fatal(err)
	}
	if ks.PrimaryID() != "1" {
		t.Fatalf("primary id=%q", ks.PrimaryID())
	}
	blob, err := ks.Marshal(testKeeper(t))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := keyset.Unmarshal("s", blob, testKeeper(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.Rotate(t.Context(), start.Add(2*time.Second), &typ); err != nil {
		t.Fatal(err)
	}
	if loaded.PrimaryID() != "2" {
		t.Fatalf("primary id=%q", loaded.PrimaryID())
	}
	if k, ok := loaded.Key("3"); !ok || k.State != keyset.StatePending {
		t.Fatalf("pending=%#v ok=%v", k, ok)
	}
}

func TestNewIDPrecedenceAndValidation(t *testing.T) {
	material := func(id string) func(context.Context) (keyset.Material, error) {
		return func(context.Context) (keyset.Material, error) {
			return keyset.Material{ID: id, Private: []byte("x")}, nil
		}
	}

	called := false
	explicit := keyset.Type{
		Policy: keyset.DefaultPolicy(),
		New: func(context.Context) (keyset.Material, error) {
			if called {
				return keyset.Material{ID: "second", Private: []byte("x")}, nil
			}
			called = true
			return keyset.Material{ID: "first", Private: []byte("x")}, nil
		},
		NewID: func([]string) (string, error) {
			t.Error("NewID called although Material.ID was set")
			return "unused", nil
		},
	}
	ks, err := keyset.New(t.Context(), "e", "e", explicit)
	if err != nil {
		t.Fatal(err)
	}
	if ks.PrimaryID() != "first" {
		t.Fatalf("primary id=%q", ks.PrimaryID())
	}

	genErr := errors.New("generator broke")
	for name, newID := range map[string]func([]string) (string, error){
		"empty":     func([]string) (string, error) { return "", nil },
		"too long":  func([]string) (string, error) { return strings.Repeat("x", 129), nil },
		"duplicate": func([]string) (string, error) { return "fixed", nil },
		"error":     func([]string) (string, error) { return "", genErr },
	} {
		typ := keyset.Type{Policy: keyset.DefaultPolicy(), New: material(""), NewID: newID}
		_, err := keyset.New(t.Context(), "x", "x", typ)
		want := keyset.ErrInvalid
		if name == "error" {
			want = genErr
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: err=%v, want %v", name, err, want)
		}
	}

	// existing is a copy; mutating it must not affect the keyset.
	mutating := keyset.Type{
		Policy: keyset.DefaultPolicy(),
		New:    material(""),
		NewID: func(existing []string) (string, error) {
			id, err := sequentialIDs(existing)
			for i := range existing {
				existing[i] = "clobbered"
			}
			return id, err
		},
	}
	ks, err = keyset.New(t.Context(), "m", "m", mutating)
	if err != nil {
		t.Fatal(err)
	}
	if ks.PrimaryID() != "1" {
		t.Fatalf("primary id=%q", ks.PrimaryID())
	}
	if _, ok := ks.Key("2"); !ok {
		t.Fatal("pending key id was clobbered")
	}
}

func TestRotateRequiresConstructorToMint(t *testing.T) {
	policy := keyset.Policy{Primary: time.Second, Propagate: 0}
	typ := testType(policy)
	ks, err := keyset.New(t.Context(), "s", "s", typ)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := ks.Marshal(testKeeper(t))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := keyset.Unmarshal("s", blob, testKeeper(t))
	if err != nil {
		t.Fatal(err)
	}
	before := loaded.Keys()
	later := time.Now().UTC().Add(2 * time.Second)
	changed, err := loaded.Rotate(t.Context(), later, nil)
	if !errors.Is(err, keyset.ErrInvalid) {
		t.Fatalf("rotate without constructor error=%v", err)
	}
	if changed {
		t.Fatal("failed rotate reported a change")
	}
	// A failed rotate must not leave a promoted primary with no pending key.
	if diff := keyStates(loaded.Keys()); diff != keyStates(before) {
		t.Fatalf("failed rotate mutated keyset: before=%s after=%s", keyStates(before), diff)
	}

	// Supplying the constructor afterwards rotates normally.
	if _, err := loaded.Rotate(t.Context(), later, &typ); err != nil {
		t.Fatal(err)
	}
	if loaded.PrimaryID() == ks.PrimaryID() {
		t.Fatal("primary was not rotated")
	}
}

func keyStates(keys []keyset.Key) string {
	var out string
	for _, k := range keys {
		out += k.ID + "=" + string(k.State) + ";"
	}
	return out
}

func TestRefuseJSONAndKeeper(t *testing.T) {
	ks, err := keyset.New(t.Context(), "a", "aes", testType(keyset.DefaultPolicy()))
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
	if !bytes.Contains(pub, []byte(`"name":"a"`)) || !bytes.Contains(pub, []byte(`"type":"aes"`)) {
		t.Fatalf("%s", pub)
	}
	if !bytes.Contains(pub, []byte(`"primary":"168h0m0s"`)) || !bytes.Contains(pub, []byte(`"propagate":"1h0m0s"`)) {
		t.Fatalf("policy durations not encoded as units: %s", pub)
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
	if got.Name() != "a" || got.Type() != "aes" {
		t.Fatalf("got name=%q type=%q", got.Name(), got.Type())
	}
	if _, ok := got.Key(ks.PrimaryID()); !ok {
		t.Fatal("unmarshaled keyset missing primary material")
	}

	clear, err := ks.Marshal(insecurecleartext.Keeper)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(clear, []byte(`"name":"a"`)) {
		t.Fatalf("%s", clear)
	}
	if !bytes.Contains(clear, []byte(`"primary":"168h0m0s"`)) {
		t.Fatalf("envelope policy durations not encoded as units: %s", clear)
	}
	withUnknownField := bytes.Replace(clear, []byte(`{"version":1`), []byte(`{"unknown":true,"version":1`), 1)
	if _, err := keyset.Unmarshal("a", withUnknownField, insecurecleartext.Keeper); err == nil {
		t.Fatal("unknown document field was accepted")
	}
}

func TestInspectableAuthenticatedEnvelope(t *testing.T) {
	ks, err := keyset.New(t.Context(), "inspect", "jwt", testType(keyset.DefaultPolicy()))
	if err != nil {
		t.Fatal(err)
	}
	keeper := testKeeper(t)
	encrypted, err := ks.Marshal(keeper)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encrypted, []byte(`"name":"inspect"`)) ||
		!bytes.Contains(encrypted, []byte(`"type":"jwt"`)) ||
		!bytes.Contains(encrypted, []byte(`"state":"primary"`)) ||
		!bytes.Contains(encrypted, []byte(`"public_key"`)) {
		t.Fatalf("public metadata is not inspectable: %s", encrypted)
	}

	public, err := keyset.UnmarshalPublic(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if public.Name != "inspect" || public.Type != "jwt" || len(public.Keys) != 2 || len(public.Keys[0].PublicKey) == 0 {
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

func TestClientRotator(t *testing.T) {
	store := memstore.New(testKeeper(t))
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	typ := testType(keyset.DefaultPolicy())
	reg := newRegistry(t, map[string]keyset.Type{"sessions": typ})
	rot, err := keyset.NewRotator(store, reg,
		keyset.WithClock(func() time.Time { return now }),
		keyset.WithEnsure(map[string]string{"sessions": "sessions"}),
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
	ks, err := client.Get(t.Context(), "sessions")
	if err != nil {
		t.Fatal(err)
	}
	primary, ok := ks.Primary()
	if !ok || len(primary.Private) == 0 {
		t.Fatalf("primary=%#v", primary)
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

func TestClientGetReturnsIndependentCopies(t *testing.T) {
	store := memstore.New(testKeeper(t))
	typ := testType(keyset.Policy{Primary: time.Second})
	ks, err := keyset.New(t.Context(), "s", "s", typ)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(t.Context(), "s", ks, nil); err != nil {
		t.Fatal(err)
	}
	client, err := keyset.NewClient(store, keyset.WithTTL(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	a, err := client.Get(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	b, err := client.Get(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("client returned the same *Keyset to two callers")
	}

	// Mutating one copy concurrently with reads of another must not race
	// (run with -race) or leak into the cache.
	var wg sync.WaitGroup
	wg.Go(func() {
		if _, err := a.Rotate(t.Context(), time.Now().Add(time.Hour), &typ); err != nil {
			t.Error(err)
		}
	})
	wg.Go(func() {
		for range 100 {
			_, _ = b.Primary()
		}
	})
	wg.Wait()

	c, err := client.Get(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if c.PrimaryID() != ks.PrimaryID() || a.PrimaryID() == ks.PrimaryID() {
		t.Fatalf("cache primary=%q rotated copy=%q original=%q", c.PrimaryID(), a.PrimaryID(), ks.PrimaryID())
	}
}

func TestClientPublicLoadsOnlyPublicMaterial(t *testing.T) {
	ks, err := keyset.New(t.Context(), "jwt", "jwt", testType(keyset.DefaultPolicy()))
	if err != nil {
		t.Fatal(err)
	}
	store := &observedStore{public: ks.Public()}
	client, err := keyset.NewClient(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Public(t.Context(), "jwt"); err != nil {
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
	reg := newRegistry(t, map[string]keyset.Type{
		"jwt": testType(keyset.DefaultPolicy()),
		"ec":  testType(keyset.DefaultPolicy()),
	})
	rotator, err := keyset.NewRotator(store, reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotator.Ensure(t.Context(), "jwt", "jwt"); err != nil {
		t.Fatal(err)
	}
	if err := rotator.Ensure(t.Context(), "jwt", "jwt"); err != nil {
		t.Fatal(err)
	}
	if err := rotator.Ensure(t.Context(), "jwt", "ec"); !errors.Is(err, keyset.ErrExist) {
		t.Fatalf("mismatched ensure error=%v", err)
	}
}

func TestRotatorSharedTypeAndUnknown(t *testing.T) {
	store := memstore.New(testKeeper(t))
	shared := testType(keyset.DefaultPolicy())
	reg := newRegistry(t, map[string]keyset.Type{"jwt": shared})
	rotator, err := keyset.NewRotator(store, reg,
		keyset.WithEnsure(map[string]string{
			"a": "jwt",
			"b": "jwt",
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotator.Once(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		ks, err := store.Get(t.Context(), name)
		if err != nil {
			t.Fatal(err)
		}
		if ks.Type() != "jwt" {
			t.Fatalf("%s type=%s", name, ks.Type())
		}
	}

	orphan, err := keyset.New(t.Context(), "orphan", "other", testType(keyset.DefaultPolicy()))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(t.Context(), "orphan", orphan, nil); err != nil {
		t.Fatal(err)
	}
	if err := rotator.Once(t.Context()); !errors.Is(err, keyset.ErrInvalid) {
		t.Fatalf("unknown type error=%v", err)
	}
}

func TestRotatorPolicyResync(t *testing.T) {
	store := memstore.New(testKeeper(t))
	old := testType(keyset.Policy{Primary: time.Hour, Propagate: time.Minute})
	ks, err := keyset.New(t.Context(), "s", "s", old)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(t.Context(), "s", ks, nil); err != nil {
		t.Fatal(err)
	}
	updated := keyset.DefaultPolicy()
	reg := newRegistry(t, map[string]keyset.Type{
		"s": {Policy: updated, New: old.New},
	})
	rotator, err := keyset.NewRotator(store, reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotator.Once(t.Context()); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Get(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Policy() != updated {
		t.Fatalf("policy=%#v", loaded.Policy())
	}
}

func TestConcurrentRotatorStop(t *testing.T) {
	store := memstore.New(testKeeper(t))
	reg := newRegistry(t, map[string]keyset.Type{})
	rotator, err := keyset.NewRotator(store, reg, keyset.WithInterval(time.Hour))
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

func TestRegistryValidation(t *testing.T) {
	if _, err := keyset.NewRegistry(map[string]keyset.Type{"": testType(keyset.DefaultPolicy())}); err == nil {
		t.Fatal("empty type name accepted")
	}
	if _, err := keyset.NewRegistry(map[string]keyset.Type{"x": {Policy: keyset.DefaultPolicy()}}); err == nil {
		t.Fatal("nil New accepted")
	}
	if _, err := keyset.NewRotator(memstore.New(testKeeper(t)), nil); err == nil {
		t.Fatal("nil registry accepted")
	}
}
