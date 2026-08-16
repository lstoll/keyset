package k8sstore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"lds.li/keyset"
)

const (
	testNamespace = "test-ns"
	testSecret    = "keysets"
)

func TestStoreLifecycle(t *testing.T) {
	store := newTestStore(t)

	first, err := keyset.New("a", keyset.Ed25519, keyset.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(t.Context(), "a", first, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.Write(t.Context(), "a", first, nil); !errors.Is(err, keyset.ErrConflict) {
		t.Fatalf("duplicate insert error=%v", err)
	}

	public, err := store.Public(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if public.Name != "a" || len(public.Keys) != 2 {
		t.Fatalf("unexpected public keyset: %#v", public)
	}
	loaded, revision, err := store.Read(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PrimaryID() != first.PrimaryID() {
		t.Fatalf("loaded primary=%d", loaded.PrimaryID())
	}
	if revision == "" {
		t.Fatal("expected non-empty resourceVersion")
	}
	if err := store.Write(t.Context(), "a", loaded, revision); err != nil {
		t.Fatal(err)
	}
	if err := store.Write(t.Context(), "a", loaded, revision); !errors.Is(err, keyset.ErrConflict) {
		t.Fatalf("stale update error=%v", err)
	}

	second, err := keyset.New("b", keyset.AES256GCM, keyset.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(t.Context(), "b", second, nil); err != nil {
		t.Fatal(err)
	}
	var names []string
	if err := store.ForEach(t.Context(), func(name string) error {
		names = append(names, name)
		_, err := store.Get(t.Context(), name)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(names) != "[a b]" {
		t.Fatalf("names=%v", names)
	}
	if _, err := store.Get(t.Context(), "missing"); !errors.Is(err, keyset.ErrNotFound) {
		t.Fatalf("missing error=%v", err)
	}
}

func TestPublicDoesNotOpenPrivateMaterial(t *testing.T) {
	client := newFakeClient(t)
	keeper := &observedKeeper{keeper: newTestKeeper(t)}
	store, err := New(client, testNamespace, testSecret, keeper)
	if err != nil {
		t.Fatal(err)
	}
	value, err := keyset.New("jwt", keyset.Ed25519, keyset.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(t.Context(), "jwt", value, nil); err != nil {
		t.Fatal(err)
	}
	keeper.rejectOpen = true
	if _, err := store.Public(t.Context(), "jwt"); err != nil {
		t.Fatal(err)
	}
	if keeper.opens != 0 {
		t.Fatalf("Public opened private material %d times", keeper.opens)
	}
	if _, err := store.Get(t.Context(), "jwt"); err == nil {
		t.Fatal("Get succeeded while Keeper rejected Open")
	}
	publicStore, err := NewPublic(client, testNamespace, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publicStore.Public(t.Context(), "jwt"); err != nil {
		t.Fatal(err)
	}
	if _, err := publicStore.Get(t.Context(), "jwt"); !errors.Is(err, keyset.ErrInvalid) {
		t.Fatalf("public-only private read error=%v", err)
	}
	if err := publicStore.Write(t.Context(), "jwt", value, nil); !errors.Is(err, keyset.ErrInvalid) {
		t.Fatalf("public-only write error=%v", err)
	}
}

func TestForEachMissingSecret(t *testing.T) {
	store := newTestStore(t)
	if err := store.ForEach(t.Context(), func(string) error {
		t.Fatal("callback invoked for missing secret")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConstructorValidation(t *testing.T) {
	client := fake.NewClientset()
	keeper := newTestKeeper(t)
	if _, err := New(nil, testNamespace, testSecret, keeper); err == nil {
		t.Fatal("nil client accepted")
	}
	if _, err := New(client, testNamespace, testSecret, nil); err == nil {
		t.Fatal("nil keeper accepted")
	}
	if _, err := New(client, "Not_A_Namespace", testSecret, keeper); err == nil {
		t.Fatal("invalid namespace accepted")
	}
	if _, err := New(client, testNamespace, "Not_A_Secret", keeper); err == nil {
		t.Fatal("invalid secret name accepted")
	}
}

func TestInvalidKeysetName(t *testing.T) {
	store := newTestStore(t)
	value, err := keyset.New("bad/name", keyset.Ed25519, keyset.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(t.Context(), "bad/name", value, nil); !errors.Is(err, keyset.ErrInvalid) {
		t.Fatalf("invalid name write error=%v", err)
	}
	if _, err := store.Get(t.Context(), "bad/name"); !errors.Is(err, keyset.ErrInvalid) {
		t.Fatalf("invalid name get error=%v", err)
	}
}

func TestRotatorOnce(t *testing.T) {
	store := newTestStore(t)
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	rotator, err := keyset.NewRotator(store,
		keyset.WithClock(func() time.Time { return now }),
		keyset.WithEnsure(map[string]keyset.Spec{
			"jwt": {Algorithm: keyset.Ed25519, Policy: keyset.DefaultPolicy()},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotator.Once(t.Context()); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := store.Read(t.Context(), "jwt")
	if err != nil {
		t.Fatal(err)
	}
	primary := loaded.PrimaryID()
	now = now.Add(8 * 24 * time.Hour)
	if err := rotator.Once(t.Context()); err != nil {
		t.Fatal(err)
	}
	rotated, _, err := store.Read(t.Context(), "jwt")
	if err != nil {
		t.Fatal(err)
	}
	if rotated.PrimaryID() == primary {
		t.Fatal("rotator did not promote a new primary")
	}
}

func TestWriteInvalidRevision(t *testing.T) {
	store := newTestStore(t)
	value, err := keyset.New("a", keyset.Ed25519, keyset.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(t.Context(), "a", value, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.Write(t.Context(), "a", value, int64(1)); !errors.Is(err, keyset.ErrInvalid) {
		t.Fatalf("int64 revision error=%v", err)
	}
	if err := store.Write(t.Context(), "a", value, ""); !errors.Is(err, keyset.ErrInvalid) {
		t.Fatalf("empty revision error=%v", err)
	}
}

func TestUpdateAPIConflict(t *testing.T) {
	client := newFakeClient(t)
	store, err := New(client, testNamespace, testSecret, newTestKeeper(t))
	if err != nil {
		t.Fatal(err)
	}
	value, err := keyset.New("a", keyset.Ed25519, keyset.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(t.Context(), "a", value, nil); err != nil {
		t.Fatal(err)
	}
	loaded, revision, err := store.Read(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	client.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, testSecret, errors.New("conflict"))
	})
	if err := store.Write(t.Context(), "a", loaded, revision); !errors.Is(err, keyset.ErrConflict) {
		t.Fatalf("api conflict error=%v", err)
	}
}

type observedKeeper struct {
	keeper     keyset.Keeper
	rejectOpen bool
	opens      int
}

func (k *observedKeeper) Seal(plaintext, aad []byte) ([]byte, error) {
	return k.keeper.Seal(plaintext, aad)
}

func (k *observedKeeper) Open(ciphertext, aad []byte) ([]byte, error) {
	k.opens++
	if k.rejectOpen {
		return nil, errors.New("Open rejected by test")
	}
	return k.keeper.Open(ciphertext, aad)
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(newFakeClient(t), testNamespace, testSecret, newTestKeeper(t))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func newFakeClient(t *testing.T) *fake.Clientset {
	t.Helper()
	client := fake.NewClientset()
	instrumentResourceVersions(client)
	return client
}

// instrumentResourceVersions assigns incrementing resourceVersions on create
// and update so optimistic concurrency can be tested without a real apiserver.
func instrumentResourceVersions(client *fake.Clientset) {
	var next atomic.Int64
	bump := func(obj runtime.Object) {
		accessor, err := meta.Accessor(obj)
		if err != nil {
			return
		}
		accessor.SetResourceVersion(strconv.FormatInt(next.Add(1), 10))
	}
	client.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		bump(action.(k8stesting.CreateAction).GetObject())
		return false, nil, nil
	})
	client.PrependReactor("update", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		bump(action.(k8stesting.UpdateAction).GetObject())
		return false, nil, nil
	})
}

func newTestKeeper(t *testing.T) keyset.Keeper {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return keyset.FromCipher(aead)
}
