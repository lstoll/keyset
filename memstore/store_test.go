package memstore

import (
	"context"
	"errors"
	"slices"
	"testing"

	"lds.li/keyset"
	"lds.li/keyset/insecurecleartext"
)

var testType = keyset.Type{
	Policy: keyset.DefaultPolicy(),
	New: func(context.Context) (keyset.Material, error) {
		return keyset.Material{Private: []byte("secret"), Public: []byte("public")}, nil
	},
}

func newKeyset(t *testing.T, name string) *keyset.Keyset {
	t.Helper()
	ks, err := keyset.New(t.Context(), name, "test", testType)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func TestReadWrite(t *testing.T) {
	ctx := t.Context()
	s := New(insecurecleartext.Keeper)

	if _, rev, err := s.Read(ctx, "a"); !errors.Is(err, keyset.ErrNotFound) || rev != nil {
		t.Fatalf("missing read rev=%v err=%v", rev, err)
	}
	if _, err := s.Public(ctx, "a"); !errors.Is(err, keyset.ErrNotFound) {
		t.Fatalf("missing public err=%v", err)
	}

	ks := newKeyset(t, "a")
	if err := s.Write(ctx, "a", ks, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(ctx, "a", ks, nil); !errors.Is(err, keyset.ErrConflict) {
		t.Fatalf("duplicate insert err=%v", err)
	}

	got, rev, err := s.Read(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if got.PrimaryID() != ks.PrimaryID() {
		t.Fatalf("primary=%q want %q", got.PrimaryID(), ks.PrimaryID())
	}
	if err := s.Write(ctx, "a", got, rev); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(ctx, "a", got, rev); !errors.Is(err, keyset.ErrConflict) {
		t.Fatalf("stale revision err=%v", err)
	}
	if err := s.Write(ctx, "a", got, "not-an-int64"); !errors.Is(err, keyset.ErrInvalid) {
		t.Fatalf("bad revision type err=%v", err)
	}
	if err := s.Write(ctx, "b", got, nil); !errors.Is(err, keyset.ErrInvalid) {
		t.Fatalf("name mismatch err=%v", err)
	}

	pub, err := s.Public(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if pub.Name != "a" || pub.PrimaryID != ks.PrimaryID() {
		t.Fatalf("public=%+v", pub)
	}
}

func TestPublicRejectsMismatchedName(t *testing.T) {
	s := New(insecurecleartext.Keeper)
	blob, err := newKeyset(t, "a").Marshal(insecurecleartext.Keeper)
	if err != nil {
		t.Fatal(err)
	}
	s.entries["b"] = entry{blob: blob, rev: 1}
	if _, err := s.Public(t.Context(), "b"); !errors.Is(err, keyset.ErrInvalid) {
		t.Fatalf("mismatched public err=%v", err)
	}
	if _, _, err := s.Read(t.Context(), "b"); err == nil {
		t.Fatal("mismatched read succeeded")
	}
}

func TestForEach(t *testing.T) {
	ctx := t.Context()
	s := New(insecurecleartext.Keeper)
	for _, name := range []string{"a", "b", "c"} {
		if err := s.Write(ctx, name, newKeyset(t, name), nil); err != nil {
			t.Fatal(err)
		}
	}
	var names []string
	if err := s.ForEach(ctx, func(name string) error {
		names = append(names, name)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"a", "b", "c"}) {
		t.Fatalf("names=%v", names)
	}

	stop := errors.New("stop")
	if err := s.ForEach(ctx, func(string) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("callback err=%v", err)
	}
}
