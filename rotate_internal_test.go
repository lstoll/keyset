package keyset

import (
	"context"
	"testing"
	"time"
)

func testBytesType(policy Policy) Type {
	return Type{
		Policy: policy,
		New: func(context.Context) (Material, error) {
			return Material{Private: []byte("secret")}, nil
		},
	}
}

func TestPhaseOutUsesPerKeyTimestamp(t *testing.T) {
	policy := Policy{
		Primary:   10 * time.Second,
		Propagate: 0,
		PhaseOut:  25 * time.Second,
		Retention: 5 * time.Second,
	}
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	ks, err := newAt(t.Context(), "jwt", "jwt", testBytesType(policy), start)
	if err != nil {
		t.Fatal(err)
	}
	firstID := ks.PrimaryID()
	for _, elapsed := range []time.Duration{10, 20, 30} {
		if _, err := ks.Rotate(t.Context(), start.Add(elapsed*time.Second), nil); err != nil {
			t.Fatal(err)
		}
	}
	first, ok := ks.keyByID(firstID)
	if !ok || first.State != StatePhasingOut {
		t.Fatalf("first key before deadline = %#v, present=%v", first, ok)
	}
	if _, err := ks.Rotate(t.Context(), start.Add(35*time.Second), nil); err != nil {
		t.Fatal(err)
	}
	first, ok = ks.keyByID(firstID)
	if !ok || first.State != StateDisabled {
		t.Fatalf("first key at deadline = %#v, present=%v", first, ok)
	}
	if _, err := ks.Rotate(t.Context(), start.Add(40*time.Second), nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := ks.keyByID(firstID); ok {
		t.Fatal("first key was not deleted after its retention period")
	}
}

func TestZeroPhaseOutKeepsKeysUsable(t *testing.T) {
	policy := Policy{Primary: time.Second}
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	ks, err := newAt(t.Context(), "data", "data", testBytesType(policy), start)
	if err != nil {
		t.Fatal(err)
	}
	firstID := ks.PrimaryID()
	for i := 1; i <= 10; i++ {
		if _, err := ks.Rotate(t.Context(), start.Add(time.Duration(i)*time.Second), nil); err != nil {
			t.Fatal(err)
		}
	}
	first, ok := ks.keyByID(firstID)
	if !ok || first.State != StatePhasingOut {
		t.Fatalf("indefinitely retained key = %#v, present=%v", first, ok)
	}
}
