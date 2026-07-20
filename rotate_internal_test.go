package keyset

import (
	"testing"
	"time"
)

func TestPhaseOutUsesPerKeyTimestamp(t *testing.T) {
	policy := Policy{
		Primary:   10 * time.Second,
		Propagate: 0,
		PhaseOut:  25 * time.Second,
		Retention: 5 * time.Second,
	}
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	ks, err := newAt("jwt", Ed25519, policy, start)
	if err != nil {
		t.Fatal(err)
	}
	firstID := ks.PrimaryID()
	for _, elapsed := range []time.Duration{10, 20, 30} {
		if _, err := ks.Rotate(start.Add(elapsed * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	first, ok := ks.keyByID(firstID)
	if !ok || first.State != statePhasingOut {
		t.Fatalf("first key before deadline = %#v, present=%v", first, ok)
	}
	if _, err := ks.Rotate(start.Add(35 * time.Second)); err != nil {
		t.Fatal(err)
	}
	first, ok = ks.keyByID(firstID)
	if !ok || first.State != stateDisabled {
		t.Fatalf("first key at deadline = %#v, present=%v", first, ok)
	}
	if _, err := ks.Rotate(start.Add(40 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok := ks.keyByID(firstID); ok {
		t.Fatal("first key was not deleted after its retention period")
	}
}

func TestZeroPhaseOutKeepsKeysUsable(t *testing.T) {
	policy := Policy{Primary: time.Second}
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	ks, err := newAt("data", AES256GCM, policy, start)
	if err != nil {
		t.Fatal(err)
	}
	firstID := ks.PrimaryID()
	for i := 1; i <= 10; i++ {
		if _, err := ks.Rotate(start.Add(time.Duration(i) * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	first, ok := ks.keyByID(firstID)
	if !ok || first.State != statePhasingOut {
		t.Fatalf("indefinitely retained key = %#v, present=%v", first, ok)
	}
}
