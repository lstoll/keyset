package keyset

import (
	"fmt"
	"log/slog"
	"sort"
	"time"
)

// Rotate advances key lifecycle for this keyset. If now is zero, time.Now is used.
func (k *Keyset) Rotate(now time.Time) (changed bool, err error) {
	if k == nil {
		return false, fmt.Errorf("%w: nil keyset", ErrInvalid)
	}
	if err := k.validate(); err != nil {
		return false, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	r := &rotator{
		k:      k,
		policy: k.doc.Policy,
		now:    now,
		logger: slog.New(slog.DiscardHandler),
	}
	r.index()
	if err := r.handleDeletions(); err != nil {
		return r.changed, err
	}
	r.index()
	if err := r.handlePhaseOut(); err != nil {
		return r.changed, err
	}
	r.index()
	if err := r.handlePromotions(); err != nil {
		return r.changed, err
	}
	r.index()
	if err := r.handleKeyGeneration(); err != nil {
		return r.changed, err
	}
	if err := k.validate(); err != nil {
		return r.changed, fmt.Errorf("keyset: inconsistent after rotate: %w", err)
	}
	return r.changed, nil
}

type rotator struct {
	k       *Keyset
	policy  Policy
	now     time.Time
	logger  *slog.Logger
	changed bool

	primary    *key
	pending    []*key
	phasingOut []*key
	disabled   []*key
}

func (r *rotator) index() {
	r.primary = nil
	r.pending = nil
	r.phasingOut = nil
	r.disabled = nil
	for i := range r.k.doc.Keys {
		ky := &r.k.doc.Keys[i]
		switch ky.State {
		case statePrimary:
			r.primary = ky
		case statePending:
			r.pending = append(r.pending, ky)
		case statePhasingOut:
			r.phasingOut = append(r.phasingOut, ky)
		case stateDisabled:
			r.disabled = append(r.disabled, ky)
		}
	}
	sort.Slice(r.pending, func(i, j int) bool {
		return r.pending[i].CreatedAt.Before(r.pending[j].CreatedAt)
	})
}

func (r *rotator) handleDeletions() error {
	keep := r.k.doc.Keys[:0]
	for i := range r.k.doc.Keys {
		ky := r.k.doc.Keys[i]
		if ky.State == stateDisabled && ky.DeleteAfter != nil && !r.now.Before(ky.DeleteAfter.UTC()) {
			r.changed = true
			continue
		}
		keep = append(keep, ky)
	}
	r.k.doc.Keys = keep
	return nil
}

func (r *rotator) handlePhaseOut() error {
	if r.policy.PhaseOut == 0 {
		return nil
	}
	for _, ky := range r.phasingOut {
		if ky.PhasedOutAt == nil || r.now.Before(ky.PhasedOutAt.UTC().Add(r.policy.PhaseOut)) {
			continue
		}
		now := r.now
		ky.State = stateDisabled
		ky.DisabledAt = &now
		if r.policy.Retention > 0 {
			del := r.now.Add(r.policy.Retention)
			ky.DeleteAfter = &del
		}
		r.changed = true
	}
	return nil
}

func (r *rotator) handlePromotions() error {
	if r.primary != nil {
		var end time.Time
		expired := false
		if r.primary.PromotedAt != nil {
			end = r.primary.PromotedAt.UTC().Add(r.policy.Primary)
			expired = !r.now.Before(end)
		} else if !r.primary.CreatedAt.IsZero() {
			end = r.primary.CreatedAt.UTC().Add(r.policy.Primary)
			expired = !r.now.Before(end)
		}
		if !expired || len(r.pending) == 0 {
			return nil
		}
		for _, pending := range r.pending {
			propEnd := pending.CreatedAt.UTC().Add(r.policy.Propagate)
			if r.now.Before(propEnd) {
				continue
			}
			r.primary.State = statePhasingOut
			now := r.now
			r.primary.PhasedOutAt = &now
			pending.State = statePrimary
			pending.PromotedAt = &now
			r.k.doc.PrimaryID = pending.ID
			r.changed = true
			return nil
		}
		return nil
	}

	if len(r.pending) == 0 {
		return fmt.Errorf("%w: no primary and no pending keys", ErrInvalid)
	}
	pending := r.pending[0]
	propEnd := pending.CreatedAt.UTC().Add(r.policy.Propagate)
	if r.now.Before(propEnd) {
		return nil
	}
	pending.State = statePrimary
	now := r.now
	pending.PromotedAt = &now
	r.k.doc.PrimaryID = pending.ID
	r.changed = true
	return nil
}

func (r *rotator) handleKeyGeneration() error {
	hasPending := false
	hasPrimary := false
	for i := range r.k.doc.Keys {
		switch r.k.doc.Keys[i].State {
		case statePending:
			hasPending = true
		case statePrimary:
			hasPrimary = true
		}
	}
	if hasPrimary && !hasPending {
		if _, err := r.k.addKey(statePending, r.now); err != nil {
			return fmt.Errorf("keyset: generate pending: %w", err)
		}
		r.changed = true
	}
	return nil
}
