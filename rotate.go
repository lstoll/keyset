package keyset

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Rotate advances key lifecycle for this keyset. If now is zero, time.Now is used.
//
// t supplies the constructor, id generator, and policy. A non-nil t replaces
// the keyset's policy with t.Policy (reported as a change if it differs) and is
// kept for later calls. If t is nil, the Type given to New is used along with
// the stored policy; keysets from Unmarshal have no Type, so minting a pending
// key returns ErrInvalid. Rotate is atomic: on error the keyset is unchanged.
func (k *Keyset) Rotate(ctx context.Context, now time.Time, t *Type) (changed bool, err error) {
	if k == nil {
		return false, fmt.Errorf("%w: nil keyset", ErrInvalid)
	}
	if err := k.validate(); err != nil {
		return false, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	// Work on a copy so a failure part way through cannot leave k half-rotated.
	w := k.clone()
	policyChanged := false
	if t != nil {
		if err := t.validate(); err != nil {
			return false, fmt.Errorf("keyset: type %q: %w", w.doc.Type, err)
		}
		tc := *t
		w.typ = &tc
		if w.doc.Policy != t.Policy {
			w.doc.Policy = t.Policy
			policyChanged = true
		}
	}
	r := &rotator{
		k:      w,
		policy: w.doc.Policy,
		now:    now,
		ctx:    ctx,
		typ:    w.typ,
	}
	for _, step := range []func() error{
		r.handleDeletions,
		r.handlePhaseOut,
		r.handlePromotions,
		r.handleKeyGeneration,
	} {
		r.index()
		if err := step(); err != nil {
			return false, err
		}
	}
	if err := w.validate(); err != nil {
		return false, fmt.Errorf("keyset: inconsistent after rotate: %w", err)
	}
	*k = *w
	return r.changed || policyChanged, nil
}

type rotator struct {
	k       *Keyset
	policy  Policy
	now     time.Time
	ctx     context.Context
	typ     *Type
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
		case StatePrimary:
			r.primary = ky
		case StatePending:
			r.pending = append(r.pending, ky)
		case StatePhasingOut:
			r.phasingOut = append(r.phasingOut, ky)
		case StateDisabled:
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
		if ky.State == StateDisabled && ky.DeleteAfter != nil && !r.now.Before(ky.DeleteAfter.UTC()) {
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
		ky.State = StateDisabled
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
			r.primary.State = StatePhasingOut
			now := r.now
			r.primary.PhasedOutAt = &now
			pending.State = StatePrimary
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
	pending.State = StatePrimary
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
		case StatePending:
			hasPending = true
		case StatePrimary:
			hasPrimary = true
		}
	}
	if hasPrimary && !hasPending {
		if _, err := r.k.addKey(r.ctx, StatePending, r.now, r.typ); err != nil {
			return fmt.Errorf("keyset: generate pending: %w", err)
		}
		r.changed = true
	}
	return nil
}
