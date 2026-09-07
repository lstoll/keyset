package keyset

import (
	"encoding/binary"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"time"
)

const (
	maxDocumentBytes = 1 << 20
	maxEnvelopeBytes = 2 << 20
)

var errRefuseJSON = errors.New("keyset: refuse JSON encode/decode of secrets; use Marshal/Unmarshal with a Keeper")

var jsonStrict = json.RejectUnknownMembers(true)

type policyJSON struct {
	Primary   string `json:"primary"`
	Propagate string `json:"propagate"`
	PhaseOut  string `json:"phase_out"`
	Retention string `json:"retention"`
}

// MarshalJSON encodes durations as time.Duration strings (e.g. "168h0m0s").
func (p Policy) MarshalJSON() ([]byte, error) {
	return json.Marshal(policyJSON{
		Primary:   p.Primary.String(),
		Propagate: p.Propagate.String(),
		PhaseOut:  p.PhaseOut.String(),
		Retention: p.Retention.String(),
	})
}

// UnmarshalJSON parses durations with time.ParseDuration.
func (p *Policy) UnmarshalJSON(data []byte) error {
	var raw policyJSON
	if err := json.Unmarshal(data, &raw, jsonStrict); err != nil {
		return err
	}
	primary, err := time.ParseDuration(raw.Primary)
	if err != nil {
		return fmt.Errorf("%w: policy.primary: %v", ErrInvalid, err)
	}
	propagate, err := time.ParseDuration(raw.Propagate)
	if err != nil {
		return fmt.Errorf("%w: policy.propagate: %v", ErrInvalid, err)
	}
	phaseOut, err := time.ParseDuration(raw.PhaseOut)
	if err != nil {
		return fmt.Errorf("%w: policy.phase_out: %v", ErrInvalid, err)
	}
	retention, err := time.ParseDuration(raw.Retention)
	if err != nil {
		return fmt.Errorf("%w: policy.retention: %v", ErrInvalid, err)
	}
	p.Primary = primary
	p.Propagate = propagate
	p.PhaseOut = phaseOut
	p.Retention = retention
	return nil
}

type envelope struct {
	Version         int            `json:"version"`
	Metadata        jsontext.Value `json:"metadata"`
	PrivateMaterial []byte         `json:"private_material"`
}

type metadataDocument struct {
	Name      string        `json:"name"`
	Type      string        `json:"type"`
	Policy    Policy        `json:"policy"`
	PrimaryID string        `json:"primary_id"`
	Keys      []metadataKey `json:"keys"`
}

type metadataKey struct {
	ID          string     `json:"id"`
	State       KeyState   `json:"state"`
	CreatedAt   time.Time  `json:"created_at"`
	PromotedAt  *time.Time `json:"promoted_at,omitempty"`
	PhasedOutAt *time.Time `json:"phased_out_at,omitempty"`
	DisabledAt  *time.Time `json:"disabled_at,omitempty"`
	DeleteAfter *time.Time `json:"delete_after,omitempty"`
	PublicKey   []byte     `json:"public_key,omitempty"`
}

type privateDocument struct {
	Keys []privateKeyMaterial `json:"keys"`
}

type privateKeyMaterial struct {
	ID         string `json:"id"`
	PrivateKey []byte `json:"private_key"`
}

// MarshalJSON always fails.
func (k Keyset) MarshalJSON() ([]byte, error) { return nil, errRefuseJSON }

// UnmarshalJSON always fails.
func (k *Keyset) UnmarshalJSON([]byte) error { return errRefuseJSON }

// MarshalJSONTo always fails.
func (k Keyset) MarshalJSONTo(*jsontext.Encoder) error { return errRefuseJSON }

// UnmarshalJSONFrom always fails.
func (k *Keyset) UnmarshalJSONFrom(*jsontext.Decoder) error { return errRefuseJSON }

// Marshal returns an inspectable envelope containing clear public metadata and
// sealed private material. The exact metadata bytes are authenticated as AAD.
// Pass insecurecleartext.Keeper to store the private material in cleartext.
func (k *Keyset) Marshal(keeper Keeper) ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: nil keyset", ErrInvalid)
	}
	if keeper == nil {
		return nil, fmt.Errorf("%w: keeper is required (use insecurecleartext.Keeper for cleartext)", ErrInvalid)
	}
	if err := k.validate(); err != nil {
		return nil, err
	}

	metadata, private := splitDocument(k.doc)
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("keyset: marshal metadata: %w", err)
	}
	privateJSON, err := json.Marshal(private)
	if err != nil {
		return nil, fmt.Errorf("keyset: marshal private material: %w", err)
	}
	if len(privateJSON) > maxDocumentBytes {
		return nil, fmt.Errorf("%w: private document too large", ErrInvalid)
	}
	sealed, err := keeper.Seal(privateJSON, envelopeAAD(k.doc.Name, metadataJSON))
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(envelope{
		Version:         envelopeVersion,
		Metadata:        jsontext.Value(metadataJSON),
		PrivateMaterial: sealed,
	})
	if err != nil {
		return nil, fmt.Errorf("keyset: marshal envelope: %w", err)
	}
	if len(encoded) > maxEnvelopeBytes {
		return nil, fmt.Errorf("%w: envelope too large", ErrInvalid)
	}
	return encoded, nil
}

// UnmarshalPublic reads and validates the clear public metadata in an envelope.
// It does not authenticate that metadata; only Unmarshal can do that with the Keeper.
func UnmarshalPublic(blob []byte) (Public, error) {
	_, metadata, _, err := decodeEnvelope(blob)
	if err != nil {
		return Public{}, err
	}
	doc := metadata.document()
	if err := validateDocumentMetadata(doc); err != nil {
		return Public{}, err
	}
	return (&Keyset{doc: doc}).Public(), nil
}

// Unmarshal opens private material and authenticates the complete public metadata.
// name is additionally bound as AAD and must match the envelope metadata.
func Unmarshal(name string, blob []byte, keeper Keeper) (*Keyset, error) {
	if keeper == nil {
		return nil, fmt.Errorf("%w: keeper is required (use insecurecleartext.Keeper for cleartext)", ErrInvalid)
	}
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalid)
	}
	_, metadata, metadataJSON, sealed, err := decodeEnvelopeWithMaterial(blob)
	if err != nil {
		return nil, err
	}
	privateJSON, err := keeper.Open(sealed, envelopeAAD(name, metadataJSON))
	if err != nil {
		return nil, err
	}
	if len(privateJSON) > maxDocumentBytes {
		return nil, fmt.Errorf("%w: private document too large", ErrInvalid)
	}
	var private privateDocument
	if err := decodeJSONStrict(privateJSON, &private); err != nil {
		return nil, fmt.Errorf("%w: invalid private document: %v", ErrInvalid, err)
	}
	doc, err := joinDocument(metadata, private)
	if err != nil {
		return nil, err
	}
	if doc.Name != name {
		return nil, fmt.Errorf("%w: document name %q does not match %q", ErrInvalid, doc.Name, name)
	}
	ks := &Keyset{doc: doc}
	if err := ks.validate(); err != nil {
		return nil, err
	}
	return ks, nil
}

func splitDocument(doc document) (metadataDocument, privateDocument) {
	metadata := metadataDocument{
		Name:      doc.Name,
		Type:      doc.Type,
		Policy:    doc.Policy,
		PrimaryID: doc.PrimaryID,
		Keys:      make([]metadataKey, 0, len(doc.Keys)),
	}
	private := privateDocument{Keys: make([]privateKeyMaterial, 0, len(doc.Keys))}
	for _, key := range doc.Keys {
		metadata.Keys = append(metadata.Keys, metadataKey{
			ID:          key.ID,
			State:       key.State,
			CreatedAt:   key.CreatedAt,
			PromotedAt:  key.PromotedAt,
			PhasedOutAt: key.PhasedOutAt,
			DisabledAt:  key.DisabledAt,
			DeleteAfter: key.DeleteAfter,
			PublicKey:   append([]byte(nil), key.PublicKey...),
		})
		private.Keys = append(private.Keys, privateKeyMaterial{
			ID:         key.ID,
			PrivateKey: append([]byte(nil), key.PrivateKey...),
		})
	}
	return metadata, private
}

func (m metadataDocument) document() document {
	doc := document{
		Name:      m.Name,
		Type:      m.Type,
		Policy:    m.Policy,
		PrimaryID: m.PrimaryID,
		Keys:      make([]key, 0, len(m.Keys)),
	}
	for _, source := range m.Keys {
		doc.Keys = append(doc.Keys, key{
			ID:          source.ID,
			State:       source.State,
			CreatedAt:   source.CreatedAt,
			PromotedAt:  source.PromotedAt,
			PhasedOutAt: source.PhasedOutAt,
			DisabledAt:  source.DisabledAt,
			DeleteAfter: source.DeleteAfter,
			PublicKey:   append([]byte(nil), source.PublicKey...),
		})
	}
	return doc
}

func joinDocument(metadata metadataDocument, private privateDocument) (document, error) {
	doc := metadata.document()
	material := make(map[string][]byte, len(private.Keys))
	for _, key := range private.Keys {
		if err := validateKeyID(key.ID); err != nil {
			return document{}, err
		}
		if len(key.PrivateKey) == 0 {
			return document{}, fmt.Errorf("%w: invalid private key material", ErrInvalid)
		}
		if _, exists := material[key.ID]; exists {
			return document{}, fmt.Errorf("%w: duplicate private key id %q", ErrInvalid, key.ID)
		}
		material[key.ID] = key.PrivateKey
	}
	if len(material) != len(doc.Keys) {
		return document{}, fmt.Errorf("%w: public and private key counts differ", ErrInvalid)
	}
	for i := range doc.Keys {
		privateKey, ok := material[doc.Keys[i].ID]
		if !ok {
			return document{}, fmt.Errorf("%w: key %q missing private material", ErrInvalid, doc.Keys[i].ID)
		}
		doc.Keys[i].PrivateKey = append([]byte(nil), privateKey...)
	}
	return doc, nil
}

func decodeEnvelope(blob []byte) (envelope, metadataDocument, []byte, error) {
	env, metadata, metadataJSON, _, err := decodeEnvelopeWithMaterial(blob)
	return env, metadata, metadataJSON, err
}

func decodeEnvelopeWithMaterial(blob []byte) (envelope, metadataDocument, []byte, []byte, error) {
	if len(blob) > maxEnvelopeBytes {
		return envelope{}, metadataDocument{}, nil, nil, fmt.Errorf("%w: envelope too large", ErrInvalid)
	}
	var env envelope
	if err := decodeJSONStrict(blob, &env); err != nil {
		return envelope{}, metadataDocument{}, nil, nil, fmt.Errorf("%w: invalid envelope: %v", ErrInvalid, err)
	}
	if env.Version != envelopeVersion {
		return envelope{}, metadataDocument{}, nil, nil, fmt.Errorf("%w: unsupported envelope version %d", ErrInvalid, env.Version)
	}
	if len(env.Metadata) == 0 || len(env.PrivateMaterial) == 0 {
		return envelope{}, metadataDocument{}, nil, nil, fmt.Errorf("%w: incomplete envelope", ErrInvalid)
	}
	var metadata metadataDocument
	if err := decodeJSONStrict([]byte(env.Metadata), &metadata); err != nil {
		return envelope{}, metadataDocument{}, nil, nil, fmt.Errorf("%w: invalid metadata: %v", ErrInvalid, err)
	}
	return env, metadata, []byte(env.Metadata), env.PrivateMaterial, nil
}

func decodeJSONStrict(data []byte, target any) error {
	return json.Unmarshal(data, target, jsonStrict)
}

func envelopeAAD(name string, metadata []byte) []byte {
	const domain = "keyset/envelope/v1:"
	out := make([]byte, len(domain)+4+len(name)+len(metadata))
	copy(out, domain)
	binary.BigEndian.PutUint32(out[len(domain):], uint32(len(name)))
	copy(out[len(domain)+4:], name)
	copy(out[len(domain)+4+len(name):], metadata)
	return out
}
