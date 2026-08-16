// Package k8sstore persists sealed keyset envelopes in a Kubernetes Secret.
//
// Each keyset is a key in Secret.Data. Kubernetes Secrets are limited to 1MiB
// of data in total; applications with many or large keysets should split them
// across Secrets or use another store.
package k8sstore

import (
	"context"
	"errors"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"lds.li/keyset"
)

// Store is a Kubernetes Secret-backed keyset.AdminStore.
type Store struct {
	client    kubernetes.Interface
	namespace string
	secret    string
	keeper    keyset.Keeper
}

// New constructs a store backed by one Secret. The caller retains ownership of
// client. Use insecurecleartext.Keeper explicitly when encryption at rest is
// unwanted.
func New(client kubernetes.Interface, namespace, secret string, keeper keyset.Keeper) (*Store, error) {
	if keeper == nil {
		return nil, errors.New("k8sstore: keeper is required")
	}
	return newStore(client, namespace, secret, keeper)
}

// NewPublic constructs a store that can call Public and ForEach without
// possessing the Keeper. Private reads and all writes return an error.
func NewPublic(client kubernetes.Interface, namespace, secret string) (*Store, error) {
	return newStore(client, namespace, secret, nil)
}

func newStore(client kubernetes.Interface, namespace, secret string, keeper keyset.Keeper) (*Store, error) {
	if client == nil {
		return nil, errors.New("k8sstore: kubernetes client is required")
	}
	if errs := validation.IsDNS1123Label(namespace); len(errs) > 0 {
		return nil, fmt.Errorf("k8sstore: invalid namespace %q: %s", namespace, errs[0])
	}
	if errs := validation.IsDNS1123Subdomain(secret); len(errs) > 0 {
		return nil, fmt.Errorf("k8sstore: invalid secret name %q: %s", secret, errs[0])
	}
	return &Store{client: client, namespace: namespace, secret: secret, keeper: keeper}, nil
}

// Get loads and authenticates a private keyset.
func (s *Store) Get(ctx context.Context, name string) (*keyset.Keyset, error) {
	loaded, _, err := s.Read(ctx, name)
	return loaded, err
}

// Public loads public metadata without opening private material with the Keeper.
func (s *Store) Public(ctx context.Context, name string) (keyset.Public, error) {
	if err := validKeysetName(name); err != nil {
		return keyset.Public{}, err
	}
	ctx = nonNilContext(ctx)
	obj, err := s.getSecret(ctx)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return keyset.Public{}, fmt.Errorf("k8sstore: %q: %w", name, keyset.ErrNotFound)
		}
		return keyset.Public{}, fmt.Errorf("k8sstore: read public %q: %w", name, err)
	}
	blob, ok := obj.Data[name]
	if !ok {
		return keyset.Public{}, fmt.Errorf("k8sstore: %q: %w", name, keyset.ErrNotFound)
	}
	public, err := keyset.UnmarshalPublic(blob)
	if err != nil {
		return keyset.Public{}, fmt.Errorf("k8sstore: parse public %q: %w", name, err)
	}
	if public.Name != name {
		return keyset.Public{}, fmt.Errorf("%w: stored public name %q does not match %q", keyset.ErrInvalid, public.Name, name)
	}
	return public, nil
}

// Read loads and authenticates a keyset and returns the Secret resourceVersion.
func (s *Store) Read(ctx context.Context, name string) (*keyset.Keyset, any, error) {
	if s.keeper == nil {
		return nil, nil, fmt.Errorf("%w: Kubernetes store has no Keeper for private reads", keyset.ErrInvalid)
	}
	if err := validKeysetName(name); err != nil {
		return nil, nil, err
	}
	ctx = nonNilContext(ctx)
	obj, err := s.getSecret(ctx)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil, fmt.Errorf("k8sstore: %q: %w", name, keyset.ErrNotFound)
		}
		return nil, nil, fmt.Errorf("k8sstore: read %q: %w", name, err)
	}
	blob, ok := obj.Data[name]
	if !ok {
		return nil, nil, fmt.Errorf("k8sstore: %q: %w", name, keyset.ErrNotFound)
	}
	loaded, err := keyset.Unmarshal(name, blob, s.keeper)
	if err != nil {
		return nil, nil, fmt.Errorf("k8sstore: open %q: %w", name, err)
	}
	return loaded, obj.ResourceVersion, nil
}

// Write inserts when revision is nil, or replaces the named data key when the
// Secret resourceVersion matches revision.
func (s *Store) Write(ctx context.Context, name string, value *keyset.Keyset, revision any) error {
	if s.keeper == nil {
		return fmt.Errorf("%w: Kubernetes store has no Keeper for writes", keyset.ErrInvalid)
	}
	if value == nil || value.Name() != name {
		return fmt.Errorf("%w: keyset and name must match", keyset.ErrInvalid)
	}
	if err := validKeysetName(name); err != nil {
		return err
	}
	ctx = nonNilContext(ctx)
	blob, err := value.Marshal(s.keeper)
	if err != nil {
		return fmt.Errorf("k8sstore: seal %q: %w", name, err)
	}

	obj, err := s.getSecret(ctx)
	if revision == nil {
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("k8sstore: read %q: %w", name, err)
			}
			created := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      s.secret,
					Namespace: s.namespace,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{name: cloneBytes(blob)},
			}
			if _, err := s.secrets().Create(ctx, created, metav1.CreateOptions{}); err != nil {
				if apierrors.IsAlreadyExists(err) {
					return fmt.Errorf("k8sstore: insert %q: %w", name, keyset.ErrConflict)
				}
				return fmt.Errorf("k8sstore: create secret: %w", err)
			}
			return nil
		}
		if _, exists := obj.Data[name]; exists {
			return fmt.Errorf("k8sstore: insert %q: %w", name, keyset.ErrConflict)
		}
		return s.updateData(ctx, obj, name, blob)
	}

	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("k8sstore: update %q: %w", name, keyset.ErrConflict)
		}
		return fmt.Errorf("k8sstore: read %q: %w", name, err)
	}
	expected, ok := revision.(string)
	if !ok || expected == "" {
		return fmt.Errorf("%w: Kubernetes revision must be a non-empty resourceVersion string", keyset.ErrInvalid)
	}
	if obj.ResourceVersion != expected {
		return fmt.Errorf("k8sstore: update %q: %w", name, keyset.ErrConflict)
	}
	if _, exists := obj.Data[name]; !exists {
		return fmt.Errorf("k8sstore: update %q: %w", name, keyset.ErrConflict)
	}
	return s.updateData(ctx, obj, name, blob)
}

// ForEach calls fn once for every keyset name. A missing Secret is an empty store.
func (s *Store) ForEach(ctx context.Context, fn func(name string) error) error {
	if fn == nil {
		return fmt.Errorf("%w: callback is required", keyset.ErrInvalid)
	}
	ctx = nonNilContext(ctx)
	obj, err := s.getSecret(ctx)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("k8sstore: list keysets: %w", err)
	}
	names := make([]string, 0, len(obj.Data))
	for name := range obj.Data {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := fn(name); err != nil {
			return fmt.Errorf("k8sstore: keyset %q callback: %w", name, err)
		}
	}
	return nil
}

func (s *Store) updateData(ctx context.Context, obj *corev1.Secret, name string, blob []byte) error {
	updated := obj.DeepCopy()
	if updated.Data == nil {
		updated.Data = make(map[string][]byte)
	}
	updated.Data[name] = cloneBytes(blob)
	if _, err := s.secrets().Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		if apierrors.IsConflict(err) {
			return fmt.Errorf("k8sstore: update %q: %w", name, keyset.ErrConflict)
		}
		return fmt.Errorf("k8sstore: update %q: %w", name, err)
	}
	return nil
}

func (s *Store) getSecret(ctx context.Context) (*corev1.Secret, error) {
	return s.secrets().Get(ctx, s.secret, metav1.GetOptions{})
}

func (s *Store) secrets() corev1client.SecretInterface {
	return s.client.CoreV1().Secrets(s.namespace)
}

func validKeysetName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is required", keyset.ErrInvalid)
	}
	if errs := validation.IsConfigMapKey(name); len(errs) > 0 {
		return fmt.Errorf("%w: invalid keyset name %q: %s", keyset.ErrInvalid, name, errs[0])
	}
	return nil
}

func cloneBytes(value []byte) []byte {
	out := make([]byte, len(value))
	copy(out, value)
	return out
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

var _ keyset.AdminStore = (*Store)(nil)
