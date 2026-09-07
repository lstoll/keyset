# keyset

Rotating keysets for Go: lifecycle, opaque key material, and sealed storage.
The library does not implement signers, MACs, or AEADs. Use the standard
library or [Tink](https://github.com/tink-crypto/tink-go) to consume the bytes.

Requires Go 1.27 or later. The storage format uses `encoding/json/v2`, which
Go 1.27 enables by default through `GOEXPERIMENT=jsonv2`; building with
`GOEXPERIMENT=nojsonv2` is not supported.

Each keyset has a name and a user-defined **type** (`jwt`, `sessions`, …).
Keys move through `pending`, `primary`, `phasing_out`, and `disabled` before
optional deletion.

## Types and material

A type supplies a constructor and a rotation policy. Constructors return
opaque private bytes and optional public bytes.

Key IDs are strings of up to 128 bytes, unique within a keyset. Each new key's
ID comes from the first of:

1. `Material.ID` from the constructor, for IDs derived from the key itself,
   such as a JWK thumbprint.
2. `Type.NewID`, which receives the keyset's existing IDs. Use it for
   sequential or short IDs that must not collide.
3. A random version 4 UUID.

A counter kept inside the constructor restarts with the process and will mint
duplicates; use `NewID` instead:

```go
sessionsType.NewID = func(existing []string) (string, error) {
	highest := 0
	for _, id := range existing {
		n, err := strconv.Atoi(id)
		if err != nil {
			return "", err
		}
		highest = max(highest, n)
	}
	return strconv.Itoa(highest + 1), nil
}
```

```go
aesType := keyset.Type{
	Policy: keyset.DefaultPolicy(),
	New: func(ctx context.Context) (keyset.Material, error) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return keyset.Material{}, err
		}
		return keyset.Material{Private: key}, nil
	},
}

ks, err := keyset.New(ctx, "sessions", "sessions", aesType)
primary, ok := ks.Primary()
block, err := aes.NewCipher(primary.Private)
aead, err := cipher.NewGCM(block)
```

Use `Primary()` / `KeyState.IsPrimary()` to produce signatures or ciphertext.
Publish every `IsUsable()` public key so verifiers can prepublish pending keys.

```go
edType := keyset.Type{
	Policy: jwtPolicy,
	New: func(ctx context.Context) (keyset.Material, error) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return keyset.Material{}, err
		}
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return keyset.Material{}, err
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return keyset.Material{}, err
		}
		return keyset.Material{Private: privBytes, Public: pubBytes}, nil
	},
}
```

## Persistence

Keysets are stored as JSON envelopes. Public keys, type, policy, and lifecycle
state remain visible. Private material is sealed by a `Keeper`, and the
visible metadata is authenticated as additional data.

```go
keeper, err := keyset.AES256GCMKeeper(masterKey)
blob, err := ks.Marshal(keeper)

public, err := keyset.UnmarshalPublic(blob) // no keeper required
ks, err = keyset.Unmarshal("jwt", blob, keeper)
```

`UnmarshalPublic` does not authenticate the visible metadata. Use `Unmarshal`
before trusting storage that may have been modified.

Cleartext private material requires an explicit import:

```go
blob, err := ks.Marshal(insecurecleartext.Keeper)
```

## Rotation

`DefaultPolicy` rotates the primary weekly and requires its successor to be
visible for at least an hour before promotion. It does not automatically
disable or delete old keys. Set `PhaseOut` and `Retention` for data with a
known lifetime.

With `PhaseOut` at zero every former primary, including its private material,
is kept forever: weekly rotation adds about 52 keys a year. A keyset's sealed
private material is limited to 1MiB, and a Kubernetes Secret to 1MiB across
all of its keysets. Large keys (RSA in particular) can reach these limits
within a few years, after which writes fail with `ErrInvalid` and rotation
stops. Set `PhaseOut` and `Retention` for any keyset that will live that long.

Register types once. Ensure names the keysets that must exist (create-only).
The rotator walks the store and looks up each keyset's stored type:

```go
reg, err := keyset.NewRegistry(map[string]keyset.Type{
	"sessions": aesType,
	"jwt":      edType,
})
store := memstore.New(keeper)
rotator, err := keyset.NewRotator(store, reg,
	keyset.WithEnsure(map[string]string{
		"sessions": "sessions",
		"jwt":      "jwt",
	}),
)
err = rotator.Once(ctx)

client, err := keyset.NewClient(store, keyset.WithTTL(5*time.Minute))
ks, err := client.Get(ctx, "sessions")
```

`Client.Get` and `Client.Public` are TTL-cached snapshots. Call the client
again to observe a rotation. `WithTTL(0)` reloads the store on every call.

Several keysets may share one type. Names not in Ensure are still rotated if
their type is registered. Unknown types are skipped and reported. Policy on
the type is the source of truth during autorotation.

To rotate without a `Rotator`, call `Keyset.Rotate(ctx, now, &typ)`. Passing
the type applies its policy and lets the keyset mint successors. A keyset
loaded with `Unmarshal` has no type of its own, so `Rotate(ctx, now, nil)`
uses the stored policy and fails with `ErrInvalid` once it needs a new key.

## SQL

`sqlstore` implements optimistic concurrency using `database/sql`. It supports
SQLite, MySQL, and PostgreSQL without importing a driver.

```go
store, err := sqlstore.New(db, keeper,
	sqlstore.WithDialect(sqlstore.PostgreSQL),
)
_, err = db.ExecContext(ctx, store.Schema())
```

Run `Schema()` through the application's migration system. Public-only services
can use `sqlstore.NewPublic` without access to the keeper.

## Kubernetes

`k8sstore` is a separate module so client-go is not a dependency of the core
library. It stores each keyset as a key in one Secret. Optimistic concurrency
uses the Secret `resourceVersion`. Kubernetes limits Secrets to 1MiB of data.

```go
store, err := k8sstore.New(client, "app", "keysets", keeper)
rotator, err := keyset.NewRotator(store, reg,
	keyset.WithEnsure(map[string]string{
		"sessions": "sessions",
		"jwt":      "jwt",
	}),
)
err = rotator.Once(ctx)
```

The caller constructs the Kubernetes client. Public-only services can use
`k8sstore.NewPublic` without access to the keeper. Use
`insecurecleartext.Keeper` when Kubernetes encryption at rest is enough.

The store needs `get`, `create`, and `update` on that Secret:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: keyset
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["keysets"]
    verbs: ["get", "update"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["create"]
```

## Releasing

`k8sstore` is its own module and is versioned separately. Its `go.mod` uses a
`replace` to build against this checkout, but consumers ignore that, so its
`require lds.li/keyset` must name a published tag. To release:

1. Tag the core module: `git tag v0.X.Y`.
2. If `k8sstore` needs that release, set `require lds.li/keyset v0.X.Y` in
   `k8sstore/go.mod`, commit, and tag it: `git tag k8sstore/v0.X.Y`.
3. Push the tags.

## Status

The API and persistence format may still change.
