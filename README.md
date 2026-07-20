# keyset

Rotating cryptographic keysets for Go, using only the standard library.

Supported key types:

- AES-256-GCM
- HMAC-SHA-256
- Ed25519
- ECDSA P-256/SHA-256 and P-384/SHA-384
- RSA-PSS 2048/SHA-256 and 3072/SHA-256

Each keyset uses one algorithm. Keys move through `pending`, `primary`,
`phasing_out`, and `disabled` states before optional deletion.

## Usage

Most applications load keysets through a `Client`. Each call checks the client
cache, loads from the store when needed, and returns a new snapshot primitive.

```go
client, err := keyset.NewClient(store, keyset.WithTTL(5*time.Minute))
if err != nil {
	return err
}

signer, err := client.Signer(ctx, "jwt")
if err != nil {
	return err
}
signature, err := signer.SignMsg(message)

aead, err := client.AEAD(ctx, "sessions")
ciphertext, err := aead.Seal(plaintext, additionalData)
plaintext, err = aead.Open(ciphertext, additionalData)
```

An existing signer, MAC, or AEAD never refreshes itself. It remains pinned to
the primary key from the snapshot used to create it. Call the client again to
observe a rotation. `WithTTL(0)` reloads the store on every call.

## Direct keysets

`New` creates an in-memory keyset without accessing a store. This is useful for
provisioning, tests, and custom storage implementations.

```go
ks, err := keyset.New("sessions", keyset.AES256GCM, keyset.DefaultPolicy())
aead, err := ks.AEAD()

ciphertext, err := aead.Seal(plaintext, additionalData)
plaintext, err = aead.Open(ciphertext, additionalData)
```

AEAD and MAC outputs contain a version and key ID. `Open` and `Verify` select
the correct key directly. Raw methods are available for protocols which carry
their own key ID.

Signing keysets return snapshot-bound signers and public-only verifiers:

```go
ks, err := keyset.New("jwt", keyset.Ed25519, keyset.DefaultPolicy())
signer, err := ks.Signer()

signature, err := signer.SignMsg(message)
verifier, err := ks.Public().Verifier()
err = verifier.VerifyKey(signer.KeyID(), message, signature)
```

The `jwk` and `jws` packages provide JOSE encoding helpers.

## Persistence

Keysets are stored as JSON envelopes. Public keys, policy, and lifecycle state
remain visible. Private material is sealed by a `Keeper`, and the visible
metadata is authenticated as additional data.

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
disable or delete old keys. Set `PhaseOut` and `Retention` for data with a known
lifetime, such as JWTs.

```go
store := memstore.New(keeper)
rotator, err := keyset.NewRotator(store,
	keyset.WithEnsure(map[string]keyset.Spec{
		"sessions": {Algorithm: keyset.AES256GCM, Policy: keyset.DefaultPolicy()},
		"jwt":      {Algorithm: keyset.Ed25519, Policy: jwtPolicy},
	}),
)
err = rotator.Once(ctx)

client, err := keyset.NewClient(store, keyset.WithTTL(5*time.Minute))
aead, err := client.AEAD(ctx, "sessions")
```

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

## Status

The API and persistence format may still change.
