package sqlstore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"lds.li/keyset"
)

func TestStoreLifecycle(t *testing.T) {
	db := openMemoryDB(t)
	keeper := newTestKeeper(t)
	store, err := New(db, keeper)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), store.Schema()); err != nil {
		t.Fatal(err)
	}

	first, err := newTestKeyset(t, "a")
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
	if loaded.PrimaryID() != first.PrimaryID() || revision != int64(1) {
		t.Fatalf("loaded primary=%s revision=%v", loaded.PrimaryID(), revision)
	}
	if err := store.Write(t.Context(), "a", loaded, revision); err != nil {
		t.Fatal(err)
	}
	if err := store.Write(t.Context(), "a", loaded, revision); !errors.Is(err, keyset.ErrConflict) {
		t.Fatalf("stale update error=%v", err)
	}

	second, err := newTestKeyset(t, "b")
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
	db := openMemoryDB(t)
	keeper := &observedKeeper{keeper: newTestKeeper(t)}
	store, err := New(db, keeper)
	if err != nil {
		t.Fatal(err)
	}
	value, err := newTestKeyset(t, "jwt")
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
	publicStore, err := NewPublic(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publicStore.Public(t.Context(), "jwt"); err != nil {
		t.Fatal(err)
	}
	if _, err := publicStore.Get(t.Context(), "jwt"); !errors.Is(err, keyset.ErrInvalid) {
		t.Fatalf("public-only private read error=%v", err)
	}
}

func TestDialectAndOptions(t *testing.T) {
	db := openMemoryDB(t)
	keeper := newTestKeeper(t)
	if _, err := New(nil, keeper); err == nil {
		t.Fatal("nil database accepted")
	}
	if _, err := New(db, nil); err == nil {
		t.Fatal("nil keeper accepted")
	}
	if _, err := New(db, keeper, WithTable("bad; DROP TABLE keys")); err == nil {
		t.Fatal("unsafe table name accepted")
	}
	if _, err := New(db, keeper, WithDialect(99)); err == nil {
		t.Fatal("invalid dialect accepted")
	}

	postgres, err := New(db, keeper, WithDialect(PostgreSQL), WithTable("app_keys"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(postgres.Schema(), `"app_keys"`) || !strings.Contains(postgres.Schema(), "BYTEA") {
		t.Fatalf("PostgreSQL schema=%s", postgres.Schema())
	}
	bound := postgres.bind("UPDATE t SET a = ?, b = ? WHERE c = ? AND d = ?")
	if bound != "UPDATE t SET a = $1, b = $2 WHERE c = $3 AND d = $4" {
		t.Fatalf("bound query=%q", bound)
	}
	mysql, err := New(db, keeper, WithDialect(MySQL))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mysql.Schema(), "`keysets`") || !strings.Contains(mysql.Schema(), "LONGBLOB") {
		t.Fatalf("MySQL schema=%s", mysql.Schema())
	}
}

func newTestKeyset(t *testing.T, name string) (*keyset.Keyset, error) {
	t.Helper()
	return keyset.New(t.Context(), name, "test", keyset.Type{
		Policy: keyset.DefaultPolicy(),
		New: func(context.Context) (keyset.Material, error) {
			return keyset.Material{Private: []byte("secret"), Public: []byte("pub")}, nil
		},
	})
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

var (
	registerMemoryDriver sync.Once
	memoryDatabases      sync.Map
	memoryDatabaseID     atomic.Uint64
)

func openMemoryDB(t *testing.T) *sql.DB {
	t.Helper()
	registerMemoryDriver.Do(func() { sql.Register("keyset-sqlstore-memory", memoryDriver{}) })
	name := fmt.Sprintf("test-%d", memoryDatabaseID.Add(1))
	backend := &memoryBackend{rows: make(map[string]memoryEntry)}
	memoryDatabases.Store(name, backend)
	db, err := sql.Open("keyset-sqlstore-memory", name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		memoryDatabases.Delete(name)
	})
	return db
}

type memoryEntry struct {
	blob     []byte
	revision int64
}

type memoryBackend struct {
	mu   sync.Mutex
	rows map[string]memoryEntry
}

type memoryDriver struct{}

func (memoryDriver) Open(name string) (driver.Conn, error) {
	backend, ok := memoryDatabases.Load(name)
	if !ok {
		return nil, fmt.Errorf("unknown memory database %q", name)
	}
	return &memoryConn{backend: backend.(*memoryBackend)}, nil
}

type memoryConn struct{ backend *memoryBackend }

func (c *memoryConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c *memoryConn) Close() error                        { return nil }
func (c *memoryConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }

func (c *memoryConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.backend.mu.Lock()
	defer c.backend.mu.Unlock()
	switch {
	case strings.HasPrefix(query, "CREATE TABLE"):
		return driver.RowsAffected(0), nil
	case strings.HasPrefix(query, "INSERT INTO"):
		name := args[0].Value.(string)
		if _, exists := c.backend.rows[name]; exists {
			return nil, errors.New("unique constraint")
		}
		c.backend.rows[name] = memoryEntry{
			blob:     append([]byte(nil), args[1].Value.([]byte)...),
			revision: args[2].Value.(int64),
		}
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(query, "UPDATE"):
		name := args[2].Value.(string)
		expected := args[3].Value.(int64)
		entry, exists := c.backend.rows[name]
		if !exists || entry.revision != expected {
			return driver.RowsAffected(0), nil
		}
		entry.blob = append([]byte(nil), args[0].Value.([]byte)...)
		entry.revision = args[1].Value.(int64)
		c.backend.rows[name] = entry
		return driver.RowsAffected(1), nil
	default:
		return nil, fmt.Errorf("unsupported exec: %s", query)
	}
}

func (c *memoryConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.backend.mu.Lock()
	defer c.backend.mu.Unlock()
	switch {
	case strings.HasPrefix(query, "SELECT keyset_data, revision"):
		entry, ok := c.backend.rows[args[0].Value.(string)]
		if !ok {
			return &memoryRows{columns: []string{"keyset_data", "revision"}}, nil
		}
		return &memoryRows{columns: []string{"keyset_data", "revision"}, data: [][]driver.Value{{append([]byte(nil), entry.blob...), entry.revision}}}, nil
	case strings.HasPrefix(query, "SELECT keyset_data FROM"):
		entry, ok := c.backend.rows[args[0].Value.(string)]
		if !ok {
			return &memoryRows{columns: []string{"keyset_data"}}, nil
		}
		return &memoryRows{columns: []string{"keyset_data"}, data: [][]driver.Value{{append([]byte(nil), entry.blob...)}}}, nil
	case strings.HasPrefix(query, "SELECT 1 FROM"):
		_, ok := c.backend.rows[args[0].Value.(string)]
		if !ok {
			return &memoryRows{columns: []string{"1"}}, nil
		}
		return &memoryRows{columns: []string{"1"}, data: [][]driver.Value{{int64(1)}}}, nil
	case strings.HasPrefix(query, "SELECT name FROM"):
		names := make([]string, 0, len(c.backend.rows))
		for name := range c.backend.rows {
			names = append(names, name)
		}
		sort.Strings(names)
		data := make([][]driver.Value, 0, len(names))
		for _, name := range names {
			data = append(data, []driver.Value{name})
		}
		return &memoryRows{columns: []string{"name"}, data: data}, nil
	default:
		return nil, fmt.Errorf("unsupported query: %s", query)
	}
}

type memoryRows struct {
	columns []string
	data    [][]driver.Value
	index   int
}

func (r *memoryRows) Columns() []string { return r.columns }
func (r *memoryRows) Close() error      { return nil }
func (r *memoryRows) Next(values []driver.Value) error {
	if r.index >= len(r.data) {
		return io.EOF
	}
	copy(values, r.data[r.index])
	r.index++
	return nil
}

var (
	_ driver.Driver         = memoryDriver{}
	_ driver.Conn           = (*memoryConn)(nil)
	_ driver.ExecerContext  = (*memoryConn)(nil)
	_ driver.QueryerContext = (*memoryConn)(nil)
)
