// Package sqlstore persists sealed keyset envelopes using database/sql.
// It does not import a database driver; applications choose their own.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"lds.li/keyset"
)

// Dialect controls placeholders, identifier quoting, and schema data types.
type Dialect uint8

const (
	SQLite Dialect = iota + 1
	MySQL
	PostgreSQL
)

// Store is a database/sql-backed keyset.AdminStore.
type Store struct {
	db      *sql.DB
	keeper  keyset.Keeper
	dialect Dialect
	table   string
}

// Option configures a Store.
type Option func(*Store) error

// WithDialect selects a SQL dialect. SQLite is the default.
func WithDialect(dialect Dialect) Option {
	return func(store *Store) error {
		if !dialect.valid() {
			return fmt.Errorf("sqlstore: invalid dialect %d", dialect)
		}
		store.dialect = dialect
		return nil
	}
}

// WithTable sets the table name. Only a single unqualified SQL identifier is accepted.
func WithTable(table string) Option {
	return func(store *Store) error {
		if !validIdentifier(table) {
			return fmt.Errorf("sqlstore: invalid table name %q", table)
		}
		store.table = table
		return nil
	}
}

// New constructs a SQL store. The caller retains ownership of db.
// Use insecurecleartext.Keeper explicitly when encryption at rest is unwanted.
func New(db *sql.DB, keeper keyset.Keeper, options ...Option) (*Store, error) {
	if keeper == nil {
		return nil, errors.New("sqlstore: keeper is required")
	}
	return newStore(db, keeper, options...)
}

// NewPublic constructs a store that can call Public and ForEach without
// possessing the Keeper. Private reads and all writes return an error.
func NewPublic(db *sql.DB, options ...Option) (*Store, error) {
	return newStore(db, nil, options...)
}

func newStore(db *sql.DB, keeper keyset.Keeper, options ...Option) (*Store, error) {
	if db == nil {
		return nil, errors.New("sqlstore: database is required")
	}
	store := &Store{db: db, keeper: keeper, dialect: SQLite, table: "keysets"}
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(store); err != nil {
			return nil, err
		}
	}
	return store, nil
}

// Schema returns an idempotent statement creating the store table.
// Applications should execute it through their normal migration mechanism.
func (s *Store) Schema() string {
	blobType := "BLOB"
	switch s.dialect {
	case MySQL:
		blobType = "LONGBLOB"
	case PostgreSQL:
		blobType = "BYTEA"
	}
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    name VARCHAR(255) PRIMARY KEY,
    keyset_data %s NOT NULL,
    revision BIGINT NOT NULL
)`, s.quotedTable(), blobType)
}

// Get loads and authenticates a private keyset.
func (s *Store) Get(ctx context.Context, name string) (*keyset.Keyset, error) {
	loaded, _, err := s.Read(ctx, name)
	return loaded, err
}

// Public loads public metadata without opening private material with the Keeper.
func (s *Store) Public(ctx context.Context, name string) (keyset.Public, error) {
	if name == "" {
		return keyset.Public{}, fmt.Errorf("%w: name is required", keyset.ErrInvalid)
	}
	ctx = nonNilContext(ctx)
	query := s.bind(fmt.Sprintf("SELECT keyset_data FROM %s WHERE name = ?", s.quotedTable()))
	var blob []byte
	if err := s.db.QueryRowContext(ctx, query, name).Scan(&blob); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return keyset.Public{}, fmt.Errorf("sqlstore: %q: %w", name, keyset.ErrNotFound)
		}
		return keyset.Public{}, fmt.Errorf("sqlstore: read public %q: %w", name, err)
	}
	public, err := keyset.UnmarshalPublic(blob)
	if err != nil {
		return keyset.Public{}, fmt.Errorf("sqlstore: parse public %q: %w", name, err)
	}
	if public.Name != name {
		return keyset.Public{}, fmt.Errorf("%w: stored public name %q does not match %q", keyset.ErrInvalid, public.Name, name)
	}
	return public, nil
}

// Read loads and authenticates a keyset and returns its int64 revision.
func (s *Store) Read(ctx context.Context, name string) (*keyset.Keyset, any, error) {
	if s.keeper == nil {
		return nil, nil, fmt.Errorf("%w: SQL store has no Keeper for private reads", keyset.ErrInvalid)
	}
	if name == "" {
		return nil, nil, fmt.Errorf("%w: name is required", keyset.ErrInvalid)
	}
	ctx = nonNilContext(ctx)
	query := s.bind(fmt.Sprintf("SELECT keyset_data, revision FROM %s WHERE name = ?", s.quotedTable()))
	var blob []byte
	var revision int64
	if err := s.db.QueryRowContext(ctx, query, name).Scan(&blob, &revision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, fmt.Errorf("sqlstore: %q: %w", name, keyset.ErrNotFound)
		}
		return nil, nil, fmt.Errorf("sqlstore: read %q: %w", name, err)
	}
	loaded, err := keyset.Unmarshal(name, blob, s.keeper)
	if err != nil {
		return nil, nil, fmt.Errorf("sqlstore: open %q: %w", name, err)
	}
	return loaded, revision, nil
}

// Write inserts when revision is nil, or atomically replaces the row when its
// current int64 revision matches revision.
func (s *Store) Write(ctx context.Context, name string, value *keyset.Keyset, revision any) error {
	if s.keeper == nil {
		return fmt.Errorf("%w: SQL store has no Keeper for writes", keyset.ErrInvalid)
	}
	if name == "" || value == nil || value.Name() != name {
		return fmt.Errorf("%w: keyset and name must match", keyset.ErrInvalid)
	}
	ctx = nonNilContext(ctx)
	blob, err := value.Marshal(s.keeper)
	if err != nil {
		return fmt.Errorf("sqlstore: seal %q: %w", name, err)
	}

	if revision == nil {
		query := s.bind(fmt.Sprintf(
			"INSERT INTO %s (name, keyset_data, revision) VALUES (?, ?, ?)", s.quotedTable()))
		if _, err := s.db.ExecContext(ctx, query, name, blob, int64(1)); err != nil {
			exists, lookupErr := s.exists(ctx, name)
			if lookupErr == nil && exists {
				return fmt.Errorf("sqlstore: insert %q: %w", name, keyset.ErrConflict)
			}
			return fmt.Errorf("sqlstore: insert %q: %w", name, err)
		}
		return nil
	}

	expected, ok := revision.(int64)
	if !ok || expected <= 0 || expected == math.MaxInt64 {
		return fmt.Errorf("%w: SQL revision must be a positive int64", keyset.ErrInvalid)
	}
	query := s.bind(fmt.Sprintf(
		"UPDATE %s SET keyset_data = ?, revision = ? WHERE name = ? AND revision = ?", s.quotedTable()))
	result, err := s.db.ExecContext(ctx, query, blob, expected+1, name, expected)
	if err != nil {
		return fmt.Errorf("sqlstore: update %q: %w", name, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlstore: update %q rows affected: %w", name, err)
	}
	if rows != 1 {
		return fmt.Errorf("sqlstore: update %q: %w", name, keyset.ErrConflict)
	}
	return nil
}

// ForEach calls fn once for every keyset name. Rows are closed before callbacks run.
func (s *Store) ForEach(ctx context.Context, fn func(name string) error) error {
	if fn == nil {
		return fmt.Errorf("%w: callback is required", keyset.ErrInvalid)
	}
	ctx = nonNilContext(ctx)
	query := fmt.Sprintf("SELECT name FROM %s ORDER BY name", s.quotedTable())
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("sqlstore: list keysets: %w", err)
	}
	names := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			return fmt.Errorf("sqlstore: scan keyset name: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("sqlstore: list keysets: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("sqlstore: close keyset rows: %w", err)
	}
	for _, name := range names {
		if err := fn(name); err != nil {
			return fmt.Errorf("sqlstore: keyset %q callback: %w", name, err)
		}
	}
	return nil
}

func (s *Store) exists(ctx context.Context, name string) (bool, error) {
	query := s.bind(fmt.Sprintf("SELECT 1 FROM %s WHERE name = ?", s.quotedTable()))
	var one int
	err := s.db.QueryRowContext(ctx, query, name).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) quotedTable() string {
	if s.dialect == MySQL {
		return "`" + s.table + "`"
	}
	return `"` + s.table + `"`
}

func (s *Store) bind(query string) string {
	if s.dialect != PostgreSQL {
		return query
	}
	var bound strings.Builder
	bound.Grow(len(query) + 8)
	var index int
	for _, char := range query {
		if char != '?' {
			bound.WriteRune(char)
			continue
		}
		index++
		bound.WriteByte('$')
		bound.WriteString(strconv.Itoa(index))
	}
	return bound.String()
}

func (d Dialect) valid() bool { return d == SQLite || d == MySQL || d == PostgreSQL }

func validIdentifier(value string) bool {
	if value == "" || !isIdentifierStart(value[0]) {
		return false
	}
	for i := 1; i < len(value); i++ {
		if !isIdentifierStart(value[i]) && (value[i] < '0' || value[i] > '9') {
			return false
		}
	}
	return true
}

func isIdentifierStart(value byte) bool {
	return value == '_' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

var _ keyset.AdminStore = (*Store)(nil)
