package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/store"
)

// Saved views persist the dashboard view builder's output. The join is
// stored structurally (tables, type, ON columns, JSON projection) — never as
// raw SQL — so every render re-validates identifiers via ListJoinedRows.

var _ store.SavedViewStore = (*SQLiteStore)(nil)

// savedViewColumnsJSON is the persisted shape of one projection entry.
type savedViewColumnsJSON struct {
	Table  string `json:"table"`
	Column string `json:"column"`
}

func encodeSavedViewColumns(cols []store.JoinColumn) (string, error) {
	out := make([]savedViewColumnsJSON, 0, len(cols))
	for _, c := range cols {
		out = append(out, savedViewColumnsJSON{Table: c.Table, Column: c.Column})
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("encode saved view columns: %w", err)
	}
	return string(raw), nil
}

func decodeSavedViewColumns(raw string) ([]store.JoinColumn, error) {
	var in []savedViewColumnsJSON
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil, fmt.Errorf("decode saved view columns: %w", err)
	}
	cols := make([]store.JoinColumn, 0, len(in))
	for _, c := range in {
		cols = append(cols, store.JoinColumn{Table: c.Table, Column: c.Column})
	}
	return cols, nil
}

// SaveView inserts a new saved view. Name and slug are UNIQUE — a duplicate
// surfaces as the driver's constraint error for the handler to translate.
func (s *SQLiteStore) SaveView(ctx context.Context, view store.SavedView) error {
	cols, err := encodeSavedViewColumns(view.Join.Columns)
	if err != nil {
		return err
	}
	if view.ID == uuid.Nil {
		view.ID = uuid.Must(uuid.NewV7())
	}
	if view.CreatedAt.IsZero() {
		view.CreatedAt = time.Now().UTC()
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO saved_views
		   (id, name, slug, base_table, join_table, join_type, on_base, on_join, columns, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		view.ID.String(), view.Name, view.Slug,
		view.Join.Base, view.Join.Join, string(view.Join.Type),
		view.Join.OnBase, view.Join.OnJoin, cols,
		view.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("save view %q: %w", view.Slug, err)
	}
	return nil
}

// ListSavedViews returns every saved view ordered by name.
func (s *SQLiteStore) ListSavedViews(ctx context.Context) ([]store.SavedView, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, slug, base_table, join_table, join_type, on_base, on_join, columns, created_at
		   FROM saved_views ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list saved views: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var views []store.SavedView
	for rows.Next() {
		view, err := scanSavedView(rows)
		if err != nil {
			return nil, err
		}
		views = append(views, *view)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate saved views: %w", err)
	}
	return views, nil
}

// GetSavedViewBySlug returns the saved view with the given slug.
func (s *SQLiteStore) GetSavedViewBySlug(ctx context.Context, slug string) (*store.SavedView, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, slug, base_table, join_table, join_type, on_base, on_join, columns, created_at
		   FROM saved_views WHERE slug = ?`, slug)
	if err != nil {
		return nil, fmt.Errorf("get saved view %q: %w", slug, err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("get saved view %q: %w", slug, err)
		}
		return nil, store.ErrNotFound
	}
	return scanSavedView(rows)
}

// DeleteSavedView removes the saved view with the given slug (no-op when
// absent).
func (s *SQLiteStore) DeleteSavedView(ctx context.Context, slug string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM saved_views WHERE slug = ?`, slug); err != nil {
		return fmt.Errorf("delete saved view %q: %w", slug, err)
	}
	return nil
}

func scanSavedView(rows *sql.Rows) (*store.SavedView, error) {
	var (
		id, name, slug, baseTable, joinTable string
		joinType, onBase, onJoin, colsRaw    string
		createdAt                            string
	)
	if err := rows.Scan(&id, &name, &slug, &baseTable, &joinTable, &joinType, &onBase, &onJoin, &colsRaw, &createdAt); err != nil {
		return nil, fmt.Errorf("scan saved view: %w", err)
	}
	parsedID, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("saved view %q has invalid id: %w", slug, err)
	}
	cols, err := decodeSavedViewColumns(colsRaw)
	if err != nil {
		return nil, err
	}
	created, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		// Tolerate second-precision timestamps from external writers.
		if created, err = time.Parse(time.RFC3339, createdAt); err != nil {
			return nil, fmt.Errorf("saved view %q has invalid created_at: %w", slug, err)
		}
	}
	return &store.SavedView{
		ID:        parsedID,
		Name:      name,
		Slug:      slug,
		CreatedAt: created,
		Join: store.JoinFilter{
			Base:    baseTable,
			Join:    joinTable,
			Type:    store.JoinType(joinType),
			OnBase:  onBase,
			OnJoin:  onJoin,
			Columns: cols,
		},
	}, nil
}

// ErrIsUniqueViolation reports whether err is a SQLite unique-constraint
// error, so handlers can translate a duplicate name/slug into a conflict
// response. Matching the message text avoids leaking driver error types
// through the store's public surface.
func ErrIsUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
