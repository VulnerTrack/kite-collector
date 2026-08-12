package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketMeta       = []byte("meta")
	bucketLatest     = []byte("latest")
	bucketSnapshots  = []byte("snapshots")
	bucketCategories = []byte("categories")
	keySnapshot      = []byte("snapshot")
	keyLastSynced    = []byte("last_otlp_sync")
)

func inventoryDBPath(dir string) string { return filepath.Join(dir, "kite.db") }

func saveInventory(dir string, snapshot inventorySnapshot) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	db, err := bolt.Open(inventoryDBPath(dir), 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return fmt.Errorf("open inventory database: %w", err)
	}
	defer db.Close()
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	return db.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists(bucketMeta)
		if err != nil {
			return err
		}
		latest, err := tx.CreateBucketIfNotExists(bucketLatest)
		if err != nil {
			return err
		}
		snapshots, err := tx.CreateBucketIfNotExists(bucketSnapshots)
		if err != nil {
			return err
		}
		categories, err := tx.CreateBucketIfNotExists(bucketCategories)
		if err != nil {
			return err
		}
		if err := meta.Put([]byte("format"), []byte("kite-windows7-bolt-v1")); err != nil {
			return err
		}
		if err := meta.Put([]byte("last_scan"), []byte(snapshot.CollectedAt.Format(time.RFC3339Nano))); err != nil {
			return err
		}
		if err := latest.Put(keySnapshot, payload); err != nil {
			return err
		}
		if err := snapshots.Put([]byte(snapshot.CollectedAt.Format("20060102T150405.000000000Z")), payload); err != nil {
			return err
		}
		for category, rows := range snapshot.Categories {
			encoded, marshalErr := json.Marshal(rows)
			if marshalErr != nil {
				return marshalErr
			}
			if err := categories.Put([]byte(category), encoded); err != nil {
				return err
			}
		}
		// Retain the newest 30 full snapshots; category indexes always represent
		// the current state and are therefore not duplicated.
		for snapshots.Stats().KeyN > 30 {
			cursor := snapshots.Cursor()
			key, _ := cursor.First()
			if key == nil {
				break
			}
			if err := snapshots.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
}

func inventoryNeedsSync(dir string, collectedAt time.Time) (bool, error) {
	db, err := bolt.Open(inventoryDBPath(dir), 0600, &bolt.Options{ReadOnly: true, Timeout: 2 * time.Second})
	if err != nil {
		return false, err
	}
	defer db.Close()
	var synced string
	err = db.View(func(tx *bolt.Tx) error {
		if bucket := tx.Bucket(bucketMeta); bucket != nil {
			synced = string(bucket.Get(keyLastSynced))
		}
		return nil
	})
	return synced != collectedAt.UTC().Format(time.RFC3339Nano), err
}

func markInventorySynced(dir string, collectedAt time.Time) error {
	db, err := bolt.Open(inventoryDBPath(dir), 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists(bucketMeta)
		if err != nil {
			return err
		}
		return meta.Put(keyLastSynced, []byte(collectedAt.UTC().Format(time.RFC3339Nano)))
	})
}

func loadLatestInventory(dir string) (*inventorySnapshot, error) {
	db, err := bolt.Open(inventoryDBPath(dir), 0600, &bolt.Options{ReadOnly: true, Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var snapshot inventorySnapshot
	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketLatest)
		if bucket == nil || bucket.Get(keySnapshot) == nil {
			return errors.New("inventory database has no snapshots yet")
		}
		return json.Unmarshal(bucket.Get(keySnapshot), &snapshot)
	})
	if err != nil {
		return nil, err
	}
	return &snapshot, nil
}

func loadInventoryCategory(dir, category string) ([]map[string]string, error) {
	db, err := bolt.Open(inventoryDBPath(dir), 0600, &bolt.Options{ReadOnly: true, Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var rows []map[string]string
	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketCategories)
		if bucket == nil || bucket.Get([]byte(category)) == nil {
			return fmt.Errorf("unknown inventory category %q", category)
		}
		return json.Unmarshal(bucket.Get([]byte(category)), &rows)
	})
	return rows, err
}

func inventoryCategoryNames(snapshot *inventorySnapshot) []string {
	names := make([]string, 0, len(snapshot.Categories))
	for name := range snapshot.Categories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func loadInventoryHistory(dir string, limit int) ([]inventorySnapshot, error) {
	db, err := bolt.Open(inventoryDBPath(dir), 0600, &bolt.Options{ReadOnly: true, Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var history []inventorySnapshot
	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketSnapshots)
		if bucket == nil {
			return nil
		}
		cursor := bucket.Cursor()
		for _, value := cursor.Last(); value != nil && (limit <= 0 || len(history) < limit); _, value = cursor.Prev() {
			var snapshot inventorySnapshot
			if err := json.Unmarshal(value, &snapshot); err != nil {
				return err
			}
			history = append(history, snapshot)
		}
		return nil
	})
	return history, err
}
