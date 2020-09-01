package storage

import (
	"time"

	"github.com/dgraph-io/badger/v2"
	"github.com/dgraph-io/badger/v2/options"
	"github.com/fox-one/mixin/config"
	"github.com/fox-one/mixin/logger"
)

type BadgerStore struct {
	custom      *config.Custom
	snapshotsDB *badger.DB
	cacheDB     *badger.DB
	closing     bool
}

func NewBadgerStore(custom *config.Custom, dir string) (*BadgerStore, error) {
	snapshotsDB, err := openDB(dir+"/snapshots", true, custom.Storage.ValueLogGC, custom.Storage.Truncate)
	if err != nil {
		return nil, err
	}
	cacheDB, err := openDB(dir+"/cache", false, custom.Storage.ValueLogGC, true)
	if err != nil {
		return nil, err
	}
	return &BadgerStore{
		custom:      custom,
		snapshotsDB: snapshotsDB,
		cacheDB:     cacheDB,
		closing:     false,
	}, nil
}

func (store *BadgerStore) Close() error {
	store.closing = true
	err := store.snapshotsDB.Close()
	if err != nil {
		return err
	}
	return store.cacheDB.Close()
}

func openDB(dir string, sync, valueLogGC, truncate bool) (*badger.DB, error) {
	opts := badger.DefaultOptions(dir)
	opts = opts.WithSyncWrites(sync)
	opts = opts.WithCompression(options.None)
	opts = opts.WithMaxCacheSize(0)
	opts = opts.WithTruncate(truncate)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}

	if valueLogGC {
		go func() {
			for {
				lsm, vlog := db.Size()
				logger.Printf("Badger LSM %d VLOG %d\n", lsm, vlog)
				if lsm > 1024*1024*8 || vlog > 1024*1024*32 {
					err := db.RunValueLogGC(0.5)
					logger.Printf("Badger RunValueLogGC %v\n", err)
				}
				time.Sleep(5 * time.Minute)
			}
		}()
	}

	return db, nil
}
