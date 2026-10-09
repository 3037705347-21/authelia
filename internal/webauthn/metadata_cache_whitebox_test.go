// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package webauthn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/logging"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/storage"
)

type testClock struct {
	now time.Time
}

func (c *testClock) Now() time.Time {
	return c.now
}

type testMDS3Fixture struct {
	key     *ecdsa.PrivateKey
	encoded string
}

func newTestMDS3Fixture(t *testing.T) *testMDS3Fixture {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test MDS3 root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	_, err = x509.ParseCertificate(der)
	require.NoError(t, err)

	return &testMDS3Fixture{key: key, encoded: base64.StdEncoding.EncodeToString(der)}
}

func (f *testMDS3Fixture) blob(t *testing.T, number int, nextUpdate time.Time, extra ...byte) []byte {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"no":         number,
		"nextUpdate": nextUpdate.Format(time.DateOnly),
		"entries":    []any{},
	})

	token.Header["x5c"] = []any{f.encoded}

	signed, err := token.SignedString(f.key)
	require.NoError(t, err)

	data := []byte(signed)

	return append(data, extra...)
}

type testMDS3Handler struct {
	mu      sync.Mutex
	data    []byte
	err     error
	calls   int
	current []int
}

func (h *testMDS3Handler) FetchMDS3(_ context.Context, current int) (data []byte, err error) {
	h.mu.Lock()

	defer h.mu.Unlock()

	h.calls++

	h.current = append(h.current, current)

	return h.data, h.err
}

func (h *testMDS3Handler) invocations() int {
	h.mu.Lock()

	defer h.mu.Unlock()

	return h.calls
}

type testCountingCacheStore struct {
	storage.CachedDataProvider
	saves   int
	deletes int
}

func (s *testCountingCacheStore) SaveCachedData(ctx context.Context, data model.CachedData) (err error) {
	s.saves++

	return s.CachedDataProvider.SaveCachedData(ctx, data)
}

func (s *testCountingCacheStore) DeleteCachedData(ctx context.Context, name string) (err error) {
	s.deletes++

	return s.CachedDataProvider.DeleteCachedData(ctx, name)
}

func (s *testCountingCacheStore) BeginTX(ctx context.Context) (context.Context, error) {
	return s.CachedDataProvider.(interface {
		BeginTX(context.Context) (context.Context, error)
	}).BeginTX(ctx)
}

func (s *testCountingCacheStore) Commit(ctx context.Context) error {
	return s.CachedDataProvider.(interface {
		Commit(context.Context) error
	}).Commit(ctx)
}

func (s *testCountingCacheStore) Rollback(ctx context.Context) error {
	return s.CachedDataProvider.(interface {
		Rollback(context.Context) error
	}).Rollback(ctx)
}

func newTestMDS3SQLiteStore(t *testing.T) storage.Provider {
	t.Helper()

	config := &schema.Configuration{Storage: schema.Storage{
		//gitleaks:allow // This is not an actual secret.
		EncryptionKey: "authelia-test-key-not-a-secret-authelia-test-key-not-a-secret",
		Local:         &schema.StorageLocal{Path: filepath.Join(t.TempDir(), "db.sqlite3")},
	}}

	store, err := storage.NewProvider(config, nil)
	require.NoError(t, err)

	require.NoError(t, store.StartupCheck())

	t.Cleanup(func() {
		_ = store.Close()
	})

	return store
}

func newTestStoreCachedMetadataProvider(t *testing.T, store storage.CachedDataProvider, fixture *testMDS3Fixture, handler MDS3Provider, policy string, now time.Time) *StoreCachedMetadataProvider {
	t.Helper()

	decoder, err := metadata.NewDecoder(metadata.WithIgnoreEntryParsingErrors(), metadata.WithRootCertificate(fixture.encoded))
	require.NoError(t, err)

	return &StoreCachedMetadataProvider{
		new:         newMetadataProviderMemory(&schema.Configuration{WebAuthn: schema.WebAuthn{Metadata: schema.WebAuthnMetadata{Enabled: true}}}),
		clock:       &testClock{now: now},
		store:       store,
		decoder:     decoder,
		handler:     handler,
		cachePolicy: policy,
		log:         logging.Logger().WithField("test", t.Name()),
	}
}

func TestStoreCachedMetadataProviderCommitGenerations(t *testing.T) {
	store := newTestMDS3SQLiteStore(t)
	fixture := newTestMDS3Fixture(t)
	handler := &testMDS3Handler{}
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

	counting := &testCountingCacheStore{CachedDataProvider: store}
	provider := newTestStoreCachedMetadataProvider(t, counting, fixture, handler, CachePolicyStrict, now)

	ctx := context.Background()

	blob1 := fixture.blob(t, 1, now.Add(30*24*time.Hour))

	mds, changed, err := provider.commit(ctx, blob1)
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, 1, mds.Parsed.Number)

	savesAfterFirst := counting.saves

	assert.Equal(t, 2, savesAfterFirst)

	gen, ok := provider.Generation()
	require.True(t, ok)
	assert.Equal(t, 1, gen.Generation)
	assert.Equal(t, 1, gen.Number)
	assert.Equal(t, len(blob1), gen.Size)
	assert.Equal(t, hashMDS3(blob1), gen.SHA256)
	assert.Equal(t, now, gen.WrittenAt)

	// Committing identical data must not write anything or bump the generation.
	_, changed, err = provider.commit(ctx, blob1)
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, savesAfterFirst, counting.saves, "identical data must not be rewritten")

	gen, ok = provider.Generation()
	require.True(t, ok)
	assert.Equal(t, 1, gen.Generation)

	// Committing different valid data creates the next generation.
	later := now.Add(time.Hour)
	provider.clock = &testClock{now: later}

	blob2 := fixture.blob(t, 2, now.Add(60*24*time.Hour))

	_, changed, err = provider.commit(ctx, blob2)
	require.NoError(t, err)
	assert.True(t, changed)

	gen, ok = provider.Generation()
	require.True(t, ok)
	assert.Equal(t, 2, gen.Generation)
	assert.Equal(t, 2, gen.Number)
	assert.Equal(t, later, gen.WrittenAt)

	// Every reader sees the same committed blob through the verified cache path.
	mds, data, err := provider.LoadCache(ctx)
	require.NoError(t, err)
	require.NotNil(t, mds)
	assert.Equal(t, blob2, data)
	assert.Equal(t, 2, mds.Parsed.Number)

	// When the blob row is lost but the ledger remains, the same generation is restored without advancing.
	require.NoError(t, store.DeleteCachedData(ctx, cacheMDS3))

	_, changed, err = provider.commit(ctx, blob2)
	require.NoError(t, err)
	assert.True(t, changed)

	gen, ok = provider.Generation()
	require.True(t, ok)
	assert.Equal(t, 2, gen.Generation)
	assert.Equal(t, later, gen.WrittenAt)
}

func TestStoreCachedMetadataProviderCommitRejectsInvalidDataAndKeepsPrevious(t *testing.T) {
	store := newTestMDS3SQLiteStore(t)
	fixture := newTestMDS3Fixture(t)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

	provider := newTestStoreCachedMetadataProvider(t, store, fixture, &testMDS3Handler{}, CachePolicyStrict, now)

	ctx := context.Background()

	blob1 := fixture.blob(t, 1, now.Add(30*24*time.Hour))

	_, changed, err := provider.commit(ctx, blob1)
	require.NoError(t, err)
	assert.True(t, changed)

	for _, data := range [][]byte{nil, {}, blob1[:len(blob1)/2], []byte("not a jwt at all")} {
		_, changed, err = provider.commit(ctx, data)
		assert.Error(t, err, "data of len %d must be rejected", len(data))
		assert.False(t, changed)
	}

	// The previous usable cache and its generation are untouched.
	mds, cached, err := provider.LoadCache(ctx)
	require.NoError(t, err)
	require.NotNil(t, mds)
	assert.Equal(t, blob1, cached)

	gen, ok := provider.Generation()
	require.True(t, ok)
	assert.Equal(t, 1, gen.Generation)
}

func TestStoreCachedMetadataProviderLoadCacheVerification(t *testing.T) {
	store := newTestMDS3SQLiteStore(t)
	fixture := newTestMDS3Fixture(t)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

	provider := newTestStoreCachedMetadataProvider(t, store, fixture, &testMDS3Handler{}, CachePolicyStrict, now)

	ctx := context.Background()

	blob1 := fixture.blob(t, 1, now.Add(30*24*time.Hour))

	_, _, err := provider.commit(ctx, blob1)
	require.NoError(t, err)

	// Empty cache is valid but uninitialized.
	empty := newTestStoreCachedMetadataProvider(t, newTestMDS3SQLiteStore(t), fixture, &testMDS3Handler{}, CachePolicyStrict, now)
	mds, data, err := empty.LoadCache(ctx)
	require.NoError(t, err)
	assert.Nil(t, mds)
	assert.Nil(t, data)

	other := newTestStoreCachedMetadataProvider(t, store, fixture, &testMDS3Handler{}, CachePolicyStrict, now)

	// A blob which does not match the recorded generation fails verification.
	require.NoError(t, store.SaveCachedData(ctx, model.CachedData{Name: cacheMDS3, Value: blob1[:len(blob1)/2]}))

	_, _, err = other.LoadCache(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verifying metadata cache")

	// Restoring the blob succeeds again.
	require.NoError(t, store.SaveCachedData(ctx, model.CachedData{Name: cacheMDS3, Value: blob1}))
	mds, _, err = other.LoadCache(ctx)
	require.NoError(t, err)
	require.NotNil(t, mds)

	// A corrupt generation record fails verification.
	require.NoError(t, store.SaveCachedData(ctx, model.CachedData{Name: cacheMDS3Generation, Value: []byte("{not-json")}))
	_, _, err = other.LoadCache(ctx)
	require.Error(t, err)

	// A missing generation record is treated as a legacy cache: the blob still verifies.
	require.NoError(t, store.DeleteCachedData(ctx, cacheMDS3Generation))
	mds, data, err = other.LoadCache(ctx)
	require.NoError(t, err)
	require.NotNil(t, mds)
	assert.Equal(t, blob1, data)

	_, ok := other.Generation()
	assert.False(t, ok)
}

func TestStoreCachedMetadataProviderInit(t *testing.T) {
	fixture := newTestMDS3Fixture(t)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

	ctx := context.Background()

	t.Run("ShouldCommitFetchedMetadata", func(t *testing.T) {
		store := newTestMDS3SQLiteStore(t)
		handler := &testMDS3Handler{data: fixture.blob(t, 1, now.Add(24*time.Hour))}
		provider := newTestStoreCachedMetadataProvider(t, store, fixture, handler, CachePolicyStrict, now)

		require.NoError(t, provider.init(ctx))

		gen, ok := provider.Generation()
		require.True(t, ok)
		assert.Equal(t, 1, gen.Generation)
	})

	t.Run("ShouldKeepValidCacheWhenFetchFailsRelaxed", func(t *testing.T) {
		store := newTestMDS3SQLiteStore(t)
		handler := &testMDS3Handler{data: fixture.blob(t, 1, now.Add(24*time.Hour))}
		provider := newTestStoreCachedMetadataProvider(t, store, fixture, handler, CachePolicyRelaxed, now)

		require.NoError(t, provider.init(ctx))

		handler.data = nil
		handler.err = errors.New("network is unavailable")

		require.NoError(t, provider.init(ctx))

		gen, ok := provider.Generation()
		require.True(t, ok)
		assert.Equal(t, 1, gen.Generation)
	})

	t.Run("ShouldFailWhenFetchFailsStrict", func(t *testing.T) {
		store := newTestMDS3SQLiteStore(t)
		handler := &testMDS3Handler{data: fixture.blob(t, 1, now.Add(24*time.Hour))}
		provider := newTestStoreCachedMetadataProvider(t, store, fixture, handler, CachePolicyStrict, now)

		require.NoError(t, provider.init(ctx))

		handler.data = nil
		handler.err = errors.New("network is unavailable")

		err := provider.init(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error initializing provider")
	})

	t.Run("ShouldFailWithoutAnyMetadata", func(t *testing.T) {
		store := newTestMDS3SQLiteStore(t)
		provider := newTestStoreCachedMetadataProvider(t, store, fixture, &testMDS3Handler{}, CachePolicyRelaxed, now)

		err := provider.init(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no metadata was loaded")
	})

	t.Run("ShouldFailOnOutdatedMetadata", func(t *testing.T) {
		store := newTestMDS3SQLiteStore(t)
		handler := &testMDS3Handler{data: fixture.blob(t, 1, now.Add(-24*time.Hour))}
		provider := newTestStoreCachedMetadataProvider(t, store, fixture, handler, CachePolicyRelaxed, now)

		err := provider.init(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "outdated metadata was loaded")

		// Nothing was committed.
		mds, _, err := newTestStoreCachedMetadataProvider(t, store, fixture, handler, CachePolicyRelaxed, now).LoadCache(ctx)
		require.NoError(t, err)
		assert.Nil(t, mds)
	})

	t.Run("ShouldBackfillLegacyLedgerOnNotModified", func(t *testing.T) {
		store := newTestMDS3SQLiteStore(t)
		blob1 := fixture.blob(t, 1, now.Add(24*time.Hour))

		require.NoError(t, store.SaveCachedData(ctx, model.CachedData{Name: cacheMDS3, Value: blob1}))

		provider := newTestStoreCachedMetadataProvider(t, store, fixture, &testMDS3Handler{}, CachePolicyStrict, now)

		require.NoError(t, provider.init(ctx))

		gen, ok := provider.Generation()
		require.True(t, ok)
		assert.Equal(t, 1, gen.Generation)
		assert.Equal(t, hashMDS3(blob1), gen.SHA256)
	})

	t.Run("ShouldIgnoreCorruptCacheAndRecoverViaFetch", func(t *testing.T) {
		store := newTestMDS3SQLiteStore(t)

		blob1 := fixture.blob(t, 1, now.Add(24*time.Hour))

		require.NoError(t, store.SaveCachedData(ctx, model.CachedData{Name: cacheMDS3, Value: []byte("partial")}))
		require.NoError(t, store.SaveCachedData(ctx, model.CachedData{Name: cacheMDS3Generation, Value: []byte("{}")}))

		handler := &testMDS3Handler{data: blob1}
		provider := newTestStoreCachedMetadataProvider(t, store, fixture, handler, CachePolicyStrict, now)

		require.NoError(t, provider.init(ctx))

		gen, ok := provider.Generation()
		require.True(t, ok)
		assert.Equal(t, 1, gen.Generation)
	})
}

func TestStoreCachedMetadataProviderGetEntry(t *testing.T) {
	fixture := newTestMDS3Fixture(t)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

	ctx := context.Background()

	aaguid := uuid.New()

	t.Run("ShouldServeCommittedCacheWithoutFetching", func(t *testing.T) {
		store := newTestMDS3SQLiteStore(t)
		handler := &testMDS3Handler{}
		provider := newTestStoreCachedMetadataProvider(t, store, fixture, handler, CachePolicyStrict, now)

		_, _, err := provider.commit(ctx, fixture.blob(t, 1, now.Add(24*time.Hour)))
		require.NoError(t, err)

		entry, err := provider.GetEntry(ctx, aaguid)
		require.NoError(t, err)
		assert.Nil(t, entry)
		assert.Equal(t, 0, handler.invocations())
	})

	t.Run("ShouldKeepPreviousCacheWhenRefreshFails", func(t *testing.T) {
		store := newTestMDS3SQLiteStore(t)
		handler := &testMDS3Handler{}
		clock := &testClock{now: now}
		provider := newTestStoreCachedMetadataProvider(t, store, fixture, handler, CachePolicyStrict, now)
		provider.clock = clock

		blob1 := fixture.blob(t, 1, now.Add(24*time.Hour))

		_, _, err := provider.commit(ctx, blob1)
		require.NoError(t, err)

		// Outdated and the upstream serves a truncated blob.
		clock.now = now.Add(48 * time.Hour)
		handler.data = blob1[:len(blob1)/2]

		entry, err := provider.GetEntry(ctx, aaguid)
		require.NoError(t, err)
		assert.Nil(t, entry)

		gen, ok := provider.Generation()
		require.True(t, ok)
		assert.Equal(t, 1, gen.Generation)

		// Immediate retries are throttled rather than re-attempted every call.
		_, err = provider.GetEntry(ctx, aaguid)
		require.NoError(t, err)
		assert.Equal(t, 1, handler.invocations())

		// Once the upstream serves a valid new blob, the new generation is committed.
		clock.now = clock.now.Add(metadataRefreshRetryInterval + time.Minute)
		handler.data = fixture.blob(t, 2, now.Add(72*time.Hour))

		_, err = provider.GetEntry(ctx, aaguid)
		require.NoError(t, err)

		gen, ok = provider.Generation()
		require.True(t, ok)
		assert.Equal(t, 2, gen.Generation)
	})

	t.Run("ShouldErrorWhenNoCacheAndFetchFails", func(t *testing.T) {
		store := newTestMDS3SQLiteStore(t)
		handler := &testMDS3Handler{err: errors.New("network is unavailable")}
		provider := newTestStoreCachedMetadataProvider(t, store, fixture, handler, CachePolicyRelaxed, now)

		_, err := provider.GetEntry(ctx, aaguid)
		require.Error(t, err)
	})
}

func TestStoreCachedMetadataProviderDeleteCache(t *testing.T) {
	store := newTestMDS3SQLiteStore(t)
	fixture := newTestMDS3Fixture(t)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

	provider := newTestStoreCachedMetadataProvider(t, store, fixture, &testMDS3Handler{}, CachePolicyStrict, now)

	ctx := context.Background()

	_, _, err := provider.commit(ctx, fixture.blob(t, 1, now.Add(24*time.Hour)))
	require.NoError(t, err)

	require.NoError(t, provider.DeleteCache(ctx))

	blob, err := store.LoadCachedData(ctx, cacheMDS3)
	require.NoError(t, err)
	assert.Nil(t, blob)

	record, err := store.LoadCachedData(ctx, cacheMDS3Generation)
	require.NoError(t, err)
	assert.Nil(t, record)

	mds, _, err := provider.LoadCache(ctx)
	require.NoError(t, err)
	assert.Nil(t, mds)

	_, ok := provider.Generation()
	assert.False(t, ok)
}

func TestProductionMDS3ProviderFetchMDS3(t *testing.T) {
	ctx := context.Background()

	t.Run("ShouldFetchCompleteBlob", func(t *testing.T) {
		body := []byte("the complete metadata blob")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(body)
		}))

		defer server.Close()

		handler := newTestProductionMDS3Provider(t, server.URL)

		data, err := handler.FetchMDS3(ctx, 0)
		require.NoError(t, err)
		assert.Equal(t, body, data)
	})

	t.Run("ShouldRejectTruncatedBlob", func(t *testing.T) {
		body := []byte("half of the metadata blob")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(fasthttp.HeaderContentLength, strconv.Itoa(len(body)*2))
			_, _ = w.Write(body)
		}))

		defer server.Close()

		handler := newTestProductionMDS3Provider(t, server.URL)

		_, err := handler.FetchMDS3(ctx, 0)
		require.Error(t, err)
	})

	t.Run("ShouldRejectEmptyBlob", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		defer server.Close()

		handler := newTestProductionMDS3Provider(t, server.URL)

		_, err := handler.FetchMDS3(ctx, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("ShouldRejectOversizedBlob", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(make([]byte, maxMDS3BlobSize+1))
		}))

		defer server.Close()

		handler := newTestProductionMDS3Provider(t, server.URL)

		_, err := handler.FetchMDS3(ctx, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "maximum allowed size")
	})

	t.Run("ShouldReturnNilOnNotModified", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "5", r.Header.Get(fasthttp.HeaderIfNoneMatch))
			w.WriteHeader(http.StatusNotModified)
		}))

		defer server.Close()

		handler := newTestProductionMDS3Provider(t, server.URL)

		data, err := handler.FetchMDS3(ctx, 5)
		require.NoError(t, err)
		assert.Nil(t, data)
	})

	t.Run("ShouldRejectUnexpectedStatus", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))

		defer server.Close()

		handler := newTestProductionMDS3Provider(t, server.URL)

		_, err := handler.FetchMDS3(ctx, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too many requests")
	})
}

func newTestProductionMDS3Provider(t *testing.T, url string) *productionMDS3Provider {
	t.Helper()

	return &productionMDS3Provider{client: &http.Client{}, url: url}
}
