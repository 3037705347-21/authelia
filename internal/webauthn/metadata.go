// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package webauthn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/metadata/providers/cached"
	"github.com/go-webauthn/webauthn/metadata/providers/memory"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/logging"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/storage"
)

// metadataRefreshRetryInterval is the minimum duration between two attempts to refresh outdated metadata while the
// refresh keeps failing or the upstream reports the same blob.
const metadataRefreshRetryInterval = 5 * time.Minute

// NewMetaDataProvider generates a new metadata.Provider given a *schema.Configuration and storage.CachedDataProvider.
func NewMetaDataProvider(config *schema.Configuration, store storage.CachedDataProvider) (provider MetaDataProvider, err error) {
	if config.WebAuthn.Metadata.Enabled {
		p := &StoreCachedMetadataProvider{
			new:         newMetadataProviderMemory(config),
			clock:       &metadata.RealClock{},
			store:       store,
			log:         logging.Logger().WithFields(map[string]any{logging.FieldProvider: "webauthn-metadata"}),
			cachePolicy: config.WebAuthn.Metadata.CachePolicy,
			handler:     &productionMDS3Provider{},
		}

		if p.decoder, err = metadata.NewDecoder(metadata.WithIgnoreEntryParsingErrors()); err != nil {
			return nil, err
		}

		provider = p
	}

	return provider, nil
}

func newMetadataProviderMemory(config *schema.Configuration) cached.NewFunc {
	return func(mds *metadata.Metadata) (provider metadata.Provider, err error) {
		return memory.New(
			memory.WithMetadata(mds.ToMap()),
			memory.WithValidateEntry(config.WebAuthn.Metadata.ValidateEntry),
			memory.WithValidateEntryPermitZeroAAGUID(config.WebAuthn.Metadata.ValidateEntryPermitZeroAAGUID),
			memory.WithValidateTrustAnchor(config.WebAuthn.Metadata.ValidateTrustAnchor),
			memory.WithValidateStatus(config.WebAuthn.Metadata.ValidateStatus),
			memory.WithStatusUndesired(config.WebAuthn.Metadata.ValidateStatusProhibited),
			memory.WithStatusDesired(config.WebAuthn.Metadata.ValidateStatusPermitted),
		)
	}
}

// MetaDataProvider is a metadata.Provider which also handles loading and caching the metadata.
type MetaDataProvider interface {
	metadata.Provider

	StartupCheck() (err error)
	Load(ctx context.Context) (mds *metadata.Metadata, data []byte, err error)
	LoadForce(ctx context.Context) (mds *metadata.Metadata, data []byte, err error)
	LoadFile(ctx context.Context, path string) (mds *metadata.Metadata, data []byte, err error)
	LoadCache(ctx context.Context) (mds *metadata.Metadata, data []byte, err error)
	SaveCache(ctx context.Context, data []byte) (changed bool, err error)
	DeleteCache(ctx context.Context) (err error)
	Outdated() (outdated bool)
	Generation() (generation MetadataGeneration, ok bool)
}

// MetadataGeneration is the ledger record for a single successfully committed MDS3 cache write. It allows every
// reader to verify that the cached blob it is using is exactly the complete blob that was validated and written.
type MetadataGeneration struct {
	Generation int       `json:"generation"`
	Number     int       `json:"number"`
	NextUpdate time.Time `json:"next_update"`
	Size       int       `json:"size"`
	SHA256     string    `json:"sha256"`
	WrittenAt  time.Time `json:"written_at"`
}

// StoreCachedMetadataProvider is a MetaDataProvider which caches the metadata in the storage provider.
type StoreCachedMetadataProvider struct {
	metadata.Provider

	new func(mds *metadata.Metadata) (provider metadata.Provider, err error)

	mu      sync.Mutex
	store   storage.CachedDataProvider
	decoder *metadata.Decoder
	clock   metadata.Clock
	handler MDS3Provider

	log *logrus.Entry

	cachePolicy string

	update      time.Time
	number      int
	gen         *MetadataGeneration
	lastRefresh time.Time
}

// StartupCheck implements the model.StartupCheck interface.
func (p *StoreCachedMetadataProvider) StartupCheck() (err error) {
	p.mu.Lock()

	defer p.mu.Unlock()

	return p.init(context.Background())
}

// GetEntry returns the metadata entry for the given AAGUID.
func (p *StoreCachedMetadataProvider) GetEntry(ctx context.Context, aaguid uuid.UUID) (entry *metadata.Entry, err error) {
	p.mu.Lock()

	defer p.mu.Unlock()

	if p.Provider == nil {
		// The startup check is not always performed (i.e. the CLI verification commands), initialize from the cache.
		if mds, provider, gen, legacy, data, lerr := p.getCache(ctx); lerr != nil {
			p.log.WithError(lerr).Warn("Cached WebAuthn MDS3 metadata failed verification and will not be used")
		} else if mds != nil {
			p.activate(mds, provider, gen)

			if legacy {
				// Backfill the generation ledger for a cache written by an older version.
				if _, _, lerr = p.commit(ctx, data); lerr != nil {
					p.log.WithError(lerr).Warn("Failed to record the cache generation for the cached WebAuthn MDS3 metadata")
				}
			}
		}
	}

	if (p.Provider == nil || p.outdated()) && p.clock.Now().Sub(p.lastRefresh) >= metadataRefreshRetryInterval {
		_, data, rerr := p.get(ctx, p.number)

		p.lastRefresh = p.clock.Now()

		switch {
		case rerr != nil:
			if p.Provider == nil {
				return nil, rerr
			}

			p.log.WithError(rerr).Warn("Failed to refresh the WebAuthn MDS3 metadata, continuing to use the cached metadata")
		case data != nil:
			if _, _, cerr := p.commit(ctx, data); cerr != nil {
				if p.Provider == nil {
					return nil, cerr
				}

				p.log.WithError(cerr).Warn("Failed to commit the refreshed WebAuthn MDS3 metadata, continuing to use the cached metadata")
			}
		}
	}

	if p.Provider == nil {
		return nil, metadata.ErrNotInitialized
	}

	return p.Provider.GetEntry(ctx, aaguid)
}

func (p *StoreCachedMetadataProvider) init(ctx context.Context) (err error) {
	if p.store == nil {
		return fmt.Errorf("error initializing provider: storage is not configured")
	}

	strict := p.cachePolicy == CachePolicyStrict

	var legacyData []byte

	if mds, provider, gen, legacy, data, lerr := p.getCache(ctx); lerr != nil {
		p.log.WithError(lerr).Warn("Cached WebAuthn MDS3 metadata failed verification and will not be used")
	} else if mds != nil {
		p.activate(mds, provider, gen)

		if legacy {
			legacyData = data
		}
	}

	var (
		candidate []byte
		fetched   *metadata.Metadata
	)

	if f, data, rerr := p.get(ctx, p.number); rerr != nil {
		if strict {
			return fmt.Errorf("error initializing provider: %w", rerr)
		}

		p.log.WithError(rerr).Debug("Error occurred fetching current metadata but the cache policy is relaxed")
	} else if data != nil {
		candidate, fetched = data, f
	}

	// Outdated data is rejected outright and never committed, preserving the previous usable cache.
	if candidate != nil && fetched.Parsed.NextUpdate.Before(p.clock.Now()) {
		return fmt.Errorf("error initializing provider: outdated metadata was loaded")
	}

	if candidate != nil {
		if _, _, cerr := p.commit(ctx, candidate); cerr != nil {
			if strict {
				return fmt.Errorf("error initializing provider: %w", cerr)
			}

			p.log.WithError(cerr).Debug("Error occurred committing current metadata but the cache policy is relaxed")
		}
	} else if legacyData != nil && p.number > 0 && !p.update.Before(p.clock.Now()) {
		// Upstream returned Not Modified: backfill the generation ledger for a cache written by an older version.
		if _, _, cerr := p.commit(ctx, legacyData); cerr != nil {
			if strict {
				return fmt.Errorf("error initializing provider: %w", cerr)
			}

			p.log.WithError(cerr).Debug("Error occurred recording cached metadata generation but the cache policy is relaxed")
		}
	}

	p.lastRefresh = p.clock.Now()

	if p.number <= 0 {
		return fmt.Errorf("error initializing provider: no metadata was loaded")
	}

	if p.update.Before(p.clock.Now()) {
		return fmt.Errorf("error initializing provider: outdated metadata was loaded")
	}

	return nil
}

// Load returns the metadata, loading it from the MDS3 provider when newer than the cached metadata.
func (p *StoreCachedMetadataProvider) Load(ctx context.Context) (mds *metadata.Metadata, data []byte, err error) {
	p.mu.Lock()

	defer p.mu.Unlock()

	return p.get(ctx, p.number)
}

// LoadForce returns the metadata, always loading it from the MDS3 provider.
func (p *StoreCachedMetadataProvider) LoadForce(ctx context.Context) (mds *metadata.Metadata, data []byte, err error) {
	p.mu.Lock()

	defer p.mu.Unlock()

	return p.get(ctx, -1)
}

// LoadFile returns the metadata loaded from the file at the given path. The cache is not modified until SaveCache is
// called, and only data which parses successfully is returned.
func (p *StoreCachedMetadataProvider) LoadFile(ctx context.Context, path string) (mds *metadata.Metadata, data []byte, err error) {
	if data, err = os.ReadFile(path); err != nil {
		return nil, nil, fmt.Errorf("error reading file '%s': %w", path, err)
	}

	p.mu.Lock()

	defer p.mu.Unlock()

	if mds, err = p.parse(bytes.NewReader(data)); err != nil {
		return nil, nil, fmt.Errorf("error parsing metadata: %w", err)
	}

	return mds, data, nil
}

// LoadCache returns the verified metadata loaded from the cache. It does not modify the cache.
func (p *StoreCachedMetadataProvider) LoadCache(ctx context.Context) (mds *metadata.Metadata, data []byte, err error) {
	p.mu.Lock()

	defer p.mu.Unlock()

	var (
		provider metadata.Provider
		gen      *MetadataGeneration
		legacy   bool
	)

	if mds, provider, gen, legacy, data, err = p.getCache(ctx); err != nil {
		return nil, nil, err
	}

	if mds == nil {
		return nil, nil, nil
	}

	if legacy {
		// Do not surface the missing generation ledger via this method, the metadata itself verified successfully.
		p.activate(mds, provider, nil)
	} else {
		p.activate(mds, provider, gen)
	}

	return mds, data, nil
}

// getCache loads both the blob and the generation ledger, and verifies the blob is the complete blob recorded by
// the ledger. The legacy return value is true when the ledger is missing for a blob which otherwise verifies.
func (p *StoreCachedMetadataProvider) getCache(ctx context.Context) (mds *metadata.Metadata, provider metadata.Provider, gen *MetadataGeneration, legacy bool, data []byte, err error) {
	var cache *model.CachedData

	if cache, err = p.store.LoadCachedData(ctx, cacheMDS3); err != nil {
		return nil, nil, nil, false, nil, fmt.Errorf("error loading metadata cache from database: %w", err)
	}

	if cache == nil || cache.Value == nil {
		return nil, nil, nil, false, nil, nil
	}

	if mds, provider, err = p.validate(cache.Value); err != nil {
		return nil, nil, nil, false, nil, fmt.Errorf("error verifying metadata cache from database: %w", err)
	}

	if gen, err = p.loadGeneration(ctx); err != nil {
		return nil, nil, nil, false, nil, err
	}

	if gen == nil {
		return mds, provider, nil, true, cache.Value, nil
	}

	if gen.Size != len(cache.Value) || gen.SHA256 != hashMDS3(cache.Value) {
		return nil, nil, nil, false, nil, fmt.Errorf("error verifying metadata cache from database: cached blob does not match the recorded generation %d", gen.Generation)
	}

	if gen.Number != mds.Parsed.Number || !gen.NextUpdate.Equal(mds.Parsed.NextUpdate) {
		return nil, nil, nil, false, nil, fmt.Errorf("error verifying metadata cache from database: recorded generation %d does not match the cached blob", gen.Generation)
	}

	return mds, provider, gen, false, cache.Value, nil
}

// SaveCache validates the given metadata in full and only replaces the cached metadata after it has been verified.
// It returns changed as false without writing anything when the data is identical to the data already cached.
func (p *StoreCachedMetadataProvider) SaveCache(ctx context.Context, data []byte) (changed bool, err error) {
	p.mu.Lock()

	defer p.mu.Unlock()

	_, changed, err = p.commit(ctx, data)

	return changed, err
}

// DeleteCache deletes the cached metadata and its generation record, and resets the active provider.
func (p *StoreCachedMetadataProvider) DeleteCache(ctx context.Context) (err error) {
	p.mu.Lock()

	defer p.mu.Unlock()

	if err = DeleteMDS3Cache(ctx, p.store); err != nil {
		return err
	}

	p.Provider = nil
	p.gen = nil
	p.update = time.Time{}
	p.number = 0

	return nil
}

// DeleteMDS3Cache deletes the MDS3 blob and generation record rows from the store. It is usable even when metadata
// is disabled and there is no active provider.
func DeleteMDS3Cache(ctx context.Context, store storage.CachedDataProvider) (err error) {
	return deleteMDS3Cache(ctx, store)
}

// commit is the validate-before-commit write path. The data is fully validated before any write occurs, the blob and
// the generation ledger are replaced together, and the active provider is only swapped to the new metadata after the
// write succeeds. Data which is identical to the committed data is not written again.
func (p *StoreCachedMetadataProvider) commit(ctx context.Context, data []byte) (mds *metadata.Metadata, changed bool, err error) {
	var provider metadata.Provider

	if mds, provider, err = p.validate(data); err != nil {
		return nil, false, fmt.Errorf("error validating metadata before updating the cache: %w", err)
	}

	sum := hashMDS3(data)

	var (
		existing *model.CachedData
		gen      *MetadataGeneration
	)

	if existing, err = p.store.LoadCachedData(ctx, cacheMDS3); err != nil {
		return nil, false, fmt.Errorf("error loading metadata cache from database: %w", err)
	}

	if gen, err = p.loadGeneration(ctx); err != nil {
		return nil, false, err
	}

	// The committed blob already matches the data: nothing to write.
	if gen != nil && gen.Size == len(data) && gen.SHA256 == sum && existing != nil && bytes.Equal(existing.Value, data) {
		p.activate(mds, provider, gen)

		return mds, false, nil
	}

	next := MetadataGeneration{
		Generation: 1,
		Number:     mds.Parsed.Number,
		NextUpdate: mds.Parsed.NextUpdate,
		Size:       len(data),
		SHA256:     sum,
		WrittenAt:  p.clock.Now(),
	}

	switch {
	case gen == nil:
		// First commit or a cache written by an older version.
	case gen.Size == len(data) && gen.SHA256 == sum:
		// The ledger records this exact blob but the blob row is missing or inconsistent: restore it without
		// advancing the generation.
		next.Generation = gen.Generation
		next.WrittenAt = gen.WrittenAt
	default:
		// Different content: a new generation is required.
		next.Generation = gen.Generation + 1
	}

	if err = p.persist(ctx, data, next); err != nil {
		return nil, false, err
	}

	p.activate(mds, provider, &next)

	p.log.WithFields(map[string]any{"generation": next.Generation, "number": next.Number, "size": next.Size}).Info("Committed new WebAuthn MDS3 metadata generation to cache")

	return mds, true, nil
}

// validate performs the full validation of a candidate blob: it must be non-empty, decode and parse successfully
// including signature and trust chain verification, and be usable to construct an in-memory provider.
func (p *StoreCachedMetadataProvider) validate(data []byte) (mds *metadata.Metadata, provider metadata.Provider, err error) {
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("metadata data is empty")
	}

	if mds, err = p.parse(bytes.NewReader(data)); err != nil {
		return nil, nil, err
	}

	if provider, err = p.new(mds); err != nil {
		return nil, nil, err
	}

	return mds, provider, nil
}

func (p *StoreCachedMetadataProvider) activate(mds *metadata.Metadata, provider metadata.Provider, gen *MetadataGeneration) {
	p.Provider = provider
	p.update, p.number = mds.Parsed.NextUpdate, mds.Parsed.Number

	p.gen = gen
}

// persist replaces the blob and generation ledger rows together in a single transaction when the store supports
// transactions, so a failed write always leaves the previous usable cache in place.
func (p *StoreCachedMetadataProvider) persist(ctx context.Context, data []byte, gen MetadataGeneration) (err error) {
	var record []byte

	if record, err = json.Marshal(gen); err != nil {
		return fmt.Errorf("error encoding metadata generation record: %w", err)
	}

	write := func(ctx context.Context) error {
		if err = p.saveCache(ctx, cacheMDS3, data); err != nil {
			return err
		}

		return p.saveCache(ctx, cacheMDS3Generation, record)
	}

	tx, ok := p.store.(cacheTransaction)
	if !ok {
		if err = write(ctx); err != nil {
			return err
		}

		return nil
	}

	var tctx context.Context

	if tctx, err = tx.BeginTX(ctx); err != nil {
		return fmt.Errorf("error beginning transaction to save metadata cache to database: %w", err)
	}

	if err = write(tctx); err != nil {
		_ = tx.Rollback(tctx)

		return err
	}

	if err = tx.Commit(tctx); err != nil {
		_ = tx.Rollback(tctx)

		return fmt.Errorf("error committing transaction saving metadata cache to database: %w", err)
	}

	return nil
}

func deleteMDS3Cache(ctx context.Context, store storage.CachedDataProvider) (err error) {
	remove := func(ctx context.Context) error {
		if err = store.DeleteCachedData(ctx, cacheMDS3Generation); err != nil {
			return fmt.Errorf("error deleting metadata generation record from database: %w", err)
		}

		if err = store.DeleteCachedData(ctx, cacheMDS3); err != nil {
			return fmt.Errorf("error deleting metadata cache from database: %w", err)
		}

		return nil
	}

	tx, ok := store.(cacheTransaction)
	if !ok {
		if err = remove(ctx); err != nil {
			return err
		}

		return nil
	}

	var tctx context.Context

	if tctx, err = tx.BeginTX(ctx); err != nil {
		return fmt.Errorf("error beginning transaction to delete metadata cache from database: %w", err)
	}

	if err = remove(tctx); err != nil {
		_ = tx.Rollback(tctx)

		return err
	}

	if err = tx.Commit(tctx); err != nil {
		_ = tx.Rollback(tctx)

		return fmt.Errorf("error committing transaction deleting metadata cache from database: %w", err)
	}

	return nil
}

func (p *StoreCachedMetadataProvider) loadGeneration(ctx context.Context) (gen *MetadataGeneration, err error) {
	var cache *model.CachedData

	if cache, err = p.store.LoadCachedData(ctx, cacheMDS3Generation); err != nil {
		return nil, fmt.Errorf("error loading metadata generation record from database: %w", err)
	}

	if cache == nil || cache.Value == nil {
		return nil, nil
	}

	gen = &MetadataGeneration{}

	if err = json.Unmarshal(cache.Value, gen); err != nil {
		return nil, fmt.Errorf("error decoding metadata generation record from database: %w", err)
	}

	return gen, nil
}

func (p *StoreCachedMetadataProvider) saveCache(ctx context.Context, name string, data []byte) (err error) {
	if len(data) == 0 {
		return fmt.Errorf("error saving metadata cache to database: data is empty")
	}

	cache := model.CachedData{Name: name, Value: data}

	if err = p.store.SaveCachedData(ctx, cache); err != nil {
		return fmt.Errorf("error saving metadata cache to database: %w", err)
	}

	return nil
}

// Outdated returns true if the cached metadata should be updated.
func (p *StoreCachedMetadataProvider) Outdated() bool {
	p.mu.Lock()

	defer p.mu.Unlock()

	return p.outdated()
}

func (p *StoreCachedMetadataProvider) outdated() bool {
	return p.clock.Now().After(p.update)
}

// Generation returns the generation record of the active committed metadata.
func (p *StoreCachedMetadataProvider) Generation() (generation MetadataGeneration, ok bool) {
	p.mu.Lock()

	defer p.mu.Unlock()

	if p.gen == nil {
		return MetadataGeneration{}, false
	}

	return *p.gen, true
}

func (p *StoreCachedMetadataProvider) get(ctx context.Context, current int) (mds *metadata.Metadata, data []byte, err error) {
	if data, err = p.latest(ctx, current); err != nil {
		return nil, nil, fmt.Errorf("error loading latest metadata: %w", err)
	}

	if data == nil {
		return nil, nil, nil
	}

	if mds, err = p.parse(bytes.NewReader(data)); err != nil {
		return nil, nil, fmt.Errorf("error parsing metadata: %w", err)
	}

	return mds, data, nil
}

func (p *StoreCachedMetadataProvider) latest(ctx context.Context, current int) (data []byte, err error) {
	if p.handler == nil {
		p.handler = &productionMDS3Provider{}
	}

	return p.handler.FetchMDS3(ctx, current)
}

func (p *StoreCachedMetadataProvider) parse(reader io.Reader) (mds *metadata.Metadata, err error) {
	var payload *metadata.PayloadJSON

	if payload, err = p.decoder.Decode(reader); err != nil {
		return nil, err
	}

	if mds, err = p.decoder.Parse(payload); err != nil {
		return nil, err
	}

	return mds, nil
}

func hashMDS3(data []byte) string {
	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}

// cacheTransaction is the subset of the storage transaction interface required to commit the cache atomically.
type cacheTransaction interface {
	BeginTX(ctx context.Context) (context.Context, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// MDS3Provider is a provider which fetches the FIDO Metadata Service 3.0 blob.
type MDS3Provider interface {
	FetchMDS3(ctx context.Context, current int) (data []byte, err error)
}

type productionMDS3Provider struct {
	client *http.Client
	url    string
}

func (h *productionMDS3Provider) FetchMDS3(ctx context.Context, current int) (data []byte, err error) {
	if h.client == nil {
		h.client = &http.Client{}
	}

	url := metadata.ProductionMDSURL

	if h.url != "" {
		url = h.url
	}

	var (
		req  *http.Request
		resp *http.Response
	)

	if req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, nil); err != nil {
		return nil, fmt.Errorf("error creating request while attempting to get latest metadata from metadata service: %w", err)
	}

	if current > 0 {
		req.Header.Set(fasthttp.HeaderIfNoneMatch, fmt.Sprintf("%d", current))
	}

	if resp, err = h.client.Do(req); err != nil {
		return nil, fmt.Errorf("error getting latest metadata from metadata service: %w", err)
	}

	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Read at most one byte more than the maximum so an oversized response can be detected instead of being
		// silently truncated.
		if data, err = io.ReadAll(io.LimitReader(resp.Body, maxMDS3BlobSize+1)); err != nil {
			return nil, fmt.Errorf("error reading latest metadata from metadata service: %w", err)
		}

		if len(data) == 0 {
			return nil, errors.New("error getting latest metadata from metadata service: response body was empty")
		}

		if int64(len(data)) > maxMDS3BlobSize {
			return nil, fmt.Errorf("error getting latest metadata from metadata service: response body exceeds the maximum allowed size of %d bytes", maxMDS3BlobSize)
		}

		// Defense in depth: explicitly verify the advertised complete body was received in full. A truncated body
		// must never be treated as a successful download.
		if resp.ContentLength > 0 && int64(len(data)) != resp.ContentLength {
			return nil, fmt.Errorf("error getting latest metadata from metadata service: incomplete response body: received %d of %d bytes", len(data), resp.ContentLength)
		}

		return data, nil
	case http.StatusNotModified:
		return nil, nil
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("error getting latest metadata from metadata service: too many requests")
	default:
		return nil, fmt.Errorf("error getting latest metadata from metadata service: unexpected status code: %d", resp.StatusCode)
	}
}
