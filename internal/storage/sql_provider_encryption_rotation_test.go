// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/utils"
)

const (
	testRotationOldKey = "authelia-test-key-not-a-secret-authelia-test-key-not-a-secret"
	testRotationNewKey = "authelia-new-test-key-not-a-secret-authelia-new-key-value-ok"
)

func rotationProviderAtPath(t *testing.T, path, key string) *SQLiteProvider {
	t.Helper()

	config := &schema.Configuration{
		Storage: schema.Storage{
			EncryptionKey: key,
			Local:         &schema.StorageLocal{Path: path},
		},
	}

	provider, err := NewSQLiteProvider(config)
	require.NoError(t, err)
	require.NotNil(t, provider)

	return provider
}

func rotationTestKey(t *testing.T, raw string) []byte {
	t.Helper()

	key, err := utils.DeriveCryptographicKey([]byte(raw), hkdfKeyInfo, sha256.New)
	require.NoError(t, err)

	return key
}

func loadRotationRecords(t *testing.T, provider *SQLiteProvider, ctx context.Context) (records []encEncryptionKeyRotation) {
	t.Helper()

	query := provider.db.Rebind(fmt.Sprintf(queryFmtSelectEncryptionKeyRotation, tableEncryptionKeyRotation))

	require.NoError(t, provider.db.SelectContext(ctx, &records, query))

	return records
}

func rotationRecordMap(records []encEncryptionKeyRotation) map[string]encEncryptionKeyRotation {
	result := make(map[string]encEncryptionKeyRotation, len(records))

	for _, record := range records {
		result[record.Table] = record
	}

	return result
}

func insertRotationRecord(t *testing.T, provider *SQLiteProvider, ctx context.Context, fingerprint, table string, total int, checksum string) {
	t.Helper()

	query := provider.db.Rebind(fmt.Sprintf(queryFmtInsertEncryptionKeyRotation, tableEncryptionKeyRotation))

	_, err := provider.db.ExecContext(ctx, query, fingerprint, table, total, checksum, time.Now().UTC())
	require.NoError(t, err)
}

func saveRotationTOTP(t *testing.T, provider *SQLiteProvider, ctx context.Context, username, secret string) {
	t.Helper()

	require.NoError(t, provider.SaveTOTPConfiguration(ctx, model.TOTPConfiguration{
		CreatedAt: time.Now().Truncate(time.Second),
		Username:  username,
		Issuer:    "Authelia",
		Algorithm: "SHA1",
		Digits:    6,
		Period:    30,
		Secret:    []byte(secret),
	}))
}

func TestSchemaEncryptionChangeKeyResumableRecordsLedger(t *testing.T) {
	provider := newTestSQLiteProviderWithEncryption(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	seedAllEncryptedData(t, provider, ctx)

	require.NoError(t, provider.SchemaEncryptionChangeKey(ctx, testRotationNewKey))

	records := loadRotationRecords(t, provider, ctx)

	tables := rotationDataTables()

	require.Len(t, records, len(tables)+1)

	ledger := rotationRecordMap(records)

	// Every data table carrying data records a non zero count and a keyed checksum.
	for _, expected := range []string{tableOneTimeCode, tableTOTPConfigurations, tableWebAuthnCredentials, tableCachedData, tableOAuth2AccessTokenSession} {
		record, ok := ledger[expected]
		require.True(t, ok, "expected a completion record for table '%s'", expected)
		assert.Positive(t, record.RowsTotal)
		assert.Len(t, record.Checksum, 64)
		assert.Equal(t, rotationFingerprint(rotationTestKey(t, testRotationNewKey)), record.KeyFingerprint)
	}

	// The encryption table holding the key related records is the final marker.
	marker, ok := ledger[tableEncryption]
	require.True(t, ok)
	assert.Positive(t, marker.RowsTotal)
	assert.Len(t, marker.Checksum, 64)

	// The check value can only be decrypted with the new key after completion.
	newKey := rotationTestKey(t, testRotationNewKey)

	var checkValue []byte

	require.NoError(t, provider.db.GetContext(ctx, &checkValue, provider.sqlSelectEncryptionValue, encryptionNameCheck))

	_, err := utils.Decrypt(checkValue, aadForSchemaVersion(schemaVersionEncryptionKeyRotation).Get(tableEncryption, columnValue, encryptionNameCheck), newKey)
	assert.NoError(t, err)
}

func TestSchemaEncryptionChangeKeyResumableReopensWithNewKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite3")

	newProvider := func(key string) *SQLiteProvider {
		config := &schema.Configuration{
			Storage: schema.Storage{
				EncryptionKey: key,
				Local:         &schema.StorageLocal{Path: path},
			},
		}

		provider, err := NewSQLiteProvider(config)
		require.NoError(t, err)

		return provider
	}

	ctx := context.Background()

	old := newProvider(testRotationOldKey)
	require.NoError(t, old.StartupCheck())

	seedAllEncryptedData(t, old, ctx)

	require.NoError(t, old.SchemaEncryptionChangeKey(ctx, testRotationNewKey))
	require.NoError(t, old.Close())

	newP := newProvider(testRotationNewKey)
	require.NoError(t, newP.StartupCheck())

	result, err := newP.SchemaEncryptionCheckKey(ctx, true)
	require.NoError(t, err)
	assert.True(t, result.Success())

	totp, err := newP.LoadTOTPConfiguration(ctx, "john")
	require.NoError(t, err)
	assert.Equal(t, []byte("JBSWY3DPEHPK3PXP"), totp.Secret)

	require.NoError(t, newP.Close())
}

func TestSchemaEncryptionChangeKeyResumesWithinPartiallyRotatedTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite3")

	provider := rotationProviderAtPath(t, path, testRotationOldKey)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	// Two rows in the same table simulate a crash after one row was re-encrypted but before the table was recorded.
	saveRotationTOTP(t, provider, ctx, "john", "JBSWY3DPEHPK3PXP")
	saveRotationTOTP(t, provider, ctx, "harry", "HARY0000000000000000000")

	var row struct {
		ID     int    `db:"id"`
		Secret []byte `db:"secret"`
	}

	require.NoError(t, provider.db.GetContext(ctx, &row, fmt.Sprintf("SELECT id, secret FROM %s WHERE username = ?", tableTOTPConfigurations), "harry"))

	newKey := rotationTestKey(t, testRotationNewKey)

	plaintext, err := utils.Decrypt(row.Secret, aadRow.Get(tableTOTPConfigurations, columnSecret, "harry"), provider.keys.encryption)
	require.NoError(t, err)

	reencrypted, err := utils.Encrypt(plaintext, aadRow.Get(tableTOTPConfigurations, columnSecret, "harry"), newKey)
	require.NoError(t, err)

	_, err = provider.db.ExecContext(ctx, provider.db.Rebind(fmt.Sprintf(queryFmtUpdateTOTPConfigurationEncryptedData, tableTOTPConfigurations)), reencrypted, row.ID)
	require.NoError(t, err)

	// No ledger records exist yet so both rows are revisited: harry is detected as already migrated, john migrates.
	require.NoError(t, provider.SchemaEncryptionChangeKey(ctx, testRotationNewKey))

	records := rotationRecordMap(loadRotationRecords(t, provider, ctx))

	record, ok := records[tableTOTPConfigurations]
	require.True(t, ok)
	assert.Equal(t, 2, record.RowsTotal)

	require.NoError(t, provider.Close())

	// Both rows must be readable when the process restarts configured with the new key.
	finished := rotationProviderAtPath(t, path, testRotationNewKey)
	require.NoError(t, finished.StartupCheck())

	john, err := finished.LoadTOTPConfiguration(ctx, "john")
	require.NoError(t, err)
	assert.Equal(t, []byte("JBSWY3DPEHPK3PXP"), john.Secret)

	harry, err := finished.LoadTOTPConfiguration(ctx, "harry")
	require.NoError(t, err)
	assert.Equal(t, []byte("HARY0000000000000000000"), harry.Secret)

	require.NoError(t, finished.Close())
}

func TestSchemaEncryptionChangeKeySkipsCompletedTable(t *testing.T) {
	provider := newTestSQLiteProviderWithEncryption(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	saveRotationTOTP(t, provider, ctx, "john", "JBSWY3DPEHPK3PXP")

	newKey := rotationTestKey(t, testRotationNewKey)

	// The one time-code table is empty and recorded as already complete using the checksum an empty table produces.
	insertRotationRecord(t, provider, ctx, rotationFingerprint(newKey), tableOneTimeCode, 0, newRotationChecksum(newKey, tableOneTimeCode).hex())

	require.NoError(t, provider.SchemaEncryptionChangeKey(ctx, testRotationNewKey))

	records := rotationRecordMap(loadRotationRecords(t, provider, ctx))

	require.Contains(t, records, tableOneTimeCode)
	assert.Equal(t, 0, records[tableOneTimeCode].RowsTotal)
	assert.Contains(t, records, tableTOTPConfigurations)
	assert.Contains(t, records, tableEncryption)
}

func TestSchemaEncryptionChangeKeyIsIdempotentAfterCompletion(t *testing.T) {
	provider := newTestSQLiteProviderWithEncryption(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	seedAllEncryptedData(t, provider, ctx)

	require.NoError(t, provider.SchemaEncryptionChangeKey(ctx, testRotationNewKey))

	first := loadRotationRecords(t, provider, ctx)

	// Re-running with the same new key must not error and must not mutate the completion records.
	require.NoError(t, provider.SchemaEncryptionChangeKey(ctx, testRotationNewKey))

	second := loadRotationRecords(t, provider, ctx)

	assert.Equal(t, first, second)
}

func TestSchemaEncryptionChangeKeyRejectsInterruptedRotationToOtherKey(t *testing.T) {
	provider := newTestSQLiteProviderWithEncryption(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	saveRotationTOTP(t, provider, ctx, "john", "JBSWY3DPEHPK3PXP")

	insertRotationRecord(t, provider, ctx, strings.Repeat("a", 64), tableTOTPConfigurations, 1, strings.Repeat("b", 64))

	err := provider.SchemaEncryptionChangeKey(ctx, testRotationNewKey)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSchemaEncryptionRotationInProgress)

	// Nothing was rotated for the rejected rotation.
	records := loadRotationRecords(t, provider, ctx)
	for _, record := range records {
		assert.NotEqual(t, rotationFingerprint(rotationTestKey(t, testRotationNewKey)), record.KeyFingerprint)
	}
}

func TestSchemaEncryptionChangeKeyFailsVerificationOnChecksumMismatch(t *testing.T) {
	provider := newTestSQLiteProviderWithEncryption(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	seedAllEncryptedData(t, provider, ctx)

	require.NoError(t, provider.SchemaEncryptionChangeKey(ctx, testRotationNewKey))

	// Tamper with the recorded checksum as if the ledger was altered after completion.
	_, err := provider.db.ExecContext(ctx, fmt.Sprintf("UPDATE %s SET checksum = ? WHERE table_name = ?", tableEncryptionKeyRotation), strings.Repeat("c", 64), tableTOTPConfigurations)
	require.NoError(t, err)

	err = provider.SchemaEncryptionChangeKey(ctx, testRotationNewKey)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSchemaEncryptionRotationVerification)
	assert.Contains(t, err.Error(), tableTOTPConfigurations)
}

func TestSchemaEncryptionChangeKeyCorruptRowIsNotHalfEncryptedAndResumes(t *testing.T) {
	provider := newTestSQLiteProviderWithEncryption(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	saveRotationTOTP(t, provider, ctx, "john", "JBSWY3DPEHPK3PXP")
	saveRotationTOTP(t, provider, ctx, "harry", "HARY0000000000000000000")

	_, err := provider.db.ExecContext(ctx, fmt.Sprintf("UPDATE %s SET %s = ? WHERE username = ?", tableTOTPConfigurations, columnSecret), []byte("this-is-not-valid-ciphertext"), "harry")
	require.NoError(t, err)

	err = provider.SchemaEncryptionChangeKey(ctx, testRotationNewKey)
	assert.EqualError(t, err, "error changing the storage encryption key: error decrypting TOTP configuration secret with id '2': cipher: message authentication failed")

	// The corrupt value is untouched and the table was not recorded as complete, nor were the key records switched.
	var secret []byte

	require.NoError(t, provider.db.GetContext(ctx, &secret, fmt.Sprintf("SELECT %s FROM %s WHERE username = ?", columnSecret, tableTOTPConfigurations), "harry"))
	assert.Equal(t, []byte("this-is-not-valid-ciphertext"), secret)

	records := rotationRecordMap(loadRotationRecords(t, provider, ctx))
	assert.NotContains(t, records, tableTOTPConfigurations)
	assert.NotContains(t, records, tableEncryption)

	// Restore the row encrypted with the old key and resume: the empty tables recorded earlier are skipped.
	oldCiphertext, err := utils.Encrypt([]byte("HARY0000000000000000000"), aadRow.Get(tableTOTPConfigurations, columnSecret, "harry"), provider.keys.encryption)
	require.NoError(t, err)

	_, err = provider.db.ExecContext(ctx, provider.db.Rebind(fmt.Sprintf(queryFmtUpdateTOTPConfigurationEncryptedData, tableTOTPConfigurations)), oldCiphertext, 2)
	require.NoError(t, err)

	require.NoError(t, provider.SchemaEncryptionChangeKey(ctx, testRotationNewKey))

	records = rotationRecordMap(loadRotationRecords(t, provider, ctx))
	assert.Contains(t, records, tableTOTPConfigurations)
	assert.Contains(t, records, tableEncryption)
}

func TestSchemaEncryptionChangeKeyRotatesManyRowsInBatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite3")

	provider := rotationProviderAtPath(t, path, testRotationOldKey)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	const total = 250

	for i := 0; i < total; i++ {
		saveRotationTOTP(t, provider, ctx, fmt.Sprintf("user-%03d", i), fmt.Sprintf("secret-%03d-secret-value-000", i))
	}

	require.NoError(t, provider.SchemaEncryptionChangeKey(ctx, testRotationNewKey))

	records := rotationRecordMap(loadRotationRecords(t, provider, ctx))

	record, ok := records[tableTOTPConfigurations]
	require.True(t, ok)
	assert.Equal(t, total, record.RowsTotal)

	// A verification pass with the new key recomputes the identical count and checksum.
	newKey := rotationTestKey(t, testRotationNewKey)

	got, digest, err := provider.rotationReencryptTOTP(ctx, newKey, newKey, aadRow)
	require.NoError(t, err)
	assert.Equal(t, total, got)
	assert.Equal(t, record.Checksum, digest)

	require.NoError(t, provider.Close())

	// Every row must be readable in pages once the process is configured with the new key.
	finished := rotationProviderAtPath(t, path, testRotationNewKey)
	require.NoError(t, finished.StartupCheck())

	loaded := 0

	for page := 0; loaded < total; page++ {
		configs, err := finished.LoadTOTPConfigurations(ctx, 100, page)
		require.NoError(t, err)

		if len(configs) == 0 {
			break
		}

		loaded += len(configs)
	}

	assert.Equal(t, total, loaded)

	require.NoError(t, finished.Close())
}

func TestSchemaEncryptionChangeKeyResumeWithAcrossProviderBatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite3")

	newProvider := func(key string) *SQLiteProvider {
		config := &schema.Configuration{
			Storage: schema.Storage{
				EncryptionKey: key,
				Local:         &schema.StorageLocal{Path: path},
			},
		}

		provider, err := NewSQLiteProvider(config)
		require.NoError(t, err)

		return provider
	}

	ctx := context.Background()

	old := newProvider(testRotationOldKey)
	require.NoError(t, old.StartupCheck())

	const total = 250

	for i := 0; i < total; i++ {
		saveRotationTOTP(t, old, ctx, fmt.Sprintf("user-%03d", i), fmt.Sprintf("secret-%03d-secret-value-000", i))
	}

	// Simulate a restart after the first batch was committed but before the table completion record was written by
	// re-encrypting the first batch directly with the new key without recording anything.
	newKey := rotationTestKey(t, testRotationNewKey)

	var rows []encTOTPConfiguration

	query := old.db.Rebind(fmt.Sprintf(queryFmtSelectTOTPConfigurationsEncryptedDataBatch, tableTOTPConfigurations))

	require.NoError(t, old.db.SelectContext(ctx, &rows, query, 0, rotationBatchSize))
	require.Len(t, rows, rotationBatchSize)

	updateQuery := old.db.Rebind(fmt.Sprintf(queryFmtUpdateTOTPConfigurationEncryptedData, tableTOTPConfigurations))

	for _, row := range rows {
		plaintext, err := utils.Decrypt(row.Secret, aadRow.Get(tableTOTPConfigurations, columnSecret, row.Username), old.keys.encryption)
		require.NoError(t, err)

		value, err := utils.Encrypt(plaintext, aadRow.Get(tableTOTPConfigurations, columnSecret, row.Username), newKey)
		require.NoError(t, err)

		_, err = old.db.ExecContext(ctx, updateQuery, value, row.ID)
		require.NoError(t, err)
	}

	require.NoError(t, old.Close())

	// A new process, configured with the old key, resumes and completes the rotation using the same new key value.
	resumed := newProvider(testRotationOldKey)
	require.NoError(t, resumed.StartupCheck())

	require.NoError(t, resumed.SchemaEncryptionChangeKey(ctx, testRotationNewKey))
	require.NoError(t, resumed.Close())

	finished := newProvider(testRotationNewKey)
	require.NoError(t, finished.StartupCheck())

	check, err := finished.SchemaEncryptionCheckKey(ctx, true)
	require.NoError(t, err)
	assert.True(t, check.Success())

	configs, err := finished.LoadTOTPConfigurations(ctx, total, 0)
	require.NoError(t, err)
	assert.Len(t, configs, total)

	require.NoError(t, finished.Close())
}
