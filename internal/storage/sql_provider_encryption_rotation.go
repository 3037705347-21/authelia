// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"sort"
	"strings"
	"time"

	"github.com/authelia/authelia/v4/internal/utils"
)

// rotationTableKind identifies a table re-encrypted as part of an encryption key rotation.
type rotationTableKind int

const (
	rotationTableKindOneTimeCode rotationTableKind = iota
	rotationTableKindTOTP
	rotationTableKindWebAuthn
	rotationTableKindCachedData
	rotationTableKindOpenIDConnect
	rotationTableKindEncryption
)

// rotationTable describes a table taking part in an encryption key rotation.
type rotationTable struct {
	kind    rotationTableKind
	name    string
	session OAuth2SessionType
}

// rotationDataTables returns the data tables re-encrypted during a key rotation in the order they are processed.
// The encryption table, which holds the key related records, is intentionally excluded as it is switched last.
func rotationDataTables() (tables []rotationTable) {
	tables = []rotationTable{
		{kind: rotationTableKindOneTimeCode, name: tableOneTimeCode},
		{kind: rotationTableKindTOTP, name: tableTOTPConfigurations},
		{kind: rotationTableKindWebAuthn, name: tableWebAuthnCredentials},
		{kind: rotationTableKindCachedData, name: tableCachedData},
	}

	for i := 0; true; i++ {
		typeOAuth2Session := OAuth2SessionType(i)

		if typeOAuth2Session.Table() == "" {
			break
		}

		tables = append(tables, rotationTable{kind: rotationTableKindOpenIDConnect, name: typeOAuth2Session.Table(), session: typeOAuth2Session})
	}

	return tables
}

// rotationFingerprint returns a stable identifier of a derived encryption key allowing interrupted rotations to be
// resumed when the same new key is provided.
func rotationFingerprint(key []byte) string {
	digest := sha256.Sum256(key)

	return hex.EncodeToString(digest[:])
}

// rotationChecksum is a keyed checksum over the plaintext values re-encrypted for a table. It can only be
// recomputed by a party in possession of the new encryption key, which means storing it does not provide an offline
// guessing oracle for the encrypted values.
type rotationChecksum struct {
	h hash.Hash
}

func newRotationChecksum(key []byte, table string) *rotationChecksum {
	c := &rotationChecksum{h: hmac.New(sha256.New, key)}

	c.write(table)

	return c
}

func (c *rotationChecksum) write(value string) {
	var prefix [4]byte

	binary.BigEndian.PutUint32(prefix[:], uint32(len(value)))

	c.h.Write(prefix[:])
	c.h.Write([]byte(value))
}

// column feeds a single encrypted column value to the checksum. Columns are fed in a fixed order.
func (c *rotationChecksum) column(column string, value []byte) {
	c.write(column)

	var prefix [4]byte

	binary.BigEndian.PutUint32(prefix[:], uint32(len(value)))

	c.h.Write(prefix[:])
	c.h.Write(value)
}

func (c *rotationChecksum) hex() string {
	return hex.EncodeToString(c.h.Sum(nil))
}

// rotationReencryptValue decrypts value with oldKey and re-encrypts it with newKey. When the value is already
// encrypted with newKey it returns the plaintext and already is true so the caller can leave the row untouched. A
// row which neither key can decrypt returns the original decryption error without performing any write, ensuring no
// half-encrypted row is ever left behind. When oldKey and newKey are equal (the verification pass) it decrypts but
// never re-encrypts or rewrites the value.
func rotationReencryptValue(value, aad, oldKey, newKey []byte) (plaintext, reencrypted []byte, already bool, err error) {
	if plaintext, err = utils.Decrypt(value, aad, oldKey); err != nil {
		oldErr := err

		if bytes.Equal(oldKey, newKey) {
			return nil, nil, false, oldErr
		}

		if plaintext, err = utils.Decrypt(value, aad, newKey); err == nil {
			return plaintext, nil, true, nil
		}

		return nil, nil, false, oldErr
	}

	if bytes.Equal(oldKey, newKey) {
		return plaintext, nil, true, nil
	}

	reencrypted, err = utils.Encrypt(plaintext, aad, newKey)

	return plaintext, reencrypted, false, err
}

// rotationBatch lazily starts a short lived transaction for the rows in a batch that require updating. Batches
// consisting entirely of rows already re-encrypted with the new key never open a transaction.
type rotationBatch struct {
	p   *SQLProvider
	ctx context.Context
	tx  SQLXTx
}

func (p *SQLProvider) newRotationBatch(ctx context.Context) *rotationBatch {
	return &rotationBatch{p: p, ctx: ctx}
}

func (b *rotationBatch) ensure() (conn SQLXConnection, err error) {
	if b.tx == nil {
		if b.tx, err = b.p.db.BeginTxx(b.ctx, nil); err != nil {
			return nil, fmt.Errorf("error beginning transaction to change encryption key: %w", err)
		}
	}

	return b.tx, nil
}

func (b *rotationBatch) exec(query string, args ...any) (err error) {
	var conn SQLXConnection

	if conn, err = b.ensure(); err != nil {
		return err
	}

	if _, err = conn.ExecContext(b.ctx, query, args...); err != nil {
		return err
	}

	return nil
}

func (b *rotationBatch) commit() (err error) {
	if b.tx == nil {
		return nil
	}

	if err = b.tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction to change encryption key: %w", err)
	}

	return nil
}

func (b *rotationBatch) rollback() {
	if b.tx != nil {
		_ = b.tx.Rollback()
	}
}

// schemaEncryptionChangeKeyResumable re-encrypts the data tables with the new key one batch at a time, recording each
// completed table in the rotation ledger so the operation can safely be resumed after an interruption. The encryption
// table holding the key related records is only switched once every data table is complete, and the new key is
// verified against all tables before the operation returns.
func (p *SQLProvider) schemaEncryptionChangeKeyResumable(ctx context.Context, newKey []byte, aad EncryptionAAD) (err error) {
	fingerprint := rotationFingerprint(newKey)

	var ledger map[string]map[string]encEncryptionKeyRotation

	if ledger, err = p.rotationLoadLedger(ctx); err != nil {
		return err
	}

	completed := ledger[fingerprint]

	if _, ok := completed[tableEncryption]; ok {
		p.log.Infof("Encryption key rotation to key '%s' is already complete, verifying it instead", fingerprint)

		return p.rotationVerify(ctx, newKey, aad, fingerprint, completed)
	}

	otherFingerprints := make([]string, 0)

	for otherFingerprint, tables := range ledger {
		if otherFingerprint == fingerprint {
			continue
		}

		if _, ok := tables[tableEncryption]; !ok {
			otherFingerprints = append(otherFingerprints, otherFingerprint)
		}
	}

	if len(otherFingerprints) != 0 {
		sort.Strings(otherFingerprints)

		return fmt.Errorf("%w: interrupted new key fingerprint '%s'", ErrSchemaEncryptionRotationInProgress, otherFingerprints[0])
	}

	tables := rotationDataTables()

	if len(completed) != 0 {
		p.log.Infof(logFmtEncryptionRotationResume, len(completed), len(tables)+1)
	}

	for _, table := range tables {
		if record, ok := completed[table.name]; ok {
			p.log.Infof(logFmtEncryptionRotationTableSkip, table.name, record.RowsTotal)

			continue
		}

		var (
			total  int
			digest string
		)

		if total, digest, err = p.rotationReencryptDataTable(ctx, table, p.keys.encryption, newKey, aad); err != nil {
			return err
		}

		if err = p.rotationSaveDataTable(ctx, fingerprint, table.name, total, digest); err != nil {
			return err
		}
	}

	p.log.Info(logFmtEncryptionRotationFinalize)

	var tx SQLXTx

	if tx, err = p.db.BeginTxx(ctx, nil); err != nil {
		return fmt.Errorf("error beginning transaction to change encryption key: %w", err)
	}

	var total int

	var digest string

	if total, digest, err = p.rotationReencryptEncryption(ctx, tx, p.keys.encryption, newKey, aad); err != nil {
		_ = tx.Rollback()

		return err
	}

	if err = p.rotationMarkComplete(ctx, tx, fingerprint, tableEncryption, total, digest); err != nil {
		_ = tx.Rollback()

		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction to change encryption key: %w", err)
	}

	if err = p.rotationVerify(ctx, newKey, aad, fingerprint, nil); err != nil {
		return err
	}

	p.log.Infof(logFmtEncryptionRotationComplete, len(tables)+1)

	return nil
}

func (p *SQLProvider) rotationLoadLedger(ctx context.Context) (ledger map[string]map[string]encEncryptionKeyRotation, err error) {
	query := p.db.Rebind(fmt.Sprintf(queryFmtSelectEncryptionKeyRotation, tableEncryptionKeyRotation))

	var records []encEncryptionKeyRotation

	if err = p.db.SelectContext(ctx, &records, query); err != nil {
		return nil, fmt.Errorf("error loading the encryption key rotation progress: %w", err)
	}

	ledger = make(map[string]map[string]encEncryptionKeyRotation)

	for _, record := range records {
		if _, ok := ledger[record.KeyFingerprint]; !ok {
			ledger[record.KeyFingerprint] = make(map[string]encEncryptionKeyRotation)
		}

		ledger[record.KeyFingerprint][record.Table] = record
	}

	return ledger, nil
}

func (p *SQLProvider) rotationMarkComplete(ctx context.Context, conn SQLXConnection, fingerprint, table string, total int, digest string) (err error) {
	query := conn.Rebind(fmt.Sprintf(queryFmtInsertEncryptionKeyRotation, tableEncryptionKeyRotation))

	if _, err = conn.ExecContext(ctx, query, fingerprint, table, total, digest, time.Now().UTC()); err != nil {
		return fmt.Errorf("error recording the encryption key rotation progress for table '%s': %w", table, err)
	}

	return nil
}

func (p *SQLProvider) rotationSaveDataTable(ctx context.Context, fingerprint, table string, total int, digest string) (err error) {
	var tx SQLXTx

	if tx, err = p.db.BeginTxx(ctx, nil); err != nil {
		return fmt.Errorf("error beginning transaction to change encryption key: %w", err)
	}

	if err = p.rotationMarkComplete(ctx, tx, fingerprint, table, total, digest); err != nil {
		_ = tx.Rollback()

		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction to change encryption key: %w", err)
	}

	return nil
}

// rotationReencryptDataTable re-encrypts every encrypted value of a data table with the new key using short batch
// transactions. Values already encrypted with the new key are detected and left untouched which makes this safe to
// re-run after an interruption. The returned total and digest cover every value that can be decrypted and are
// identical when invoked again with oldKey equal to newKey for verification.
func (p *SQLProvider) rotationReencryptDataTable(ctx context.Context, table rotationTable, oldKey, newKey []byte, aad EncryptionAAD) (total int, digest string, err error) {
	switch table.kind {
	case rotationTableKindOneTimeCode:
		return p.rotationReencryptOneTimeCode(ctx, oldKey, newKey, aad)
	case rotationTableKindTOTP:
		return p.rotationReencryptTOTP(ctx, oldKey, newKey, aad)
	case rotationTableKindWebAuthn:
		return p.rotationReencryptWebAuthn(ctx, oldKey, newKey, aad)
	case rotationTableKindCachedData:
		return p.rotationReencryptCachedData(ctx, oldKey, newKey, aad)
	case rotationTableKindOpenIDConnect:
		return p.rotationReencryptOpenIDConnect(table.session)(ctx, oldKey, newKey, aad)
	default:
		return 0, "", fmt.Errorf("unknown encryption key rotation table '%s'", table.name)
	}
}

func (p *SQLProvider) rotationReencryptOneTimeCode(ctx context.Context, oldKey, newKey []byte, aad EncryptionAAD) (total int, digest string, err error) {
	table := tableOneTimeCode

	var count int

	if err = p.db.GetContext(ctx, &count, fmt.Sprintf(queryFmtSelectRowCount, table)); err != nil {
		return 0, "", err
	}

	cs := newRotationChecksum(newKey, table)

	if count != 0 {
		selectQuery := p.db.Rebind(fmt.Sprintf(queryFmtSelectOTCEncryptedDataBatch, table))
		updateQuery := p.db.Rebind(fmt.Sprintf(queryFmtUpdateOTCEncryptedData, table))

		lastID := 0

		for {
			var rows []encOneTimeCode

			if err = p.db.SelectContext(ctx, &rows, selectQuery, lastID, rotationBatchSize); err != nil {
				return 0, "", fmt.Errorf("error selecting one-time codes: %w", err)
			}

			if len(rows) == 0 {
				break
			}

			batch := p.newRotationBatch(ctx)

			for _, row := range rows {
				plaintext, value, already, derr := rotationReencryptValue(row.Code, aad.Get(table, columnCode, row.Signature), oldKey, newKey)
				if derr != nil {
					batch.rollback()

					return 0, "", fmt.Errorf("error decrypting one-time code with id '%d': %w", row.ID, derr)
				}

				cs.column(columnCode, plaintext)

				total++

				if !already {
					if err = batch.exec(updateQuery, value, row.ID); err != nil {
						batch.rollback()

						return 0, "", fmt.Errorf("error updating one-time code with id '%d': %w", row.ID, err)
					}
				}
			}

			if err = batch.commit(); err != nil {
				return 0, "", err
			}

			lastID = rows[len(rows)-1].ID

			p.log.Debugf(logFmtEncryptionRotationTableProgress, total, count, table)

			if len(rows) < rotationBatchSize {
				break
			}
		}
	}

	p.log.Debugf(logFmtEncryptionChangeKeyTableComplete, total, table)

	return total, cs.hex(), nil
}

func (p *SQLProvider) rotationReencryptTOTP(ctx context.Context, oldKey, newKey []byte, aad EncryptionAAD) (total int, digest string, err error) {
	table := tableTOTPConfigurations

	var count int

	if err = p.db.GetContext(ctx, &count, fmt.Sprintf(queryFmtSelectRowCount, table)); err != nil {
		return 0, "", err
	}

	cs := newRotationChecksum(newKey, table)

	if count != 0 {
		selectQuery := p.db.Rebind(fmt.Sprintf(queryFmtSelectTOTPConfigurationsEncryptedDataBatch, table))
		updateQuery := p.db.Rebind(fmt.Sprintf(queryFmtUpdateTOTPConfigurationEncryptedData, table))

		lastID := 0

		for {
			var rows []encTOTPConfiguration

			if err = p.db.SelectContext(ctx, &rows, selectQuery, lastID, rotationBatchSize); err != nil {
				return 0, "", fmt.Errorf("error selecting TOTP configurations: %w", err)
			}

			if len(rows) == 0 {
				break
			}

			batch := p.newRotationBatch(ctx)

			for _, row := range rows {
				plaintext, value, already, derr := rotationReencryptValue(row.Secret, aad.Get(table, columnSecret, row.Username), oldKey, newKey)
				if derr != nil {
					batch.rollback()

					return 0, "", fmt.Errorf("error decrypting TOTP configuration secret with id '%d': %w", row.ID, derr)
				}

				cs.column(columnSecret, plaintext)

				total++

				if !already {
					if err = batch.exec(updateQuery, value, row.ID); err != nil {
						batch.rollback()

						return 0, "", fmt.Errorf("error updating TOTP configuration secret with id '%d': %w", row.ID, err)
					}
				}
			}

			if err = batch.commit(); err != nil {
				return 0, "", err
			}

			lastID = rows[len(rows)-1].ID

			p.log.Debugf(logFmtEncryptionRotationTableProgress, total, count, table)

			if len(rows) < rotationBatchSize {
				break
			}
		}
	}

	p.log.Debugf(logFmtEncryptionChangeKeyTableComplete, total, table)

	return total, cs.hex(), nil
}

func (p *SQLProvider) rotationReencryptWebAuthn(ctx context.Context, oldKey, newKey []byte, aad EncryptionAAD) (total int, digest string, err error) {
	table := tableWebAuthnCredentials

	var count int

	if err = p.db.GetContext(ctx, &count, fmt.Sprintf(queryFmtSelectRowCount, table)); err != nil {
		return 0, "", err
	}

	cs := newRotationChecksum(newKey, table)

	if count != 0 {
		selectQuery := p.db.Rebind(fmt.Sprintf(queryFmtSelectWebAuthnCredentialsEncryptedDataBatch, table))
		updateQuery := p.db.Rebind(fmt.Sprintf(queryFmtUpdateWebAuthnCredentialsEncryptedData, table))

		lastID := 0

		for {
			var rows []encWebAuthnCredential

			if err = p.db.SelectContext(ctx, &rows, selectQuery, lastID, rotationBatchSize); err != nil {
				return 0, "", fmt.Errorf("error selecting WebAuthn credentials: %w", err)
			}

			if len(rows) == 0 {
				break
			}

			batch := p.newRotationBatch(ctx)

			for _, row := range rows {
				plaintext, value, already, derr := rotationReencryptValue(row.PublicKey, aad.GetIssuer(table, "public_key", row.KID, row.RPID), oldKey, newKey)
				if derr != nil {
					batch.rollback()

					return 0, "", fmt.Errorf("error decrypting WebAuthn credential public key with id '%d': %w", row.ID, derr)
				}

				cs.column("public_key", plaintext)

				total++

				changed := false

				if !already {
					row.PublicKey = value

					changed = true
				}

				if row.Attestation != nil {
					var attestationPlaintext, attestationValue []byte

					var attestationAlready bool

					if attestationPlaintext, attestationValue, attestationAlready, derr = rotationReencryptValue(row.Attestation, aad.GetIssuer(table, "attestation", row.KID, row.RPID), oldKey, newKey); derr != nil {
						batch.rollback()

						return 0, "", fmt.Errorf("error decrypting WebAuthn credential attestation with id '%d': %w", row.ID, derr)
					}

					cs.column("attestation", attestationPlaintext)

					if !attestationAlready {
						row.Attestation = attestationValue

						changed = true
					}
				}

				if changed {
					if err = batch.exec(updateQuery, row.PublicKey, row.Attestation, row.ID); err != nil {
						batch.rollback()

						return 0, "", fmt.Errorf("error updating WebAuthn credential encrypted columns with id '%d': %w", row.ID, err)
					}
				}
			}

			if err = batch.commit(); err != nil {
				return 0, "", err
			}

			lastID = rows[len(rows)-1].ID

			p.log.Debugf(logFmtEncryptionRotationTableProgress, total, count, table)

			if len(rows) < rotationBatchSize {
				break
			}
		}
	}

	p.log.Debugf(logFmtEncryptionChangeKeyTableComplete, total, table)

	return total, cs.hex(), nil
}

func (p *SQLProvider) rotationReencryptCachedData(ctx context.Context, oldKey, newKey []byte, aad EncryptionAAD) (total int, digest string, err error) {
	table := tableCachedData

	cs := newRotationChecksum(newKey, table)

	selectQuery := p.db.Rebind(fmt.Sprintf(queryFmtSelectCachedDataValueEncryptedBatch, table))
	updateQuery := p.db.Rebind(fmt.Sprintf(queryFmtUpdateCachedDataEncryptedData, table))

	lastID := 0

	for {
		var rows []encCachedData

		if err = p.db.SelectContext(ctx, &rows, selectQuery, true, lastID, rotationBatchSize); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, cs.hex(), nil
			}

			return 0, "", fmt.Errorf("error selecting cached data: %w", err)
		}

		if len(rows) == 0 {
			break
		}

		batch := p.newRotationBatch(ctx)

		for _, row := range rows {
			if len(row.Value) == 0 {
				continue
			}

			plaintext, value, already, derr := rotationReencryptValue(row.Value, aad.Get(table, columnValue, row.Name), oldKey, newKey)
			if derr != nil {
				batch.rollback()

				return 0, "", fmt.Errorf("error decrypting cached data value id '%d': %w", row.ID, derr)
			}

			cs.column(columnValue, plaintext)

			total++

			if !already {
				if err = batch.exec(updateQuery, value, row.ID); err != nil {
					batch.rollback()

					return 0, "", fmt.Errorf("error updating cached data encrypted columns with id '%d': %w", row.ID, err)
				}
			}
		}

		if err = batch.commit(); err != nil {
			return 0, "", err
		}

		lastID = rows[len(rows)-1].ID

		if len(rows) < rotationBatchSize {
			break
		}
	}

	p.log.Debugf(logFmtEncryptionChangeKeyTableComplete, total, table)

	return total, cs.hex(), nil
}

func (p *SQLProvider) rotationReencryptOpenIDConnect(typeOAuth2Session OAuth2SessionType) func(ctx context.Context, oldKey, newKey []byte, aad EncryptionAAD) (total int, digest string, err error) {
	return func(ctx context.Context, oldKey, newKey []byte, aad EncryptionAAD) (total int, digest string, err error) {
		table := typeOAuth2Session.Table()

		var count int

		if err = p.db.GetContext(ctx, &count, fmt.Sprintf(queryFmtSelectRowCount, table)); err != nil {
			return 0, "", err
		}

		cs := newRotationChecksum(newKey, table)

		if count != 0 {
			selectQuery := p.db.Rebind(fmt.Sprintf(queryFmtSelectOAuth2SessionEncryptedDataBatch, table))
			updateQuery := p.db.Rebind(fmt.Sprintf(queryFmtUpdateOAuth2ConsentSessionEncryptedData, table))

			lastID := 0

			for {
				var rows []encOAuth2Session

				if err = p.db.SelectContext(ctx, &rows, selectQuery, lastID, rotationBatchSize); err != nil {
					return 0, "", fmt.Errorf("error selecting oauth2 %s sessions: %w", typeOAuth2Session.String(), err)
				}

				if len(rows) == 0 {
					break
				}

				batch := p.newRotationBatch(ctx)

				for _, row := range rows {
					plaintext, value, already, derr := rotationReencryptValue(row.Session, aad.Get(typeOAuth2Session.AAD(), columnSessionData, row.Signature), oldKey, newKey)
					if derr != nil {
						batch.rollback()

						return 0, "", fmt.Errorf("error decrypting oauth2 %s session data with id '%d': %w", typeOAuth2Session.String(), row.ID, derr)
					}

					cs.column(columnSessionData, plaintext)

					total++

					if !already {
						if err = batch.exec(updateQuery, value, row.ID); err != nil {
							batch.rollback()

							return 0, "", fmt.Errorf("error updating oauth2 %s session data with id '%d': %w", typeOAuth2Session.String(), row.ID, err)
						}
					}
				}

				if err = batch.commit(); err != nil {
					return 0, "", err
				}

				lastID = rows[len(rows)-1].ID

				p.log.Debugf(logFmtEncryptionRotationTableProgress, total, count, table)

				if len(rows) < rotationBatchSize {
					break
				}
			}
		}

		p.log.Debugf(logFmtEncryptionChangeKeyTableComplete, total, table)

		return total, cs.hex(), nil
	}
}

// rotationReencryptEncryption switches the key related records. It runs on the provided connection so the final
// invocation shares its transaction with the completion marker, guaranteeing the records are only considered switched
// when the switch itself has committed.
func (p *SQLProvider) rotationReencryptEncryption(ctx context.Context, conn SQLXConnection, oldKey, newKey []byte, aad EncryptionAAD) (total int, digest string, err error) {
	table := tableEncryption

	var count int

	if err = conn.GetContext(ctx, &count, fmt.Sprintf(queryFmtSelectRowCount, table)); err != nil {
		return 0, "", err
	}

	cs := newRotationChecksum(newKey, table)

	if count == 0 {
		return 0, cs.hex(), nil
	}

	rows := make([]encEncryption, 0, count)

	if err = conn.SelectContext(ctx, &rows, fmt.Sprintf(queryFmtSelectEncryptionEncryptedData, table)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, cs.hex(), nil
		}

		return 0, "", fmt.Errorf("error selecting encryption value: %w", err)
	}

	query := conn.Rebind(fmt.Sprintf(queryFmtUpdateEncryptionEncryptedData, table))

	for _, row := range rows {
		plaintext, value, already, derr := rotationReencryptValue(row.Value, aad.Get(table, columnValue, row.Name), oldKey, newKey)
		if derr != nil {
			return 0, "", fmt.Errorf("error decrypting encryption value with id '%d': %w", row.ID, derr)
		}

		cs.column(columnValue, plaintext)

		total++

		if !already {
			if _, err = conn.ExecContext(ctx, query, value, row.ID); err != nil {
				return 0, "", fmt.Errorf("error updating encryption value with id '%d': %w", row.ID, err)
			}
		}
	}

	p.log.Debugf(logFmtEncryptionChangeKeyTableComplete, total, table)

	return total, cs.hex(), nil
}

// rotationVerify scans every rotated table with the new key and confirms it decrypts cleanly, that the verbose key
// validation including the encryption check value succeeds, and that the per-table row counts and keyed checksums
// recorded in the ledger match the values computed from the data. This is the evidence the rotation completed
// without leaving any value that can't be decrypted with the new key.
func (p *SQLProvider) rotationVerify(ctx context.Context, newKey []byte, aad EncryptionAAD, fingerprint string, known map[string]encEncryptionKeyRotation) (err error) {
	encryptionKey := p.keys.encryption

	p.keys.encryption = newKey

	defer func() {
		p.keys.encryption = encryptionKey
	}()

	var result EncryptionValidationResult

	if result, err = p.SchemaEncryptionCheckKey(ctx, true); err != nil {
		return fmt.Errorf("%w: %v", ErrSchemaEncryptionRotationVerification, err)
	}

	if !result.Success() {
		if result.InvalidCheckValue {
			return fmt.Errorf("%w: the encryption check value can't be decrypted with the new key", ErrSchemaEncryptionRotationVerification)
		}

		names := make([]string, 0)

		invalid := 0

		for name, table := range result.Tables {
			if table.Invalid != 0 || table.Error != nil {
				names = append(names, name)
				invalid += table.Invalid
			}
		}

		sort.Strings(names)

		return fmt.Errorf("%w: %d row(s) in table(s) %s can't be decrypted with the new key", ErrSchemaEncryptionRotationVerification, invalid, strings.Join(names, ", "))
	}

	if known == nil {
		var ledger map[string]map[string]encEncryptionKeyRotation

		if ledger, err = p.rotationLoadLedger(ctx); err != nil {
			return fmt.Errorf("%w: %v", ErrSchemaEncryptionRotationVerification, err)
		}

		known = ledger[fingerprint]
	}

	tables := rotationDataTables()

	tables = append(tables, rotationTable{kind: rotationTableKindEncryption, name: tableEncryption})

	for _, table := range tables {
		record, ok := known[table.name]
		if !ok {
			return fmt.Errorf("%w: no completion record exists for table '%s'", ErrSchemaEncryptionRotationVerification, table.name)
		}

		var total int

		var digest string

		switch table.kind {
		case rotationTableKindEncryption:
			total, digest, err = p.rotationReencryptEncryption(ctx, p.db, newKey, newKey, aad)
		default:
			total, digest, err = p.rotationReencryptDataTable(ctx, table, newKey, newKey, aad)
		}

		if err != nil {
			return fmt.Errorf("%w: %v", ErrSchemaEncryptionRotationVerification, err)
		}

		if total != record.RowsTotal {
			return fmt.Errorf("%w: table '%s' has %d row(s) but %d were recorded as re-encrypted", ErrSchemaEncryptionRotationVerification, table.name, total, record.RowsTotal)
		}

		if !hmac.Equal([]byte(digest), []byte(record.Checksum)) {
			return fmt.Errorf("%w: table '%s' checksum %s does not match the recorded checksum %s", ErrSchemaEncryptionRotationVerification, table.name, digest, record.Checksum)
		}
	}

	return nil
}
