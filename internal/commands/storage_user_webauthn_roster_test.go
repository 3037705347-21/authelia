// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/storage"
)

const (
	testWebAuthnRosterRPID        = "example.com"
	testWebAuthnRosterProvisioner = "hardware-roster"
)

func newWebAuthnRosterTestStore(t *testing.T) storage.Provider {
	t.Helper()

	config := &schema.Configuration{
		Storage: schema.Storage{
			//gitleaks:allow // This is not an actual secret.
			EncryptionKey: "authelia-test-key-not-a-secret-authelia-test-key-not-a-secret",
			Local: &schema.StorageLocal{
				Path: filepath.Join(t.TempDir(), "db.sqlite3"),
			},
		},
	}

	store, err := storage.NewProvider(config, nil)
	require.NoError(t, err)
	require.NoError(t, store.StartupCheck())

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	return store
}

func testWebAuthnRosterData(kid, publicKey, username, description string) model.WebAuthnCredentialData {
	return model.WebAuthnCredentialData{
		RPID:        testWebAuthnRosterRPID,
		Username:    username,
		Description: description,
		KID:         base64.StdEncoding.EncodeToString([]byte(kid)),
		PublicKey:   base64.StdEncoding.EncodeToString([]byte(publicKey)),
	}
}

func writeWebAuthnRosterFile(t *testing.T, filename string, roster model.WebAuthnCredentialRoster) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), filename)

	data, err := yaml.Marshal(roster)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(path, data, 0600))

	return path
}

func saveWebAuthnTestCredential(t *testing.T, ctx context.Context, store storage.Provider, username, description, kid, provisioner string) {
	t.Helper()

	require.NoError(t, store.SaveWebAuthnCredential(ctx, model.WebAuthnCredential{
		CreatedAt:       time.Now().Truncate(time.Second),
		RPID:            testWebAuthnRosterRPID,
		Username:        username,
		Description:     description,
		Provisioner:     provisioner,
		KID:             model.NewBase64([]byte(kid)),
		AttestationType: "none",
		Attachment:      "cross-platform",
		PublicKey:       []byte("pk-" + kid),
	}))
}

type webAuthnCredentialStateEntry struct {
	username    string
	description string
	provisioner string
}

func webAuthnCredentialState(t *testing.T, ctx context.Context, store storage.Provider) (state map[string]webAuthnCredentialStateEntry) {
	t.Helper()

	credentials, err := loadAllWebAuthnCredentials(ctx, store)
	require.NoError(t, err)

	state = make(map[string]webAuthnCredentialStateEntry, len(credentials))

	for _, credential := range credentials {
		state[credential.KID.String()] = webAuthnCredentialStateEntry{
			username:    credential.Username,
			description: credential.Description,
			provisioner: credential.Provisioner,
		}
	}

	return state
}

func reconcileWebAuthnRoster(t *testing.T, ctx context.Context, store storage.Provider, filename string, dryRun bool) (plan *webAuthnCredentialRosterPlan, output string, err error) {
	t.Helper()

	roster, err := loadWebAuthnCredentialRoster(filename)
	if err != nil {
		return nil, "", err
	}

	if plan, err = planWebAuthnCredentialRoster(ctx, store, roster); err != nil {
		return nil, "", err
	}

	buf := new(bytes.Buffer)

	writeWebAuthnCredentialRosterPlan(buf, plan, dryRun)

	if !dryRun {
		if err = applyWebAuthnCredentialRosterPlan(ctx, buf, store, plan); err != nil {
			return plan, buf.String(), err
		}
	}

	return plan, buf.String(), nil
}

func TestStorageUserWebAuthnRosterInsertsAndPreservesSelfRegistered(t *testing.T) {
	ctx := context.Background()

	store := newWebAuthnRosterTestStore(t)

	saveWebAuthnTestCredential(t, ctx, store, "alice", "my-browser-passkey", "kid-self", "")

	path := writeWebAuthnRosterFile(t, "roster.yml", model.WebAuthnCredentialRoster{
		Provisioner: testWebAuthnRosterProvisioner,
		RPID:        testWebAuthnRosterRPID,
		WebAuthnCredentials: []model.WebAuthnCredentialData{
			testWebAuthnRosterData("kid-a", "pk-kid-a", "alice", "key-a"),
			testWebAuthnRosterData("kid-b", "pk-kid-b", "bob", "key-b"),
		},
	})

	before := webAuthnCredentialState(t, ctx, store)

	plan, output, err := reconcileWebAuthnRoster(t, ctx, store, path, false)
	require.NoError(t, err)
	assert.Equal(t, 2, plan.count(webAuthnCredentialRosterOpInsert))
	assert.Contains(t, output, "Added WebAuthn credential for user 'alice'")

	after := webAuthnCredentialState(t, ctx, store)

	// The two roster credentials are added with the provisioner tag.
	assert.Contains(t, after, model.NewBase64([]byte("kid-a")).String())
	assert.Equal(t, testWebAuthnRosterProvisioner, after[model.NewBase64([]byte("kid-a")).String()].provisioner)
	assert.Contains(t, after, model.NewBase64([]byte("kid-b")).String())

	// The self-registered credential is untouched.
	assert.Equal(t, before[model.NewBase64([]byte("kid-self")).String()], after[model.NewBase64([]byte("kid-self")).String()])
	assert.Equal(t, "", after[model.NewBase64([]byte("kid-self")).String()].provisioner)
}

func TestStorageUserWebAuthnRosterIsIdempotent(t *testing.T) {
	ctx := context.Background()

	store := newWebAuthnRosterTestStore(t)

	roster := model.WebAuthnCredentialRoster{
		Provisioner: testWebAuthnRosterProvisioner,
		RPID:        testWebAuthnRosterRPID,
		WebAuthnCredentials: []model.WebAuthnCredentialData{
			testWebAuthnRosterData("kid-a", "pk-kid-a", "alice", "key-a"),
			testWebAuthnRosterData("kid-b", "pk-kid-b", "bob", "key-b"),
		},
	}

	path := writeWebAuthnRosterFile(t, "roster.yml", roster)

	_, _, err := reconcileWebAuthnRoster(t, ctx, store, path, false)
	require.NoError(t, err)

	first := webAuthnCredentialState(t, ctx, store)

	plan, output, err := reconcileWebAuthnRoster(t, ctx, store, path, false)
	require.NoError(t, err)
	assert.Empty(t, plan.Ops)
	assert.Equal(t, 2, plan.Unchanged)
	assert.Contains(t, output, "No changes required")

	second := webAuthnCredentialState(t, ctx, store)
	assert.Equal(t, first, second)
}

func TestStorageUserWebAuthnRosterUpdatesManagedDescription(t *testing.T) {
	ctx := context.Background()

	store := newWebAuthnRosterTestStore(t)

	saveWebAuthnTestCredential(t, ctx, store, "alice", "old-desc", "kid-a", testWebAuthnRosterProvisioner)
	saveWebAuthnTestCredential(t, ctx, store, "alice", "keep-passkey", "kid-self", "")

	roster := model.WebAuthnCredentialRoster{
		Provisioner: testWebAuthnRosterProvisioner,
		RPID:        testWebAuthnRosterRPID,
		WebAuthnCredentials: []model.WebAuthnCredentialData{
			testWebAuthnRosterData("kid-a", "pk-kid-a", "alice", "new-desc"),
		},
	}

	path := writeWebAuthnRosterFile(t, "roster.yml", roster)

	plan, _, err := reconcileWebAuthnRoster(t, ctx, store, path, false)
	require.NoError(t, err)
	require.Len(t, plan.Ops, 1)
	assert.Equal(t, webAuthnCredentialRosterOpUpdate, plan.Ops[0].Type)
	assert.Equal(t, "old-desc", plan.Ops[0].OldDescription)

	state := webAuthnCredentialState(t, ctx, store)

	assert.Equal(t, "new-desc", state[model.NewBase64([]byte("kid-a")).String()].description)
	assert.Equal(t, "keep-passkey", state[model.NewBase64([]byte("kid-self")).String()].description)
}

func TestStorageUserWebAuthnRosterRevokesAbsentManagedCredentials(t *testing.T) {
	ctx := context.Background()

	store := newWebAuthnRosterTestStore(t)

	saveWebAuthnTestCredential(t, ctx, store, "alice", "key-a", "kid-a", testWebAuthnRosterProvisioner)
	saveWebAuthnTestCredential(t, ctx, store, "bob", "key-gone", "kid-gone", testWebAuthnRosterProvisioner)
	saveWebAuthnTestCredential(t, ctx, store, "alice", "my-passkey", "kid-self", "")
	saveWebAuthnTestCredential(t, ctx, store, "carol", "other-roster-key", "kid-other", "other-roster")

	roster := model.WebAuthnCredentialRoster{
		Provisioner: testWebAuthnRosterProvisioner,
		RPID:        testWebAuthnRosterRPID,
		WebAuthnCredentials: []model.WebAuthnCredentialData{
			testWebAuthnRosterData("kid-a", "pk-kid-a", "alice", "key-a"),
		},
	}

	path := writeWebAuthnRosterFile(t, "roster.yml", roster)

	plan, _, err := reconcileWebAuthnRoster(t, ctx, store, path, false)
	require.NoError(t, err)
	require.Len(t, plan.Ops, 1)
	assert.Equal(t, webAuthnCredentialRosterOpRevoke, plan.Ops[0].Type)
	assert.Equal(t, "kid-gone", plan.Ops[0].Credential.KID.String())

	state := webAuthnCredentialState(t, ctx, store)

	assert.NotContains(t, state, model.NewBase64([]byte("kid-gone")).String())
	assert.Contains(t, state, model.NewBase64([]byte("kid-a")).String())
	assert.Contains(t, state, model.NewBase64([]byte("kid-self")).String())
	assert.Equal(t, "", state[model.NewBase64([]byte("kid-self")).String()].provisioner)
	assert.Contains(t, state, model.NewBase64([]byte("kid-other")).String())
	assert.Equal(t, "other-roster", state[model.NewBase64([]byte("kid-other")).String()].provisioner)
}

func TestStorageUserWebAuthnRosterAdoptsSelfRegisteredCredential(t *testing.T) {
	ctx := context.Background()

	store := newWebAuthnRosterTestStore(t)

	saveWebAuthnTestCredential(t, ctx, store, "alice", "key-a", "kid-a", "")

	roster := model.WebAuthnCredentialRoster{
		Provisioner: testWebAuthnRosterProvisioner,
		RPID:        testWebAuthnRosterRPID,
		WebAuthnCredentials: []model.WebAuthnCredentialData{
			testWebAuthnRosterData("kid-a", "pk-kid-a", "alice", "key-a"),
		},
	}

	path := writeWebAuthnRosterFile(t, "roster.yml", roster)

	plan, _, err := reconcileWebAuthnRoster(t, ctx, store, path, false)
	require.NoError(t, err)
	require.Len(t, plan.Ops, 1)
	assert.Equal(t, webAuthnCredentialRosterOpAdopt, plan.Ops[0].Type)

	state := webAuthnCredentialState(t, ctx, store)

	assert.Equal(t, testWebAuthnRosterProvisioner, state[model.NewBase64([]byte("kid-a")).String()].provisioner)

	// Re-running after adoption reports no changes.
	plan2, _, err := reconcileWebAuthnRoster(t, ctx, store, path, false)
	require.NoError(t, err)
	assert.Empty(t, plan2.Ops)
	assert.Equal(t, 1, plan2.Unchanged)
}

func TestStorageUserWebAuthnRosterDryRunMakesNoChanges(t *testing.T) {
	ctx := context.Background()

	store := newWebAuthnRosterTestStore(t)

	path := writeWebAuthnRosterFile(t, "roster.yml", model.WebAuthnCredentialRoster{
		Provisioner: testWebAuthnRosterProvisioner,
		RPID:        testWebAuthnRosterRPID,
		WebAuthnCredentials: []model.WebAuthnCredentialData{
			testWebAuthnRosterData("kid-a", "pk-kid-a", "alice", "key-a"),
		},
	})

	before := webAuthnCredentialState(t, ctx, store)

	plan, output, err := reconcileWebAuthnRoster(t, ctx, store, path, true)
	require.NoError(t, err)
	assert.Len(t, plan.Ops, 1)
	assert.Contains(t, output, "Dry run")

	after := webAuthnCredentialState(t, ctx, store)
	assert.Equal(t, before, after)
}

func TestStorageUserWebAuthnRosterInvalidRosterMakesNoChanges(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name   string
		roster model.WebAuthnCredentialRoster
	}{
		{
			"ShouldErrMissingProvisioner",
			model.WebAuthnCredentialRoster{
				RPID: testWebAuthnRosterRPID,
				WebAuthnCredentials: []model.WebAuthnCredentialData{
					testWebAuthnRosterData("kid-a", "pk-kid-a", "alice", "key-a"),
				},
			},
		},
		{
			"ShouldErrInvalidProvisioner",
			model.WebAuthnCredentialRoster{
				Provisioner: "bad provisioner!",
				RPID:        testWebAuthnRosterRPID,
				WebAuthnCredentials: []model.WebAuthnCredentialData{
					testWebAuthnRosterData("kid-a", "pk-kid-a", "alice", "key-a"),
				},
			},
		},
		{
			"ShouldErrNoEntries",
			model.WebAuthnCredentialRoster{
				Provisioner: testWebAuthnRosterProvisioner,
				RPID:        testWebAuthnRosterRPID,
			},
		},
		{
			"ShouldErrMissingUsername",
			model.WebAuthnCredentialRoster{
				Provisioner: testWebAuthnRosterProvisioner,
				RPID:        testWebAuthnRosterRPID,
				WebAuthnCredentials: []model.WebAuthnCredentialData{
					testWebAuthnRosterData("kid-a", "pk-kid-a", "", "key-a"),
				},
			},
		},
		{
			"ShouldErrMissingRPID",
			model.WebAuthnCredentialRoster{
				Provisioner: testWebAuthnRosterProvisioner,
				WebAuthnCredentials: []model.WebAuthnCredentialData{
					testWebAuthnRosterData("kid-a", "pk-kid-a", "alice", "key-a"),
				},
			},
		},
		{
			"ShouldErrDuplicateKID",
			model.WebAuthnCredentialRoster{
				Provisioner: testWebAuthnRosterProvisioner,
				RPID:        testWebAuthnRosterRPID,
				WebAuthnCredentials: []model.WebAuthnCredentialData{
					testWebAuthnRosterData("kid-a", "pk-kid-a", "alice", "key-a"),
					testWebAuthnRosterData("kid-a", "pk-kid-a", "bob", "key-b"),
				},
			},
		},
		{
			"ShouldErrDuplicateDescription",
			model.WebAuthnCredentialRoster{
				Provisioner: testWebAuthnRosterProvisioner,
				RPID:        testWebAuthnRosterRPID,
				WebAuthnCredentials: []model.WebAuthnCredentialData{
					testWebAuthnRosterData("kid-a", "pk-kid-a", "alice", "same"),
					testWebAuthnRosterData("kid-b", "pk-kid-b", "alice", "same"),
				},
			},
		},
		{
			"ShouldErrInvalidKIDBase64",
			model.WebAuthnCredentialRoster{
				Provisioner: testWebAuthnRosterProvisioner,
				RPID:        testWebAuthnRosterRPID,
				WebAuthnCredentials: []model.WebAuthnCredentialData{
					{
						RPID:        testWebAuthnRosterRPID,
						Username:    "alice",
						Description: "key-a",
						KID:         "not base64!",
						PublicKey:   base64.StdEncoding.EncodeToString([]byte("pk-kid-a")),
					},
				},
			},
		},
		{
			"ShouldErrEmptyPublicKey",
			model.WebAuthnCredentialRoster{
				Provisioner: testWebAuthnRosterProvisioner,
				RPID:        testWebAuthnRosterRPID,
				WebAuthnCredentials: []model.WebAuthnCredentialData{
					{
						RPID:        testWebAuthnRosterRPID,
						Username:    "alice",
						Description: "key-a",
						KID:         base64.StdEncoding.EncodeToString([]byte("kid-a")),
					},
				},
			},
		},
		{
			"ShouldErrKIDRegisteredToAnotherUser",
			model.WebAuthnCredentialRoster{
				Provisioner: testWebAuthnRosterProvisioner,
				RPID:        testWebAuthnRosterRPID,
				WebAuthnCredentials: []model.WebAuthnCredentialData{
					testWebAuthnRosterData("kid-a", "pk-kid-a", "bob", "key-a"),
				},
			},
		},
		{
			"ShouldErrPublicKeyMismatch",
			model.WebAuthnCredentialRoster{
				Provisioner: testWebAuthnRosterProvisioner,
				RPID:        testWebAuthnRosterRPID,
				WebAuthnCredentials: []model.WebAuthnCredentialData{
					testWebAuthnRosterData("kid-a", "totally-different-key", "alice", "key-a"),
				},
			},
		},
		{
			"ShouldErrManagedByAnotherProvisioner",
			model.WebAuthnCredentialRoster{
				Provisioner: testWebAuthnRosterProvisioner,
				RPID:        testWebAuthnRosterRPID,
				WebAuthnCredentials: []model.WebAuthnCredentialData{
					testWebAuthnRosterData("kid-other", "pk-kid-other", "carol", "other-roster-key"),
				},
			},
		},
		{
			"ShouldErrDescriptionSlotTakenBySelfRegistered",
			model.WebAuthnCredentialRoster{
				Provisioner: testWebAuthnRosterProvisioner,
				RPID:        testWebAuthnRosterRPID,
				WebAuthnCredentials: []model.WebAuthnCredentialData{
					testWebAuthnRosterData("kid-new", "pk-kid-new", "alice", "taken-desc"),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := newWebAuthnRosterTestStore(t)

			saveWebAuthnTestCredential(t, ctx, store, "alice", "key-a", "kid-a", testWebAuthnRosterProvisioner)
			saveWebAuthnTestCredential(t, ctx, store, "carol", "other-roster-key", "kid-other", "other-roster")
			saveWebAuthnTestCredential(t, ctx, store, "alice", "taken-desc", "kid-taken", "")

			path := writeWebAuthnRosterFile(t, "roster.yml", tc.roster)

			before := webAuthnCredentialState(t, ctx, store)

			_, _, err := reconcileWebAuthnRoster(t, ctx, store, path, false)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "roster validation failed")

			after := webAuthnCredentialState(t, ctx, store)
			assert.Equal(t, before, after)
		})
	}
}

func TestStorageUserWebAuthnRosterValidationAggregatesAllProblems(t *testing.T) {
	ctx := context.Background()

	store := newWebAuthnRosterTestStore(t)

	path := writeWebAuthnRosterFile(t, "roster.yml", model.WebAuthnCredentialRoster{
		Provisioner: testWebAuthnRosterProvisioner,
		RPID:        testWebAuthnRosterRPID,
		WebAuthnCredentials: []model.WebAuthnCredentialData{
			testWebAuthnRosterData("kid-a", "pk-kid-a", "alice", "key-a"),
			testWebAuthnRosterData("kid-a", "pk-kid-a", "", ""),
		},
	})

	_, _, err := reconcileWebAuthnRoster(t, ctx, store, path, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roster entry 2")
	assert.Contains(t, err.Error(), "duplicate kid")
}

func TestStorageUserWebAuthnRosterResumesAfterInterruption(t *testing.T) {
	ctx := context.Background()

	store := newWebAuthnRosterTestStore(t)

	roster := model.WebAuthnCredentialRoster{
		Provisioner: testWebAuthnRosterProvisioner,
		RPID:        testWebAuthnRosterRPID,
		WebAuthnCredentials: []model.WebAuthnCredentialData{
			testWebAuthnRosterData("kid-a", "pk-kid-a", "alice", "key-a"),
			testWebAuthnRosterData("kid-b", "pk-kid-b", "bob", "key-b"),
			testWebAuthnRosterData("kid-c", "pk-kid-c", "carol", "key-c"),
		},
	}

	path := writeWebAuthnRosterFile(t, "roster.yml", roster)

	// Initial run: simulate an interruption after the first operation was committed.
	loaded, err := loadWebAuthnCredentialRoster(path)
	require.NoError(t, err)

	plan, err := planWebAuthnCredentialRoster(ctx, store, loaded)
	require.NoError(t, err)
	require.Len(t, plan.Ops, 3)

	partial := &webAuthnCredentialRosterPlan{Provisioner: plan.Provisioner, Ops: plan.Ops[:1]}

	require.NoError(t, applyWebAuthnCredentialRosterPlan(ctx, new(bytes.Buffer), store, partial))

	// Re-run from the beginning: the first entry is now unchanged and the remaining two are applied.
	resumePlan, _, err := reconcileWebAuthnRoster(t, ctx, store, path, false)
	require.NoError(t, err)

	var inserted int

	for _, op := range resumePlan.Ops {
		assert.NotEqual(t, webAuthnCredentialRosterOpRevoke, op.Type)
		assert.NotEqual(t, webAuthnCredentialRosterOpUpdate, op.Type)

		if op.Type == webAuthnCredentialRosterOpInsert {
			inserted++
		}
	}

	assert.Equal(t, 2, inserted)
	assert.Equal(t, 1, resumePlan.Unchanged)

	state := webAuthnCredentialState(t, ctx, store)

	for _, kid := range []string{"kid-a", "kid-b", "kid-c"} {
		entry, ok := state[model.NewBase64([]byte(kid)).String()]
		assert.True(t, ok)
		assert.Equal(t, testWebAuthnRosterProvisioner, entry.provisioner)
	}

	// A final run converges with no operations.
	finalPlan, _, err := reconcileWebAuthnRoster(t, ctx, store, path, false)
	require.NoError(t, err)
	assert.Empty(t, finalPlan.Ops)
	assert.Equal(t, 3, finalPlan.Unchanged)
}

func TestStorageUserWebAuthnRosterLoadErrors(t *testing.T) {
	ctx := context.Background()

	store := newWebAuthnRosterTestStore(t)

	_, _, err := reconcileWebAuthnRoster(t, ctx, store, filepath.Join(t.TempDir(), "does-not-exist.yml"), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify a filename that exists")

	dir := t.TempDir()

	_, _, err = reconcileWebAuthnRoster(t, ctx, store, dir, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is a directory")
}
