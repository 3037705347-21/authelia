// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/storage"
)

var reconcileTestNow = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func writeRosterFile(t *testing.T, name, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)

	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	return path
}

func newReconcileFlags(t *testing.T, path string, dryRun bool) *pflag.FlagSet {
	t.Helper()

	flags := pflag.NewFlagSet("reconcile", pflag.ContinueOnError)

	flags.String(cmdFlagNameFile, path, "")
	flags.Bool("dry-run", dryRun, "")

	return flags
}

// normalizeOutput collapses all runs of whitespace in each line so tabwriter aligned output can be asserted on
// deterministically.
func normalizeOutput(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")

	for i, line := range lines {
		lines[i] = strings.Join(strings.Fields(line), " ")
	}

	return strings.Join(lines, "\n")
}

func seedBannedUser(t *testing.T, ctx context.Context, store storage.Provider, username, source string, expires sql.NullTime, reason string) {
	t.Helper()

	ban := &model.BannedUser{Username: username, Source: source, Expires: expires}

	if reason != "" {
		ban.Reason = sql.NullString{Valid: true, String: reason}
	}

	require.NoError(t, store.SaveBannedUser(ctx, ban))
}

func seedBannedIP(t *testing.T, ctx context.Context, store storage.Provider, ip, source string, expires sql.NullTime, reason string) {
	t.Helper()

	ban := &model.BannedIP{IP: model.NewIP(net.ParseIP(ip)), Source: source, Expires: expires}

	if reason != "" {
		ban.Reason = sql.NullString{Valid: true, String: reason}
	}

	require.NoError(t, store.SaveBannedIP(ctx, ban))
}

func TestLoadStorageBansRoster(t *testing.T) {
	t.Run("ValidYAML", func(t *testing.T) {
		path := writeRosterFile(t, "bans.yml", `
users:
  - username: john
    permanent: true
    reason: security roster
  - username: bob
    expires: "2026-10-12T12:00:00Z"
ips:
  - ip: 10.0.0.1
    duration: "24 hours"
  - ip: "2001:db8::1"
    permanent: true
`)

		users, ips, err := loadStorageBansRoster(path, reconcileTestNow)

		require.NoError(t, err)
		require.Len(t, users, 2)
		require.Len(t, ips, 2)

		assert.False(t, users["john"].expires.Valid)
		assert.Equal(t, "security roster", users["john"].reason)
		assert.True(t, users["bob"].expires.Valid)
		assert.False(t, users["bob"].relative)
		assert.True(t, ips["10.0.0.1"].relative)
		assert.Equal(t, reconcileTestNow.Add(24*time.Hour), ips["10.0.0.1"].expires.Time)
		assert.Contains(t, ips, "2001:db8::1")
	})

	t.Run("ValidJSON", func(t *testing.T) {
		path := writeRosterFile(t, "bans.json", `{"users":[{"username":"john","permanent":true}],"ips":[]}`)

		users, ips, err := loadStorageBansRoster(path, reconcileTestNow)

		require.NoError(t, err)
		require.Contains(t, users, "john")
		assert.Empty(t, ips)
	})

	t.Run("MissingFile", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.yml")

		_, _, err := loadStorageBansRoster(path, reconcileTestNow)

		assert.EqualError(t, err, fmt.Sprintf("failed to read roster file '%s': open %s: no such file or directory", path, path))
	})

	testCases := []struct {
		name     string
		filename string
		content  string
		err      string
	}{
		{
			"ShouldErrNoFile",
			"",
			"",
			"must specify a roster file using the --file flag",
		},
		{
			"ShouldErrBadYAML",
			"bans.yml",
			"users: [",
			"failed to parse roster file",
		},
		{
			"ShouldErrMissingUsername",
			"bans.yml",
			"users:\n  - permanent: true\n",
			"invalid roster entry users[0]: username is required",
		},
		{
			"ShouldErrInvalidIP",
			"bans.yml",
			"ips:\n  - ip: not-an-ip\n    permanent: true\n",
			"invalid roster entry ips[0]: invalid ip address 'not-an-ip'",
		},
		{
			"ShouldErrMissingTiming",
			"bans.yml",
			"users:\n  - username: john\n",
			"exactly one of the permanent, expires, or duration options must be specified",
		},
		{
			"ShouldErrConflictingTiming",
			"bans.yml",
			"users:\n  - username: john\n    permanent: true\n    duration: 1h\n",
			"exactly one of the permanent, expires, or duration options must be specified",
		},
		{
			"ShouldErrBadExpires",
			"bans.yml",
			"users:\n  - username: john\n    expires: tomorrow\n",
			"failed to parse expires 'tomorrow' as an RFC3339 timestamp",
		},
		{
			"ShouldErrPastExpires",
			"bans.yml",
			"users:\n  - username: john\n    expires: \"2026-10-08T12:00:00Z\"\n",
			"must be in the future",
		},
		{
			"ShouldErrBadDuration",
			"bans.yml",
			"ips:\n  - ip: 10.0.0.1\n    duration: forever\n",
			"failed to parse duration 'forever'",
		},
		{
			"ShouldErrDuplicateUser",
			"bans.yml",
			"users:\n  - username: john\n    permanent: true\n  - username: john\n    permanent: true\n",
			"invalid roster entry users[1]: duplicate username 'john'",
		},
		{
			"ShouldErrDuplicateIP",
			"bans.yml",
			"ips:\n  - ip: 10.0.0.1\n    permanent: true\n  - ip: \"10.0.0.1\"\n    permanent: true\n",
			"invalid roster entry ips[1]: duplicate ip '10.0.0.1'",
		},
		{
			"ShouldErrReasonTooLong",
			"bans.yml",
			"users:\n  - username: john\n    permanent: true\n    reason: \"" + strings.Repeat("x", 101) + "\"\n",
			"reason exceeds the maximum length of 100",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var path string

			if tc.filename != "" && tc.content != "" {
				path = writeRosterFile(t, tc.filename, tc.content)
			}

			_, _, err := loadStorageBansRoster(path, reconcileTestNow)

			require.Error(t, err)
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

func TestRunStorageBansReconcileLifecycle(t *testing.T) {
	store := newTestSQLiteStore(t)

	ctx := context.Background()

	// Use a fixed but dynamic point in the future so database active filtering using the wall clock never interferes.
	now := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)

	roster1 := fmt.Sprintf(`
users:
  - username: john
    permanent: true
    reason: security roster
  - username: bob
    expires: %q
ips:
  - ip: 10.0.0.1
    duration: "24h"
`, now.Add(72*time.Hour).Format(time.RFC3339))

	// A regulation sourced ban and a manually added cli ban must never be touched by the reconciliation.
	seedBannedUser(t, ctx, store, "reguser", "regulation", sql.NullTime{Valid: true, Time: now.Add(time.Hour)}, "Exceeding Maximum Retries")
	seedBannedIP(t, ctx, store, "192.168.9.9", "regulation", sql.NullTime{Valid: true, Time: now.Add(2 * time.Hour)}, "Exceeding Maximum Retries")
	seedBannedIP(t, ctx, store, "172.16.0.1", "cli", sql.NullTime{Valid: false}, "")

	assertForeignBansIntact := func(t *testing.T) {
		t.Helper()

		reguser, err := store.LoadBannedUser(ctx, "reguser")
		require.NoError(t, err)
		require.Len(t, reguser, 1)
		assert.Equal(t, "regulation", reguser[0].Source)

		regip, err := store.LoadBannedIP(ctx, model.NewIP(net.ParseIP("192.168.9.9")))
		require.NoError(t, err)
		require.Len(t, regip, 1)
		assert.Equal(t, "regulation", regip[0].Source)

		clip, err := store.LoadBannedIP(ctx, model.NewIP(net.ParseIP("172.16.0.1")))
		require.NoError(t, err)
		require.Len(t, clip, 1)
		assert.Equal(t, "cli", clip[0].Source)
	}

	t.Run("ShouldAddRosterBans", func(t *testing.T) {
		path := writeRosterFile(t, "bans.yml", roster1)

		buf := new(bytes.Buffer)

		require.NoError(t, runStorageBansReconcile(ctx, buf, newReconcileFlags(t, path, false), store, now))

		out := normalizeOutput(buf.String())

		assert.Contains(t, out, "user john ADD never security roster")
		assert.Contains(t, out, "ip 10.0.0.1 ADD "+now.Add(24*time.Hour).Format(time.DateTime))
		assert.Contains(t, out, "Reconciliation complete: 3 added, 0 renewed, 0 revoked, 0 unchanged.")

		john, err := store.LoadBannedUser(ctx, "john")
		require.NoError(t, err)
		require.Len(t, john, 1)
		assert.Equal(t, storageBansSourceRoster, john[0].Source)
		assert.False(t, john[0].Expires.Valid)
		assert.Equal(t, "security roster", john[0].Reason.String)

		bob, err := store.LoadBannedUser(ctx, "bob")
		require.NoError(t, err)
		require.Len(t, bob, 1)
		assert.Equal(t, storageBansSourceRoster, bob[0].Source)
		assert.True(t, bob[0].Expires.Time.Equal(now.Add(72*time.Hour)))

		ipbans, err := store.LoadBannedIP(ctx, model.NewIP(net.ParseIP("10.0.0.1")))
		require.NoError(t, err)
		require.Len(t, ipbans, 1)
		assert.Equal(t, storageBansSourceRoster, ipbans[0].Source)
		assert.True(t, ipbans[0].Expires.Time.Equal(now.Add(24*time.Hour)))

		assertForeignBansIntact(t)
	})

	t.Run("ShouldBeIdempotent", func(t *testing.T) {
		path := writeRosterFile(t, "bans.yml", roster1)

		beforeJohn, err := store.LoadBannedUser(ctx, "john")
		require.NoError(t, err)
		require.Len(t, beforeJohn, 1)

		beforeBob, err := store.LoadBannedUser(ctx, "bob")
		require.NoError(t, err)
		require.Len(t, beforeBob, 1)

		beforeIP, err := store.LoadBannedIP(ctx, model.NewIP(net.ParseIP("10.0.0.1")))
		require.NoError(t, err)
		require.Len(t, beforeIP, 1)

		buf := new(bytes.Buffer)

		require.NoError(t, runStorageBansReconcile(ctx, buf, newReconcileFlags(t, path, false), store, now))

		out := normalizeOutput(buf.String())

		assert.Contains(t, out, "Reconciliation complete: 0 added, 0 renewed, 0 revoked, 3 unchanged.")
		assert.Contains(t, out, "user john UNCHANGED never")
		assert.Contains(t, out, "user bob UNCHANGED "+now.Add(72*time.Hour).Format(time.DateTime))
		assert.Contains(t, out, "ip 10.0.0.1 UNCHANGED "+now.Add(24*time.Hour).Format(time.DateTime))

		afterJohn, err := store.LoadBannedUser(ctx, "john")
		require.NoError(t, err)
		require.Len(t, afterJohn, 1)
		assert.Equal(t, beforeJohn[0].ID, afterJohn[0].ID)

		afterBob, err := store.LoadBannedUser(ctx, "bob")
		require.NoError(t, err)
		require.Len(t, afterBob, 1)
		assert.Equal(t, beforeBob[0].ID, afterBob[0].ID)

		afterIP, err := store.LoadBannedIP(ctx, model.NewIP(net.ParseIP("10.0.0.1")))
		require.NoError(t, err)
		require.Len(t, afterIP, 1)
		assert.Equal(t, beforeIP[0].ID, afterIP[0].ID)
	})

	t.Run("ShouldRenewRelativeDurationAndNeverShorten", func(t *testing.T) {
		path := writeRosterFile(t, "bans.yml", roster1)

		// An hour later the 24h duration ban should be extended; absolute and permanent bans remain unchanged.
		buf := new(bytes.Buffer)

		require.NoError(t, runStorageBansReconcile(ctx, buf, newReconcileFlags(t, path, false), store, now.Add(time.Hour)))

		out := normalizeOutput(buf.String())

		assert.Contains(t, out, "ip 10.0.0.1 RENEW "+now.Add(25*time.Hour).Format(time.DateTime))
		assert.Contains(t, out, "Reconciliation complete: 0 added, 1 renewed, 0 revoked, 2 unchanged.")

		ipbans, err := store.LoadBannedIP(ctx, model.NewIP(net.ParseIP("10.0.0.1")))
		require.NoError(t, err)
		require.Len(t, ipbans, 1)
		assert.True(t, ipbans[0].Expires.Time.Equal(now.Add(25*time.Hour)))

		// A shorter desired lifetime must never shorten the existing ban, while all other roster entries stay managed.
		shortRoster := fmt.Sprintf(`
users:
  - username: john
    permanent: true
    reason: security roster
  - username: bob
    expires: %q
ips:
  - ip: 10.0.0.1
    duration: "1h"
`, now.Add(72*time.Hour).Format(time.RFC3339))

		shortPath := writeRosterFile(t, "short.yml", shortRoster)

		buf = new(bytes.Buffer)

		require.NoError(t, runStorageBansReconcile(ctx, buf, newReconcileFlags(t, shortPath, false), store, now.Add(time.Hour)))

		out = normalizeOutput(buf.String())

		assert.Contains(t, out, "ip 10.0.0.1 UNCHANGED "+now.Add(25*time.Hour).Format(time.DateTime))
		assert.Contains(t, out, "Reconciliation complete: 0 added, 0 renewed, 0 revoked, 3 unchanged.")

		ipbans, err = store.LoadBannedIP(ctx, model.NewIP(net.ParseIP("10.0.0.1")))
		require.NoError(t, err)
		require.Len(t, ipbans, 1)
		assert.True(t, ipbans[0].Expires.Time.Equal(now.Add(25*time.Hour)))
	})

	t.Run("ShouldRevokeRemovedAndRenewChanged", func(t *testing.T) {
		// john removed from the roster, bob's expiry changed, mary added, and the ip is removed.
		roster2 := fmt.Sprintf(`
users:
  - username: bob
    expires: %q
  - username: mary
    permanent: true
ips: []
`, now.Add(240*time.Hour).Format(time.RFC3339))

		path := writeRosterFile(t, "bans.yml", roster2)

		buf := new(bytes.Buffer)

		require.NoError(t, runStorageBansReconcile(ctx, buf, newReconcileFlags(t, path, false), store, now.Add(2*time.Hour)))

		out := normalizeOutput(buf.String())

		assert.Contains(t, out, "Reconciliation complete: 1 added, 1 renewed, 2 revoked, 0 unchanged.")
		assert.Contains(t, out, "user john REVOKE never security roster")
		assert.Contains(t, out, "ip 10.0.0.1 REVOKE "+now.Add(25*time.Hour).Format(time.DateTime))
		assert.Contains(t, out, "user mary ADD never")
		assert.Contains(t, out, "user bob RENEW "+now.Add(240*time.Hour).Format(time.DateTime))

		john, err := store.LoadBannedUser(ctx, "john")
		require.NoError(t, err)
		assert.Empty(t, john)

		ipbans, err := store.LoadBannedIP(ctx, model.NewIP(net.ParseIP("10.0.0.1")))
		require.NoError(t, err)
		assert.Empty(t, ipbans)

		bob, err := store.LoadBannedUser(ctx, "bob")
		require.NoError(t, err)
		require.Len(t, bob, 1)
		assert.True(t, bob[0].Expires.Time.Equal(now.Add(240*time.Hour)))

		assertForeignBansIntact(t)
	})

	t.Run("ShouldRenewOnReasonOrPermanenceChange", func(t *testing.T) {
		roster := `
users:
  - username: mary
    permanent: true
    reason: updated reason
`
		path := writeRosterFile(t, "bans.yml", roster)

		buf := new(bytes.Buffer)

		require.NoError(t, runStorageBansReconcile(ctx, buf, newReconcileFlags(t, path, false), store, now))

		assert.Contains(t, normalizeOutput(buf.String()), "user mary RENEW never updated reason")

		mary, err := store.LoadBannedUser(ctx, "mary")
		require.NoError(t, err)
		require.Len(t, mary, 1)
		assert.Equal(t, "updated reason", mary[0].Reason.String)
		assert.False(t, mary[0].Expires.Valid)
	})

	t.Run("ShouldConsolidateDuplicateManagedRows", func(t *testing.T) {
		seedBannedUser(t, ctx, store, "dup", storageBansSourceRoster, sql.NullTime{Valid: true, Time: now.Add(time.Hour)}, "")
		seedBannedUser(t, ctx, store, "dup", storageBansSourceRoster, sql.NullTime{Valid: false}, "")

		roster := fmt.Sprintf(`
users:
  - username: bob
    expires: %q
  - username: mary
    permanent: true
    reason: updated reason
  - username: dup
    permanent: true
`, now.Add(240*time.Hour).Format(time.RFC3339))

		path := writeRosterFile(t, "dup.yml", roster)

		buf := new(bytes.Buffer)

		require.NoError(t, runStorageBansReconcile(ctx, buf, newReconcileFlags(t, path, false), store, now))

		out := normalizeOutput(buf.String())

		assert.Contains(t, out, "user bob ADD "+now.Add(240*time.Hour).Format(time.DateTime))
		assert.Contains(t, out, "user dup UNCHANGED never")
		assert.Contains(t, out, "user dup REVOKE "+now.Add(time.Hour).Format(time.DateTime))
		assert.Contains(t, out, "Reconciliation complete: 1 added, 0 renewed, 1 revoked, 2 unchanged.")

		dups, err := store.LoadBannedUser(ctx, "dup")
		require.NoError(t, err)
		require.Len(t, dups, 1)
		assert.False(t, dups[0].Expires.Valid)
	})

	t.Run("ShouldRejectInvalidRosterAtomically", func(t *testing.T) {
		mary, err := store.LoadBannedUser(ctx, "mary")
		require.NoError(t, err)
		require.Len(t, mary, 1)

		beforeForeign, err := store.LoadBannedUser(ctx, "reguser")
		require.NoError(t, err)
		require.Len(t, beforeForeign, 1)

		bad := writeRosterFile(t, "bad.yml", "ips:\n  - ip: not-an-ip\n    permanent: true\n")

		buf := new(bytes.Buffer)

		err = runStorageBansReconcile(ctx, buf, newReconcileFlags(t, bad, false), store, now)

		require.EqualError(t, err, "invalid roster entry ips[0]: invalid ip address 'not-an-ip'")

		// Nothing changed after the failed reconciliation.
		maryAfter, err := store.LoadBannedUser(ctx, "mary")
		require.NoError(t, err)
		require.Len(t, maryAfter, 1)
		assert.Equal(t, mary[0].ID, maryAfter[0].ID)

		assertForeignBansIntact(t)
	})

	t.Run("ShouldDryRun", func(t *testing.T) {
		roster := `
users:
  - username: ghost
    permanent: true
ips:
  - ip: 10.10.10.10
    duration: "1h"
`
		path := writeRosterFile(t, "dry.yml", roster)

		buf := new(bytes.Buffer)

		require.NoError(t, runStorageBansReconcile(ctx, buf, newReconcileFlags(t, path, true), store, now))

		// The managed entries absent from this roster are planned as revokes but nothing is actually written.
		assert.Contains(t, buf.String(), "Dry run: 2 added, 0 renewed, 3 revoked, 0 unchanged. No changes were made.")

		ghost, err := store.LoadBannedUser(ctx, "ghost")
		require.NoError(t, err)
		assert.Empty(t, ghost)

		dryip, err := store.LoadBannedIP(ctx, model.NewIP(net.ParseIP("10.10.10.10")))
		require.NoError(t, err)
		assert.Empty(t, dryip)

		// Existing managed entries are still active.
		mary, err := store.LoadBannedUser(ctx, "mary")
		require.NoError(t, err)
		require.Len(t, mary, 1)

		bob, err := store.LoadBannedUser(ctx, "bob")
		require.NoError(t, err)
		require.Len(t, bob, 1)
	})
}
