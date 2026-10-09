// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/regulation"
	"github.com/authelia/authelia/v4/internal/storage"
	"github.com/authelia/authelia/v4/internal/utils"
)

// storageBansSourceRoster is the ban source used for bans that are managed by a ban roster. The source column is a
// VARCHAR(10) so this value must not be longer than 10 characters.
const storageBansSourceRoster = "roster"

const (
	rosterReconcileActionAdd       = "ADD"
	rosterReconcileActionRenew     = "RENEW"
	rosterReconcileActionRevoke    = "REVOKE"
	rosterReconcileActionUnchanged = "UNCHANGED"
)

// storageBansRoster represents the ban roster file which lists the users and ips that should be banned.
type storageBansRoster struct {
	Users []storageBansRosterUser `yaml:"users" json:"users" toml:"users"`
	IPs   []storageBansRosterIP   `yaml:"ips" json:"ips" toml:"ips"`
}

// storageBansRosterUser represents a single user entry in the ban roster file.
type storageBansRosterUser struct {
	Username  string `yaml:"username" json:"username" toml:"username"`
	Permanent bool   `yaml:"permanent" json:"permanent" toml:"permanent"`
	Expires   string `yaml:"expires" json:"expires" toml:"expires"`
	Duration  string `yaml:"duration" json:"duration" toml:"duration"`
	Reason    string `yaml:"reason" json:"reason" toml:"reason"`
}

// storageBansRosterIP represents a single ip entry in the ban roster file.
type storageBansRosterIP struct {
	IP        string `yaml:"ip" json:"ip" toml:"ip"`
	Permanent bool   `yaml:"permanent" json:"permanent" toml:"permanent"`
	Expires   string `yaml:"expires" json:"expires" toml:"expires"`
	Duration  string `yaml:"duration" json:"duration" toml:"duration"`
	Reason    string `yaml:"reason" json:"reason" toml:"reason"`
}

// rosterDesiredBan is the resolved desired state of a single managed ban.
type rosterDesiredBan struct {
	expires  sql.NullTime
	reason   string
	relative bool
}

// rosterPlanEntry is a single action computed during the reconciliation.
type rosterPlanEntry struct {
	use       string
	target    string
	action    string
	expires   sql.NullTime
	reason    string
	revokeIDs []int
}

// StorageBansReconcileRunE returns the RunE for the authelia storage bans reconcile command.
func (ctx *CmdCtx) StorageBansReconcileRunE() func(cmd *cobra.Command, args []string) (err error) {
	return func(cmd *cobra.Command, args []string) (err error) {
		defer func() {
			if err := ctx.providers.StorageProvider.Close(); err != nil {
				panic(err)
			}
		}()

		if err = ctx.CheckSchema(); err != nil {
			return storageWrapCheckSchemaErr(err)
		}

		return runStorageBansReconcile(ctx, cmd.OutOrStdout(), cmd.Flags(), ctx.providers.StorageProvider, time.Now())
	}
}

func runStorageBansReconcile(ctx context.Context, w io.Writer, flags *pflag.FlagSet, store storage.Provider, now time.Time) (err error) {
	var (
		filename string
		dryRun   bool
	)

	if filename, err = flags.GetString(cmdFlagNameFile); err != nil {
		return err
	}

	if dryRun, err = flags.GetBool("dry-run"); err != nil {
		return err
	}

	var desiredUsers map[string]rosterDesiredBan

	var desiredIPs map[string]rosterDesiredBan

	if desiredUsers, desiredIPs, err = loadStorageBansRoster(filename, now); err != nil {
		return err
	}

	committed := true

	if !dryRun {
		var txCtx context.Context

		if txCtx, err = store.BeginTX(ctx); err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}

		ctx = txCtx

		committed = false

		defer func() {
			if !committed {
				_ = store.Rollback(ctx)
			}
		}()
	}

	var plan []rosterPlanEntry

	if plan, err = planStorageBansReconcile(ctx, store, desiredUsers, desiredIPs); err != nil {
		return err
	}

	if !dryRun {
		for i := range plan {
			if err = applyStorageBansReconcileEntry(ctx, store, plan[i]); err != nil {
				return err
			}
		}

		if err = store.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		committed = true
	}

	writeStorageBansReconcilePlan(w, plan, dryRun)

	return nil
}

// loadStorageBansRoster reads and fully validates the roster file. Validation is performed entirely before any database
// interaction so that an invalid roster never results in partial changes.
func loadStorageBansRoster(filename string, now time.Time) (users map[string]rosterDesiredBan, ips map[string]rosterDesiredBan, err error) {
	if filename == "" {
		return nil, nil, fmt.Errorf("must specify a roster file using the --file flag")
	}

	var data []byte

	if data, err = os.ReadFile(filename); err != nil {
		return nil, nil, fmt.Errorf("failed to read roster file '%s': %w", filename, err)
	}

	roster := storageBansRoster{}

	if err = importFile(filename, data, &roster); err != nil {
		return nil, nil, fmt.Errorf("failed to parse roster file '%s': %w", filename, err)
	}

	users = make(map[string]rosterDesiredBan, len(roster.Users))

	ips = make(map[string]rosterDesiredBan, len(roster.IPs))

	for i, entry := range roster.Users {
		if entry.Username == "" {
			return nil, nil, fmt.Errorf("invalid roster entry users[%d]: username is required", i)
		}

		if len(entry.Username) > 100 {
			return nil, nil, fmt.Errorf("invalid roster entry users[%d] ('%s'): username exceeds the maximum length of 100", i, entry.Username)
		}

		var desired rosterDesiredBan

		if desired, err = resolveRosterDesiredBan(entry.Permanent, entry.Expires, entry.Duration, entry.Reason, now); err != nil {
			return nil, nil, fmt.Errorf("invalid roster entry users[%d] ('%s'): %w", i, entry.Username, err)
		}

		if _, ok := users[entry.Username]; ok {
			return nil, nil, fmt.Errorf("invalid roster entry users[%d]: duplicate username '%s'", i, entry.Username)
		}

		users[entry.Username] = desired
	}

	for i, entry := range roster.IPs {
		if entry.IP == "" {
			return nil, nil, fmt.Errorf("invalid roster entry ips[%d]: ip is required", i)
		}

		parsed := net.ParseIP(entry.IP)

		if parsed == nil {
			return nil, nil, fmt.Errorf("invalid roster entry ips[%d]: invalid ip address '%s'", i, entry.IP)
		}

		target := parsed.String()

		var desired rosterDesiredBan

		if desired, err = resolveRosterDesiredBan(entry.Permanent, entry.Expires, entry.Duration, entry.Reason, now); err != nil {
			return nil, nil, fmt.Errorf("invalid roster entry ips[%d] ('%s'): %w", i, entry.IP, err)
		}

		if _, ok := ips[target]; ok {
			return nil, nil, fmt.Errorf("invalid roster entry ips[%d]: duplicate ip '%s'", i, entry.IP)
		}

		ips[target] = desired
	}

	return users, ips, nil
}

// resolveRosterDesiredBan validates the timing and reason of a roster entry and resolves the desired ban state.
func resolveRosterDesiredBan(permanent bool, expires, duration, reason string, now time.Time) (desired rosterDesiredBan, err error) {
	specifiers := 0

	if permanent {
		specifiers++
	}

	if expires != "" {
		specifiers++
	}

	if duration != "" {
		specifiers++
	}

	if specifiers != 1 {
		return rosterDesiredBan{}, fmt.Errorf("exactly one of the permanent, expires, or duration options must be specified")
	}

	if len(reason) > 100 {
		return rosterDesiredBan{}, fmt.Errorf("reason exceeds the maximum length of 100")
	}

	desired.reason = reason

	switch {
	case permanent:
		return desired, nil
	case expires != "":
		var parsed time.Time

		if parsed, err = time.Parse(time.RFC3339, expires); err != nil {
			return rosterDesiredBan{}, fmt.Errorf("failed to parse expires '%s' as an RFC3339 timestamp: %w", expires, err)
		}

		if !parsed.After(now) {
			return rosterDesiredBan{}, fmt.Errorf("expires '%s' must be in the future", parsed.Format(time.RFC3339))
		}

		desired.expires = sql.NullTime{Valid: true, Time: parsed}

		return desired, nil
	default:
		var parsed time.Duration

		if parsed, err = utils.ParseDurationString(duration); err != nil {
			return rosterDesiredBan{}, fmt.Errorf("failed to parse duration '%s': %w", duration, err)
		}

		if parsed <= 0 {
			return rosterDesiredBan{}, fmt.Errorf("duration must be a positive value")
		}

		desired.expires = sql.NullTime{Valid: true, Time: now.Add(parsed)}
		desired.relative = true

		return desired, nil
	}
}

// planStorageBansReconcile loads the active bans and computes the difference between the current state and the desired
// roster state. Only bans with the roster source are managed; bans from other sources such as regulation are ignored.
func planStorageBansReconcile(ctx context.Context, store storage.Provider, desiredUsers map[string]rosterDesiredBan, desiredIPs map[string]rosterDesiredBan) (plan []rosterPlanEntry, err error) {
	var bansUser []model.BannedUser

	if bansUser, err = loadAllActiveBannedUsers(ctx, store); err != nil {
		return nil, err
	}

	managedUsers := make(map[string][]model.BannedUser)

	for _, ban := range bansUser {
		if ban.Source == storageBansSourceRoster {
			managedUsers[ban.Username] = append(managedUsers[ban.Username], ban)
		}
	}

	for target, desired := range desiredUsers {
		plan = appendRosterUserPlan(plan, target, desired, managedUsers[target])
	}

	for target, bans := range managedUsers {
		if _, ok := desiredUsers[target]; ok {
			continue
		}

		for _, ban := range bans {
			plan = append(plan, rosterPlanEntry{use: cmdUseUser, target: target, action: rosterReconcileActionRevoke, expires: ban.Expires, reason: ban.Reason.String, revokeIDs: []int{ban.ID}})
		}
	}

	var bansIP []model.BannedIP

	if bansIP, err = loadAllActiveBannedIPs(ctx, store); err != nil {
		return nil, err
	}

	managedIPs := make(map[string][]model.BannedIP)

	for _, ban := range bansIP {
		if ban.Source == storageBansSourceRoster {
			managedIPs[ban.IP.String()] = append(managedIPs[ban.IP.String()], ban)
		}
	}

	for target, desired := range desiredIPs {
		plan = appendRosterIPPlan(plan, target, desired, managedIPs[target])
	}

	for target, bans := range managedIPs {
		if _, ok := desiredIPs[target]; ok {
			continue
		}

		for _, ban := range bans {
			plan = append(plan, rosterPlanEntry{use: cmdUseIP, target: target, action: rosterReconcileActionRevoke, expires: ban.Expires, reason: ban.Reason.String, revokeIDs: []int{ban.ID}})
		}
	}

	sort.Slice(plan, func(i, j int) bool {
		if plan[i].use != plan[j].use {
			return plan[i].use < plan[j].use
		}

		if plan[i].target != plan[j].target {
			return plan[i].target < plan[j].target
		}

		if plan[i].action != plan[j].action {
			return plan[i].action < plan[j].action
		}

		return firstRevokeID(plan[i]) < firstRevokeID(plan[j])
	})

	return plan, nil
}

func appendRosterUserPlan(plan []rosterPlanEntry, target string, desired rosterDesiredBan, managed []model.BannedUser) []rosterPlanEntry {
	for i, ban := range managed {
		if rosterUserBanMatches(ban, desired) {
			plan = append(plan, rosterPlanEntry{use: cmdUseUser, target: target, action: rosterReconcileActionUnchanged, expires: ban.Expires, reason: ban.Reason.String})

			for j, duplicate := range managed {
				if j != i {
					plan = append(plan, rosterPlanEntry{use: cmdUseUser, target: target, action: rosterReconcileActionRevoke, expires: duplicate.Expires, reason: duplicate.Reason.String, revokeIDs: []int{duplicate.ID}})
				}
			}

			return plan
		}
	}

	entry := rosterPlanEntry{use: cmdUseUser, target: target, expires: desired.expires, reason: desired.reason}

	if len(managed) == 0 {
		entry.action = rosterReconcileActionAdd
	} else {
		entry.action = rosterReconcileActionRenew

		entry.revokeIDs = make([]int, 0, len(managed))

		for _, ban := range managed {
			entry.revokeIDs = append(entry.revokeIDs, ban.ID)
		}
	}

	return append(plan, entry)
}

func appendRosterIPPlan(plan []rosterPlanEntry, target string, desired rosterDesiredBan, managed []model.BannedIP) []rosterPlanEntry {
	for i, ban := range managed {
		if rosterIPBanMatches(ban, desired) {
			plan = append(plan, rosterPlanEntry{use: cmdUseIP, target: target, action: rosterReconcileActionUnchanged, expires: ban.Expires, reason: ban.Reason.String})

			for j, duplicate := range managed {
				if j != i {
					plan = append(plan, rosterPlanEntry{use: cmdUseIP, target: target, action: rosterReconcileActionRevoke, expires: duplicate.Expires, reason: duplicate.Reason.String, revokeIDs: []int{duplicate.ID}})
				}
			}

			return plan
		}
	}

	entry := rosterPlanEntry{use: cmdUseIP, target: target, expires: desired.expires, reason: desired.reason}

	if len(managed) == 0 {
		entry.action = rosterReconcileActionAdd
	} else {
		entry.action = rosterReconcileActionRenew

		entry.revokeIDs = make([]int, 0, len(managed))

		for _, ban := range managed {
			entry.revokeIDs = append(entry.revokeIDs, ban.ID)
		}
	}

	return append(plan, entry)
}

// rosterUserBanMatches returns true when an existing managed ban already satisfies the desired state. A ban created with
// a relative duration is considered a match when it expires at or after the desired expiry so that bans are extended
// but never shortened.
func rosterUserBanMatches(ban model.BannedUser, desired rosterDesiredBan) bool {
	if ban.Reason.Valid != (desired.reason != "") || ban.Reason.String != desired.reason {
		return false
	}

	if !desired.expires.Valid {
		return !ban.Expires.Valid
	}

	if !ban.Expires.Valid {
		return false
	}

	if desired.relative {
		return !ban.Expires.Time.Before(desired.expires.Time)
	}

	return ban.Expires.Time.Equal(desired.expires.Time)
}

// rosterIPBanMatches returns true when an existing managed ban already satisfies the desired state. A ban created with
// a relative duration is considered a match when it expires at or after the desired expiry so that bans are extended
// but never shortened.
func rosterIPBanMatches(ban model.BannedIP, desired rosterDesiredBan) bool {
	if ban.Reason.Valid != (desired.reason != "") || ban.Reason.String != desired.reason {
		return false
	}

	if !desired.expires.Valid {
		return !ban.Expires.Valid
	}

	if !ban.Expires.Valid {
		return false
	}

	if desired.relative {
		return !ban.Expires.Time.Before(desired.expires.Time)
	}

	return ban.Expires.Time.Equal(desired.expires.Time)
}

func applyStorageBansReconcileEntry(ctx context.Context, store storage.Provider, entry rosterPlanEntry) (err error) {
	for _, id := range entry.revokeIDs {
		switch entry.use {
		case cmdUseUser:
			if err = store.RevokeBannedUser(ctx, id, time.Now()); err != nil {
				return fmt.Errorf("failed to revoke managed user ban with id '%d': %w", id, err)
			}
		case cmdUseIP:
			if err = store.RevokeBannedIP(ctx, id, time.Now()); err != nil {
				return fmt.Errorf("failed to revoke managed ip ban with id '%d': %w", id, err)
			}
		}
	}

	switch entry.action {
	case rosterReconcileActionAdd, rosterReconcileActionRenew:
		reason := sql.NullString{}

		if entry.reason != "" {
			reason = sql.NullString{Valid: true, String: entry.reason}
		}

		switch entry.use {
		case cmdUseUser:
			ban := &model.BannedUser{Username: entry.target, Source: storageBansSourceRoster, Expires: entry.expires, Reason: reason}

			if err = store.SaveBannedUser(ctx, ban); err != nil {
				return fmt.Errorf("failed to ban user '%s': %w", entry.target, err)
			}
		case cmdUseIP:
			ban := &model.BannedIP{IP: model.NewIP(net.ParseIP(entry.target)), Source: storageBansSourceRoster, Expires: entry.expires, Reason: reason}

			if err = store.SaveBannedIP(ctx, ban); err != nil {
				return fmt.Errorf("failed to ban ip '%s': %w", entry.target, err)
			}
		}
	}

	return nil
}

func loadAllActiveBannedUsers(ctx context.Context, store storage.Provider) (results []model.BannedUser, err error) {
	const limit = 10

	for page := 0; true; page++ {
		var bans []model.BannedUser

		if bans, err = store.LoadBannedUsers(ctx, limit, page); err != nil {
			return nil, err
		}

		results = append(results, bans...)

		if len(bans) < limit {
			break
		}
	}

	return results, nil
}

func loadAllActiveBannedIPs(ctx context.Context, store storage.Provider) (results []model.BannedIP, err error) {
	const limit = 10

	for page := 0; true; page++ {
		var bans []model.BannedIP

		if bans, err = store.LoadBannedIPs(ctx, limit, page); err != nil {
			return nil, err
		}

		results = append(results, bans...)

		if len(bans) < limit {
			break
		}
	}

	return results, nil
}

func firstRevokeID(entry rosterPlanEntry) int {
	if len(entry.revokeIDs) == 0 {
		return 0
	}

	return entry.revokeIDs[0]
}

func writeStorageBansReconcilePlan(w io.Writer, plan []rosterPlanEntry, dryRun bool) {
	tw := tabwriter.NewWriter(w, 1, 1, 1, ' ', 0)

	_, _ = fmt.Fprintln(tw, "Type\tTarget\tAction\tExpires\tReason")

	var added, renewed, revoked, unchanged int

	for _, entry := range plan {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", entry.use, entry.target, entry.action, regulation.FormatExpiresShort(entry.expires), entry.reason)

		switch entry.action {
		case rosterReconcileActionAdd:
			added++
		case rosterReconcileActionRenew:
			renewed++
		case rosterReconcileActionRevoke:
			revoked++
		case rosterReconcileActionUnchanged:
			unchanged++
		}
	}

	_ = tw.Flush()

	if dryRun {
		_, _ = fmt.Fprintf(w, "Dry run: %d added, %d renewed, %d revoked, %d unchanged. No changes were made.\n", added, renewed, revoked, unchanged)
	} else {
		_, _ = fmt.Fprintf(w, "Reconciliation complete: %d added, %d renewed, %d revoked, %d unchanged.\n", added, renewed, revoked, unchanged)
	}
}
