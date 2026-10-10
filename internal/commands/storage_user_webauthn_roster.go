// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/storage"
)

const webAuthnCredentialRosterProvisionerMaxLen = 64

var webAuthnCredentialRosterProvisionerExp = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

type webAuthnCredentialRosterOpType string

const (
	webAuthnCredentialRosterOpRevoke    webAuthnCredentialRosterOpType = "revoke"
	webAuthnCredentialRosterOpInsert    webAuthnCredentialRosterOpType = "insert"
	webAuthnCredentialRosterOpAdopt     webAuthnCredentialRosterOpType = "adopt"
	webAuthnCredentialRosterOpUpdate    webAuthnCredentialRosterOpType = "update"
	webAuthnCredentialRosterOpUnchanged webAuthnCredentialRosterOpType = "unchanged"
)

// webAuthnCredentialRosterOp is a single mutation calculated from the difference between the roster and the database.
type webAuthnCredentialRosterOp struct {
	Type webAuthnCredentialRosterOpType

	// Entry is the zero based index of the roster entry this operation was derived from, or -1 for a revoke operation
	// discovered by the managed credential sweep.
	Entry int

	// Credential is the desired credential for insert/adopt/update operations and the current credential for revoke
	// operations.
	Credential model.WebAuthnCredential

	// ExistingID is the database id of the credential this operation mutates.
	ExistingID int

	// OldDescription is the current description when an update operation changes it.
	OldDescription string
}

// webAuthnCredentialRosterPlan is the ordered set of mutations required to converge the database to the roster.
type webAuthnCredentialRosterPlan struct {
	Provisioner string
	Ops         []webAuthnCredentialRosterOp
	Unchanged   int
}

func (p *webAuthnCredentialRosterPlan) count(opType webAuthnCredentialRosterOpType) (count int) {
	for _, op := range p.Ops {
		if op.Type == opType {
			count++
		}
	}

	return count
}

// loadWebAuthnCredentialRoster reads and parses the roster file. The format is determined by the file extension.
func loadWebAuthnCredentialRoster(filename string) (roster *model.WebAuthnCredentialRoster, err error) {
	var (
		stat os.FileInfo
		data []byte
	)

	if stat, err = os.Stat(filename); err != nil {
		return nil, fmt.Errorf("must specify a filename that exists but '%s' had an error opening it: %w", filename, err)
	}

	if stat.IsDir() {
		return nil, fmt.Errorf("must specify a filename that exists but '%s' is a directory", filename)
	}

	if data, err = os.ReadFile(filename); err != nil {
		return nil, err
	}

	roster = &model.WebAuthnCredentialRoster{}

	if err = importFile(filename, data, roster); err != nil {
		return nil, err
	}

	return roster, nil
}

// planWebAuthnCredentialRoster validates the entire roster against the current database state and calculates the
// ordered operations required to converge. No writes are performed and any validation problem results in a nil plan.
func planWebAuthnCredentialRoster(ctx context.Context, store storage.Provider, roster *model.WebAuthnCredentialRoster) (plan *webAuthnCredentialRosterPlan, err error) {
	var (
		problems []string
		desired  = make([]model.WebAuthnCredential, len(roster.WebAuthnCredentials))
		valid    = make([]bool, len(roster.WebAuthnCredentials))
	)

	provisioner := roster.Provisioner

	switch {
	case provisioner == "":
		problems = append(problems, "roster must set a non-empty 'provisioner'")
	case len(provisioner) > webAuthnCredentialRosterProvisionerMaxLen:
		problems = append(problems, fmt.Sprintf("roster provisioner '%s' must be no more than %d characters", provisioner, webAuthnCredentialRosterProvisionerMaxLen))
	case !webAuthnCredentialRosterProvisionerExp.MatchString(provisioner):
		problems = append(problems, fmt.Sprintf("roster provisioner '%s' must only contain letters, numbers, '.', '_' or '-'", provisioner))
	}

	if len(roster.WebAuthnCredentials) == 0 {
		problems = append(problems, "roster must contain at least one entry in 'webauthn_credentials'")
	}

	kidEntries := map[string]int{}

	slotEntries := map[string]int{}

	rosterKIDs := map[string]struct{}{}

	for i, data := range roster.WebAuthnCredentials {
		prefix := fmt.Sprintf("roster entry %d", i+1)

		rpid := data.RPID

		if rpid == "" {
			rpid = roster.RPID
		}

		if strings.TrimSpace(data.Username) == "" {
			problems = append(problems, fmt.Sprintf("%s: username must not be empty", prefix))
		}

		if rpid == "" {
			problems = append(problems, fmt.Sprintf("%s (username '%s'): rpid must be set on the entry or as the roster default", prefix, data.Username))
		}

		switch {
		case strings.TrimSpace(data.Description) == "":
			problems = append(problems, fmt.Sprintf("%s (username '%s'): description must not be empty", prefix, data.Username))
		case len(data.Description) > webAuthnCredentialRosterProvisionerMaxLen:
			problems = append(problems, fmt.Sprintf("%s (username '%s'): description must be no more than %d characters", prefix, data.Username, webAuthnCredentialRosterProvisionerMaxLen))
		}

		if data.Provisioner != "" && data.Provisioner != provisioner {
			problems = append(problems, fmt.Sprintf("%s (username '%s'): entry provisioner '%s' does not match the roster provisioner '%s'", prefix, data.Username, data.Provisioner, provisioner))
		}

		credential, cerr := data.ToCredential()
		if cerr != nil {
			problems = append(problems, fmt.Sprintf("%s (username '%s'): %v", prefix, data.Username, cerr))

			continue
		}

		credential.RPID = rpid
		credential.Username = data.Username
		credential.Description = data.Description
		credential.Provisioner = provisioner

		if len(credential.KID.Bytes()) == 0 {
			problems = append(problems, fmt.Sprintf("%s (username '%s'): kid must not be empty", prefix, data.Username))
		}

		if len(credential.PublicKey) == 0 {
			problems = append(problems, fmt.Sprintf("%s (username '%s'): public_key must not be empty", prefix, data.Username))
		}

		kid := credential.KID.String()

		if _, ok := rosterKIDs[kid]; ok {
			problems = append(problems, fmt.Sprintf("%s (username '%s'): duplicate kid '%s' in roster", prefix, data.Username, kid))
		} else {
			rosterKIDs[kid] = struct{}{}

			kidEntries[kid] = i
		}

		slot := webAuthnCredentialSlotKey(rpid, data.Username, data.Description)

		if previous, ok := slotEntries[slot]; ok {
			problems = append(problems, fmt.Sprintf("%s (username '%s'): duplicate rpid/username/description combination in roster, already used by entry %d", prefix, data.Username, previous+1))
		} else {
			slotEntries[slot] = i
		}

		desired[i] = *credential
		valid[i] = true
	}

	if len(problems) != 0 {
		return nil, fmt.Errorf("roster validation failed:\n\t%s", strings.Join(problems, "\n\t"))
	}

	existing, err := loadAllWebAuthnCredentials(ctx, store)
	if err != nil {
		return nil, err
	}

	byKID := map[string]model.WebAuthnCredential{}

	bySlot := map[string]model.WebAuthnCredential{}

	for _, credential := range existing {
		byKID[credential.KID.String()] = credential
		bySlot[webAuthnCredentialSlotKey(credential.RPID, credential.Username, credential.Description)] = credential
	}

	plan = &webAuthnCredentialRosterPlan{Provisioner: provisioner}

	var (
		inserts []webAuthnCredentialRosterOp
		adopts  []webAuthnCredentialRosterOp
		updates []webAuthnCredentialRosterOp
	)

	for i := range desired {
		if !valid[i] {
			continue
		}

		credential := desired[i]

		prefix := fmt.Sprintf("roster entry %d (username '%s', kid '%s')", i+1, credential.Username, credential.KID.String())

		current, ok := byKID[credential.KID.String()]

		if !ok {
			slot := webAuthnCredentialSlotKey(credential.RPID, credential.Username, credential.Description)

			if occupant, occupied := bySlot[slot]; occupied && !webAuthnCredentialRosterSlotReleasable(occupant, provisioner, credential.KID.String(), rosterKIDs) {
				problems = append(problems, fmt.Sprintf("%s: can't insert, description '%s' is already used by kid '%s' with provisioner '%s'", prefix, credential.Description, occupant.KID, occupant.Provisioner))

				continue
			}

			if credential.CreatedAt.IsZero() {
				credential.CreatedAt = time.Now().Truncate(time.Second)
			}

			inserts = append(inserts, webAuthnCredentialRosterOp{Type: webAuthnCredentialRosterOpInsert, Entry: i, Credential: credential})

			continue
		}

		if current.RPID != credential.RPID || current.Username != credential.Username {
			problems = append(problems, fmt.Sprintf("%s: kid is already registered to rpid '%s' username '%s'", prefix, current.RPID, current.Username))

			continue
		}

		switch current.Provisioner {
		case provisioner:
			if !bytes.Equal(current.PublicKey, credential.PublicKey) {
				problems = append(problems, fmt.Sprintf("%s: public_key does not match the existing credential with this kid", prefix))

				continue
			}

			if current.Description == credential.Description {
				plan.Unchanged++

				continue
			}

			slot := webAuthnCredentialSlotKey(credential.RPID, credential.Username, credential.Description)

			if occupant, occupied := bySlot[slot]; occupied && !webAuthnCredentialRosterSlotReleasable(occupant, provisioner, credential.KID.String(), rosterKIDs) {
				problems = append(problems, fmt.Sprintf("%s: can't change description to '%s', it is already used by kid '%s' with provisioner '%s'", prefix, credential.Description, occupant.KID, occupant.Provisioner))

				continue
			}

			updates = append(updates, webAuthnCredentialRosterOp{Type: webAuthnCredentialRosterOpUpdate, Entry: i, Credential: credential, ExistingID: current.ID, OldDescription: current.Description})
		case "":
			if !bytes.Equal(current.PublicKey, credential.PublicKey) {
				problems = append(problems, fmt.Sprintf("%s: public_key does not match the self-registered credential with this kid", prefix))

				continue
			}

			adopts = append(adopts, webAuthnCredentialRosterOp{Type: webAuthnCredentialRosterOpAdopt, Entry: i, Credential: credential, ExistingID: current.ID})

			if current.Description != credential.Description {
				slot := webAuthnCredentialSlotKey(credential.RPID, credential.Username, credential.Description)

				if occupant, occupied := bySlot[slot]; occupied && !webAuthnCredentialRosterSlotReleasable(occupant, provisioner, credential.KID.String(), rosterKIDs) {
					problems = append(problems, fmt.Sprintf("%s: can't change description to '%s', it is already used by kid '%s' with provisioner '%s'", prefix, credential.Description, occupant.KID, occupant.Provisioner))

					continue
				}

				updates = append(updates, webAuthnCredentialRosterOp{Type: webAuthnCredentialRosterOpUpdate, Entry: i, Credential: credential, ExistingID: current.ID, OldDescription: current.Description})
			}
		default:
			problems = append(problems, fmt.Sprintf("%s: kid is managed by another provisioner '%s'", prefix, current.Provisioner))
		}
	}

	var revokes []webAuthnCredentialRosterOp

	for _, credential := range existing {
		if credential.Provisioner != provisioner {
			continue
		}

		if _, ok := rosterKIDs[credential.KID.String()]; ok {
			continue
		}

		revokes = append(revokes, webAuthnCredentialRosterOp{Type: webAuthnCredentialRosterOpRevoke, Entry: -1, Credential: credential, ExistingID: credential.ID})
	}

	if len(problems) != 0 {
		return nil, fmt.Errorf("roster validation failed:\n\t%s", strings.Join(problems, "\n\t"))
	}

	// Revocations run first so that unique (rpid, username, description) slots are released before inserts/updates.
	plan.Ops = append(plan.Ops, revokes...)
	plan.Ops = append(plan.Ops, inserts...)
	plan.Ops = append(plan.Ops, adopts...)
	plan.Ops = append(plan.Ops, updates...)

	return plan, nil
}

// webAuthnCredentialSlotKey is the composite key of the databases unique (rpid, username, description) index.
func webAuthnCredentialSlotKey(rpid, username, description string) string {
	return strings.Join([]string{rpid, username, description}, "\x00")
}

// webAuthnCredentialRosterSlotReleasable returns true when the credential occupying a unique description slot does
// not block a roster mutation targeting the same slot.
func webAuthnCredentialRosterSlotReleasable(occupant model.WebAuthnCredential, provisioner, kid string, rosterKIDs map[string]struct{}) bool {
	if occupant.KID.String() == kid {
		return true
	}

	_, inRoster := rosterKIDs[occupant.KID.String()]

	// A managed credential that the roster is about to revoke releases its slot before the mutation is applied.
	return occupant.Provisioner == provisioner && !inRoster
}

// loadAllWebAuthnCredentials loads every WebAuthn credential using the same pagination as the other storage commands.
func loadAllWebAuthnCredentials(ctx context.Context, store storage.Provider) (credentials []model.WebAuthnCredential, err error) {
	limit := 10

	for page := 0; true; page++ {
		var pageCredentials []model.WebAuthnCredential

		if pageCredentials, err = store.LoadWebAuthnCredentials(ctx, limit, page); err != nil {
			return nil, fmt.Errorf("failed to load WebAuthn credentials: %w", err)
		}

		credentials = append(credentials, pageCredentials...)

		if len(pageCredentials) < limit {
			break
		}
	}

	return credentials, nil
}

// applyWebAuthnCredentialRosterPlan executes the plan operations individually. Each operation is independently
// committed and idempotent; re-running the reconciliation after an interruption recomputes the plan and only applies
// the remaining operations.
func applyWebAuthnCredentialRosterPlan(ctx context.Context, w io.Writer, store storage.Provider, plan *webAuthnCredentialRosterPlan) (err error) {
	for _, op := range plan.Ops {
		switch op.Type {
		case webAuthnCredentialRosterOpRevoke:
			if err = store.DeleteWebAuthnCredential(ctx, op.Credential.KID.String()); err != nil {
				return fmt.Errorf("failed to revoke WebAuthn credential with kid '%s': %w", op.Credential.KID, err)
			}

			_, _ = fmt.Fprintf(w, "Revoked WebAuthn credential for user '%s' with description '%s' (kid '%s')\n", op.Credential.Username, op.Credential.Description, op.Credential.KID)
		case webAuthnCredentialRosterOpInsert:
			if err = store.SaveWebAuthnCredential(ctx, op.Credential); err != nil {
				return fmt.Errorf("failed to add WebAuthn credential for user '%s' kid '%s': %w", op.Credential.Username, op.Credential.KID, err)
			}

			_, _ = fmt.Fprintf(w, "Added WebAuthn credential for user '%s' with description '%s' (kid '%s')\n", op.Credential.Username, op.Credential.Description, op.Credential.KID)
		case webAuthnCredentialRosterOpAdopt:
			if err = store.UpdateWebAuthnCredentialProvisioner(ctx, op.ExistingID, plan.Provisioner); err != nil {
				return fmt.Errorf("failed to adopt WebAuthn credential id '%d' for user '%s': %w", op.ExistingID, op.Credential.Username, err)
			}

			_, _ = fmt.Fprintf(w, "Adopted self-registered WebAuthn credential id '%d' for user '%s' (kid '%s')\n", op.ExistingID, op.Credential.Username, op.Credential.KID)
		case webAuthnCredentialRosterOpUpdate:
			if err = store.UpdateWebAuthnCredentialDescription(ctx, op.Credential.Username, op.ExistingID, op.Credential.Description); err != nil {
				return fmt.Errorf("failed to update description for WebAuthn credential id '%d' of user '%s': %w", op.ExistingID, op.Credential.Username, err)
			}

			_, _ = fmt.Fprintf(w, "Updated description of WebAuthn credential id '%d' for user '%s': '%s' -> '%s'\n", op.ExistingID, op.Credential.Username, op.OldDescription, op.Credential.Description)
		}
	}

	return nil
}

// writeWebAuthnCredentialRosterPlan writes a human readable summary of the plan.
func writeWebAuthnCredentialRosterPlan(w io.Writer, plan *webAuthnCredentialRosterPlan, dryRun bool) {
	_, _ = fmt.Fprintf(w, "WebAuthn Credential Reconciliation Plan (provisioner '%s'):\n\n", plan.Provisioner)

	if len(plan.Ops) == 0 {
		_, _ = fmt.Fprintln(w, "No changes required, the database already matches the roster.")
	} else {
		for _, op := range plan.Ops {
			switch op.Type {
			case webAuthnCredentialRosterOpRevoke:
				_, _ = fmt.Fprintf(w, "  - revoke   user '%s' description '%s' kid '%s'\n", op.Credential.Username, op.Credential.Description, op.Credential.KID)
			case webAuthnCredentialRosterOpInsert:
				_, _ = fmt.Fprintf(w, "  + add      user '%s' description '%s' kid '%s'\n", op.Credential.Username, op.Credential.Description, op.Credential.KID)
			case webAuthnCredentialRosterOpAdopt:
				_, _ = fmt.Fprintf(w, "  ^ adopt    user '%s' description '%s' kid '%s'\n", op.Credential.Username, op.Credential.Description, op.Credential.KID)
			case webAuthnCredentialRosterOpUpdate:
				_, _ = fmt.Fprintf(w, "  ~ update   user '%s' description '%s' -> '%s' kid '%s'\n", op.Credential.Username, op.OldDescription, op.Credential.Description, op.Credential.KID)
			}
		}
	}

	_, _ = fmt.Fprintf(w, "\nSummary: add=%d update=%d adopt=%d revoke=%d unchanged=%d\n",
		plan.count(webAuthnCredentialRosterOpInsert),
		plan.count(webAuthnCredentialRosterOpUpdate),
		plan.count(webAuthnCredentialRosterOpAdopt),
		plan.count(webAuthnCredentialRosterOpRevoke),
		plan.Unchanged,
	)

	if dryRun {
		_, _ = fmt.Fprintln(w, "\nDry run, no changes were made.")
	}
}

// StorageUserWebAuthnReconcileRunE is the RunE for the authelia storage user webauthn reconcile command.
func (ctx *CmdCtx) StorageUserWebAuthnReconcileRunE(cmd *cobra.Command, args []string) (err error) {
	defer func() {
		if err := ctx.providers.StorageProvider.Close(); err != nil {
			panic(err)
		}
	}()

	if err = ctx.CheckSchema(); err != nil {
		return storageWrapCheckSchemaErr(err)
	}

	dryRun, err := cmd.Flags().GetBool(cmdFlagNameDryRun)
	if err != nil {
		return err
	}

	var roster *model.WebAuthnCredentialRoster

	if roster, err = loadWebAuthnCredentialRoster(args[0]); err != nil {
		return err
	}

	w := cmd.OutOrStdout()

	plan, err := planWebAuthnCredentialRoster(ctx, ctx.providers.StorageProvider, roster)
	if err != nil {
		return err
	}

	writeWebAuthnCredentialRosterPlan(w, plan, dryRun)

	if dryRun {
		return nil
	}

	if err = applyWebAuthnCredentialRosterPlan(ctx, w, ctx.providers.StorageProvider, plan); err != nil {
		return err
	}

	if len(plan.Ops) != 0 {
		_, _ = fmt.Fprintf(w, "\nSuccessfully reconciled %d WebAuthn credentials using provisioner '%s'.\n", len(plan.Ops), plan.Provisioner)
	}

	return nil
}
