package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-kit/ui"
)

// snapshotter is the part of the nftables backend the staging flow needs beyond
// the generic firewall.Backend: a read of the whole ruleset as text, which is
// what the connectivity-safe rollback replays. Only the nftables backend and
// its demo implement it, which is what gates the staging keys.
type snapshotter interface {
	SnapshotRuleset(ctx context.Context) (string, error)
}

// keepExpiredMsg is the rollback timer firing: the operator did not confirm
// they still have access in time. The token distinguishes it from a stale timer
// left over from a batch that was already committed or rolled back.
type keepExpiredMsg struct{ token int }

// applyReadyMsg carries the atomic-apply command once the pre-apply snapshot has
// been captured, so the confirm dialog can preview the exact transaction.
type applyReadyMsg struct {
	change firewall.Change
	err    error
}

// stageOrConfirm is the fork every mutation takes: with staging on, the change
// joins the pending set instead of opening a confirm dialog; with it off, it is
// previewed and confirmed as always. It is the one place the staging mode
// changes what a build does, which keeps every builder unaware of it.
func (a *app) stageOrConfirm(title, body string, change firewall.Change) {
	if !a.stagingOn || a.staging == nil {
		a.openConfirm(title, body, change)
		return
	}
	// Staging captures the change and returns to the table; the form or menu it
	// came from is done, the same way opening a confirm would have closed it.
	a.mode = modeTable
	if err := a.staging.Stage(change); err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return
	}
	a.setStatusf(ui.StatusInfo,
		"staged: %s  ·  %d pending, S to review or apply",
		firstLine(change.Description), a.staging.Len())
}

// toggleStaging turns staging mode on or off. It is refused on a backend that
// cannot roll back, and while a batch is waiting to be committed, because the
// pending set is then the record of what has to be resolved first.
func (a *app) toggleStaging() {
	if a.staging == nil {
		a.setStatus(ui.StatusWarn,
			"staging is only available on the nftables backend, which can "+
				"snapshot its ruleset to roll a batch back")
		return
	}
	if a.awaitingKeep {
		a.setStatus(ui.StatusWarn,
			"an applied batch is waiting: press k to keep it, or let it revert")
		return
	}
	a.stagingOn = !a.stagingOn
	if a.stagingOn {
		a.setStatusf(ui.StatusInfo,
			"staging on: changes are collected, not applied  ·  %d pending",
			a.staging.Len())
		return
	}
	a.setStatus(ui.StatusInfo, "staging off: changes apply immediately again")
}

// openStagingMenu offers what can be done with the pending set: apply it as one
// transaction, drop one change, or discard the lot.
func (a *app) openStagingMenu() tea.Cmd {
	if a.staging == nil {
		a.setStatus(ui.StatusWarn, "this backend has no staging")
		return nil
	}
	if a.awaitingKeep {
		a.setStatus(ui.StatusWarn,
			"the applied batch is waiting: press k to keep it before staging more")
		return nil
	}
	if a.staging.Len() == 0 {
		a.setStatus(ui.StatusInfo,
			"nothing is staged — press s to turn staging on, then add changes")
		return nil
	}
	options := []string{
		fmt.Sprintf("Apply %d staged change(s) atomically", a.staging.Len()),
		"Drop a staged change",
		"Discard every staged change",
	}
	a.picker = ui.NewPicker("Staged changes", options, options[0])
	a.pickerFor = pickerStagingAction
	a.mode = modePicker
	return nil
}

// stagingAction dispatches the choice from the staging menu.
func (a *app) stagingAction(choice string) tea.Cmd {
	switch {
	case strings.HasPrefix(choice, "Apply"):
		return a.beginApply()
	case strings.HasPrefix(choice, "Drop"):
		return a.openStagingDropPicker()
	case strings.HasPrefix(choice, "Discard"):
		if err := a.staging.Clear(); err != nil {
			a.setStatus(ui.StatusError, err.Error())
			return nil
		}
		a.setStatus(ui.StatusInfo, "the staged changes were discarded")
		return nil
	}
	return nil
}

// openStagingDropPicker lists the pending changes so one can be removed.
func (a *app) openStagingDropPicker() tea.Cmd {
	pending := a.staging.Pending()
	if len(pending) == 0 {
		a.setStatus(ui.StatusInfo, "nothing is staged")
		return nil
	}
	options := make([]string, 0, len(pending))
	for i, change := range pending {
		options = append(options,
			fmt.Sprintf("%d. %s", i+1, firstLine(change.Description)))
	}
	a.picker = ui.NewPicker("Drop which staged change", options, options[0])
	a.pickerFor = pickerStagingDrop
	a.mode = modePicker
	return nil
}

// dropStaged removes the change the drop picker named. The 1-based prefix the
// option carries is how the choice maps back to its index.
func (a *app) dropStaged(choice string) {
	index, _, ok := strings.Cut(choice, ".")
	if !ok {
		return
	}
	var i int
	if _, err := fmt.Sscanf(index, "%d", &i); err != nil {
		return
	}
	if err := a.staging.Drop(i - 1); err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return
	}
	a.setStatusf(ui.StatusInfo, "dropped a staged change  ·  %d pending",
		a.staging.Len())
}

// beginApply captures the pre-apply snapshot and builds the atomic-apply
// command. The snapshot read is privileged and can block, so it runs off the
// update loop and returns through applyReadyMsg.
func (a *app) beginApply() tea.Cmd {
	snap := a.snap
	session := a.staging
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ruleset, err := snap.SnapshotRuleset(ctx)
		if err != nil {
			return applyReadyMsg{err: fmt.Errorf(
				"could not snapshot the ruleset to make the apply reversible: %w", err)}
		}
		session.Snapshot(ruleset)
		cmd, err := session.Apply()
		if err != nil {
			return applyReadyMsg{err: err}
		}
		return applyReadyMsg{change: firewall.One(cmd)}
	}
}

// openApplyConfirm previews the whole transaction — the nft script that goes to
// nft's standard input, which no command-line preview can show — and marks the
// change so a yes arms the keep timer.
func (a *app) openApplyConfirm(change firewall.Change) {
	body := fmt.Sprintf(
		"These %d change(s) apply as one nft transaction: all of them, or none. "+
			"After they apply you have %s to press k and keep them; if you lose "+
			"access and do not, the snapshot below is restored automatically.",
		a.staging.Len(), a.staging.Timeout().Round(time.Second))
	a.pendingApply = true
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   "Apply the staged batch",
		Body:    body,
		Command: a.staging.PreviewApply(),
		Danger:  true,
		Payload: change,
	}
}

// armKeep starts the keep-confirmation window once the batch has applied. The
// timeout is driven by the update loop's own clock — a tick carrying the
// current token — rather than the session's timer, so the rollback is a normal
// confirmed command through the same run path as everything else.
func (a *app) armKeep() tea.Cmd {
	if err := a.staging.Arm(nil); err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return a.load()
	}
	a.awaitingKeep = true
	a.stagingOn = false
	a.keepToken++
	a.keepTickPending = true
	timeout := a.staging.Timeout()
	a.setStatusf(ui.StatusWarn,
		"applied — press k to keep, or it reverts in %s", timeout.Round(time.Second))
	a.loading = true
	// Reload first; the load handler starts the countdown once the applied
	// ruleset is on screen, so the operator confirms against what they see.
	return a.load()
}

// keepStaged is the operator confirming they still have access: the batch
// stays, the timer is stopped, and staging is back to collecting.
func (a *app) keepStaged() tea.Cmd {
	if !a.awaitingKeep {
		return nil
	}
	if err := a.staging.Commit(); err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.awaitingKeep = false
	a.keepToken++ // invalidate the pending expiry tick
	a.setStatus(ui.StatusOK, "kept: the applied changes stay in place")
	return nil
}

// keepExpired is the rollback timer firing. It rolls back only when the token
// still matches — a batch that was kept or already rolled back has bumped the
// token — so a late tick is a no-op.
func (a *app) keepExpired(token int) tea.Cmd {
	if !a.awaitingKeep || token != a.keepToken {
		return nil
	}
	cmd, err := a.staging.Rollback()
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.awaitingKeep = false
	a.keepToken++
	a.busy = true
	a.setStatus(ui.StatusWarn,
		"no keep within the window — restoring the snapshot to protect access")
	return a.run(firewall.One(cmd))
}
