package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/nftables/staging"
	"github.com/tui-tools/tui-kit/ui"
)

// ruleEditor is the part of a backend the edit-in-place flow needs: the spec a
// rule decomposes into, to pre-fill the form, and the replace-by-handle
// command the submitted form builds. Only the nftables backend and its demo
// implement it.
type ruleEditor interface {
	RuleSpecFor(group string, rule firewall.Rule) (firewall.RuleSpec, error)
	BuildEditRule(group string, rule firewall.Rule,
		spec firewall.RuleSpec) (firewall.Change, error)
}

// ruleMover is the part of a backend the move keys need. The Change it builds
// is a copy plus a delete that only make sense as one transaction, which the
// caller guarantees: staged into the atomic batch, or wrapped in a single
// `nft -f` when staging is off.
type ruleMover interface {
	BuildMoveRule(group string, rule firewall.Rule,
		delta int) (firewall.Change, error)
}

// startEdit opens the add-rule form pre-filled with the selected rule, in edit
// mode: submitting replaces the rule in place, keeping its handle and
// position. A rule the backend cannot decompose into the form is refused here,
// before the form opens, with the backend's own reason.
func (a *app) startEdit() tea.Cmd {
	editor, ok := a.backend.(ruleEditor)
	if !ok {
		a.setStatus(ui.StatusWarn,
			"this backend does not edit a rule in place: delete it with d and "+
				"add the new one with a")
		return nil
	}
	rule, ok := a.selectedRule()
	if !ok {
		a.setStatus(ui.StatusWarn, "no rule selected")
		return nil
	}
	spec, err := editor.RuleSpecFor(a.group, rule)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.form = newRuleForm(a.caps, a.model.Services)
	a.form.title = fmt.Sprintf("Edit rule (replaces handle %s in place)", rule.ID)
	a.form.prefill(spec)
	a.editing = true
	a.editTarget = rule
	a.mode = modeForm
	return nil
}

// confirmMove builds the up-or-down move for the selected rule. With staging
// on it joins the pending batch, where the whole batch is already one nft
// transaction; with staging off it is wrapped as a single `nft -f` so the copy
// and the delete still apply together or not at all.
func (a *app) confirmMove(delta int) tea.Cmd {
	mover, ok := a.backend.(ruleMover)
	if !ok {
		a.setStatus(ui.StatusWarn,
			"this backend does not reorder rules; rule order is only "+
				"meaningful on nftables")
		return nil
	}
	rule, ok := a.selectedRule()
	if !ok {
		a.setStatus(ui.StatusWarn, "no rule selected")
		return nil
	}
	change, err := mover.BuildMoveRule(a.group, rule, delta)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	if a.stagingOn && a.staging != nil {
		a.stageOrConfirm(change.Description, "", change)
		return nil
	}

	atomic := staging.AtomicCommand(change)
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title: change.Description,
		Body: "The statements below apply as one nft -f transaction: both of " +
			"them, or neither.\n" + change.Note + ".",
		Command: strings.TrimRight(atomic.Stdin, "\n"),
		Danger:  true,
		Payload: firewall.One(atomic),
	}
	return nil
}
