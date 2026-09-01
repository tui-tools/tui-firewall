package main

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/nftables"
	"github.com/tui-tools/tui-kit/ui"
)

// ruleDisabler is the part of a backend the D key needs. Disabling is not a
// firewall concept every backend has: ufw and firewalld would have to delete
// the rule and hope, and nftables can do it honestly only because this tool
// keeps its own record of what it took out. So the key is offered where the
// interface is, and nowhere else.
//
// The build and the commit are two calls on purpose. A change that was
// previewed and cancelled must leave the record untouched, so nothing is
// remembered until the command has actually run.
type ruleDisabler interface {
	BuildToggleDisabled(group string, rule firewall.Rule) (nftables.Toggle, error)
	CommitToggleDisabled(toggle nftables.Toggle)
}

// confirmToggleDisabled builds the disable — or, on a row that already stands
// for a disabled rule, the enable — for the selection.
//
// It never joins a staged batch. A staged change applies later, and the record
// of what is disabled is written the moment the command succeeds: staging the
// one and not the other would leave the file claiming a rule is disabled while
// the kernel still enforces it, which is the exact lie the whole preview
// contract exists to prevent. So the toggle applies on its own, as one nft
// command, and then offers the save that puts the record on disk.
func (a *app) confirmToggleDisabled() tea.Cmd {
	disabler, ok := a.backend.(ruleDisabler)
	if !ok {
		a.setStatus(ui.StatusWarn,
			"this backend has no disabled state: delete the rule with d and "+
				"add it again when you want it back")
		return nil
	}
	rule, ok := a.selectedRule()
	if !ok {
		a.setStatus(ui.StatusWarn, "no rule selected")
		return nil
	}
	if a.awaitingKeep {
		a.setStatus(ui.StatusWarn,
			"an applied batch is waiting: press k to keep it first")
		return nil
	}
	if a.stagingOn {
		a.setStatus(ui.StatusWarn,
			"disabling is not staged: the ruleset and this tool's own record "+
				"of what is disabled have to change together, so press s to "+
				"leave staging first")
		return nil
	}
	toggle, err := disabler.BuildToggleDisabled(a.group, rule)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}

	a.pendingDisable = &toggle
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   toggle.Change.Description,
		Body:    "Rule: " + describeRule(rule) + "\n" + toggle.Change.Note + ".",
		Command: a.backend.Preview(toggle.Change),
		Danger:  true,
		Payload: toggle.Change,
	}
	return nil
}

// commitToggleDisabled records a toggle that has run. The save that writes the
// record to disk is offered by the reload that follows, so the disabled rule
// is on screen before the dialog that saves it opens.
func (a *app) commitToggleDisabled(toggle nftables.Toggle) {
	if disabler, ok := a.backend.(ruleDisabler); ok {
		disabler.CommitToggleDisabled(toggle)
	}
}

// disabledCount is how many rules this backend is holding disabled, and
// whether that record has been saved. It is a header fact rather than a status
// message: a rule that is not being enforced and is not on disk either is a
// standing state of the machine, not the outcome of the last key press.
func (a *app) disabledCount() (count int, unsaved bool, ok bool) {
	saver, isSaver := a.backend.(tableSaver)
	if !isSaver {
		return 0, false, false
	}
	spec := saver.Spec()
	if spec.Empty() {
		return 0, false, false
	}
	return spec.Len(), saver.SpecDirty(), true
}

// disabledRow reports whether a row stands for a rule the backend is holding
// disabled rather than one the firewall is enforcing.
func disabledRow(rule firewall.Rule) bool {
	return rule.Extra[firewall.ExtraDisabled] != ""
}

// disabledTag renders the state column: the word on a rule that is not being
// enforced, and nothing on one that is. The eye should be drawn only to the
// rows that are switched off.
func disabledTag(rule firewall.Rule) string {
	if disabledRow(rule) {
		return nftables.DisabledMarker
	}
	return ""
}
