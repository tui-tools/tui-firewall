package main

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/iptables"
	"github.com/tui-tools/tui-kit/ui"
)

// persister is the part of a backend whose changes live in the running kernel
// only until they are written to the file its persistence layer restores at
// boot: the iptables backend and its demo. W runs its persist step, previewed
// with the diff it makes to the saved files; the header says whether the two
// have drifted apart.
type persister interface {
	PreparePersist(ctx context.Context) (firewall.Change, string, error)
	PersistState() iptables.Persistence
}

// persistReadyMsg carries the persist change once the running rules and the
// saved files have been read, with the diff between them.
type persistReadyMsg struct {
	change firewall.Change
	diff   string
	err    error
}

// beginPersist reads the running rules and the saved files off the update
// loop, and comes back through persistReadyMsg.
func (a *app) beginPersist(p persister) tea.Cmd {
	if a.awaitingKeep {
		a.setStatus(ui.StatusWarn,
			"an applied batch is waiting: press k to keep it before persisting")
		return nil
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		change, diff, err := p.PreparePersist(ctx)
		return persistReadyMsg{change: change, diff: diff, err: err}
	}
}

// openPersistConfirm previews the persist step: the command, and under it the
// diff between the saved files and what is running, so "what does persisting
// change" is answered before anything is written.
func (a *app) openPersistConfirm(msg persistReadyMsg) {
	if msg.diff == "" {
		a.setStatus(ui.StatusOK,
			"the saved rules already match the running ones; nothing to persist")
		return
	}
	body := "The running rules are written to the files restored at boot, " +
		"replacing what the diff below shows.\n" + msg.change.Note + "."
	if a.stagingOn && a.staging != nil && a.staging.Len() > 0 {
		body += "\nStaged changes that were not applied yet are not part of " +
			"this save."
	}
	a.pendingSave = true
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   msg.change.Description,
		Body:    body,
		Command: a.backend.Preview(msg.change) + "\n\n" + msg.diff,
		Payload: msg.change,
	}
}

// persistFact renders the header fact for a backend with a persistence layer:
// whether the running rules match the saved ones, and the key that saves them.
func (a *app) persistFact() (ui.Fact, bool) {
	p, ok := a.backend.(persister)
	if !ok {
		return ui.Fact{}, false
	}
	state := p.PersistState()
	if !state.Found() {
		style := a.theme.Danger
		return ui.Fact{Label: "saved", Value: "nothing restores these at boot",
			Style: &style}, true
	}
	drift := state.Drift
	switch {
	case !drift.Known:
		style := a.theme.Warn
		return ui.Fact{Label: "saved", Value: "unknown", Style: &style}, true
	case drift.InSync:
		return ui.Fact{Label: "saved", Value: "in sync"}, true
	default:
		style := a.theme.Warn
		return ui.Fact{Label: "saved",
			Value: fmt.Sprintf("differs: %s (W)", drift.Summary()), Style: &style}, true
	}
}
