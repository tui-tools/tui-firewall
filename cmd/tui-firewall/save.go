package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/nftables"
	"github.com/tui-tools/tui-kit/ui"
)

// tableSaver is the part of a backend the Save action needs: a serialisation
// of the table this tool owns, as text `nft -f` can load back. The nftables
// backend and its demo implement it; ufw and firewalld persist through their
// own daemons and need no file from us.
type tableSaver interface {
	SnapshotOwnTable(ctx context.Context) (string, error)
}

// saveReadyMsg carries the capture once it has been read off the machine: the
// install command to confirm, and the diff against the file as it stands.
type saveReadyMsg struct {
	change firewall.Change
	diff   string
	path   string
	err    error
}

// beginSave captures the owned table and prepares the install command. The
// capture is a privileged read that can block, so it runs off the update loop
// and comes back through saveReadyMsg.
func (a *app) beginSave() tea.Cmd {
	saver, ok := a.backend.(tableSaver)
	if !ok {
		a.setStatus(ui.StatusWarn,
			"saving the ruleset to a file is an nftables feature; ufw and "+
				"firewalld persist their own configuration")
		return nil
	}
	if a.awaitingKeep {
		a.setStatus(ui.StatusWarn,
			"an applied batch is waiting: press k to keep it before saving")
		return nil
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		listing, err := saver.SnapshotOwnTable(ctx)
		if err != nil {
			return saveReadyMsg{err: fmt.Errorf(
				"could not capture table %s to save it: %w", nftables.OwnTable, err)}
		}
		path, bootNote := nftables.SavePath()
		change, err := nftables.BuildSave(listing, path, bootNote)
		if err != nil {
			return saveReadyMsg{err: err}
		}
		diff := nftables.UnifiedDiff(currentSaveFile(path),
			strings.TrimSpace(listing)+"\n", path, "the capture to save")
		return saveReadyMsg{change: change, diff: diff, path: path}
	}
}

// currentSaveFile reads what the save path holds now, for the diff the preview
// shows. A file that is missing or unreadable diffs as empty, which renders
// every captured line as an addition — exactly what installing it would do.
func currentSaveFile(path string) string {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the vetted save location (constant or the TUI_FIREWALL_SAVE_PATH override), read only to render the preview diff
	if err != nil {
		return ""
	}
	return string(data)
}

// openSaveConfirm previews the save: the install command, and under it the
// unified diff between the file as it stands and the capture about to replace
// it, so "what does saving change" is answered before anything is written.
//
// Save never joins a staged batch: the batch is an nft transaction and this is
// a file write, and mixing the two would make the atomic apply a lie. What it
// writes is the running table — a staged change that was not applied yet is
// not in the file, and the body says so while staging is collecting.
func (a *app) openSaveConfirm(msg saveReadyMsg) {
	if msg.diff == "" {
		a.setStatusf(ui.StatusOK, "%s already matches the running table %s",
			msg.path, nftables.OwnTable)
		return
	}
	body := fmt.Sprintf(
		"The running table %s is written to %s, replacing the file shown in "+
			"the diff below.\n%s.", nftables.OwnTable, msg.path, msg.change.Note)
	if a.stagingOn && a.staging != nil && a.staging.Len() > 0 {
		body += "\nStaged changes that were not applied yet are not part of " +
			"this file."
	}
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   msg.change.Description,
		Body:    body,
		Command: a.backend.Preview(msg.change) + "\n\n" + msg.diff,
		Payload: msg.change,
	}
}
