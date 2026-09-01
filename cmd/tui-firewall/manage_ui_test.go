package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/nftables"
)

const inputView = "inet tui / input"

func TestSaveKeyPreviewsTheDiffAndInstalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tui-firewall.nft")
	t.Setenv(nftables.SavePathEnv, path)
	a, fake := newNftablesApp(t, 120, 30)

	send(t, a, "W")
	if a.mode != modeConfirm {
		t.Fatalf("W should open the save confirm, mode = %v", a.mode)
	}
	for _, want := range []string{
		"install -m 644 /dev/stdin " + path,
		"+table inet tui {",
	} {
		if !strings.Contains(a.confirm.Command, want) {
			t.Errorf("the save preview should carry %q:\n%s", want, a.confirm.Command)
		}
	}
	if !strings.Contains(a.confirm.Body, nftables.SavePathEnv) {
		t.Errorf("the body should carry the boot note:\n%s", a.confirm.Body)
	}

	send(t, a, "y")
	if fake.SavedPath != path {
		t.Errorf("confirming should have run the install, SavedPath = %q", fake.SavedPath)
	}
	if !strings.Contains(fake.Saved, "table inet tui {") {
		t.Errorf("the demo should have recorded the capture:\n%s", fake.Saved)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("the demo must not write the file")
	}
}

func TestSaveReportsAnUnchangedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tui-firewall.nft")
	t.Setenv(nftables.SavePathEnv, path)
	a, fake := newNftablesApp(t, 120, 30)

	// Pretend a previous save already wrote exactly the current capture.
	listing, err := fake.SnapshotOwnTable(t.Context())
	if err != nil {
		t.Fatalf("SnapshotOwnTable: %v", err)
	}
	content := strings.TrimSpace(listing) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("seeding the save file: %v", err)
	}

	send(t, a, "W")
	if a.mode != modeTable {
		t.Fatalf("an up-to-date file needs no dialog, mode = %v", a.mode)
	}
	if !strings.Contains(a.status, "already matches") {
		t.Errorf("status = %q", a.status)
	}
}

func TestEditKeyOpensThePrefilledFormAndReplaces(t *testing.T) {
	a, _ := newNftablesApp(t, 130, 30)
	gotoView(t, a, inputView)
	a.cursor = 4 // handle 14, the WAN ssh drop

	send(t, a, "E")
	if a.mode != modeForm {
		t.Fatalf("E should open the form, mode = %v", a.mode)
	}
	if !strings.Contains(a.form.title, "handle 14") {
		t.Errorf("the form should say what it replaces: %q", a.form.title)
	}
	for key, want := range map[string]string{
		"action": "DENY", "iif": "wan0", "proto": "tcp", "ports": "22",
		"comment": "no ssh from the wan",
	} {
		if got := a.form.get(key); got != want {
			t.Errorf("prefilled %s = %q, want %q", key, got, want)
		}
	}

	a.form.setFieldForTest("ports", "2222")
	a.form.setFieldForTest("comment", "no ssh from the wan")
	send(t, a, "enter")
	if a.mode != modeConfirm {
		t.Fatalf("submitting the edit should open a confirm, mode = %v", a.mode)
	}
	for _, want := range []string{
		"replace rule inet tui input handle 14", "tcp dport 2222",
	} {
		if !strings.Contains(a.confirm.Command, want) {
			t.Errorf("the edit preview should carry %q:\n%s", want, a.confirm.Command)
		}
	}
	if a.editing {
		t.Error("submitting must clear the editing state")
	}
}

func TestEditEscClearsTheEditingState(t *testing.T) {
	a, _ := newNftablesApp(t, 130, 30)
	gotoView(t, a, inputView)
	a.cursor = 4
	send(t, a, "E")
	send(t, a, "esc")
	if a.editing {
		t.Error("esc must clear the editing state")
	}
	// The next a is a plain add again.
	send(t, a, "a")
	if a.form.title != "Add rule" {
		t.Errorf("after an aborted edit, a opens a plain add form: %q", a.form.title)
	}
}

func TestEditRefusesARuleItCannotRebuild(t *testing.T) {
	a, _ := newNftablesApp(t, 130, 30)
	gotoView(t, a, inputView)
	a.cursor = 6 // handle 16, the log-only tail rule with a level
	send(t, a, "E")
	if a.mode != modeTable {
		t.Fatalf("the refusal happens before the form opens, mode = %v", a.mode)
	}
	if !strings.Contains(a.status, "handle 16") {
		t.Errorf("the refusal should name the rule: %q", a.status)
	}
}

func TestMoveKeysBuildOneAtomicTransaction(t *testing.T) {
	a, fake := newNftablesApp(t, 130, 30)
	gotoView(t, a, inputView)
	a.cursor = 1 // handle 11, "keep state"

	send(t, a, "J")
	if a.mode != modeConfirm {
		t.Fatalf("J should open the move confirm, mode = %v", a.mode)
	}
	for _, want := range []string{
		"add rule inet tui input index 2",
		"delete rule inet tui input handle 11",
	} {
		if !strings.Contains(a.confirm.Command, want) {
			t.Errorf("the move preview should carry %q:\n%s", want, a.confirm.Command)
		}
	}
	change, ok := a.confirm.Payload.(firewall.Change)
	if !ok || len(change.Commands) != 1 ||
		strings.Join(change.Commands[0].Argv, " ") != "nft -f -" {
		t.Fatalf("the move must run as one nft -f, got %+v", change)
	}

	send(t, a, "y")
	chain, _ := fake.Ruleset().Chain(nftables.OwnTable, "input")
	if chain.Rules[2].Comment != "keep state" {
		t.Errorf("the rule should now sit one position lower, position 3 is %q",
			chain.Rules[2].Comment)
	}
}

func TestMoveRefusesTheFirstRuleUp(t *testing.T) {
	a, _ := newNftablesApp(t, 130, 30)
	gotoView(t, a, inputView)
	a.cursor = 0
	send(t, a, "K")
	if a.mode != modeTable {
		t.Fatalf("a refused move opens nothing, mode = %v", a.mode)
	}
	if !strings.Contains(a.status, "already first") {
		t.Errorf("status = %q", a.status)
	}
}

func TestMoveJoinsTheStagedBatch(t *testing.T) {
	a, _ := newNftablesApp(t, 130, 30)
	gotoView(t, a, inputView)
	a.cursor = 1
	send(t, a, "s") // staging on
	send(t, a, "J")
	if a.staging.Len() != 1 {
		t.Fatalf("with staging on a move is staged, pending = %d", a.staging.Len())
	}
	if a.mode != modeTable {
		t.Errorf("staging a move opens no dialog, mode = %v", a.mode)
	}
}

func TestManageKeysRefuseOnBackendsWithoutThem(t *testing.T) {
	a, _ := newTestApp(t, 100, 30) // the ufw demo
	for _, key := range []string{"E", "W", "K", "J"} {
		send(t, a, key)
		if a.mode != modeTable {
			t.Fatalf("%s on ufw should only set a status, mode = %v", key, a.mode)
		}
		if a.status == "" {
			t.Errorf("%s on ufw should explain itself", key)
		}
	}
}
