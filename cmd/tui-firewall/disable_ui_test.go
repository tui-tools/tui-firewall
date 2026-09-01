package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/nftables"
)

// disableRow presses D on the current selection and confirms, which is the
// whole gesture a user makes.
func disableRow(t *testing.T, a *app) {
	t.Helper()
	send(t, a, "D")
	if a.mode != modeConfirm {
		t.Fatalf("D should open the confirm dialog, mode = %v", a.mode)
	}
	send(t, a, "y")
}

func TestDisableKeyGreysTheRuleAndOffersTheSave(t *testing.T) {
	t.Setenv(nftables.SavePathEnv, filepath.Join(t.TempDir(), "tui-firewall.nft"))
	a, fake := newNftablesApp(t, 130, 30)
	gotoView(t, a, inputView)
	a.cursor = 4 // handle 14, the WAN ssh drop
	target, _ := a.selectedRule()

	send(t, a, "D")
	if a.mode != modeConfirm {
		t.Fatalf("D should open the confirm dialog, mode = %v", a.mode)
	}
	if !strings.Contains(a.confirm.Command, "nft delete rule inet tui input handle 14") {
		t.Errorf("the preview should show the delete:\n%s", a.confirm.Command)
	}
	if !strings.Contains(a.confirm.Body, "remembers it at position") {
		t.Errorf("the body should say what is remembered:\n%s", a.confirm.Body)
	}

	send(t, a, "y")
	if fake.Spec().Len() != 1 {
		t.Fatalf("the demo should hold one disabled rule, got %d", fake.Spec().Len())
	}
	if !fake.SpecDirty() {
		t.Error("the record is not on disk yet, so it should read as unsaved")
	}
	// The save is offered on its own, without another key press.
	if a.mode != modeConfirm || !a.pendingSave {
		t.Fatalf("disabling should offer the save, mode = %v pendingSave = %v",
			a.mode, a.pendingSave)
	}
	if !strings.Contains(a.confirm.Command, nftables.DisabledMarker) {
		t.Errorf("the save preview should carry the disabled rule:\n%s", a.confirm.Command)
	}

	// Decline the save and look at the table: the rule is still a row, marked.
	send(t, a, "n")
	row, ok := a.selectedRule()
	if !ok {
		t.Fatal("the selection should still be on a row")
	}
	_ = row
	found := false
	for _, r := range a.visible {
		if r.Extra[firewall.ExtraDisabled] == "" {
			continue
		}
		found = true
		if !nftables.DisabledID(r.ID) {
			t.Errorf("a disabled row is named by the spec, got %q", r.ID)
		}
		if r.Ports != target.Ports || r.Comment != target.Comment {
			t.Errorf("the disabled row should still describe the rule: %+v", r)
		}
	}
	if !found {
		t.Fatal("the disabled rule should still be a row in the chain view")
	}

	out := a.View()
	for _, want := range []string{"STATE", nftables.DisabledMarker,
		"1 disabled, unsaved (W)"} {
		if !strings.Contains(out, want) {
			t.Errorf("the screen should carry %q:\n%s", want, out)
		}
	}
}

func TestDisableThenEnableFromTheUIPutsTheRuleBack(t *testing.T) {
	t.Setenv(nftables.SavePathEnv, filepath.Join(t.TempDir(), "tui-firewall.nft"))
	a, fake := newNftablesApp(t, 130, 30)
	gotoView(t, a, inputView)
	before := len(a.visible)
	a.cursor = 4
	target, _ := a.selectedRule()

	disableRow(t, a)
	send(t, a, "n") // decline the offered save

	// Put the cursor on the disabled row and toggle it back.
	index := -1
	for i, r := range a.visible {
		if r.Extra[firewall.ExtraDisabled] != "" {
			index = i
		}
	}
	if index < 0 {
		t.Fatal("no disabled row to enable")
	}
	a.cursor = index
	send(t, a, "D")
	if a.mode != modeConfirm {
		t.Fatalf("D on a disabled row should open the confirm, mode = %v", a.mode)
	}
	if !strings.Contains(a.confirm.Command, "nft insert rule inet tui input index 4") {
		t.Errorf("enabling should insert at the recorded position:\n%s", a.confirm.Command)
	}
	send(t, a, "y")
	send(t, a, "n") // decline the offered save again

	if !fake.Spec().Empty() {
		t.Errorf("enabling should have emptied the spec, %d left", fake.Spec().Len())
	}
	if len(a.visible) != before {
		t.Fatalf("the chain should be back to %d rows, got %d", before, len(a.visible))
	}
	back := a.visible[4]
	if back.Extra[firewall.ExtraDisabled] != "" {
		t.Error("the rule at position 5 should be live again")
	}
	if back.Ports != target.Ports || back.Comment != target.Comment {
		t.Errorf("the rule did not come back where it was: %+v", back)
	}
}

func TestSavingAfterADisableClearsTheUnsavedMark(t *testing.T) {
	t.Setenv(nftables.SavePathEnv, filepath.Join(t.TempDir(), "tui-firewall.nft"))
	a, fake := newNftablesApp(t, 130, 30)
	gotoView(t, a, inputView)
	a.cursor = 4

	disableRow(t, a)
	send(t, a, "y") // accept the offered save
	if fake.SpecDirty() {
		t.Error("saving should have cleared the unsaved mark")
	}
	spec, err := nftables.ParseSpec(fake.Saved)
	if err != nil {
		t.Fatalf("what was saved should parse: %v", err)
	}
	if spec.Len() != 1 {
		t.Errorf("the saved file should carry the disabled rule, got %d", spec.Len())
	}
	if !strings.Contains(a.View(), "1 disabled") ||
		strings.Contains(a.View(), "unsaved (W)") {
		t.Errorf("the header should read as saved:\n%s", a.View())
	}
}

func TestDisableIsRefusedWhileStagingCollects(t *testing.T) {
	a, _ := newNftablesApp(t, 130, 30)
	gotoView(t, a, inputView)
	a.cursor = 4
	send(t, a, "s") // staging on

	send(t, a, "D")
	if a.mode != modeTable {
		t.Fatalf("disabling should be refused, not staged; mode = %v", a.mode)
	}
	if !strings.Contains(a.status, "not staged") {
		t.Errorf("status = %q", a.status)
	}
}

func TestDisableIsNotOfferedOnUFW(t *testing.T) {
	a, _ := newTestApp(t, 100, 24)
	send(t, a, "D")
	if !strings.Contains(a.status, "no disabled state") {
		t.Errorf("ufw should say it has no disabled state, status = %q", a.status)
	}
	if strings.Contains(a.View(), "D disable") {
		t.Error("the help bar should not offer D on a backend that has no disable")
	}
}
