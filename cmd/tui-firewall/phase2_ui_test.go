package main

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/nftables"
)

// TestAddFlowRuleThroughTheForm drives the add-rule form the way a router
// operator would: an interface match, the stateful default, and ICMP with a
// type — the three matches phase 2 added — and checks the preview is the rule
// they described.
func TestAddFlowRuleThroughTheForm(t *testing.T) {
	a, _ := newNftablesApp(t, 130, 30)
	send(t, a, "a")
	a.form.setFieldForTest("proto", "icmp")
	a.form.setFieldForTest("icmptype", "echo-request")
	a.form.setFieldForTest("iif", "wan0")
	a.form.setFieldForTest("ctstate", "established,related")
	// End on a text field so enter submits instead of opening a picker.
	a.form.setFieldForTest("comment", "ping from the wan")
	send(t, a, "enter")

	if a.mode != modeConfirm {
		t.Fatalf("the form should have opened a confirm, mode = %v", a.mode)
	}
	want := `iifname "wan0" ct state established,related ip protocol icmp ` +
		`icmp type echo-request counter accept`
	if !strings.Contains(a.confirm.Command, want) {
		t.Errorf("preview does not carry the flow rule:\n%s\nwant substring\n%s",
			a.confirm.Command, want)
	}
}

// TestAddKeyStartsTheAddForEachView is gap 7: pressing a in the NAT and alias
// views opens the actions those views add through, rather than a refusal that
// tells the user to press x.
func TestAddKeyStartsTheAddForEachView(t *testing.T) {
	a, _ := newNftablesApp(t, 120, 30)

	gotoView(t, a, nftables.GroupAliases)
	send(t, a, "a")
	if a.mode != modePicker {
		t.Fatalf("a in the alias view should open the actions menu, mode = %v", a.mode)
	}
	send(t, a, "esc")

	gotoView(t, a, nftables.GroupNAT)
	send(t, a, "a")
	if a.mode != modePicker {
		t.Fatalf("a in the NAT view should open the actions menu, mode = %v", a.mode)
	}
}

// TestDeleteTableThroughTheMenu is gap 4: the actions menu can take the tool's
// own table apart, previewed like any other mutation.
func TestDeleteTableThroughTheMenu(t *testing.T) {
	a, _ := newNftablesApp(t, 120, 30)
	send(t, a, "x")
	if !selectOption(t, a, "Delete the whole "+nftables.OwnTable.String()+" table") {
		t.Fatal("the actions menu does not offer deleting the table")
	}
	if a.mode != modeConfirm {
		t.Fatalf("deleting the table should preview a confirm, mode = %v", a.mode)
	}
	if !strings.Contains(a.confirm.Command, "delete table inet tui") {
		t.Errorf("the preview is not the table delete: %s", a.confirm.Command)
	}
}

// TestStagingIsNftablesOnly checks the gate: a backend that cannot snapshot its
// ruleset (ufw) has no staging, so the key is a no-op with an explanation.
func TestStagingIsNftablesOnly(t *testing.T) {
	a, _ := newTestApp(t, 100, 30)
	if a.staging != nil {
		t.Fatal("ufw has no rollback, so it should have no staging session")
	}
	send(t, a, "s")
	if a.stagingOn {
		t.Error("staging cannot be turned on where it is not supported")
	}
}

// TestStagingApplyThenKeep is the connectivity-safe apply, all the way through
// the UI: stage two changes, apply them as one transaction, and keep them.
func TestStagingApplyThenKeep(t *testing.T) {
	a, fake := newNftablesApp(t, 120, 30)
	send(t, a, "s")
	if !a.stagingOn {
		t.Fatal("staging did not turn on")
	}

	stageRule(t, a, "udp", "51820", "wireguard in")
	stageRule(t, a, "tcp", "8443", "console in")
	if a.staging.Len() != 2 {
		t.Fatalf("expected two staged changes, got %d", a.staging.Len())
	}
	// Nothing has been applied yet: the demo ruleset still lacks the new ports.
	if strings.Contains(renderInput(t, a), "wireguard in") {
		t.Fatal("a staged change must not be applied before the batch is")
	}

	applyStaged(t, a)
	if !a.awaitingKeep {
		t.Fatalf("after applying, the batch should await a keep; mode=%v", a.mode)
	}
	// Both changes are now live, and in one transaction.
	if !strings.Contains(renderInput(t, a), "wireguard in") ||
		!strings.Contains(renderInput(t, a), "console in") {
		t.Errorf("the applied batch is not in the ruleset:\n%s", renderInput(t, a))
	}

	send(t, a, "k")
	if a.awaitingKeep {
		t.Error("k should have confirmed the batch is kept")
	}
	if len(fake.Log) == 0 {
		t.Error("the apply should have run a command against the backend")
	}
	// The changes stay after the keep.
	if !strings.Contains(renderInput(t, a), "wireguard in") {
		t.Error("a kept batch must stay in place")
	}
}

// TestStagingRollsBackWhenKeepIsNeverGiven is the lockout case: the batch
// applied, the operator never confirmed, and the keep timer fired. The snapshot
// is restored, so the staged changes are gone again.
func TestStagingRollsBackWhenKeepIsNeverGiven(t *testing.T) {
	a, _ := newNftablesApp(t, 120, 30)
	send(t, a, "s")
	stageRule(t, a, "udp", "51820", "wireguard in")
	applyStaged(t, a)
	if !a.awaitingKeep {
		t.Fatal("the batch should be awaiting a keep")
	}
	if !strings.Contains(renderInput(t, a), "wireguard in") {
		t.Fatal("the batch should be applied while it awaits a keep")
	}

	// Drive the keep timer's expiry directly: the tick would take a real minute,
	// and the timer itself is unit-tested in the staging package.
	token := a.keepToken
	_, cmd := a.Update(keepExpiredMsg{token: token})
	for i := 0; i < 8 && cmd != nil; i++ {
		msg, ok := runFast(cmd)
		if !ok || msg == nil {
			break
		}
		_, cmd = a.Update(msg)
	}

	if a.awaitingKeep {
		t.Error("an expired keep window should have rolled back")
	}
	if strings.Contains(renderInput(t, a), "wireguard in") {
		t.Errorf("the rollback did not restore the snapshot:\n%s", renderInput(t, a))
	}
}

// stageRule adds one filter rule through the form, which stages it while
// staging mode is on.
func stageRule(t *testing.T, a *app, proto, ports, comment string) {
	t.Helper()
	send(t, a, "a")
	a.form.setFieldForTest("proto", proto)
	a.form.setFieldForTest("ports", ports)
	a.form.setFieldForTest("comment", comment)
	send(t, a, "enter")
	if a.mode == modeConfirm {
		t.Fatal("with staging on, a rule should be staged, not confirmed")
	}
}

// applyStaged opens the staging menu, applies the batch, and confirms the
// preview.
func applyStaged(t *testing.T, a *app) {
	t.Helper()
	send(t, a, "S")
	if a.mode != modePicker {
		t.Fatalf("S should open the staging menu, mode = %v", a.mode)
	}
	// The Apply entry is the first option and the one the picker opens on.
	send(t, a, "enter")
	if a.mode != modeConfirm {
		t.Fatalf("applying should preview a confirm, mode = %v", a.mode)
	}
	if !strings.HasPrefix(strings.TrimSpace(a.confirm.Command), "add rule") &&
		!strings.Contains(a.confirm.Command, "add rule") {
		t.Errorf("the apply preview should be the nft script, got:\n%s",
			a.confirm.Command)
	}
	send(t, a, "y")
}

// renderInput moves to the input chain view and returns it, for asserting on
// what the ruleset shows after a change.
func renderInput(t *testing.T, a *app) string {
	t.Helper()
	gotoView(t, a, "inet tui / input")
	return a.View()
}
