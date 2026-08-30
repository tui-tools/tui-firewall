package main

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/firewalld"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/theme"
)

// newFirewalldApp builds the app over the firewalld demo, which is the same
// backend `--demo=firewalld` runs, so what these tests exercise is what a
// reader sees on that screen.
func newFirewalldApp(t *testing.T, width, height int) (*app, *firewalld.Fake) {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	fake := firewalld.NewFake()
	a := newApp(fake, theme.FromPalette(theme.TokyoNight()), compat.Result{})
	a.width, a.height = width, height
	a.Update(a.Init()())
	return a, fake
}

// previewOf returns the command preview of the open confirm dialog.
func previewOf(t *testing.T, a *app) string {
	t.Helper()
	if a.mode != modeConfirm {
		t.Fatalf("no confirm dialog is open (mode %v): %s", a.mode, a.status)
	}
	return a.confirm.Command
}

func TestFirewalldDemoRendersZonesAndScopes(t *testing.T) {
	a, _ := newFirewalldApp(t, 110, 30)
	out := a.View()

	for _, want := range []string{
		"tui-firewall", "firewalld", "public", "Zone:", "KIND", "WHERE",
		"service", "interface", "runtime only", "log denied",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the firewalld frame should mention %q\n%s", want, out)
		}
	}
	// The zone selector only appears because firewalld has several groups.
	if !strings.Contains(out, "switches") {
		t.Error("a multi-zone backend should offer the group selector")
	}
}

func TestFirewalldResponsiveColumns(t *testing.T) {
	// The kind column replaces the direction one, which firewalld does not
	// use; the frame must still fit at every width.
	for _, size := range [][2]int{{20, 6}, {40, 10}, {80, 24}, {110, 30}, {200, 60}} {
		a, _ := newFirewalldApp(t, size[0], size[1])
		frame := a.View()
		if frame == "" {
			t.Fatalf("size %v produced an empty frame", size)
		}
		// A terminal narrower than the fixed columns cannot be honoured by
		// any table; from a usable width on, no line may overflow.
		if size[0] < 40 {
			continue
		}
		for _, line := range strings.Split(frame, "\n") {
			if width := len([]rune(line)); width > size[0] {
				t.Errorf("size %v: a line is %d columns wide: %q",
					size, width, line)
			}
		}
	}
}

func TestFirewalldAddServicePreviewsBothLines(t *testing.T) {
	a, _ := newFirewalldApp(t, 110, 30)

	send(t, a, "a")
	if a.mode != modeForm {
		t.Fatalf("expected the add form, got mode %v", a.mode)
	}
	// Action defaults to ALLOW; choose a service, then submit from a text
	// field — enter on a choice field opens its picker instead.
	a.form.setFieldForTest("service", "wireguard")
	a.form.setFieldForTest("ports", "")
	send(t, a, "enter")

	preview := previewOf(t, a)
	for _, want := range []string{
		"firewall-cmd --zone=public --add-service=wireguard",
		"firewall-cmd --permanent --zone=public --add-service=wireguard",
	} {
		if !strings.Contains(preview, want) {
			t.Errorf("preview should contain %q, got:\n%s", want, preview)
		}
	}
	if !strings.Contains(a.confirm.Body, "no reload") {
		t.Errorf("the dialog should say how the change is applied: %q", a.confirm.Body)
	}
}

func TestFirewalldDeleteRemovesFromBothConfigurations(t *testing.T) {
	a, fake := newFirewalldApp(t, 110, 30)

	// Find the ssh service rule and put the cursor on it.
	index := -1
	for i, rule := range a.visible {
		if rule.Kind == firewall.KindService && rule.Raw == "ssh" {
			index = i
			break
		}
	}
	if index < 0 {
		t.Fatal("the demo should have an ssh service in the default zone")
	}
	a.cursor = index

	send(t, a, "d")
	preview := previewOf(t, a)
	if !strings.Contains(preview, "--remove-service=ssh") ||
		!strings.Contains(preview, "--permanent --zone=public --remove-service=ssh") {
		t.Errorf("preview:\n%s", preview)
	}

	send(t, a, "y")
	if len(fake.Log) != 2 {
		t.Fatalf("ran %d commands, want the runtime and the permanent one", len(fake.Log))
	}
	for _, rule := range a.visible {
		if rule.Kind == firewall.KindService && rule.Raw == "ssh" {
			t.Error("ssh should be gone from both configurations")
		}
	}
}

func TestFirewalldDeleteOfARuntimeOnlyEntryStaysRuntime(t *testing.T) {
	a, fake := newFirewalldApp(t, 110, 30)

	index := -1
	for i, rule := range a.visible {
		if rule.Note == "runtime only" {
			index = i
			break
		}
	}
	if index < 0 {
		t.Fatal("the demo should have a runtime-only entry")
	}
	a.cursor = index

	send(t, a, "d")
	preview := previewOf(t, a)
	if strings.Contains(preview, "--permanent") {
		t.Errorf("a runtime-only entry must not be removed permanently:\n%s", preview)
	}

	send(t, a, "y")
	if len(fake.Log) != 1 {
		t.Errorf("ran %d commands, want 1", len(fake.Log))
	}
}

func TestFirewalldEnableKeyExplainsItself(t *testing.T) {
	a, fake := newFirewalldApp(t, 110, 30)
	send(t, a, "e")
	if a.mode == modeConfirm {
		t.Fatal("firewalld must not be started or stopped from here")
	}
	if !strings.Contains(a.status, "systemctl") {
		t.Errorf("status = %q, want it to point at systemctl", a.status)
	}
	if len(fake.Log) != 0 {
		t.Error("nothing should have run")
	}
}

func TestFirewalldTargetChangeIsPermanentPlusReload(t *testing.T) {
	a, _ := newFirewalldApp(t, 110, 30)

	send(t, a, "p") // policy slot picker: firewalld has exactly one, "target"
	send(t, a, "enter")
	// Pick DROP from the target list.
	for a.picker.Selected() != firewalld.TargetDrop {
		send(t, a, "down")
	}
	send(t, a, "enter")

	preview := previewOf(t, a)
	if !strings.Contains(preview, "--permanent --zone=public --set-target=DROP") ||
		!strings.Contains(preview, "firewall-cmd --reload") {
		t.Errorf("preview:\n%s", preview)
	}
}

func TestFirewalldActionsMenuRunsPanicMode(t *testing.T) {
	a, fake := newFirewalldApp(t, 110, 30)

	send(t, a, "x")
	if a.mode != modePicker {
		t.Fatalf("expected the actions menu, got mode %v", a.mode)
	}
	for !strings.Contains(a.picker.Selected(), "panic mode ON") {
		send(t, a, "down")
	}
	send(t, a, "enter")

	if !strings.Contains(previewOf(t, a), "firewall-cmd --panic-on") {
		t.Errorf("preview = %q", previewOf(t, a))
	}
	if !strings.Contains(a.confirm.Body, "SSH session") {
		t.Errorf("panic mode needs its warning: %q", a.confirm.Body)
	}

	send(t, a, "y")
	if len(fake.Log) != 1 {
		t.Fatalf("ran %d commands, want 1", len(fake.Log))
	}
	if a.model.Warning != firewalld.PanicWarning {
		t.Errorf("warning = %q, want the panic banner", a.model.Warning)
	}
	if !strings.Contains(a.View(), "panic mode is on") {
		t.Error("panic mode must be visible on the screen")
	}
}

func TestFirewalldActionsMenuCollectsTwoAnswers(t *testing.T) {
	a, fake := newFirewalldApp(t, 110, 30)

	send(t, a, "x")
	for !strings.Contains(a.picker.Selected(), "Move an interface") {
		send(t, a, "down")
	}
	send(t, a, "enter") // choose the action, opening the interface picker
	for a.picker.Selected() != "eth1" {
		send(t, a, "down")
	}
	send(t, a, "enter") // interface chosen, the zone picker opens
	for a.picker.Selected() != "trusted" {
		send(t, a, "down")
	}
	send(t, a, "enter")

	preview := previewOf(t, a)
	if !strings.Contains(preview, "--zone=trusted --change-interface=eth1") {
		t.Errorf("preview:\n%s", preview)
	}

	send(t, a, "y")
	if len(fake.Log) != 2 {
		t.Fatalf("ran %d commands, want the runtime and the permanent one", len(fake.Log))
	}
	trusted, ok := a.model.Group("trusted")
	if !ok {
		t.Fatal("no trusted zone")
	}
	found := false
	for _, rule := range trusted.Rules {
		if rule.Kind == firewall.KindInterface && rule.Raw == "eth1" {
			found = true
		}
	}
	if !found {
		t.Error("eth1 should now belong to the trusted zone")
	}
}

func TestFirewalldActionsMenuAsksForFreeText(t *testing.T) {
	a, _ := newFirewalldApp(t, 110, 30)

	send(t, a, "x")
	for !strings.Contains(a.picker.Selected(), "Bind a source") {
		send(t, a, "down")
	}
	send(t, a, "enter")
	if a.mode != modePrompt {
		t.Fatalf("expected a text prompt, got mode %v", a.mode)
	}
	for _, r := range "10.9.0.0/16" {
		send(t, a, string(r))
	}
	send(t, a, "enter")

	if !strings.Contains(previewOf(t, a), "--add-source=10.9.0.0/16") {
		t.Errorf("preview:\n%s", previewOf(t, a))
	}
}

func TestFirewalldGroupSwitchingWalksTheZones(t *testing.T) {
	a, _ := newFirewalldApp(t, 110, 30)
	if a.group != "public" {
		t.Fatalf("group = %q, want the default zone first", a.group)
	}
	send(t, a, "]")
	if a.group == "public" {
		t.Error("] should move to the next zone")
	}
	send(t, a, "[")
	if a.group != "public" {
		t.Errorf("[ should come back, got %q", a.group)
	}
}

func TestFirewalldReloadWarnsAboutRuntimeOnlyEntries(t *testing.T) {
	a, _ := newFirewalldApp(t, 110, 30)
	send(t, a, "r")
	if !strings.Contains(a.confirm.Body, "runtime-only") {
		t.Errorf("body = %q", a.confirm.Body)
	}
	if !a.confirm.Danger {
		t.Error("a reload can drop connections, so it is a danger dialog")
	}
}
