package main

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/ufw"
	"github.com/tui-tools/tui-kit/theme"
)

// newTestApp builds the demo app at a fixed size, with colors disabled so
// assertions can look for plain text.
func newTestApp(t *testing.T, width, height int) (*app, *ufw.Fake) {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	fake := ufw.NewFake()
	a := newApp(fake, theme.FromPalette(theme.TokyoNight()))
	a.width, a.height = width, height
	// Drain Init's load command synchronously: the fake never blocks.
	msg := a.Init()()
	a.Update(msg)
	return a, fake
}

// send delivers a key and applies any resulting message, which keeps the
// tests synchronous.
func send(t *testing.T, a *app, key string) {
	t.Helper()
	_, cmd := a.Update(keyMsg(key))
	// A handful of rounds is plenty: load → reload is the longest chain.
	for i := 0; i < 8 && cmd != nil; i++ {
		msg, ok := runFast(cmd)
		if !ok || msg == nil {
			return
		}
		_, cmd = a.Update(msg)
	}
}

// runFast executes a command and returns its message, giving up on the ones
// that block on purpose (the text input's cursor blink), which no test cares
// about. The fake backend answers instantly, so the timeout never trips on a
// message a test is waiting for.
func runFast(cmd tea.Cmd) (tea.Msg, bool) {
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	select {
	case msg := <-done:
		return msg, true
	case <-time.After(200 * time.Millisecond):
		return nil, false
	}
}

// keyMsg builds the tea.KeyMsg for a key name.
func keyMsg(name string) tea.KeyMsg {
	switch name {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(name)}
	}
}

func TestDemoRendersFirstFrame(t *testing.T) {
	a, _ := newTestApp(t, 100, 30)
	out := a.View()

	for _, want := range []string{
		"tui-firewall", "demo", "enabled", "incoming", "logging",
		"ACTION", "22/tcp", "Nginx Full", "10.0.0.0/8",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the first frame should mention %q\n%s", want, out)
		}
	}
}

func TestResponsiveColumns(t *testing.T) {
	wide, _ := newTestApp(t, 120, 30)
	narrow, _ := newTestApp(t, 60, 30)

	if !strings.Contains(wide.View(), "COMMENT") {
		t.Error("a wide terminal should show the comment column")
	}
	if strings.Contains(narrow.View(), "COMMENT") {
		t.Error("a narrow terminal should drop the comment column")
	}

	// A tiny terminal must still render without panicking.
	for _, size := range [][2]int{{20, 6}, {40, 10}, {200, 60}} {
		a, _ := newTestApp(t, size[0], size[1])
		if a.View() == "" {
			t.Errorf("size %v produced an empty frame", size)
		}
	}
}

func TestFilterRules(t *testing.T) {
	a, _ := newTestApp(t, 100, 30)
	total := len(a.visible)

	send(t, a, "/")
	for _, r := range "5432" {
		send(t, a, string(r))
	}
	if len(a.visible) >= total || len(a.visible) == 0 {
		t.Fatalf("filter kept %d of %d rules", len(a.visible), total)
	}
	send(t, a, "enter")
	if a.mode != modeTable {
		t.Error("enter should close the filter prompt")
	}
	if !strings.Contains(a.View(), "5432") {
		t.Error("the filtered table should show the matching rule")
	}

	// Cancelling the prompt clears the filter.
	send(t, a, "/")
	send(t, a, "esc")
	if a.filter != "" || len(a.visible) != total {
		t.Errorf("esc should clear the filter, got %q with %d rules",
			a.filter, len(a.visible))
	}
}

func TestDeleteAsksForConfirmationAndPreviewsCommand(t *testing.T) {
	a, fake := newTestApp(t, 100, 30)
	send(t, a, "d")

	if a.mode != modeConfirm {
		t.Fatal("d should open the confirm dialog")
	}
	out := a.View()
	if !strings.Contains(out, "ufw --force delete 1") {
		t.Errorf("the dialog must preview the exact command\n%s", out)
	}
	if len(fake.Log) != 0 {
		t.Fatal("nothing may run before the user confirms")
	}

	// Cancelling runs nothing.
	send(t, a, "n")
	if len(fake.Log) != 0 {
		t.Fatal("cancelling must not run the command")
	}
	if a.mode != modeTable {
		t.Error("the dialog should be closed")
	}

	// Confirming runs exactly one command.
	before := len(a.visible)
	send(t, a, "d")
	send(t, a, "y")
	if len(fake.Log) != 1 {
		t.Fatalf("len(Log) = %d, want 1", len(fake.Log))
	}
	if got := fake.Log[0].String(); got != "ufw --force delete 1" {
		t.Errorf("ran %q", got)
	}
	if len(a.visible) != before-1 {
		t.Errorf("the view should reload after the change: %d rules, want %d",
			len(a.visible), before-1)
	}
}

func TestToggleEnablePreviewsCommand(t *testing.T) {
	a, fake := newTestApp(t, 100, 30)
	send(t, a, "e")

	out := a.View()
	if !strings.Contains(out, "ufw disable") {
		t.Errorf("the dialog must preview the disable command\n%s", out)
	}
	if !strings.Contains(out, "All traffic will be allowed") {
		t.Error("the dialog should explain the consequence")
	}
	send(t, a, "y")

	if a.model.Enabled {
		t.Error("the firewall should be disabled after confirming")
	}
	if !strings.Contains(a.View(), "disabled") {
		t.Error("the header should report the new state")
	}

	// Enabling again warns about SSH.
	send(t, a, "e")
	if !strings.Contains(a.View(), "SSH") {
		t.Error("enabling should warn about locking out the SSH session")
	}
	send(t, a, "y")
	if !a.model.Enabled {
		t.Error("the firewall should be enabled again")
	}
	if len(fake.Log) != 2 {
		t.Errorf("len(Log) = %d, want 2", len(fake.Log))
	}
}

func TestLoggingPickerBuildsCommand(t *testing.T) {
	a, fake := newTestApp(t, 100, 30)
	send(t, a, "L")
	if a.mode != modePicker {
		t.Fatal("L should open the logging picker")
	}
	// The picker starts on the current level (low); move to medium.
	send(t, a, "down")
	send(t, a, "enter")

	if a.mode != modeConfirm {
		t.Fatal("choosing a level should open the confirm dialog")
	}
	if !strings.Contains(a.View(), "ufw logging medium") {
		t.Errorf("unexpected preview\n%s", a.View())
	}
	send(t, a, "y")
	if a.model.Logging != ufw.LogMedium {
		t.Errorf("Logging = %q, want medium", a.model.Logging)
	}
	if len(fake.Log) != 1 {
		t.Errorf("len(Log) = %d, want 1", len(fake.Log))
	}
}

func TestPolicyFlowIsTwoSteps(t *testing.T) {
	a, fake := newTestApp(t, 100, 30)
	send(t, a, "p")
	if a.mode != modePicker {
		t.Fatal("p should open the policy slot picker")
	}
	// First pick the slot (incoming), then the value.
	send(t, a, "enter")
	if a.mode != modePicker {
		t.Fatal("the value picker should follow the slot picker")
	}
	if a.pendingSlot != firewall.PolicyIncoming {
		t.Errorf("pendingSlot = %q, want incoming", a.pendingSlot)
	}
	// Options are allow/deny/reject and the cursor sits on the current deny.
	send(t, a, "up")
	send(t, a, "enter")
	if !strings.Contains(a.View(), "ufw default allow incoming") {
		t.Errorf("unexpected preview\n%s", a.View())
	}
	send(t, a, "y")

	group, _ := a.model.Group(a.group)
	if group.Default.Incoming != firewall.PolicyAllow {
		t.Errorf("incoming = %q, want allow", group.Default.Incoming)
	}
	if len(fake.Log) != 1 {
		t.Errorf("len(Log) = %d, want 1", len(fake.Log))
	}
}

func TestAddRuleFormBuildsCommand(t *testing.T) {
	a, fake := newTestApp(t, 100, 34)
	send(t, a, "a")
	if a.mode != modeForm {
		t.Fatal("a should open the rule form")
	}
	if !strings.Contains(a.View(), "Add rule") {
		t.Error("the form should be titled")
	}

	// Action: ALLOW is first; move to DENY with the right arrow.
	send(t, a, "right")
	// Move to the ports field and type a port.
	for a.form.fields[a.form.active].key != "ports" {
		send(t, a, "tab")
	}
	for _, r := range "8080" {
		send(t, a, string(r))
	}
	// Protocol is the next field: cycle from (none) to tcp.
	send(t, a, "tab")
	send(t, a, "right")
	// Submit from a text field.
	for a.form.fields[a.form.active].key != "from" {
		send(t, a, "tab")
	}
	send(t, a, "enter")

	if a.mode != modeConfirm {
		t.Fatalf("submitting should open the confirm dialog, mode = %v", a.mode)
	}
	if !strings.Contains(a.View(), "ufw deny 8080/tcp") {
		t.Errorf("unexpected preview\n%s", a.View())
	}
	send(t, a, "y")

	if len(fake.Log) != 1 {
		t.Fatalf("len(Log) = %d, want 1", len(fake.Log))
	}
	added := a.visible[len(a.visible)-1]
	if added.Ports != "8080" || added.Action != firewall.ActionDeny {
		t.Errorf("added rule = %+v", added)
	}
}

func TestAddRuleFormRejectsIncompleteSpec(t *testing.T) {
	a, fake := newTestApp(t, 100, 34)
	send(t, a, "a")
	// Submit with nothing but the default action selected.
	for a.form.fields[a.form.active].key != "from" {
		send(t, a, "tab")
	}
	send(t, a, "enter")

	if a.mode == modeConfirm {
		t.Fatal("an incomplete rule must not reach the confirm dialog")
	}
	if !strings.Contains(a.status, "at least") {
		t.Errorf("status = %q, want an explanation", a.status)
	}
	if len(fake.Log) != 0 {
		t.Error("nothing may run")
	}
}

func TestAppProfilePickerFillsTheField(t *testing.T) {
	a, _ := newTestApp(t, 100, 34)
	send(t, a, "a")
	for a.form.fields[a.form.active].key != "service" {
		send(t, a, "tab")
	}
	// Enter on a choice field opens the picker.
	send(t, a, "enter")
	if a.mode != modePicker {
		t.Fatal("enter on the app profile field should open the picker")
	}
	if !strings.Contains(a.View(), "OpenSSH") {
		t.Error("the picker should list the demo app profiles")
	}
	// (none) is first; pick the next entry.
	send(t, a, "down")
	send(t, a, "enter")

	if a.mode != modeForm {
		t.Fatal("the picker should return to the form")
	}
	if got := a.form.get("service"); got != "CUPS" {
		t.Errorf("service = %q, want CUPS", got)
	}
}

func TestHelpScreen(t *testing.T) {
	a, _ := newTestApp(t, 100, 34)
	send(t, a, "?")
	out := a.View()
	if !strings.Contains(out, "previewed and confirmed") {
		t.Errorf("the help screen should state the safety rule\n%s", out)
	}
	send(t, a, "q")
	if a.mode != modeTable {
		t.Error("any key should close the help screen")
	}
}

func TestSingleGroupHidesTheSelector(t *testing.T) {
	a, _ := newTestApp(t, 120, 30)
	if len(a.model.Groups) != 1 {
		t.Fatalf("the ufw demo should expose one group, got %d", len(a.model.Groups))
	}
	if strings.Contains(a.View(), "to switch") {
		t.Error("the group selector must be hidden with a single group")
	}
	// The group keys are inert rather than broken.
	send(t, a, "]")
	if a.group != ufw.GroupName {
		t.Errorf("group = %q, want %q", a.group, ufw.GroupName)
	}
}

func TestBackendErrorReachesTheStatusLine(t *testing.T) {
	a, fake := newTestApp(t, 100, 30)
	fake.FailWith = errFake
	send(t, a, "r")
	send(t, a, "y")

	if !strings.Contains(a.status, errFake.Error()) {
		t.Errorf("status = %q, want the backend error", a.status)
	}
	if !strings.Contains(a.View(), errFake.Error()) {
		t.Error("the error should be visible on screen")
	}
}
