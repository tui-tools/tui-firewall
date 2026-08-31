package main

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/nftables"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/theme"
)

// newNftablesApp builds the app over the nftables demo, which is the same
// backend `--demo=nftables` runs, so what these tests exercise is what a
// reader sees on that screen.
func newNftablesApp(t *testing.T, width, height int) (*app, *nftables.Fake) {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	fake := nftables.NewFake()
	a := newApp(fake, theme.FromPalette(theme.TokyoNight()), compat.Result{})
	a.width, a.height = width, height
	a.Update(a.Init()())
	return a, fake
}

// gotoView moves the selection to the named group.
func gotoView(t *testing.T, a *app, name string) {
	t.Helper()
	if _, ok := a.model.Group(name); !ok {
		t.Fatalf("there is no view called %q", name)
	}
	a.group = name
	a.cursor, a.offset = 0, 0
	a.applyFilter()
}

func TestNftablesDemoRendersTheRouterRules(t *testing.T) {
	a, _ := newNftablesApp(t, 120, 30)
	out := a.View()

	for _, want := range []string{
		"tui-firewall", "input (inet tui)", "ACTION", "IN", "OUT", "PROTO",
		"SOURCE", "DESTINATION", "PORT", "COUNTER",
		"@lan_hosts", "wan0", "ping from the wan",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the nftables frame should mention %q\n%s", want, out)
		}
	}
	// nftables has no on/off switch, no logging level and nothing to reload,
	// so none of those three keys is advertised.
	for _, unwanted := range []string{"enable/disable", "logging", "reload"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("the hint bar should not offer %q on nftables\n%s", unwanted, out)
		}
	}
}

func TestNftablesResponsiveColumns(t *testing.T) {
	views := []string{"inet tui / input", nftables.GroupNAT, nftables.GroupAliases}
	for _, view := range views {
		for _, size := range [][2]int{{20, 6}, {40, 10}, {80, 24}, {120, 30}, {200, 60}} {
			a, _ := newNftablesApp(t, size[0], size[1])
			gotoView(t, a, view)
			frame := a.View()
			if frame == "" {
				t.Fatalf("%s at %v produced an empty frame", view, size)
			}
			if size[0] < 40 {
				continue
			}
			for _, line := range strings.Split(frame, "\n") {
				if width := len([]rune(line)); width > size[0] {
					t.Errorf("%s at %v: a line is %d columns wide: %q",
						view, size, width, line)
				}
			}
		}
	}
}

func TestNftablesNATView(t *testing.T) {
	a, _ := newNftablesApp(t, 120, 30)
	gotoView(t, a, nftables.GroupNAT)
	out := a.View()

	for _, want := range []string{
		"NAT", "KIND", "TRANSLATED TO", "masquerade", "dnat to 10.10.0.5:80",
		"snat to 203.0.113.9", "5 NAT rules",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the NAT view should mention %q\n%s", want, out)
		}
	}
	// It is a view of its own, not the rule table: the verdict column has no
	// place here, because every row's verdict is the translation.
	if strings.Contains(out, "DESTINATION") {
		t.Error("the NAT view should not be showing the rule table's columns")
	}
}

func TestNftablesAliasView(t *testing.T) {
	a, _ := newNftablesApp(t, 120, 30)
	gotoView(t, a, nftables.GroupAliases)
	out := a.View()

	for _, want := range []string{
		"Aliases", "NAME", "HOLDS", "MEMBERS", "USED BY", "CONTENTS",
		"lan_hosts", "ipv4_addr (interval)", "10.10.0.0/24", "3 aliases",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the alias view should mention %q\n%s", want, out)
		}
	}
}

func TestNftablesAliasViewMarksAnUnusedAlias(t *testing.T) {
	// The reference count is the reason the view exists: an alias nothing
	// refers to has to read differently from one three rules depend on.
	a, fake := newNftablesApp(t, 120, 30)
	change, err := fake.Ruleset().BuildExtra(nftables.ExtraCreateAlias,
		[]string{"unused_hosts", "ipv4_addr", "yes", ""})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	runChange(t, a, change)

	gotoView(t, a, nftables.GroupAliases)
	out := a.View()
	if !strings.Contains(out, "unused") {
		t.Errorf("an alias no rule refers to should say so\n%s", out)
	}
}

func TestNftablesViewPicker(t *testing.T) {
	a, _ := newNftablesApp(t, 120, 30)
	send(t, a, "v")
	if a.mode != modePicker {
		t.Fatalf("v should open the view picker, got mode %v", a.mode)
	}
	out := a.View()
	for _, want := range []string{"inet tui / input", "NAT", "Aliases"} {
		if !strings.Contains(out, want) {
			t.Errorf("the picker should offer %q\n%s", want, out)
		}
	}
}

func TestNftablesAddRulePreview(t *testing.T) {
	a, _ := newNftablesApp(t, 120, 30)
	send(t, a, "a")
	if a.mode != modeForm {
		t.Fatalf("expected the add form, got mode %v", a.mode)
	}
	// The direction field is not offered: an nftables rule takes its
	// direction from the chain it lives in.
	if a.form.get("direction") != "" {
		t.Error("the form should not ask for a direction on nftables")
	}
	a.form.setFieldForTest("proto", "tcp")
	a.form.setFieldForTest("comment", "the new service")
	a.form.setFieldForTest("ports", "8443")
	send(t, a, "enter")

	want := `nft add rule inet tui input tcp dport 8443 counter accept ` +
		`comment "the new service"`
	if got := previewOf(t, a); got != want {
		t.Errorf("preview =\n  %s\nwant\n  %s", got, want)
	}
}

func TestNftablesDeletePreviewNamesTheHandle(t *testing.T) {
	a, _ := newNftablesApp(t, 120, 30)
	a.cursor = 2
	send(t, a, "d")
	preview := previewOf(t, a)
	if !strings.HasPrefix(preview, "nft delete rule inet tui input handle ") {
		t.Errorf("preview = %q, want a delete by handle", preview)
	}
	if !a.confirm.Danger {
		t.Error("deleting a rule is a dangerous change")
	}
}

func TestNftablesPolicyPreview(t *testing.T) {
	a, _ := newNftablesApp(t, 120, 30)
	send(t, a, "p")
	if a.mode != modePicker {
		t.Fatalf("p should open the policy slot picker, got %v", a.mode)
	}
	// The input chain exposes exactly one slot, so the first choice is it.
	send(t, a, "enter")
	// The value picker opens on the policy the chain already has, which is
	// drop; the change worth previewing is the other one.
	if !selectOption(t, a, string(firewall.PolicyAllow)) {
		t.Fatal("the policy picker should offer allow")
	}
	want := "nft chain inet tui input { policy accept ; }"
	if got := previewOf(t, a); got != want {
		t.Errorf("preview = %q, want %q", got, want)
	}
}

func TestNftablesActionsMenuBuildsAPortForward(t *testing.T) {
	a, _ := newNftablesApp(t, 120, 30)
	send(t, a, "x")
	if a.mode != modePicker {
		t.Fatalf("x should open the actions menu, got %v", a.mode)
	}
	if !selectOption(t, a, "Forward a port to a host behind the router") {
		t.Fatal("the port forward action should be offered on the router demo")
	}
	for _, answer := range []string{"wan0", "tcp", "2222", "10.10.0.7", "22"} {
		answerStep(t, a, answer)
	}

	want := `nft add rule inet tui prerouting iifname "wan0" tcp dport 2222 ` +
		`counter dnat ip to 10.10.0.7:22 comment "tcp 2222 to 10.10.0.7:22"`
	if got := previewOf(t, a); got != want {
		t.Errorf("preview =\n  %s\nwant\n  %s", got, want)
	}
	if !strings.Contains(a.confirm.Body, "reachable") {
		t.Errorf("the dialog should say what a port forward exposes: %q",
			a.confirm.Body)
	}
}

func TestNftablesActionsMenuBuildsAnAlias(t *testing.T) {
	a, _ := newNftablesApp(t, 120, 30)
	send(t, a, "x")
	if !selectOption(t, a, "Create an alias (a named set)") {
		t.Fatal("the create-alias action should be offered")
	}
	answerStep(t, a, "vpn_peers")
	answerStep(t, a, "ipv4_addr")
	answerStep(t, a, "yes")
	answerStep(t, a, "peers allowed in")

	want := `nft add set inet tui vpn_peers { type ipv4_addr ; flags interval ; ` +
		`comment "peers allowed in" ; }`
	if got := previewOf(t, a); got != want {
		t.Errorf("preview =\n  %s\nwant\n  %s", got, want)
	}
}

func TestNftablesRefusesWhatItCannotPromise(t *testing.T) {
	a, _ := newNftablesApp(t, 120, 30)
	cases := []struct {
		key  string
		want string
	}{
		{"e", "no on/off switch"},
		{"r", "nothing to reload"},
		{"L", "does not expose logging levels"},
	}
	for _, tc := range cases {
		send(t, a, tc.key)
		if a.mode == modeConfirm {
			t.Fatalf("%s should not open a confirm dialog", tc.key)
		}
		if !strings.Contains(a.status, tc.want) {
			t.Errorf("%s: status = %q, want it to mention %q",
				tc.key, a.status, tc.want)
		}
	}
}

func TestNftablesAppliedRuleReachesTheTable(t *testing.T) {
	// The whole loop, through the UI: preview, confirm, run, re-read.
	a, _ := newNftablesApp(t, 120, 30)
	send(t, a, "a")
	a.form.setFieldForTest("proto", "udp")
	a.form.setFieldForTest("comment", "wireguard in")
	a.form.setFieldForTest("ports", "51820")
	send(t, a, "enter")
	send(t, a, "y")
	drain(t, a)

	if !strings.Contains(a.View(), "wireguard in") {
		t.Errorf("the added rule should be on screen:\n%s", a.View())
	}
}

// runChange applies a change through the app the way a confirmed dialog does.
func runChange(t *testing.T, a *app, change firewall.Change) {
	t.Helper()
	msg := a.run(change)()
	a.Update(msg)
	drain(t, a)
}

// drain runs the reload the app schedules after a change.
func drain(t *testing.T, a *app) {
	t.Helper()
	if cmd := a.load(); cmd != nil {
		a.Update(cmd())
	}
}

// selectOption moves an open picker to a labelled entry and accepts it. It
// walks to the top first, because a picker opens on whatever is current and
// the entry being looked for may be above it.
func selectOption(t *testing.T, a *app, label string) bool {
	t.Helper()
	for range 30 {
		send(t, a, "up")
		if a.mode != modePicker {
			return false
		}
	}
	for range 30 {
		if a.picker.Selected() == label {
			send(t, a, "enter")
			return true
		}
		send(t, a, "down")
		if a.mode != modePicker {
			return false
		}
	}
	return false
}

// answerStep answers whichever dialog an action opened for its next step: a
// picker entry or a line of text.
func answerStep(t *testing.T, a *app, answer string) {
	t.Helper()
	switch a.mode {
	case modePicker:
		if !selectOption(t, a, answer) {
			t.Fatalf("the picker does not offer %q", answer)
		}
	case modePrompt:
		a.input.Model.SetValue(answer)
		send(t, a, "enter")
	default:
		t.Fatalf("no dialog is open for the answer %q (mode %v)", answer, a.mode)
	}
}
