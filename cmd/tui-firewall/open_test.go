package main

import (
	"bytes"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/firewalld"
	"github.com/tui-tools/tui-firewall/internal/iptables"
	"github.com/tui-tools/tui-firewall/internal/nftables"
	"github.com/tui-tools/tui-firewall/internal/ufw"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/runner"
	"github.com/tui-tools/tui-kit/theme"
)

// handoffComment is the comment tui-tailscale hands over: a space and a pair
// of parentheses, the two things an unquoted preview gets wrong in a shell.
const handoffComment = "headscale control (tailnet)"

func TestParseOpenPorts(t *testing.T) {
	got, err := parseOpenPorts(" 19443/tcp, 41641/UDP ")
	if err != nil {
		t.Fatalf("parseOpenPorts: %v", err)
	}
	want := []openPort{{19443, "tcp"}, {41641, "udp"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	for _, bad := range []string{
		"", "19443", "19443/", "19443/icmp", "0/tcp", "65536/tcp", "abc/tcp",
		"80:90/tcp", "80,/tcp", "19443/tcp,19443/tcp", "19443/tcp,",
	} {
		if _, err := parseOpenPorts(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestOpenFlagRepeatsAndRefusesDuplicates(t *testing.T) {
	var o openFlag
	if err := o.Set("19443/tcp"); err != nil {
		t.Fatal(err)
	}
	if err := o.Set("41641/udp"); err != nil {
		t.Fatal(err)
	}
	if got := o.String(); got != "19443/tcp,41641/udp" {
		t.Errorf("repeated --open = %q", got)
	}
	if err := o.Set("19443/tcp"); err == nil {
		t.Error("a port given twice across flags should be refused")
	}
}

func TestParseFlagsOpen(t *testing.T) {
	opts, err := parseFlags([]string{"--open", "19443/tcp,41641/udp",
		"--comment", handoffComment, "--demo"}, devNull(t))
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if len(opts.open.ports) != 2 || opts.comment != handoffComment {
		t.Errorf("parsed %+v", opts)
	}
	if err := validateOpenOptions(opts); err != nil {
		t.Errorf("a valid hand-off was refused: %v", err)
	}
	if _, err := parseFlags([]string{"--open", "19443"}, devNull(t)); err == nil {
		t.Error("--open without a protocol should fail at start")
	}
}

func TestValidateOpenOptions(t *testing.T) {
	ports := openFlag{ports: []openPort{{19443, "tcp"}}}
	cases := []struct {
		name string
		opts options
		want string
	}{
		{"comment alone", options{comment: "x"}, "--comment only applies to --open"},
		{"with check", options{open: ports, check: true}, "--check"},
		{"with report", options{open: ports, report: true}, "--report"},
		{"multi-line comment", options{open: ports, comment: "a\nb"}, "single line"},
		{"long comment", options{open: ports, comment: strings.Repeat("x", 129)},
			"at most 128"},
	}
	for _, tc := range cases {
		err := validateOpenOptions(tc.opts)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", tc.name, err, tc.want)
		}
	}
	if err := validateOpenOptions(options{}); err != nil {
		t.Errorf("no --open is fine: %v", err)
	}
}

// newOpenApp builds a demo app with an --open sequence armed, the way run
// does, and drains the first load.
func newOpenApp(t *testing.T, backend firewall.Backend, result compat.Result,
	value, comment string) *app {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	ports, err := parseOpenPorts(value)
	if err != nil {
		t.Fatal(err)
	}
	a := newApp(backend, theme.FromPalette(theme.TokyoNight()), result)
	a.width, a.height = 120, 34
	a.queueOpen(ports, comment)
	a.Update(a.Init()())
	return a
}

func TestOpenOnUfwFormsInSequence(t *testing.T) {
	a := newOpenApp(t, ufw.NewFake(), testCompat(t, "ufw 0.36.2"),
		"19443/tcp,41641/udp", handoffComment)

	if a.mode != modeForm {
		t.Fatalf("--open should open the form after the first load, mode = %v", a.mode)
	}
	if !strings.Contains(a.form.title, "19443/tcp · 1 of 2") {
		t.Errorf("form title = %q", a.form.title)
	}
	for key, want := range map[string]string{
		"action": "ALLOW", "ports": "19443", "proto": "tcp", "comment": handoffComment,
	} {
		if got := a.form.get(key); got != want {
			t.Errorf("field %s = %q, want %q", key, got, want)
		}
	}

	// Enter on the focused comment field goes straight to the preview.
	send(t, a, "enter")
	want := `ufw allow proto tcp to any port 19443 comment 'headscale control (tailnet)'`
	if got := previewOf(t, a); !strings.Contains(got, "comment 'headscale control (tailnet)'") {
		t.Errorf("preview = %q, want the comment quoted, like %q", got, want)
	}
	send(t, a, "y")

	// The rule landed, the list reloaded, and the second port's form is up.
	if a.mode != modeForm || !strings.Contains(a.form.title, "41641/udp · 2 of 2") {
		t.Fatalf("the second form should follow, mode = %v, title %q", a.mode, a.form.title)
	}
	if got := a.form.get("proto"); got != "udp" {
		t.Errorf("second form protocol = %q", got)
	}
	found := false
	for _, r := range a.visible {
		if r.Comment == handoffComment && strings.Contains(r.To, "19443") {
			found = true
		}
	}
	if !found {
		t.Errorf("the first rule should be in the reloaded list: %+v", a.visible)
	}

	// esc skips a port; the sequence then ends and the table is back.
	send(t, a, "esc")
	if a.mode != modeTable || a.open != nil {
		t.Errorf("the sequence should be over, mode = %v, open = %+v", a.mode, a.open)
	}
}

func TestOpenCancelledConfirmMovesOn(t *testing.T) {
	a := newOpenApp(t, ufw.NewFake(), testCompat(t, "ufw 0.36.2"),
		"19443/tcp,41641/udp", "")
	send(t, a, "enter")
	previewOf(t, a)
	send(t, a, "n")
	if a.mode != modeForm || a.form.get("ports") != "41641" {
		t.Errorf("a declined confirm should lead to the next port, mode = %v", a.mode)
	}
}

func TestOpenOnFirewalldDropsTheComment(t *testing.T) {
	a := newOpenApp(t, firewalld.NewFake(), compat.Result{}, "19443/tcp", handoffComment)
	if a.mode != modeForm {
		t.Fatalf("mode = %v, status %q", a.mode, a.status)
	}
	if !strings.Contains(a.status, "--comment is not used") {
		t.Errorf("status should say the comment is dropped: %q", a.status)
	}
	if !strings.Contains(a.form.view(a.theme, a.width, a.height), "--comment is not used") {
		t.Error("the form should say the comment is not used")
	}
	if a.group != a.model.Groups[0].Name {
		t.Errorf("the rule should go to the default zone, got %q", a.group)
	}
	send(t, a, "enter")
	if got := previewOf(t, a); !strings.Contains(got, "--add-port=19443/tcp") {
		t.Errorf("preview = %q", got)
	}
}

func TestOpenOnNftablesTargetsTheOwnInputChain(t *testing.T) {
	a := newOpenApp(t, nftables.NewFake(), compat.Result{}, "19443/tcp", handoffComment)
	if a.mode != modeForm {
		t.Fatalf("mode = %v, status %q", a.mode, a.status)
	}
	if a.group != "inet tui / input" {
		t.Errorf("group = %q", a.group)
	}
	send(t, a, "enter")
	want := `nft add rule inet tui input tcp dport 19443 counter accept ` +
		`comment '"headscale control (tailnet)"'`
	if got := previewOf(t, a); got != want {
		t.Errorf("preview =\n  %s\nwant\n  %s", got, want)
	}
}

func TestOpenOnIptablesCoversBothFamilies(t *testing.T) {
	a := newOpenApp(t, iptables.NewFake(), compat.Result{}, "19443/tcp", handoffComment)
	if a.mode != modeForm {
		t.Fatalf("mode = %v, status %q", a.mode, a.status)
	}
	var previews []string
	for i := 0; i < 2; i++ {
		send(t, a, "enter")
		previews = append(previews, previewOf(t, a))
		send(t, a, "y")
	}
	if !strings.HasPrefix(previews[0], "iptables ") ||
		!strings.HasPrefix(previews[1], "ip6tables ") {
		t.Errorf("one rule per family expected:\n%s", strings.Join(previews, "\n"))
	}
	for _, p := range previews {
		if !strings.Contains(p, "--comment 'headscale control (tailnet)'") {
			t.Errorf("the comment should be quoted: %s", p)
		}
	}
	if a.mode != modeTable || a.open != nil {
		t.Errorf("the sequence should be over, mode = %v", a.mode)
	}
}

// TestPreviewPastesAsTheSameArgv is the promise behind the preview: every line
// of it, pasted into a POSIX shell, is the argv the tool runs. Each backend
// builds a rule whose text carries spaces, parentheses and quotes, and a real
// shell reads the preview back.
func TestPreviewPastesAsTheSameArgv(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh to paste into")
	}
	comment := "headscale control (tailnet) it's $HOME; `x`"
	spec := firewall.RuleSpec{Action: firewall.ActionAllow, Proto: "tcp",
		Ports: "19443", Comment: comment}
	cases := []struct {
		name    string
		backend firewall.Backend
		group   string
		spec    firewall.RuleSpec
	}{
		{"ufw", ufw.NewFake(), "", spec},
		{"iptables", iptables.NewFake(),
			iptables.GroupName(iptables.V4, iptables.TableFilter, "INPUT"), spec},
		{"nftables", nftables.NewFake(), "inet tui / input", spec},
		// firewalld has no comments; a rich rule is its argument with spaces
		// and double quotes in it.
		{"firewalld", firewalld.NewFake(), "public", firewall.RuleSpec{
			Action: firewall.ActionAllow, Proto: "tcp", Ports: "19443",
			From: "10.0.0.0/8", Family: firewall.FamilyIPv4, Log: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			group := tc.group
			if group == "" {
				model, err := tc.backend.Load(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				group = model.Groups[0].Name
			}
			change, err := tc.backend.BuildAddRule(group, tc.spec)
			if err != nil {
				t.Fatalf("BuildAddRule: %v", err)
			}
			for _, cmd := range change.Commands {
				assertPastes(t, cmd)
			}
		})
	}
}

// assertPastes feeds a command's preview line to sh and compares the words
// the shell hands over with the argv the runner would execute.
func assertPastes(t *testing.T, cmd runner.Command) {
	t.Helper()
	line := cmd.String()
	want := append(append([]string{}, cmd.Env...), cmd.Argv...)
	// The line is handed to the shell as data and evaluated there, which is
	// the point: it is what a user pasting the preview would run.
	out, err := exec.Command("sh", "-c", //nolint:gosec // test-only, fixed script
		`eval "set -- $1"; for a in "$@"; do printf '%s\0' "$a"; done`,
		"sh", line).Output()
	if err != nil {
		t.Fatalf("sh could not read the preview %q: %v", line, err)
	}
	got := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("preview %s\npastes as %q\nruns     %q", line, got, want)
	}
	if !bytes.Contains([]byte(line), []byte("'")) &&
		strings.ContainsAny(strings.Join(cmd.Argv, ""), " ()\"") {
		t.Errorf("an argument that needs quoting went unquoted: %s", line)
	}
}

// devNull is a sink for the usage text a flag error prints.
func devNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// TestOpenWaitsForAnInputChain covers an empty nftables ruleset: there is no
// chain to add to, so the sequence says so and waits; once a reload finds the
// chains (the user created them with x), the first form opens.
func TestOpenWaitsForAnInputChain(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	a := newApp(nftables.NewFake(), theme.FromPalette(theme.TokyoNight()), compat.Result{})
	a.queueOpen([]openPort{{19443, "tcp"}}, handoffComment)
	a.Update(loadedMsg{model: firewall.Model{Backend: "nftables"}})
	if a.mode != modeTable || a.open == nil {
		t.Fatalf("the sequence should wait, mode = %v", a.mode)
	}
	if !strings.Contains(a.status, "no input chain yet") {
		t.Errorf("status = %q", a.status)
	}
	a.Update(a.Init()())
	if a.mode != modeForm || a.form.get("ports") != "19443" {
		t.Errorf("the form should open once the chain exists, mode = %v", a.mode)
	}
}
