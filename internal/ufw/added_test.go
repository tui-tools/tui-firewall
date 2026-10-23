package ufw

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// readFixture loads a file from testdata.
func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(data)
}

// TestParseAddedFixture reads `ufw show added` as ufw 0.36.2 printed it on an
// Ubuntu 24.04 machine with the firewall inactive.
func TestParseAddedFixture(t *testing.T) {
	rules := ParseAdded(readFixture(t, "show-added-inactive.txt"))
	type row struct {
		action  firewall.Action
		dir     firewall.Direction
		to      string
		from    string
		ports   string
		proto   string
		service string
		comment string
		family  firewall.Family
	}
	in, out, fwd := firewall.DirIn, firewall.DirOut, firewall.DirForward
	want := []row{
		{"DENY", in, "Anywhere", "203.0.113.9", "", "", "", "", firewall.FamilyIPv4},
		{"ALLOW", in, "9100/tcp", "192.0.2.0/24", "9100", "tcp", "", "", firewall.FamilyIPv4},
		{"ALLOW", out, "53/udp", "Anywhere", "53", "udp", "", "", firewall.FamilyAny},
		{"ALLOW", in, "22/tcp on eth0", "Anywhere", "22", "tcp", "", "", firewall.FamilyAny},
		{"ALLOW", in, "OpenSSH", "198.51.100.7 5000", "", "", "OpenSSH", "", firewall.FamilyIPv4},
		{"LIMIT", in, "22/tcp", "Anywhere", "22", "tcp", "", "", firewall.FamilyAny},
		{"ALLOW", in, "Web Full", "Anywhere", "", "", "Web Full", "", firewall.FamilyAny},
		{"ALLOW", in, "Web Full", "192.0.2.10", "", "", "Web Full", "", firewall.FamilyIPv4},
		{"ALLOW", in, "8080/tcp", "Anywhere", "8080", "tcp", "", "staging app, temporary",
			firewall.FamilyAny},
		{"ALLOW", fwd, "Anywhere on eth1", "Anywhere on eth0", "", "", "", "fwd", firewall.FamilyAny},
		{"REJECT", in, "Anywhere on eth0", "203.0.113.0/24", "", "", "", "", firewall.FamilyIPv4},
		{"ALLOW", in, "2000:2100/udp", "Anywhere", "2000:2100", "udp", "", "", firewall.FamilyAny},
		{"ALLOW", in, "1194/udp", "Anywhere", "1194", "udp", "", "", firewall.FamilyAny},
		{"LIMIT", in, "OpenSSH", "Anywhere", "", "", "OpenSSH", "admin # ssh, rate limited",
			firewall.FamilyAny},
		{"DENY", out, "198.51.100.0/24 25/tcp", "Anywhere", "25", "tcp", "", "", firewall.FamilyIPv4},
		{"ALLOW", in, "22/tcp", "2001:db8::/32", "22", "tcp", "", "", firewall.FamilyIPv6},
	}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules, want %d: %+v", len(rules), len(want), rules)
	}
	for i, w := range want {
		r := rules[i]
		got := row{r.Action, r.Direction, r.To, r.From, r.Ports, r.Proto, r.Service, r.Comment, r.Family}
		if got != w {
			t.Errorf("rule %d (%s):\n got %+v\nwant %+v", i, r.Raw, got, w)
		}
		if r.Index != 0 {
			t.Errorf("rule %d: Index = %d, want 0 (an inactive ufw numbers nothing)", i, r.Index)
		}
		if r.Extra[firewall.ExtraDisabled] != InactiveMarker {
			t.Errorf("rule %d: not marked inactive: %v", i, r.Extra)
		}
		if r.ID == "" || strings.HasPrefix(r.ID, "ufw ") {
			t.Errorf("rule %d: ID = %q, want the rule text", i, r.ID)
		}
	}
}

func TestParseAddedEmptyAndNoise(t *testing.T) {
	for _, in := range []string{
		"",
		"Added user rules (see 'ufw status' for running firewall):\n(None)",
		"ufw frobnicate 22\nufw allow\nufw allow 'unbalanced\nufw allow from\n",
	} {
		if got := ParseAdded(in); len(got) != 0 {
			t.Errorf("ParseAdded(%q) = %+v, want none", in, got)
		}
	}
}

// TestDeleteByRuleArgs checks the delete command built from each listed rule.
// Every one of these was run against ufw 0.36.2 with the firewall inactive and
// removed its rule (both halves where it had two).
func TestDeleteByRuleArgs(t *testing.T) {
	cases := map[string][]string{
		"allow 8080/tcp comment 'staging app, temporary'": {
			"ufw", "--force", "delete", "allow", "8080/tcp", "comment", "staging app, temporary"},
		"allow 'Web Full'": {"ufw", "--force", "delete", "allow", "Web Full"},
		"allow from 192.0.2.10 to any app 'Web Full'": {
			"ufw", "--force", "delete", "allow", "from", "192.0.2.10", "to", "any", "app", "Web Full"},
		"route allow in on eth0 out on eth1 comment 'fwd'": {
			"ufw", "--force", "route", "delete", "allow", "in", "on", "eth0", "out", "on", "eth1",
			"comment", "fwd"},
		"limit OpenSSH comment 'admin # ssh, rate limited'": {
			"ufw", "--force", "delete", "limit", "OpenSSH", "comment", "admin # ssh, rate limited"},
		// ufw does not escape a quote inside a comment; the comment is the
		// tail of the line, so it survives whole.
		"allow 22/tcp comment 'it's mine'": {
			"ufw", "--force", "delete", "allow", "22/tcp", "comment", "it's mine"},
	}
	for text, want := range cases {
		got, err := deleteByRuleArgs(text)
		if err != nil {
			t.Errorf("deleteByRuleArgs(%q): %v", text, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("deleteByRuleArgs(%q)\n got %q\nwant %q", text, got, want)
		}
	}
	for _, bad := range []string{"", "frobnicate 22", "allow 'Web Full"} {
		if _, err := deleteByRuleArgs(bad); err == nil {
			t.Errorf("deleteByRuleArgs(%q) succeeded, want an error", bad)
		}
	}
}

func TestBuildDeleteRuleInactive(t *testing.T) {
	rules := ParseAdded("ufw allow 8080/tcp comment 'staging app, temporary'\n")
	if len(rules) != 1 {
		t.Fatalf("got %d rules", len(rules))
	}
	change, err := BuildDeleteRule(GroupName, rules[0])
	if err != nil {
		t.Fatal(err)
	}
	if got, want := change.String(),
		"ufw --force delete allow 8080/tcp comment 'staging app, temporary'"; got != want {
		t.Errorf("command = %q, want %q", got, want)
	}
	if !change.Destructive || change.Note == "" {
		t.Errorf("change = %+v, want destructive with a note", change)
	}
}

// TestReadSettings reads the stock Ubuntu 24.04 configuration files.
func TestReadSettings(t *testing.T) {
	dir := t.TempDir()
	proc := filepath.Join(dir, "net")
	if err := os.MkdirAll(filepath.Join(proc, "ipv4"), 0o750); err != nil {
		t.Fatal(err)
	}
	files := hostFiles{
		Defaults: filepath.Join("testdata", "default-ufw.conf"),
		Conf:     filepath.Join("testdata", "ufw.conf"),
		ProcNet:  proc,
	}

	// Forwarding off: ufw prints "disabled (routed)".
	writeFile(t, filepath.Join(proc, "ipv4", "ip_forward"), "0\n")
	s := readSettings(files)
	want := firewall.Policies{Incoming: firewall.PolicyDeny, Outgoing: firewall.PolicyAllow,
		RoutedDisabled: true}
	if s.defaults != want {
		t.Errorf("defaults = %+v, want %+v", s.defaults, want)
	}
	if s.logging != LogLow || !s.loggingOn {
		t.Errorf("logging = %q on=%v, want low on", s.logging, s.loggingOn)
	}

	// Forwarding on: the configured forward policy.
	writeFile(t, filepath.Join(proc, "ipv4", "ip_forward"), "1\n")
	s = readSettings(files)
	want = firewall.Policies{Incoming: firewall.PolicyDeny, Outgoing: firewall.PolicyAllow,
		Routed: firewall.PolicyDeny}
	if s.defaults != want {
		t.Errorf("defaults = %+v, want %+v", s.defaults, want)
	}

	// Nothing readable: everything stays unknown.
	s = readSettings(hostFiles{Defaults: "/nonexistent", Conf: "/nonexistent",
		ProcNet: "/nonexistent"})
	if s != (settings{}) {
		t.Errorf("settings = %+v, want zero", s)
	}
}

func TestSettingsFromConf(t *testing.T) {
	conf := map[string]string{}
	parseConf("DEFAULT_INPUT_POLICY=\"REJECT\"\nDEFAULT_OUTPUT_POLICY='DROP'\n"+
		"# DEFAULT_FORWARD_POLICY=\"ACCEPT\"\nDEFAULT_FORWARD_POLICY=ACCEPT\nLOGLEVEL=off\n", conf)
	s := settingsFromConf(conf, nil)
	want := firewall.Policies{Incoming: firewall.PolicyReject, Outgoing: firewall.PolicyDeny,
		Routed: firewall.PolicyAllow}
	if s.defaults != want {
		t.Errorf("defaults = %+v, want %+v", s.defaults, want)
	}
	if s.logging != LogOff || s.loggingOn {
		t.Errorf("logging = %q on=%v, want off", s.logging, s.loggingOn)
	}
}

// TestApplyInactiveState is the bug this exists for: an inactive ufw used to
// read as a firewall with no rules and unknown policies.
func TestApplyInactiveState(t *testing.T) {
	model := MergeModels(ParseStatus("Status: inactive\n"), ParseStatus("Status: inactive\n"))
	s := settings{defaults: firewall.Policies{Incoming: firewall.PolicyDeny,
		Outgoing: firewall.PolicyAllow, RoutedDisabled: true}, logging: LogLow, loggingOn: true}
	got := applyInactiveState(model, readFixture(t, "show-added-inactive.txt"), s)
	if got.Enabled {
		t.Error("Enabled = true, want false")
	}
	if n := len(got.Groups[0].Rules); n != 16 {
		t.Errorf("rules = %d, want 16", n)
	}
	if got.Groups[0].Default != s.defaults {
		t.Errorf("defaults = %+v", got.Groups[0].Default)
	}
	if got.Logging != LogLow || !got.LoggingOn {
		t.Errorf("logging = %q on=%v", got.Logging, got.LoggingOn)
	}

	// What `ufw status` reported is never overwritten.
	active := MergeModels(ParseStatus(verboseSample), ParseStatus(numberedSample))
	kept := applyInactiveState(active, "ufw allow 1/tcp\n", s)
	if !reflect.DeepEqual(kept, active) {
		t.Error("applyInactiveState changed a model that already had rules and defaults")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
