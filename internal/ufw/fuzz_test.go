package ufw

import (
	"strconv"
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// `ufw status` is output this tool did not write: bytes from a program on a
// machine we have never seen, turned into the rules the dialog shows and the
// numbers a delete is built around. A parser that invents a rule number, or
// hands back a name with a newline in it, is how a confirm dialog ends up
// describing something other than what will run.
//
// `go test` replays every seed below on each commit; `go test -fuzz` explores
// past them locally — see tui-kit/templates/FUZZING.md for the family rule.

// seedStatus starts the corpus from the captured samples the table tests use,
// plus the shapes a real capture never has: nothing, a lone separator, a
// header with no table, a truncated rule line.
func seedStatus(f *testing.F) {
	f.Helper()
	f.Add(verboseSample)
	f.Add(numberedSample)
	f.Add("")
	f.Add("\n\n\n")
	f.Add("Status: inactive\n")
	f.Add("To                         Action      From\n")
	f.Add("[ 1] 22/tcp                     LIMIT IN")
	f.Add("[ 1] 22/tcp  LIMIT IN  Anywhere  # ")
}

// checkRule asserts what every caller of a parsed rule is allowed to assume:
// the verdict is one the UI knows how to draw, the columns are trimmed, and
// the number a delete is built from agrees with the ID it was read out of.
func checkRule(t *testing.T, r firewall.Rule) {
	t.Helper()
	switch r.Action {
	case firewall.ActionAllow, firewall.ActionDeny, firewall.ActionReject,
		firewall.ActionLimit:
	default:
		t.Fatalf("action = %q, not one ufw prints", r.Action)
	}
	switch r.Direction {
	case firewall.DirAny, firewall.DirIn, firewall.DirOut, firewall.DirForward:
	default:
		t.Fatalf("direction = %q, not one ufw prints", r.Direction)
	}
	switch r.Family {
	case firewall.FamilyAny, firewall.FamilyIPv4, firewall.FamilyIPv6:
	default:
		t.Fatalf("family = %q, not one ufw prints", r.Family)
	}
	switch r.Proto {
	case "", "tcp", "udp":
	default:
		t.Fatalf("proto = %q, want tcp, udp or empty", r.Proto)
	}
	for name, field := range map[string]string{
		"to": r.To, "from": r.From, "raw": r.Raw,
		"ports": r.Ports, "service": r.Service, "comment": r.Comment,
	} {
		if field != strings.TrimSpace(field) {
			t.Fatalf("%s field is not trimmed: %q", name, field)
		}
		if strings.ContainsAny(field, "\n\r") {
			t.Fatalf("%s field carries a newline: %q", name, field)
		}
	}
	if r.Raw == "" {
		t.Fatal("rule kept no raw rendering")
	}
	// The ID is what `ufw delete <n>` is built from, so it has to be the
	// number the line was actually printed with, or nothing at all.
	if r.ID != "" {
		n, err := strconv.Atoi(r.ID)
		if err != nil || n != r.Index {
			t.Fatalf("ID %q does not match index %d", r.ID, r.Index)
		}
	}
	if r.Index < 0 {
		t.Fatalf("index = %d, want non-negative", r.Index)
	}
	if r.Ports != "" && !strings.Contains(r.To, r.Ports) {
		t.Fatalf("ports %q were not read out of the To column %q", r.Ports, r.To)
	}
}

func FuzzParseStatus(f *testing.F) {
	seedStatus(f)
	f.Fuzz(func(t *testing.T, out string) {
		m := ParseStatus(out)
		if m.Backend != "ufw" {
			t.Fatalf("backend = %q, want ufw", m.Backend)
		}
		// ufw has exactly one group whatever the output says, because the
		// group is the tool's own structure and not something it read.
		if len(m.Groups) != 1 || m.Groups[0].Name != GroupName {
			t.Fatalf("groups = %+v, want the single %q group", m.Groups, GroupName)
		}
		if m.Logging != "" && m.Logging != strings.TrimSpace(m.Logging) {
			t.Fatalf("logging level is not trimmed: %q", m.Logging)
		}
		if !m.LoggingOn && m.Logging != "" && m.Logging != LogOff {
			t.Fatalf("logging is off but the level is %q", m.Logging)
		}
		d := m.Groups[0].Default
		for _, p := range []firewall.Policy{d.Incoming, d.Outgoing, d.Routed} {
			if strings.ContainsAny(string(p), " \t\n") {
				t.Fatalf("default policy carries whitespace: %q", p)
			}
		}
		if d.RoutedDisabled && d.Routed != "" {
			t.Fatalf("routing is disabled but the policy is %q", d.Routed)
		}
		for _, r := range m.Groups[0].Rules {
			checkRule(t, r)
		}
	})
}

// FuzzMergeModels covers the step after the parse: the verbose and the
// numbered listing are two captures of the same firewall, and the merged
// result is what the UI actually shows.
func FuzzMergeModels(f *testing.F) {
	f.Add(verboseSample, numberedSample)
	f.Add(numberedSample, verboseSample)
	f.Add("", "")
	f.Add("Status: active\n", "")
	f.Fuzz(func(t *testing.T, verbose, numbered string) {
		m := MergeModels(ParseStatus(verbose), ParseStatus(numbered))
		if len(m.Groups) != 1 {
			t.Fatalf("merged into %d groups, want 1", len(m.Groups))
		}
		for _, r := range m.Groups[0].Rules {
			checkRule(t, r)
		}
	})
}

func FuzzParseAppList(f *testing.F) {
	f.Add("Available applications:\n  CUPS\n  Nginx Full\n  OpenSSH\n")
	f.Add("No applications are available.\n")
	f.Add("")
	f.Add("Available applications:")
	f.Add("Available applications:\n   \n\tOpenSSH\n")
	f.Fuzz(func(t *testing.T, out string) {
		// A profile name is passed straight to `ufw allow <name>`, so a blank
		// or untrimmed entry would build a command around nothing.
		for _, name := range ParseAppList(out) {
			if name == "" {
				t.Fatal("blank profile name")
			}
			if name != strings.TrimSpace(name) {
				t.Fatalf("profile name is not trimmed: %q", name)
			}
			if !strings.Contains(out, name) {
				t.Fatalf("profile %q is not in the output it was read from", name)
			}
		}
	})
}
