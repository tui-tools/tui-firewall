package firewalld

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `firewall-cmd --list-all-zones` and its siblings are output this tool did
// not write, and what comes out of these parsers is what the dialog shows and
// what a `--remove-rich-rule` is built around. A rich rule that comes back
// altered is a delete aimed at something else; a zone name with a space in it
// is an argument that splits.
//
// `go test` replays every seed below on each commit; `go test -fuzz` explores
// past them locally — see tui-kit/templates/FUZZING.md for the family rule.

// seed starts the corpus from the captured fixtures the table tests use, plus
// the shapes a real capture never has: nothing, a bare separator, a key with
// no section, a continuation with nothing to continue.
func seed(f *testing.F, names ...string) {
	f.Helper()
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // the name is a literal in the tests, and testdata is in the repository
		if err != nil {
			f.Fatalf("read fixture %s: %v", name, err)
		}
		f.Add(string(raw))
	}
	f.Add("")
	f.Add("\n\n\n")
	f.Add(":")
	f.Add("  services:")
	f.Add("\tfamily=\"ipv4\"")
	f.Add("public (active)\n  target: default\n  services:\n")
}

func FuzzParseSections(f *testing.F) {
	seed(f, "list-all.txt", "list-all-zones.txt", "list-all-rich.txt",
		"policy-list-all.txt", "permanent-list-all-zones.txt",
		"list-all-zones-firewalld244.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for _, s := range ParseSections(out) {
			// The name is the `--zone=` / `--policy=` argument every command
			// this section leads to is built with.
			if s.Name == "" || strings.ContainsAny(s.Name, " \t\n\r") {
				t.Fatalf("section name is not a bare word: %q", s.Name)
			}
			if len(s.Order) != len(s.Fields) {
				t.Fatalf("%d keys in order, %d in fields", len(s.Order), len(s.Fields))
			}
			seen := map[string]bool{}
			for _, key := range s.Order {
				if seen[key] {
					t.Fatalf("key %q listed twice in the order", key)
				}
				seen[key] = true
				if !s.Has(key) {
					t.Fatalf("key %q is in the order but not in the fields", key)
				}
			}
			for key, values := range s.Fields {
				if !seen[key] {
					t.Fatalf("key %q is in the fields but not in the order", key)
				}
				if key == "" {
					t.Fatal("blank key")
				}
				if key == KeyRichRules {
					continue
				}
				// Every other value becomes one command-line argument, so it
				// is a single token or the command would split.
				for _, v := range values {
					if v == "" || strings.ContainsAny(v, " \t\n\r") {
						t.Fatalf("value of %q is not a bare token: %q", key, v)
					}
				}
			}
			// A rich rule is its own delete argument, so it has to come back
			// exactly as firewalld printed it.
			if got, want := len(s.RichRules), len(s.Fields[KeyRichRules]); got != want {
				t.Fatalf("%d rich rules, %d rich-rule values", got, want)
			}
			for i, rule := range s.RichRules {
				if rule == "" || rule != strings.TrimSpace(rule) {
					t.Fatalf("rich rule %d is blank or untrimmed: %q", i, rule)
				}
				if !strings.Contains(out, rule) {
					t.Fatalf("rich rule %d is not in the output it was read from: %q", i, rule)
				}
				if s.Fields[KeyRichRules][i] != rule {
					t.Fatalf("rich rule %d differs from its field value", i)
				}
			}
			if s.First(KeyTarget) != "" && !s.Has(KeyTarget) {
				t.Fatal("target has a value but is not registered")
			}
			if s.Flag(KeyMasquerade) && s.First(KeyMasquerade) != "yes" {
				t.Fatal("masquerade reads as set without a yes")
			}
		}
	})
}

func FuzzParseActiveZones(f *testing.F) {
	seed(f, "get-active-zones.txt", "get-active-zones-firewalld244.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for _, z := range ParseActiveZones(out) {
			if z.Name == "" || strings.ContainsAny(z.Name, " \t\n\r") {
				t.Fatalf("zone name is not a bare word: %q", z.Name)
			}
			for _, v := range append(append([]string{}, z.Interfaces...), z.Sources...) {
				if v == "" || strings.ContainsAny(v, " \t\n\r") {
					t.Fatalf("zone %q carries a value that is not a bare token: %q", z.Name, v)
				}
			}
		}
	})
}

func FuzzParseList(f *testing.F) {
	f.Add("public work home dmz\n")
	f.Add("ssh  dhcpv6-client\tcockpit\n")
	f.Add("")
	f.Add("   \n\t\n")
	f.Fuzz(func(t *testing.T, out string) {
		// Each item is passed back as a single `--add-service=` argument.
		for _, item := range ParseList(out) {
			if item == "" || strings.ContainsAny(item, " \t\n\r") {
				t.Fatalf("list item is not a bare token: %q", item)
			}
			if !strings.Contains(out, item) {
				t.Fatalf("item %q is not in the output it was read from", item)
			}
		}
	})
}

func FuzzParseRichRule(f *testing.F) {
	f.Add(`rule family="ipv4" source address="10.0.0.0/8" service name="ssh" accept`)
	f.Add(`rule family="ipv6" port port="80" protocol="tcp" log prefix="web " level="info" limit value="3/m" accept`)
	f.Add(`rule protocol value="esp" reject`)
	f.Add(`rule source ipset="blocklist" drop`)
	f.Add("")
	f.Add(`rule family="`)
	f.Fuzz(func(t *testing.T, raw string) {
		r := ParseRichRule(raw)
		// Raw is the string --remove-rich-rule takes back: it is never
		// anything but what came in.
		if r.Raw != raw {
			t.Fatalf("Raw = %q, want the input unchanged", raw)
		}
		switch r.Verdict {
		case "", "accept", "reject", "drop", "mark":
		default:
			t.Fatalf("verdict = %q, not one firewalld prints", r.Verdict)
		}
		// A slice of pairs rather than a map literal: govulncheck's SSA
		// builder cannot lower a range over one.
		for _, p := range []struct{ name, value string }{
			{"family", r.Family}, {"source", r.Source},
			{"destination", r.Destination}, {"service", r.Service},
			{"port", r.Port}, {"protocol", r.Protocol},
			{"log prefix", r.LogPrefix},
		} {
			name, part := p.name, p.value
			if part == "" {
				continue
			}
			// Every part was read out of a quoted value, so it can hold
			// neither a quote nor a line break, and it is a substring of the
			// rule it was read from.
			if strings.ContainsAny(part, "\"\n\r") {
				t.Fatalf("%s carries a quote or a line break: %q", name, part)
			}
			if !strings.Contains(raw, part) {
				t.Fatalf("%s %q is not in the rule it was read from", name, part)
			}
		}
		if r.Log && !strings.Contains(raw, " log") {
			t.Fatal("logging was reported for a rule that does not mention it")
		}
	})
}
