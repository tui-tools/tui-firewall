package nftables

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// inputGroup is the group name of the fixture's input chain, the same string
// the UI hands back to the backend.
func inputGroup(t *testing.T, r Ruleset) string {
	t.Helper()
	chain, ok := r.Chain(OwnTable, "input")
	if !ok {
		t.Fatal("the fixture has no input chain")
	}
	return GroupName(chain)
}

func TestSpecForReadsARuleBackIntoTheForm(t *testing.T) {
	ruleset := parseFixture(t, "router")
	// Handle 14 is the WAN ssh drop: iifname wan0, tcp dport 22, drop.
	spec, err := ruleset.SpecFor(inputGroup(t, ruleset), firewall.Rule{ID: "14"})
	if err != nil {
		t.Fatalf("SpecFor: %v", err)
	}
	if spec.Action != firewall.ActionDeny {
		t.Errorf("Action = %q, want %q", spec.Action, firewall.ActionDeny)
	}
	if spec.InIface != "wan0" {
		t.Errorf("InIface = %q, want wan0", spec.InIface)
	}
	if spec.Proto != "tcp" || spec.Ports != "22" {
		t.Errorf("Proto/Ports = %q/%q, want tcp/22", spec.Proto, spec.Ports)
	}
	if spec.Comment != "no ssh from the wan" {
		t.Errorf("Comment = %q", spec.Comment)
	}
	if spec.Log {
		t.Error("handle 14 does not log")
	}
}

func TestSpecForKeepsAnAliasSource(t *testing.T) {
	ruleset := parseFixture(t, "router")
	// Handle 12 matches @lan_hosts and @admin_ports.
	spec, err := ruleset.SpecFor(inputGroup(t, ruleset), firewall.Rule{ID: "12"})
	if err != nil {
		t.Fatalf("SpecFor: %v", err)
	}
	if spec.Service != "@lan_hosts" {
		t.Errorf("Service = %q, want @lan_hosts", spec.Service)
	}
	if spec.From != "" {
		t.Errorf("an alias source must not also fill From, got %q", spec.From)
	}
	if spec.Ports != "@admin_ports" {
		t.Errorf("Ports = %q, want @admin_ports", spec.Ports)
	}
}

func TestBuildEditRuleReplacesInPlace(t *testing.T) {
	ruleset := parseFixture(t, "router")
	chain, _ := ruleset.Chain(OwnTable, "input")
	group := inputGroup(t, ruleset)
	spec, err := ruleset.SpecFor(group, firewall.Rule{ID: "14"})
	if err != nil {
		t.Fatalf("SpecFor: %v", err)
	}
	// The edit: a new port, and logging turned on.
	spec.Ports = "2222"
	spec.Log = true

	change, err := ruleset.EditRule(group, firewall.Rule{ID: "14"}, spec)
	if err != nil {
		t.Fatalf("EditRule: %v", err)
	}
	got := argvString(t, change)
	want := `nft replace rule inet tui input handle 14 iifname "wan0" ` +
		`tcp dport 2222 log prefix "tui:input drop " counter drop ` +
		`comment "no ssh from the wan"`
	if got != want {
		t.Errorf("argv =\n  %s\nwant\n  %s", got, want)
	}
	if !change.Destructive {
		t.Error("an edit resets the counter and can change traffic: destructive")
	}
	_ = chain
}

func TestBuildEditRuleRefusesAPosition(t *testing.T) {
	ruleset := parseFixture(t, "router")
	group := inputGroup(t, ruleset)
	spec, err := ruleset.SpecFor(group, firewall.Rule{ID: "14"})
	if err != nil {
		t.Fatalf("SpecFor: %v", err)
	}
	spec.Position = 2
	if _, err := ruleset.EditRule(group, firewall.Rule{ID: "14"}, spec); err == nil ||
		!strings.Contains(err.Error(), "keeps its position") {
		t.Errorf("a position on an edit should be refused, got %v", err)
	}
}

func TestBuildEditRuleRefusesUnmodeledRules(t *testing.T) {
	ruleset := parseFixture(t, "router")
	chain, _ := ruleset.Chain(OwnTable, "input")
	target := Rule{
		Handle: 99,
		Match: Match{
			Verdict:   "accept",
			Unmodeled: []string{"meta mark 0x1"},
		},
	}
	_, err := ruleset.BuildEditRule(chain, target, firewall.RuleSpec{
		Action: firewall.ActionAllow, Ports: "22", Proto: "tcp"})
	if err == nil || !strings.Contains(err.Error(), "only as text") {
		t.Errorf("an unmodeled rule must be refused like the log toggle does, got %v", err)
	}
}

func TestSpecForRefusesASourcePortMatch(t *testing.T) {
	ruleset := parseFixture(t, "router")
	chain, _ := ruleset.Chain(OwnTable, "input")
	target := Rule{Handle: 99, Match: Match{Verdict: "accept", SPort: "1000"}}
	if _, err := ruleset.SpecForRule(chain, target); err == nil ||
		!strings.Contains(err.Error(), "source port") {
		t.Errorf("a source-port rule cannot round-trip the form, got %v", err)
	}
}

func TestSpecForRefusesLogArguments(t *testing.T) {
	ruleset := parseFixture(t, "router")
	// Handle 16 logs with a level, which an edit could not carry over.
	_, err := ruleset.SpecFor(inputGroup(t, ruleset), firewall.Rule{ID: "16"})
	if err == nil || !strings.Contains(err.Error(), "logs with arguments") {
		t.Errorf("a log level must refuse the edit before the form opens, got %v", err)
	}
}

func TestEditRefusesTheNonChainGroups(t *testing.T) {
	ruleset := parseFixture(t, "router")
	for _, group := range []string{GroupNAT, GroupAliases} {
		if _, err := ruleset.EditRule(group, firewall.Rule{ID: "23"},
			firewall.RuleSpec{}); err == nil {
			t.Errorf("editing in %s should be refused", group)
		}
	}
}

func TestBuildEditRuleGuardsInjectionInEveryOperand(t *testing.T) {
	ruleset := parseFixture(t, "router")
	group := inputGroup(t, ruleset)
	base, err := ruleset.SpecFor(group, firewall.Rule{ID: "14"})
	if err != nil {
		t.Fatalf("SpecFor: %v", err)
	}
	poison := func(mutate func(*firewall.RuleSpec)) error {
		spec := base
		mutate(&spec)
		_, err := ruleset.EditRule(group, firewall.Rule{ID: "14"}, spec)
		return err
	}
	cases := map[string]func(*firewall.RuleSpec){
		"ports":   func(s *firewall.RuleSpec) { s.Ports = "22; flush ruleset" },
		"iface":   func(s *firewall.RuleSpec) { s.InIface = `wan0" accept` },
		"from":    func(s *firewall.RuleSpec) { s.From = "10.0.0.1\ndrop" },
		"comment": func(s *firewall.RuleSpec) { s.Comment = "a \"quoted\" word" },
	}
	for name, mutate := range cases {
		if err := poison(mutate); err == nil {
			t.Errorf("%s: an operand carrying nft syntax must be refused", name)
		}
	}
}
