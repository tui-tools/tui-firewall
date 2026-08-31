package nftables

import (
	"context"
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// argvString joins a change's single command for assertions.
func argvString(t *testing.T, change firewall.Change) string {
	t.Helper()
	if len(change.Commands) != 1 {
		t.Fatalf("expected one command, got %d", len(change.Commands))
	}
	return strings.Join(change.Commands[0].Argv, " ")
}

func TestBuildToggleLogAddsLog(t *testing.T) {
	ruleset := parseFixture(t, "router")
	chain, _ := ruleset.Chain(OwnTable, "input")
	// Handle 14 is the WAN ssh drop, which does not log.
	rule, ok := findRuleByHandle(chain, 14)
	if !ok {
		t.Fatal("the WAN ssh drop rule is missing")
	}
	change, err := ruleset.BuildToggleLog(chain, rule)
	if err != nil {
		t.Fatalf("BuildToggleLog: %v", err)
	}
	got := argvString(t, change)
	want := `nft replace rule inet tui input handle 14 iifname "wan0" ` +
		`tcp dport 22 log prefix "tui:input drop " counter drop ` +
		`comment "no ssh from the wan"`
	if got != want {
		t.Errorf("argv =\n  %s\nwant\n  %s", got, want)
	}
	if !change.Destructive {
		t.Error("replacing a rule resets its counter and should be marked destructive")
	}
}

func TestBuildToggleLogRemovesLog(t *testing.T) {
	ruleset := parseFixture(t, "router")
	chain, _ := ruleset.Chain(OwnTable, "input")
	// Handle 16 is the tail log-only rule.
	rule, _ := findRuleByHandle(chain, 16)
	change, err := ruleset.BuildToggleLog(chain, rule)
	if err != nil {
		t.Fatalf("BuildToggleLog: %v", err)
	}
	got := argvString(t, change)
	if strings.Contains(got, "log prefix") {
		t.Errorf("toggling off should drop the log statement: %s", got)
	}
	want := "nft replace rule inet tui input handle 16 counter"
	if got != want {
		t.Errorf("argv = %q, want %q", got, want)
	}
}

func TestBuildToggleLogKeepsAliasAndVerdict(t *testing.T) {
	ruleset := parseFixture(t, "router")
	chain, _ := ruleset.Chain(OwnTable, "input")
	// Handle 12 matches an alias source and an alias port, and accepts.
	rule, _ := findRuleByHandle(chain, 12)
	got := argvString(t, mustToggle(t, ruleset, chain, rule))
	for _, want := range []string{
		"@lan_hosts", "@admin_ports", `log prefix "tui:input accept "`, "accept",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("argv %q missing %q", got, want)
		}
	}
}

func TestBuildToggleLogKeepsRejectAnswer(t *testing.T) {
	ruleset := parseFixture(t, "router")
	chain, _ := ruleset.Chain(OwnTable, "output")
	// Handle 18 rejects with a tcp reset; the reset must survive the rebuild.
	rule, _ := findRuleByHandle(chain, 18)
	got := argvString(t, mustToggle(t, ruleset, chain, rule))
	if !strings.Contains(got, "reject with tcp reset") {
		t.Errorf("the reject answer was lost: %s", got)
	}
	if !strings.Contains(got, `log prefix "tui:output reject "`) {
		t.Errorf("the log prefix carries the verdict: %s", got)
	}
}

func TestBuildToggleLogRefusesNAT(t *testing.T) {
	ruleset := parseFixture(t, "router")
	chain, _ := ruleset.Chain(OwnTable, "postrouting")
	// Handle 25 is a masquerade rule.
	rule, _ := findRuleByHandle(chain, 25)
	if _, err := ruleset.BuildToggleLog(chain, rule); err == nil {
		t.Fatal("toggling logging on a NAT rule should be refused")
	}
}

func TestToggleLogViaGroupRefusesNATAndAlias(t *testing.T) {
	ruleset := parseFixture(t, "router")
	if _, err := ruleset.ToggleLog(GroupNAT, firewall.Rule{ID: "1"}); err == nil {
		t.Error("the NAT view has no per-rule log toggle")
	}
	if _, err := ruleset.ToggleLog(GroupAliases, firewall.Rule{ID: "lan_hosts"}); err == nil {
		t.Error("an alias does not log")
	}
}

func TestToggleLogRefusesMissingHandle(t *testing.T) {
	ruleset := parseFixture(t, "router")
	chain, _ := ruleset.Chain(OwnTable, "input")
	group := GroupName(chain)
	if _, err := ruleset.ToggleLog(group, firewall.Rule{ID: "not-a-handle"}); err == nil {
		t.Error("a row with no handle cannot be toggled")
	}
	if _, err := ruleset.ToggleLog(group, firewall.Rule{ID: "99999"}); err == nil {
		t.Error("a handle no longer in the chain should be refused")
	}
}

// TestFakeAppliesToggle proves the demo backend applies the replace the toggle
// builds: after running it, the row the demo shows logs, with the prefix the
// toggle wrote. It is what makes --demo behave like a real toggle.
func TestFakeAppliesToggle(t *testing.T) {
	fake := NewFake()
	chain, _ := fake.Ruleset().Chain(OwnTable, "input")
	rule, _ := findRuleByHandle(chain, 14)
	change, err := fake.Ruleset().BuildToggleLog(chain, rule)
	if err != nil {
		t.Fatalf("BuildToggleLog: %v", err)
	}
	if _, err := fake.Run(context.Background(), change); err != nil {
		t.Fatalf("applying the toggle: %v", err)
	}
	chain2, _ := fake.Ruleset().Chain(OwnTable, "input")
	rule2, ok := findRuleByHandle(chain2, 14)
	if !ok {
		t.Fatal("the rule lost its handle in the replace")
	}
	if !rule2.Match.Log {
		t.Error("the replaced rule does not report as logging")
	}
	if rule2.Match.Verdict != "drop" {
		t.Errorf("the replaced rule's verdict = %q, want drop", rule2.Match.Verdict)
	}
	if rule2.Index != rule.Index {
		t.Errorf("the replace moved the rule from index %d to %d", rule.Index, rule2.Index)
	}
}

// mustToggle builds a toggle or fails the test.
func mustToggle(t *testing.T, rs Ruleset, chain Chain, rule Rule) firewall.Change {
	t.Helper()
	change, err := rs.BuildToggleLog(chain, rule)
	if err != nil {
		t.Fatalf("BuildToggleLog: %v", err)
	}
	return change
}
