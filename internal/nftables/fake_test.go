package nftables

import (
	"context"
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// applyToFake builds a change with the fake's own builders and runs it,
// which is exactly the path --demo takes.
func applyToFake(t *testing.T, fake *Fake, change firewall.Change, err error) string {
	t.Helper()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	out, err := fake.Run(context.Background(), change)
	if err != nil {
		t.Fatalf("run %s: %v", change.String(), err)
	}
	return out
}

func TestFakeStartsFromTheRouterFixture(t *testing.T) {
	fake := NewFake()
	model, err := fake.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if model.Backend != "nftables" {
		t.Errorf("backend = %q", model.Backend)
	}
	if _, ok := model.Group("inet tui / input"); !ok {
		t.Error("the demo should show the router's input chain")
	}
	if fake.Name() != "demo" {
		t.Errorf("Name = %q, want demo", fake.Name())
	}
	if !strings.Contains(fake.Describe(), "no changes are applied") {
		t.Errorf("Describe = %q, want it to say nothing is applied", fake.Describe())
	}
}

func TestFakeAppliesAnAddedRule(t *testing.T) {
	fake := NewFake()
	spec := firewall.RuleSpec{
		Action: firewall.ActionAllow, Proto: "tcp", Ports: "8443",
		From: "10.10.0.0/24", Comment: "the new service",
	}
	change, err := fake.BuildAddRule("inet tui / input", spec)
	applyToFake(t, fake, change, err)

	model, _ := fake.Load(context.Background())
	group, _ := model.Group("inet tui / input")
	last := group.Rules[len(group.Rules)-1]
	if last.Comment != "the new service" {
		t.Fatalf("the added rule is not last: %+v", last)
	}
	if last.Action != firewall.ActionAllow || last.Ports != "8443" ||
		last.Proto != "tcp" || last.From != "10.10.0.0/24" {
		t.Errorf("added rule = %+v, want the spec that was previewed", last)
	}
	if last.Extra[firewall.ExtraCounter] == "" {
		t.Error("every rule this backend writes carries a counter")
	}
	if len(fake.Log) != 1 {
		t.Errorf("commands run = %d, want 1", len(fake.Log))
	}
}

func TestFakeInsertsAtAPosition(t *testing.T) {
	fake := NewFake()
	spec := firewall.RuleSpec{
		Action: firewall.ActionDeny, Proto: "tcp", Ports: "23",
		Comment: "no telnet", Position: 1,
	}
	change, err := fake.BuildAddRule("inet tui / input", spec)
	applyToFake(t, fake, change, err)

	model, _ := fake.Load(context.Background())
	group, _ := model.Group("inet tui / input")
	if group.Rules[0].Comment != "no telnet" {
		t.Errorf("first rule = %+v, want the inserted one", group.Rules[0])
	}
	if group.Rules[0].Index != 1 || group.Rules[1].Index != 2 {
		t.Error("the rest of the chain should have been renumbered")
	}
}

func TestFakeDeletesByHandle(t *testing.T) {
	fake := NewFake()
	model, _ := fake.Load(context.Background())
	group, _ := model.Group("inet tui / input")
	before := len(group.Rules)
	target := group.Rules[2]

	change, err := fake.BuildDeleteRule("inet tui / input", target)
	applyToFake(t, fake, change, err)

	model, _ = fake.Load(context.Background())
	group, _ = model.Group("inet tui / input")
	if len(group.Rules) != before-1 {
		t.Fatalf("rules = %d, want %d", len(group.Rules), before-1)
	}
	for _, rule := range group.Rules {
		if rule.ID == target.ID {
			t.Errorf("handle %s should be gone", target.ID)
		}
	}
}

func TestFakeChangesAPolicy(t *testing.T) {
	fake := NewFake()
	change, err := fake.BuildSetPolicy("inet tui / input",
		firewall.PolicyIncoming, firewall.PolicyAllow)
	applyToFake(t, fake, change, err)

	model, _ := fake.Load(context.Background())
	group, _ := model.Group("inet tui / input")
	if group.Default.Incoming != firewall.PolicyAllow {
		t.Errorf("policy = %q, want allow", group.Default.Incoming)
	}
}

func TestFakeAppliesTheAliasActions(t *testing.T) {
	fake := NewFake()
	ruleset := fake.Ruleset()

	change, err := ruleset.BuildExtra(ExtraCreateAlias,
		[]string{"vpn_peers", "ipv4_addr", "yes", "wireguard peers"})
	applyToFake(t, fake, change, err)

	change, err = fake.Ruleset().BuildExtra(ExtraAddElement,
		[]string{"vpn_peers", "10.99.0.0/24"})
	applyToFake(t, fake, change, err)

	model, _ := fake.Load(context.Background())
	group, _ := model.Group(GroupAliases)
	var found firewall.Rule
	for _, rule := range group.Rules {
		if rule.Service == "vpn_peers" {
			found = rule
		}
	}
	if found.Service == "" {
		t.Fatal("the new alias should be in the alias view")
	}
	if found.Extra[firewall.ExtraElements] != "1" {
		t.Errorf("elements = %q, want 1", found.Extra[firewall.ExtraElements])
	}
	if found.Extra[firewall.ExtraReferences] != "0" {
		t.Errorf("a brand new alias is used by nobody, got %q",
			found.Extra[firewall.ExtraReferences])
	}
	if found.Comment != "wireguard peers" {
		t.Errorf("comment = %q", found.Comment)
	}

	// And it can be deleted again, because nothing refers to it.
	change, err = fake.Ruleset().BuildDeleteSet(OwnTable, "vpn_peers")
	applyToFake(t, fake, change, err)
	if _, ok := fake.Ruleset().Set(OwnTable, "vpn_peers"); ok {
		t.Error("the alias should be gone")
	}
}

func TestFakeAppliesAPortForward(t *testing.T) {
	fake := NewFake()
	change, err := fake.Ruleset().BuildExtra(ExtraPortForward,
		[]string{"wan0", "tcp", "2222", "10.10.0.7", "22"})
	applyToFake(t, fake, change, err)

	// The NAT view lists prerouting before postrouting, so the new forward is
	// the last of the prerouting rules rather than the last row.
	group, _ := mustLoad(t, fake).Group(GroupNAT)
	var added firewall.Rule
	for _, rule := range group.Rules {
		if rule.Ports == "2222" {
			added = rule
		}
	}
	if added.Kind != "dnat" {
		t.Fatalf("kind = %q, want dnat", added.Kind)
	}
	if got := added.Extra[firewall.ExtraTarget]; got != "dnat to 10.10.0.7:22" {
		t.Errorf("target = %q", got)
	}
	if added.Extra[firewall.ExtraInIface] != "wan0" {
		t.Errorf("rule = %+v, want it to match tcp/2222 on wan0", added)
	}
}

func TestFakeAppliesMasquerade(t *testing.T) {
	fake := NewFake()
	change, err := fake.Ruleset().BuildExtra(ExtraMasquerade, []string{"wan2"})
	applyToFake(t, fake, change, err)

	group, _ := mustLoad(t, fake).Group(GroupNAT)
	last := group.Rules[len(group.Rules)-1]
	if last.Kind != "masquerade" || last.Extra[firewall.ExtraOutIface] != "wan2" {
		t.Errorf("rule = %+v, want a masquerade out of wan2", last)
	}
}

func TestFakeBuildsTheStructureFromNothing(t *testing.T) {
	// The path a machine with no table of ours takes: create the table, then
	// the chains, then a rule. Every step goes through the real builders.
	fake := &Fake{ruleset: Ruleset{}, nextHandle: 1}

	for _, id := range []string{ExtraCreateTable, ExtraCreateFilterChains,
		ExtraCreateNATChains} {
		change, err := fake.Ruleset().BuildExtra(id, nil)
		applyToFake(t, fake, change, err)
	}

	ruleset := fake.Ruleset()
	if _, ok := ruleset.Table(OwnTable); !ok {
		t.Fatal("the table should exist")
	}
	for _, name := range []string{"input", "forward", "output", "prerouting",
		"postrouting"} {
		chain, ok := ruleset.Chain(OwnTable, name)
		if !ok {
			t.Fatalf("chain %s is missing", name)
		}
		if !chain.Base() || chain.Policy != PolicyAccept {
			t.Errorf("chain %s = %+v, want a base chain with policy accept",
				name, chain)
		}
	}

	change, err := ruleset.AddRule("inet tui / input", firewall.RuleSpec{
		Action: firewall.ActionAllow, Proto: "tcp", Ports: "22",
		Comment: "keep ssh",
	})
	applyToFake(t, fake, change, err)
	group, _ := mustLoad(t, fake).Group("inet tui / input")
	if len(group.Rules) != 1 || group.Rules[0].Comment != "keep ssh" {
		t.Errorf("rules = %+v, want the one rule that was added", group.Rules)
	}
}

func TestFakeRefusesWhatTheRealBackendRefuses(t *testing.T) {
	fake := NewFake()
	if _, err := fake.BuildSetEnabled(true); err == nil ||
		!strings.Contains(err.Error(), "no on/off switch") {
		t.Errorf("expected the enable refusal, got: %v", err)
	}
	if _, err := fake.BuildReload(); err == nil ||
		!strings.Contains(err.Error(), "nothing to reload") {
		t.Errorf("expected the reload refusal, got: %v", err)
	}
	if _, err := fake.BuildSetLogging("high"); err == nil ||
		!strings.Contains(err.Error(), "statement on a rule") {
		t.Errorf("expected the logging refusal, got: %v", err)
	}
	if _, err := fake.BuildExtra("", "nope", nil); err == nil {
		t.Error("an unknown action should be refused")
	}
}

func TestFakeStopsAtTheFirstFailure(t *testing.T) {
	fake := NewFake()
	fake.FailWith = errorf("the kernel said no")
	_, err := fake.Run(context.Background(), BuildCreateTable())
	if err == nil || !strings.Contains(err.Error(), "the kernel said no") {
		t.Errorf("expected the injected failure, got: %v", err)
	}
}

func TestFakePreviewIsTheCommand(t *testing.T) {
	// The promise the whole family is built on: what the dialog shows is what
	// runs, with no privilege prefix in the demo because it never escalates.
	fake := NewFake()
	change, err := fake.BuildAddRule("inet tui / input", firewall.RuleSpec{
		Action: firewall.ActionAllow, Proto: "tcp", Ports: "22",
	})
	if err != nil {
		t.Fatalf("BuildAddRule: %v", err)
	}
	preview := fake.Preview(change)
	if preview != change.String() {
		t.Errorf("preview = %q, want the command itself", preview)
	}
	if _, err := fake.Run(context.Background(), change); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := fake.Log[0].String(); got != preview {
		t.Errorf("ran %q after previewing %q", got, preview)
	}
}

// mustLoad loads the fake's model or fails the test.
func mustLoad(t *testing.T, fake *Fake) firewall.Model {
	t.Helper()
	model, err := fake.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return model
}
