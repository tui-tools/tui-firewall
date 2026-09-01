package nftables

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/nftables/staging"
)

// moveCommands joins each command of a move for assertions.
func moveCommands(t *testing.T, change firewall.Change) []string {
	t.Helper()
	if len(change.Commands) != 2 {
		t.Fatalf("a move is a copy plus a delete, got %d commands", len(change.Commands))
	}
	out := make([]string, 0, 2)
	for _, cmd := range change.Commands {
		out = append(out, strings.Join(cmd.Argv, " "))
	}
	return out
}

func TestBuildMoveRuleUp(t *testing.T) {
	ruleset := parseFixture(t, "router")
	// Handle 14 sits at 0-based position 4 of input (handles 10..16).
	change, err := ruleset.MoveRule(inputGroup(t, ruleset), firewall.Rule{ID: "14"}, -1)
	if err != nil {
		t.Fatalf("MoveRule: %v", err)
	}
	cmds := moveCommands(t, change)
	wantPlace := `nft insert rule inet tui input index 3 iifname "wan0" ` +
		`tcp dport 22 counter drop comment "no ssh from the wan"`
	if cmds[0] != wantPlace {
		t.Errorf("place =\n  %s\nwant\n  %s", cmds[0], wantPlace)
	}
	if cmds[1] != "nft delete rule inet tui input handle 14" {
		t.Errorf("delete = %q", cmds[1])
	}
	if !change.Destructive {
		t.Error("a move rewrites the rule and should be destructive")
	}
	if !strings.Contains(change.Note, "atomic") {
		t.Errorf("the note must say the two commands are one transaction: %q", change.Note)
	}
}

func TestBuildMoveRuleDown(t *testing.T) {
	ruleset := parseFixture(t, "router")
	change, err := ruleset.MoveRule(inputGroup(t, ruleset), firewall.Rule{ID: "14"}, 1)
	if err != nil {
		t.Fatalf("MoveRule: %v", err)
	}
	cmds := moveCommands(t, change)
	if !strings.HasPrefix(cmds[0], "nft add rule inet tui input index 5 ") {
		t.Errorf("moving down appends after the next rule: %q", cmds[0])
	}
}

func TestBuildMoveRuleRefusesTheEnds(t *testing.T) {
	ruleset := parseFixture(t, "router")
	group := inputGroup(t, ruleset)
	if _, err := ruleset.MoveRule(group, firewall.Rule{ID: "10"}, -1); err == nil ||
		!strings.Contains(err.Error(), "already first") {
		t.Errorf("moving the first rule up should be refused, got %v", err)
	}
	chain, _ := ruleset.Chain(OwnTable, "output")
	outGroup := GroupName(chain)
	last := chain.Rules[len(chain.Rules)-1]
	if _, err := ruleset.MoveRule(outGroup,
		firewall.Rule{ID: strconv.Itoa(last.Handle)}, 1); err == nil ||
		!strings.Contains(err.Error(), "already last") {
		t.Errorf("moving the last rule down should be refused, got %v", err)
	}
}

func TestBuildMoveRuleKeepsTheLogStatement(t *testing.T) {
	ruleset := parseFixture(t, "router")
	chain, _ := ruleset.Chain(OwnTable, "input")
	target, ok := findRuleByHandle(chain, 14)
	if !ok {
		t.Fatal("handle 14 is missing")
	}
	target.Match.Log = true
	target.Match.LogPrefix = "tui:input drop "
	change, err := ruleset.BuildMoveRule(chain, target, -1)
	if err != nil {
		t.Fatalf("BuildMoveRule: %v", err)
	}
	place := strings.Join(change.Commands[0].Argv, " ")
	if !strings.Contains(place, `log prefix "tui:input drop "`) {
		t.Errorf("the moved copy must keep its own log statement: %s", place)
	}
}

func TestBuildMoveRuleRefusesUnmodeledAndNAT(t *testing.T) {
	ruleset := parseFixture(t, "router")
	chain, _ := ruleset.Chain(OwnTable, "input")
	unmodeled := Rule{Handle: 99, Match: Match{
		Verdict: "accept", Unmodeled: []string{"limit rate 5/second"}}}
	if _, err := ruleset.BuildMoveRule(chain, unmodeled, -1); err == nil {
		t.Error("a rule the model does not hold in full must not be moved")
	}
	if _, err := ruleset.MoveRule(GroupNAT, firewall.Rule{ID: "23"}, -1); err == nil {
		t.Error("the NAT view has no move")
	}
	if _, err := ruleset.MoveRule(GroupAliases, firewall.Rule{ID: "x"}, -1); err == nil {
		t.Error("the alias view has no move")
	}
}

// TestMoveAppliesAtomicallyThroughTheFake proves the whole path: the move's
// two commands wrapped as one `nft -f` transaction, applied by the demo the
// way nft would, leaving the rule at its new position and the old handle gone.
func TestMoveAppliesAtomicallyThroughTheFake(t *testing.T) {
	fake := NewFake()
	group := inputGroup(t, fake.Ruleset())
	change, err := fake.BuildMoveRule(group, firewall.Rule{ID: "14"}, -1)
	if err != nil {
		t.Fatalf("BuildMoveRule: %v", err)
	}
	atomic := staging.AtomicCommand(change)
	if strings.Join(atomic.Argv, " ") != "nft -f -" {
		t.Fatalf("the wrapper must be one nft -f, got %v", atomic.Argv)
	}
	if _, err := fake.Run(context.Background(), firewall.One(atomic)); err != nil {
		t.Fatalf("applying the move: %v", err)
	}

	chain, _ := fake.Ruleset().Chain(OwnTable, "input")
	if len(chain.Rules) != 7 {
		t.Fatalf("the chain should still hold 7 rules, has %d", len(chain.Rules))
	}
	if chain.Rules[3].Comment != "no ssh from the wan" {
		t.Errorf("position 4 should now be the moved rule, is %q (handle %d)",
			chain.Rules[3].Comment, chain.Rules[3].Handle)
	}
	if chain.Rules[4].Comment != "admin from lan v6" {
		t.Errorf("the displaced rule should follow, position 5 is %q",
			chain.Rules[4].Comment)
	}
	if _, ok := findRuleByHandle(chain, 14); ok {
		t.Error("the old handle must be gone after the move")
	}
}
