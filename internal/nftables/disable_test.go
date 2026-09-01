package nftables

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// demoInput is the chain view the demo router opens on, and the one the
// disable tests act in.
const demoInput = "inet tui / input"

// rowAt returns the model row at a position of the demo's input chain.
func rowAt(t *testing.T, model firewall.Model, group string, i int) firewall.Rule {
	t.Helper()
	g, ok := model.Group(group)
	if !ok {
		t.Fatalf("there is no group %q", group)
	}
	if i >= len(g.Rules) {
		t.Fatalf("group %q has %d rules, wanted row %d", group, len(g.Rules), i)
	}
	return g.Rules[i]
}

func TestDisableThenEnableRestoresThePosition(t *testing.T) {
	fake := NewFake()
	model, err := fake.Load(t.Context())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	before, _ := model.Group(demoInput)
	// The third rule of the chain: far enough in that a position that is not
	// kept would show up as a different neighbour.
	target := before.Rules[2]

	toggle, err := fake.BuildToggleDisabled(demoInput, target)
	if err != nil {
		t.Fatalf("BuildToggleDisabled: %v", err)
	}
	if toggle.Enabling {
		t.Fatal("a live rule toggles to disabled, not to enabled")
	}
	if toggle.Entry.Index != 2 {
		t.Errorf("the entry records position %d, want 2", toggle.Entry.Index)
	}
	preview := toggle.Change.String()
	if !strings.Contains(preview, "nft delete rule inet tui input handle "+target.ID) {
		t.Errorf("disabling should delete the rule by handle:\n%s", preview)
	}
	if _, err := fake.Run(t.Context(), toggle.Change); err != nil {
		t.Fatalf("running the disable: %v", err)
	}
	fake.CommitToggleDisabled(toggle)

	model, err = fake.Load(t.Context())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	after, _ := model.Group(demoInput)
	if len(after.Rules) != len(before.Rules) {
		t.Fatalf("the disabled rule should still be a row: %d rows, want %d",
			len(after.Rules), len(before.Rules))
	}
	row := after.Rules[2]
	if row.Extra[firewall.ExtraDisabled] != DisabledMarker {
		t.Errorf("row 3 should be the disabled one: %+v", row)
	}
	if row.Index != 0 {
		t.Errorf("a disabled row holds no position in the live chain, got %d", row.Index)
	}
	if !DisabledID(row.ID) {
		t.Errorf("a disabled row is named by the spec, got id %q", row.ID)
	}
	if row.Extra[firewall.ExtraCounter] != "" {
		t.Errorf("a disabled rule has no counter, got %q", row.Extra[firewall.ExtraCounter])
	}
	// The rule really is out of the ruleset the kernel would enforce.
	chain, ok := fake.Ruleset().Chain(OwnTable, "input")
	if !ok {
		t.Fatal("the input chain should still exist")
	}
	if len(chain.Rules) != len(before.Rules)-1 {
		t.Errorf("the live chain still holds %d rules", len(chain.Rules))
	}

	// And back again.
	toggle, err = fake.BuildToggleDisabled(demoInput, row)
	if err != nil {
		t.Fatalf("BuildToggleDisabled (enable): %v", err)
	}
	if !toggle.Enabling {
		t.Fatal("a disabled row toggles to enabled")
	}
	preview = toggle.Change.String()
	if !strings.Contains(preview, "nft insert rule inet tui input index 2 ") {
		t.Errorf("enabling should insert at the recorded position:\n%s", preview)
	}
	if _, err := fake.Run(t.Context(), toggle.Change); err != nil {
		t.Fatalf("running the enable: %v", err)
	}
	fake.CommitToggleDisabled(toggle)

	model, err = fake.Load(t.Context())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	restored, _ := model.Group(demoInput)
	if len(restored.Rules) != len(before.Rules) {
		t.Fatalf("the chain should be back to %d rules, got %d",
			len(before.Rules), len(restored.Rules))
	}
	back := restored.Rules[2]
	if back.Extra[firewall.ExtraDisabled] != "" {
		t.Error("the rule should be live again")
	}
	// A re-added rule gets a fresh handle, so the row identity moves; what
	// must come back is the rule, at its position.
	if back.Action != target.Action || back.Ports != target.Ports ||
		back.From != target.From || back.To != target.To ||
		back.Comment != target.Comment {
		t.Errorf("the rule did not come back as it was:\n got %+v\nwant %+v",
			back, target)
	}
	if !fake.Spec().Empty() {
		t.Errorf("enabling should have emptied the spec, %d left", fake.Spec().Len())
	}
}

func TestEnableAppendsWhenTheChainHasShrunk(t *testing.T) {
	fake := NewFake()
	rs := fake.Ruleset()
	chain, ok := rs.Chain(OwnTable, "input")
	if !ok {
		t.Fatal("no input chain")
	}
	entry := DisabledRule{
		Index: len(chain.Rules) + 5,
		Expr:  []string{"counter", "drop"},
		Rule:  Rule{Table: OwnTable, Chain: "input", Handle: 999},
	}
	change, err := rs.BuildEnableRule(chain, entry)
	if err != nil {
		t.Fatalf("BuildEnableRule: %v", err)
	}
	preview := change.String()
	if !strings.Contains(preview, "nft add rule inet tui input counter drop") {
		t.Errorf("a position past the end appends:\n%s", preview)
	}
	if !strings.Contains(change.Description, "end of input") {
		t.Errorf("the preview should say where it lands: %q", change.Description)
	}
}

func TestDisableRefusesWhatItCannotPutBack(t *testing.T) {
	fake := NewFake()
	model, err := fake.Load(t.Context())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	for _, tc := range []struct {
		name  string
		group string
		row   firewall.Rule
		want  string
	}{
		{"an alias", GroupAliases, rowAt(t, model, GroupAliases, 0), "not a rule"},
		{"a NAT rule", GroupNAT, rowAt(t, model, GroupNAT, 0), "filter rules"},
		{"a row with no handle", demoInput,
			firewall.Rule{ID: "not-a-handle"}, "no handle"},
		{"a handle that is gone", demoInput,
			firewall.Rule{ID: "999999"}, "no longer in chain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fake.BuildToggleDisabled(tc.group, tc.row)
			if err == nil {
				t.Fatal("this should have been refused")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestDisableRefusesARuleTheModelDoesNotHoldInFull(t *testing.T) {
	rs := Ruleset{Tables: []Table{{
		TableID: OwnTable,
		Chains: []Chain{{
			Table: OwnTable, Name: "input", Type: "filter", Hook: "input",
			Policy: PolicyDrop,
			Rules: []Rule{
				{Table: OwnTable, Chain: "input", Handle: 1, Index: 1,
					Match: Match{Verdict: "accept", Unmodeled: []string{"meta mark 0x1"}}},
				{Table: OwnTable, Chain: "input", Handle: 2, Index: 2,
					Match: Match{Verdict: "accept", Log: true, LogGroup: "5"}},
			},
		}},
	}}}
	chain, _ := rs.Chain(OwnTable, "input")

	if _, _, err := rs.BuildDisableRule(chain, chain.Rules[0]); err == nil ||
		!strings.Contains(err.Error(), "shows only as text") {
		t.Errorf("an unmodelled match should be refused, got %v", err)
	}
	if _, _, err := rs.BuildDisableRule(chain, chain.Rules[1]); err == nil ||
		!strings.Contains(err.Error(), "nflog group") {
		t.Errorf("a log statement with arguments should be refused, got %v", err)
	}
}

func TestActionsRefuseADisabledRow(t *testing.T) {
	fake := NewFake()
	row := firewall.Rule{ID: "off:14"}
	for name, build := range map[string]func() error{
		"delete": func() error {
			_, err := fake.BuildDeleteRule(demoInput, row)
			return err
		},
		"edit": func() error {
			_, err := fake.BuildEditRule(demoInput, row, firewall.RuleSpec{})
			return err
		},
		"move": func() error {
			_, err := fake.BuildMoveRule(demoInput, row, 1)
			return err
		},
		"log toggle": func() error {
			_, err := fake.BuildToggleLog(demoInput, row)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := build()
			if err == nil {
				t.Fatal("a disabled rule is not in the ruleset; this should be refused")
			}
			if !strings.Contains(err.Error(), "press D to enable it first") {
				t.Errorf("error = %q", err)
			}
		})
	}
}

func TestEnableRefusesAnEntryTheSpecDoesNotHold(t *testing.T) {
	fake := NewFake()
	if _, err := fake.BuildToggleDisabled(demoInput, firewall.Rule{ID: "off:14"}); err == nil ||
		!strings.Contains(err.Error(), "no disabled rule") {
		t.Errorf("error = %v", err)
	}
}

func TestSavedFileCarriesTheDisabledRuleAndLoadsBack(t *testing.T) {
	fake := NewFake()
	model, err := fake.Load(t.Context())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	group, _ := model.Group(demoInput)
	toggle, err := fake.BuildToggleDisabled(demoInput, group.Rules[2])
	if err != nil {
		t.Fatalf("BuildToggleDisabled: %v", err)
	}
	if _, err := fake.Run(t.Context(), toggle.Change); err != nil {
		t.Fatalf("running the disable: %v", err)
	}
	fake.CommitToggleDisabled(toggle)

	listing, err := fake.SnapshotOwnTable(t.Context())
	if err != nil {
		t.Fatalf("SnapshotOwnTable: %v", err)
	}
	change, content, err := BuildSave(listing, fake.Spec(), savePathPlain, "boot note")
	if err != nil {
		t.Fatalf("BuildSave: %v", err)
	}
	if !strings.Contains(change.Note, "comment lines nft ignores") {
		t.Errorf("the note should say how the disabled rules ride: %q", change.Note)
	}
	if change.Commands[0].Stdin != content {
		t.Error("the command should write exactly the content the diff was drawn from")
	}
	// The live half of the file is still the table nft printed.
	if !strings.Contains(content, "table inet tui {") {
		t.Errorf("the file lost the table:\n%s", content)
	}
	back, err := ParseSpec(content)
	if err != nil {
		t.Fatalf("the saved file should load back: %v", err)
	}
	if back.Len() != 1 || back.Disabled[0].ID() != toggle.Entry.ID() {
		t.Errorf("the disabled rule did not survive the file: %+v", back)
	}
}
