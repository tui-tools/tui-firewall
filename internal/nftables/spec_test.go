package nftables

import (
	"strings"
	"testing"
)

// disabledFixture is one entry with everything a rule can carry, so the round
// trip is asserted on the shape the real thing has rather than on a stub.
func disabledFixture() DisabledRule {
	return DisabledRule{
		Index:  2,
		Expr:   []string{"iifname", "\"wan0\"", "tcp", "dport", "22", "counter", "drop", "comment", "\"no ssh from the wan\""},
		Family: "v4",
		Rule: Rule{
			Table:   OwnTable,
			Chain:   "input",
			Handle:  14,
			Comment: "no ssh from the wan",
			Raw:     "iifname \"wan0\" tcp dport 22 counter drop",
			Match: Match{
				Verdict: "drop", IIF: "wan0", Proto: "tcp", DPort: "22",
			},
		},
	}
}

func TestSaveFileRoundTripsTheSpec(t *testing.T) {
	listing := "table inet tui {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n\t}\n}"
	spec := Spec{Disabled: []DisabledRule{disabledFixture()}}

	content, err := RenderSaveFile(listing, spec)
	if err != nil {
		t.Fatalf("RenderSaveFile: %v", err)
	}
	if !strings.HasPrefix(content, specMarkerPrefix+SpecVersion+"\n") {
		t.Errorf("the file should open with the version marker:\n%s", content)
	}
	if !strings.Contains(content, "\n"+disabledPrefix+"{") {
		t.Errorf("the disabled rule should ride in its own comment line:\n%s", content)
	}
	// Everything this tool adds is a comment, so nft still reads the file.
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "# tui-firewall:") {
			continue
		}
		if strings.Contains(line, "tui-firewall:") {
			t.Errorf("a tui-firewall marker escaped its comment line: %q", line)
		}
	}

	back, err := ParseSpec(content)
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	if len(back.Disabled) != 1 {
		t.Fatalf("read back %d disabled rules, want 1", len(back.Disabled))
	}
	got := back.Disabled[0]
	want := disabledFixture()
	if got.Index != want.Index || got.Family != want.Family {
		t.Errorf("position/family did not survive: %+v", got)
	}
	if strings.Join(got.Expr, " ") != strings.Join(want.Expr, " ") {
		t.Errorf("expr = %q", got.Expr)
	}
	if got.ID() != want.ID() || got.Rule.Chain != "input" || got.Rule.Table != OwnTable {
		t.Errorf("identity did not survive: %+v", got.Rule)
	}
	if got.Rule.Match.DPort != "22" || got.Rule.Match.Verdict != "drop" {
		t.Errorf("the modelled rule did not survive: %+v", got.Rule.Match)
	}
}

func TestSaveFileWithNothingDisabledStaysVersionOne(t *testing.T) {
	listing := "table inet tui {\n}"
	content, err := RenderSaveFile(listing, Spec{})
	if err != nil {
		t.Fatalf("RenderSaveFile: %v", err)
	}
	if content != listing {
		t.Errorf("a spec with nothing disabled must not change the file:\n%q", content)
	}
}

func TestParseSpecReadsAVersionOneFile(t *testing.T) {
	// Exactly what earlier versions wrote: nft's listing, nothing else.
	spec, err := ParseSpec("table inet tui {\n\tchain input {\n\t}\n}\n")
	if err != nil {
		t.Fatalf("a v1 file must still load: %v", err)
	}
	if !spec.Empty() {
		t.Errorf("a v1 file has nothing disabled, got %d", spec.Len())
	}
}

func TestParseSpecRefusals(t *testing.T) {
	valid := `{"index":0,"expr":["counter","drop"],"rule":{"table":{"family":"inet","name":"tui"},"chain":"input","handle":7,"index":0,"match":{},"raw":"counter drop"}}`
	header := specMarkerPrefix + SpecVersion + "\n"

	for _, tc := range []struct {
		name    string
		content string
	}{
		{"a version this build does not read",
			specMarkerPrefix + "v9\n" + disabledPrefix + valid},
		{"a disabled rule with no marker in front of it",
			disabledPrefix + valid},
		{"json that is not a disabled rule",
			header + disabledPrefix + "{not json"},
		{"a statement word carrying a second nft command",
			header + disabledPrefix + `{"index":0,"expr":["counter","drop;","flush","ruleset"],"rule":{"table":{"family":"inet","name":"tui"},"chain":"input","handle":7,"index":0,"match":{},"raw":""}}`},
		{"a statement word carrying a newline",
			header + disabledPrefix + `{"index":0,"expr":["counter","drop\nflush ruleset"],"rule":{"table":{"family":"inet","name":"tui"},"chain":"input","handle":7,"index":0,"match":{},"raw":""}}`},
		{"a quoted word smuggling a closing quote",
			header + disabledPrefix + `{"index":0,"expr":["comment","\"a\" flush ruleset \""],"rule":{"table":{"family":"inet","name":"tui"},"chain":"input","handle":7,"index":0,"match":{},"raw":""}}`},
		{"a chain name that is nft syntax",
			header + disabledPrefix + `{"index":0,"expr":["counter","drop"],"rule":{"table":{"family":"inet","name":"tui"},"chain":"input; flush ruleset","handle":7,"index":0,"match":{},"raw":""}}`},
		{"a table name that is nft syntax",
			header + disabledPrefix + `{"index":0,"expr":["counter","drop"],"rule":{"table":{"family":"inet","name":"tui}; flush ruleset"},"chain":"input","handle":7,"index":0,"match":{},"raw":""}}`},
		{"a negative position",
			header + disabledPrefix + `{"index":-3,"expr":["counter","drop"],"rule":{"table":{"family":"inet","name":"tui"},"chain":"input","handle":7,"index":0,"match":{},"raw":""}}`},
		{"nothing to put back",
			header + disabledPrefix + `{"index":0,"expr":[],"rule":{"table":{"family":"inet","name":"tui"},"chain":"input","handle":7,"index":0,"match":{},"raw":""}}`},
		{"an address family nft does not have",
			header + disabledPrefix + `{"index":0,"expr":["counter","drop"],"family":"v5","rule":{"table":{"family":"inet","name":"tui"},"chain":"input","handle":7,"index":0,"match":{},"raw":""}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseSpec(tc.content); err == nil {
				t.Fatal("this file should have been refused")
			}
		})
	}

	// The valid one is valid, so the refusals above are about what they claim.
	spec, err := ParseSpec(header + disabledPrefix + valid)
	if err != nil {
		t.Fatalf("the control case should parse: %v", err)
	}
	if spec.Len() != 1 {
		t.Fatalf("the control case should hold one rule, got %d", spec.Len())
	}
}

func TestParseSpecSanitisesWhatItDraws(t *testing.T) {
	content := specMarkerPrefix + SpecVersion + "\n" + disabledPrefix +
		`{"index":0,"expr":["counter","drop"],"rule":{"table":{"family":"inet","name":"tui"},"chain":"input","handle":7,"index":0,"comment":"two\nlines","match":{"saddr":"10.0.0.1\t"},"raw":"a\nb"}}`
	spec, err := ParseSpec(content)
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	rule := spec.Disabled[0].Rule
	for name, value := range map[string]string{
		"comment": rule.Comment, "raw": rule.Raw, "saddr": rule.Match.Saddr,
	} {
		if strings.ContainsAny(value, "\n\r\t") {
			t.Errorf("%s reached the table with a control character: %q", name, value)
		}
	}
}

func TestSpecBookkeeping(t *testing.T) {
	entry := disabledFixture()
	var spec Spec
	spec.Apply(Toggle{Entry: entry})
	spec.Apply(Toggle{Entry: entry}) // the same rule twice is still one rule
	if spec.Len() != 1 {
		t.Fatalf("disabling twice recorded %d rules", spec.Len())
	}
	if _, ok := spec.Find(OwnTable, "input", entry.ID()); !ok {
		t.Fatal("the entry should be findable by the row id")
	}
	if _, ok := spec.Find(OwnTable, "forward", entry.ID()); ok {
		t.Error("an entry must not be found in another chain")
	}
	spec.Apply(Toggle{Entry: entry, Enabling: true})
	if !spec.Empty() {
		t.Errorf("enabling should have emptied the spec, %d left", spec.Len())
	}
}
