package nftables

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// Every parser in this package reads bytes another program produced, on a
// machine nobody here has seen. `nft -j list ruleset` is nft's own JSON, but
// "it is JSON" is a claim about the syntax and not about the shapes inside
// it, and a reader that returns nonsense on an unexpected shape is how a
// firewall tool ends up showing a rule that is not there.
//
// So each of the four readers carries a target, seeded from the same fixtures
// the table tests read plus the shapes a real capture never has, and each
// asserts an invariant rather than an output: what a caller of this package is
// entitled to assume, whatever the input was.
//
// See tui-kit/templates/FUZZING.md. `go test` runs every seed on every commit;
// continuous fuzzing is a thing you run:
//
//	go test -run=^$ -fuzz=FuzzParseRuleset -fuzztime=5m ./internal/nftables/

// seedFixtures adds every fixture to a corpus, plus the shapes that break a
// reader and never appear in a capture.
func seedFixtures(f *testing.F) {
	f.Helper()
	for _, name := range fixtures {
		data, err := readTestdata(name)
		if err != nil {
			f.Fatalf("reading seed %s: %v", name, err)
		}
		f.Add(data)
	}
	for _, shape := range []string{
		"",
		"{}",
		"[]",
		"null",
		`{"nftables":[]}`,
		`{"nftables":null}`,
		`{"nftables":[{}]}`,
		`{"nftables":[{"metainfo":{}}]}`,
		`{"nftables":[{"metainfo":{"json_schema_version":2}}]}`,
		`{"nftables":[{"table":{}}]}`,
		`{"nftables":[{"chain":{"name":"c"}}]}`,
		`{"nftables":[{"rule":{"chain":"c","expr":null}}]}`,
		`{"nftables":[{"set":{"name":"s","type":["ipv4_addr","inet_service"]}}]}`,
		`{"nftables":[{"rule":{"family":"inet","table":"t","chain":"c / d",` +
			`"handle":1,"expr":[{"accept":null}]}}]}`,
	} {
		f.Add([]byte(shape))
	}
}

func FuzzParseRuleset(f *testing.F) {
	seedFixtures(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		ruleset, err := ParseRuleset(data)
		if err != nil {
			// A refusal is a fine answer. What it must not be is a refusal
			// that also handed back state.
			if !ruleset.Empty() {
				t.Fatalf("ParseRuleset failed and still returned %d tables",
					len(ruleset.Tables))
			}
			return
		}

		// Reading the same bytes twice has to give the same answer: a UI that
		// re-reads on every change would otherwise flicker between them.
		again, err := ParseRuleset(data)
		if err != nil {
			t.Fatalf("the second parse of the same bytes failed: %v", err)
		}
		if len(again.Tables) != len(ruleset.Tables) {
			t.Fatalf("parsing twice gave %d and %d tables",
				len(ruleset.Tables), len(again.Tables))
		}

		seenTables := map[TableID]bool{}
		totalRules := 0
		for _, table := range ruleset.Tables {
			// Tables are addressed by family and name, and the whole package
			// looks them up that way; two tables with one identity would make
			// every lookup ambiguous.
			if seenTables[table.TableID] {
				t.Fatalf("table %s appears twice", table.TableID)
			}
			seenTables[table.TableID] = true

			for _, set := range table.Sets {
				if set.Name == "" {
					t.Fatal("a set with no name is not addressable")
				}
				if set.Table != table.TableID {
					t.Fatalf("set %s says it is in %s, not %s",
						set.Name, set.Table, table.TableID)
				}
				if set.References < 0 {
					t.Fatalf("set %s has %d references", set.Name, set.References)
				}
			}

			for _, chain := range table.Chains {
				if chain.Name == "" {
					t.Fatal("a chain with no name is not addressable")
				}
				if chain.Table != table.TableID {
					t.Fatalf("chain %s says it is in %s, not %s",
						chain.Name, chain.Table, table.TableID)
				}
				// A chain with no hook has no policy, and the mutation guard
				// reads exactly that to decide whether it may be written to.
				if !chain.Base() && chain.Policy != "" {
					t.Fatalf("chain %s has no hook and a policy %q",
						chain.Name, chain.Policy)
				}
				for i, rule := range chain.Rules {
					if rule.Index != i+1 {
						t.Fatalf("rule %d of %s is numbered %d",
							i, chain.Name, rule.Index)
					}
					if rule.Chain != chain.Name {
						t.Fatalf("rule says it is in chain %s, not %s",
							rule.Chain, chain.Name)
					}
					assertRuleIsPrintable(t, rule)
					totalRules++
				}
			}
		}

		// A set cannot be referred to by more rules than there are rules.
		for _, table := range ruleset.Tables {
			for _, set := range table.Sets {
				if set.References > totalRules {
					t.Fatalf("set %s is used by %d of %d rules",
						set.Name, set.References, totalRules)
				}
			}
		}

		assertModelIsCoherent(t, ruleset)
	})
}

// assertRuleIsPrintable checks what the UI is entitled to assume about a rule
// before it puts one in a table cell.
func assertRuleIsPrintable(t *testing.T, rule Rule) {
	t.Helper()
	for name, value := range map[string]string{
		"raw": rule.Raw, "verdict": rule.Match.Verdict,
		"iif": rule.Match.IIF, "oif": rule.Match.OIF,
		"proto": rule.Match.Proto, "saddr": rule.Match.Saddr,
		"daddr": rule.Match.Daddr, "dport": rule.Match.DPort,
	} {
		// Every one of these goes into a single-line table cell. A newline in
		// one would break the table's own layout, not just the cell.
		if strings.ContainsAny(value, "\n\r") {
			t.Fatalf("rule %s contains a line break: %q", name, value)
		}
		if !utf8.ValidString(value) {
			t.Fatalf("rule %s is not valid UTF-8: %q", name, value)
		}
	}
	for _, name := range rule.Match.Sets {
		if name == "" {
			t.Fatal("a set reference with no name")
		}
		if strings.HasPrefix(name, "@") {
			t.Fatalf("set reference %q keeps the @ that names it", name)
		}
	}
	if family := rule.Match.Family(); family != "" && family != "v4" && family != "v6" {
		t.Fatalf("family = %q, want v4, v6 or nothing", family)
	}
}

// assertModelIsCoherent checks the promise the UI is built on: every group it
// is handed either names a chain that resolves back to itself, or is one of
// the two views that are not chains.
func assertModelIsCoherent(t *testing.T, ruleset Ruleset) {
	t.Helper()
	model := Model(ruleset)
	for _, group := range model.Groups {
		if group.Name == "" {
			t.Fatal("a group with no name cannot be selected")
		}
		if group.Name == GroupNAT || group.Name == GroupAliases {
			continue
		}
		chain, err := ruleset.ChainForGroup(group.Name)
		if err != nil {
			// A chain whose name carries the separator cannot round-trip,
			// and refusing is the right answer. Writing to it must be
			// refused too, and for the same reason.
			if writeErr := ruleset.Writable(group.Name); writeErr == nil {
				t.Fatalf("group %q does not resolve but is writable", group.Name)
			}
			continue
		}
		if GroupName(chain) != group.Name {
			t.Fatalf("group %q resolved to a chain named %q",
				group.Name, GroupName(chain))
		}
		if len(chain.Rules) != len(group.Rules) {
			t.Fatalf("group %q shows %d of %d rules",
				group.Name, len(group.Rules), len(chain.Rules))
		}
	}
	// Detection reads the same ruleset and must agree with the guard: a table
	// a manager owns is never writable.
	management := DetectManagement(ruleset)
	for _, table := range ruleset.Tables {
		if !management.Owns(table.TableID) || table.TableID == OwnTable {
			continue
		}
		for _, chain := range table.Chains {
			if err := ruleset.checkMutable(chain); err == nil {
				t.Fatalf("chain %s of managed table %s is writable",
					chain.Name, table.TableID)
			}
		}
	}
}

func FuzzDecodeExprs(f *testing.F) {
	// Seed with every expression list the fixtures carry, which is the whole
	// vocabulary this package has ever seen nft use.
	for _, name := range fixtures {
		var doc document
		if err := json.Unmarshal(readSeed(f, name), &doc); err != nil {
			continue
		}
		for _, entry := range doc.Nftables {
			raw, ok := entry["rule"]
			if !ok {
				continue
			}
			var rule ruleJSON
			if err := json.Unmarshal(raw, &rule); err != nil {
				continue
			}
			if encoded, err := json.Marshal(rule.Expr); err == nil {
				f.Add(encoded)
			}
		}
	}
	for _, shape := range []string{
		"[]", "null", "[null]", "[{}]", "[[]]", `["accept"]`,
		`[{"accept":null,"drop":null}]`,
		`[{"match":{}}]`,
		`[{"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":"x"}}]`,
		`[{"match":{"left":{"payload":{"base":"th","offset":0,"len":16}},"right":1}}]`,
		`[{"counter":{"packets":-1,"bytes":-1}}]`,
		`[{"dnat":{"addr":"10.0.0.1"}},{"snat":null}]`,
		`[{"limit":{"rate":5,"per":"second"}}]`,
		`[{"match":{"left":{"payload":{"protocol":"ip","field":"saddr"}},` +
			`"right":"@a"}},{"match":{"left":{"payload":{"protocol":"tcp",` +
			`"field":"dport"}},"right":{"set":["@b","@c"]}}}]`,
		// The ct state and ICMP shapes phase 2 models: an array of states, a
		// single state, a set of states, and an ICMP type match.
		`[{"match":{"op":"in","left":{"ct":{"key":"state"}},` +
			`"right":["established","related"]}}]`,
		`[{"match":{"op":"==","left":{"ct":{"key":"state"}},"right":"new"}}]`,
		`[{"match":{"op":"in","left":{"ct":{"key":"state"}},` +
			`"right":{"set":["established","related","new"]}}}]`,
		`[{"match":{"left":{"ct":{"key":"state"}},"right":null}}]`,
		`[{"match":{"left":{"payload":{"protocol":"icmp","field":"type"}},` +
			`"right":"echo-request"}},{"match":{"left":{"payload":` +
			`{"protocol":"ip","field":"protocol"}},"right":"icmp"}}]`,
		// The log and nflog shapes item 10 models: a kernel log with a prefix
		// and level, a log carrying a group (an nflog in disguise), a bare
		// nflog, and a reject whose "with" answer must survive.
		`[{"log":{"prefix":"tui:input drop ","level":"info"}},{"drop":null}]`,
		`[{"log":{"prefix":"tui:input ","group":2}}]`,
		`[{"nflog":{"group":5,"prefix":"tui:forward accept "}},{"accept":null}]`,
		`[{"nflog":null}]`,
		`[{"reject":{"type":"tcp reset"}}]`,
		`[{"reject":{"type":"icmpx","expr":"admin-prohibited"}}]`,
	} {
		f.Add([]byte(shape))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var exprs []any
		if err := json.Unmarshal(data, &exprs); err != nil {
			return
		}
		match, raw := decodeExprs(exprs)

		// The Raw line is one table cell and one line of the detail view.
		if strings.ContainsAny(raw, "\n\r") {
			t.Fatalf("the raw rendering spans lines: %q", raw)
		}
		if !utf8.ValidString(raw) {
			t.Fatalf("the raw rendering is not valid UTF-8: %q", raw)
		}
		if strings.TrimSpace(raw) != raw {
			t.Fatalf("the raw rendering is not trimmed: %q", raw)
		}

		// Every set the columns record has to be visible in the raw line as
		// well, or the alias reference count would be counting something the
		// user cannot see.
		for _, name := range match.Sets {
			if name == "" {
				t.Fatal("an empty set reference")
			}
			if !strings.Contains(raw, "@"+name) {
				t.Fatalf("set %q is counted but not in the raw line %q", name, raw)
			}
		}
		// A modelled ct state is a single-line cell and is visible in the raw
		// line, the way every other column is: what the count and the columns
		// show has to be what the detail line shows.
		if match.CTState != "" {
			if strings.ContainsAny(match.CTState, "\n\r") {
				t.Fatalf("ct state spans lines: %q", match.CTState)
			}
			if !strings.Contains(raw, "ct state "+match.CTState) {
				t.Fatalf("ct state %q is modelled but not in the raw line %q",
					match.CTState, raw)
			}
		}
		// A NAT statement and a verdict are the same decision; they cannot
		// disagree about which one it was.
		if match.NAT != nil && match.Verdict != match.NAT.Kind {
			t.Fatalf("verdict %q with a %q translation",
				match.Verdict, match.NAT.Kind)
		}
		// Decoding is a pure function of the input.
		againMatch, againRaw := decodeExprs(exprs)
		if againRaw != raw || againMatch.Verdict != match.Verdict {
			t.Fatal("decoding the same expressions twice gave two answers")
		}
	})
}

func FuzzRenderElements(f *testing.F) {
	for _, name := range fixtures {
		var doc document
		if err := json.Unmarshal(readSeed(f, name), &doc); err != nil {
			continue
		}
		for _, entry := range doc.Nftables {
			raw, ok := entry["set"]
			if !ok {
				continue
			}
			var set setJSON
			if err := json.Unmarshal(raw, &set); err != nil {
				continue
			}
			if encoded, err := json.Marshal(set.Elem); err == nil {
				f.Add(encoded)
			}
		}
	}
	for _, shape := range []string{
		"[]", "null", "[null]", "[{}]", `["10.0.0.1",22,true]`,
		`[{"prefix":{"addr":"10.0.0.0","len":8}}]`,
		`[{"prefix":{"addr":"10.0.0.0"}}]`,
		`[{"range":[1]}]`, `[{"range":[1,2,3]}]`,
		`[{"concat":["10.0.0.1",80]}]`,
		`[{"elem":{"val":"10.0.0.1","comment":"a host","timeout":30}}]`,
		`[{"elem":{}}]`,
	} {
		f.Add([]byte(shape))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var elems []any
		if err := json.Unmarshal(data, &elems); err != nil {
			return
		}
		rendered := renderElements(elems)
		if len(rendered) > len(elems) {
			t.Fatalf("%d elements rendered into %d", len(elems), len(rendered))
		}
		for _, element := range rendered {
			// An element that rendered to nothing is dropped, never kept as a
			// blank row in the alias view.
			if element == "" {
				t.Fatal("a blank element was kept")
			}
			if !utf8.ValidString(element) {
				t.Fatalf("element is not valid UTF-8: %q", element)
			}
		}
		// The alias view joins the elements with a comma into one cell.
		if joined := strings.Join(rendered, ", "); strings.ContainsAny(joined, "\n\r") {
			t.Fatalf("an element spans lines: %q", joined)
		}
	})
}

func FuzzBuildRuleCommand(f *testing.F) {
	// The other direction: text the user typed becomes an nft argv. nft joins
	// its arguments into one buffer and parses that, so an operand carrying a
	// semicolon or a quote is the nftables equivalent of a shell injection,
	// and the only thing standing between the two is this builder.
	seeds := [][]string{
		{"ALLOW", "tcp", "22", "", "", "", ""},
		{"DENY", "udp", "53", "10.0.0.0/8", "", "", "v4"},
		{"REJECT", "tcp", "80,443", "", "192.168.1.1", "web", ""},
		{"ALLOW", "tcp", "2000:2100", "@lan_hosts", "", "range", "v4"},
		{"ALLOW", "", "", "fd00::/8", "", "", "v6"},
		{"ALLOW", "tcp", "22; drop", "", "", "", ""},
		{"ALLOW", "tcp", "22", "", "", "a \" quote", ""},
		{"ALLOW", "tcp", "22", "", "", "two\nlines", ""},
		{"", "", "", "", "", "", ""},
	}
	for _, seed := range seeds {
		f.Add(seed[0], seed[1], seed[2], seed[3], seed[4], seed[5], seed[6])
	}

	ruleset, err := ParseRuleset(mustReadSeedBytes(f, "router"))
	if err != nil {
		f.Fatalf("reading the router fixture: %v", err)
	}
	chain, ok := ruleset.Chain(OwnTable, "input")
	if !ok {
		f.Fatal("the router fixture has no input chain")
	}

	f.Fuzz(func(t *testing.T, action, proto, ports, from, to, comment, family string) {
		change, err := ruleset.BuildAddRule(chain, firewall.RuleSpec{
			Action:  firewall.Action(action),
			Proto:   proto,
			Ports:   ports,
			From:    from,
			To:      to,
			Comment: comment,
			Family:  firewall.Family(family),
		})
		if err != nil {
			return
		}
		if len(change.Commands) != 1 {
			t.Fatalf("an added rule is one command, got %d", len(change.Commands))
		}
		argv := change.Commands[0].Argv
		if len(argv) < 7 || argv[0] != "nft" {
			t.Fatalf("argv does not start an nft command: %q", argv)
		}
		if argv[1] != "add" && argv[1] != "insert" {
			t.Fatalf("argv[1] = %q, want add or insert", argv[1])
		}
		// The chain the rule lands in is the chain that was asked for, and
		// nothing the user typed may move it.
		if argv[3] != chain.Table.Family || argv[4] != chain.Table.Name ||
			argv[5] != chain.Name {
			t.Fatalf("the rule was aimed at %q", argv[3:6])
		}
		for i, word := range argv {
			// nft concatenates its arguments and parses the result, so a
			// newline in any of them would start a second command.
			if strings.ContainsAny(word, "\n\r") {
				t.Fatalf("argv[%d] = %q spans lines", i, word)
			}
			isComment := i > 0 && argv[i-1] == "comment"
			// A quote is legal in exactly one place: around a comment, where
			// the builder put it and where nft's grammar needs it. Inside
			// those quotes a semicolon is text — nft's lexer has already
			// decided the word is a string — and everywhere else it would end
			// the statement and begin another.
			switch {
			case isComment:
				if !strings.HasPrefix(word, "\"") || !strings.HasSuffix(word, "\"") ||
					strings.Count(word, "\"") != 2 || len(word) < 2 {
					t.Fatalf("comment %q is not one quoted word", word)
				}
			case structuralWords[word]:
				// A brace or a semicolon the builder emitted as a word of its
				// own is nft's punctuation, put there on purpose.
			case strings.ContainsAny(word, ";\"'{}\\"):
				t.Fatalf("argv[%d] = %q carries nft syntax", i, word)
			}
		}
		// Every rule this backend writes counts, and every rule decides.
		if !containsWord(argv, "counter") {
			t.Fatalf("no counter in %q", argv)
		}
	})
}

// FuzzBuildFlowRule is the phase-2 half of the builder fuzz: the router-shaped
// matches (interface, connection state, ICMP) become nft argv words. The same
// injection guard the port and address path has must hold for these, because
// they carry text the user typed just as directly.
func FuzzBuildFlowRule(f *testing.F) {
	seeds := [][]string{
		{"lan0", "wan0", "established,related", "tcp", ""},
		{"", "", "new", "icmp", "echo-request"},
		{"wan0; drop", "", "", "", ""},
		{"", "", "established,\ndrop", "", ""},
		{"eth0", "eth1", "invalid", "icmpv6", "nd-router-advert"},
		{"", "", "", "esp", ""},
		{"", "", "", "icmp", "\"bad\""},
	}
	for _, seed := range seeds {
		f.Add(seed[0], seed[1], seed[2], seed[3], seed[4])
	}

	ruleset, err := ParseRuleset(mustReadSeedBytes(f, "router"))
	if err != nil {
		f.Fatalf("reading the router fixture: %v", err)
	}
	chain, ok := ruleset.Chain(OwnTable, "input")
	if !ok {
		f.Fatal("the router fixture has no input chain")
	}

	f.Fuzz(func(t *testing.T, iif, oif, ctstate, proto, icmpType string) {
		var states []string
		if ctstate != "" {
			states = strings.Split(ctstate, ",")
		}
		change, err := ruleset.BuildAddRule(chain, firewall.RuleSpec{
			Action:   firewall.ActionAllow,
			InIface:  iif,
			OutIface: oif,
			CTStates: states,
			Proto:    proto,
			ICMPType: icmpType,
		})
		if err != nil {
			return
		}
		if len(change.Commands) != 1 {
			t.Fatalf("a flow rule is one command, got %d", len(change.Commands))
		}
		argv := change.Commands[0].Argv
		for i, word := range argv {
			if strings.ContainsAny(word, "\n\r") {
				t.Fatalf("argv[%d] = %q spans lines", i, word)
			}
			// An interface name is the one operand quoted here; inside those
			// quotes a stray character is text, and nowhere else may syntax slip
			// through.
			quoted := strings.HasPrefix(word, "\"") && strings.HasSuffix(word, "\"") &&
				strings.Count(word, "\"") == 2 && len(word) >= 2
			switch {
			case quoted, structuralWords[word]:
			case strings.ContainsAny(word, ";\"'{}\\"):
				t.Fatalf("argv[%d] = %q carries nft syntax", i, word)
			}
		}
		if !containsWord(argv, "counter") {
			t.Fatalf("no counter in %q", argv)
		}
	})
}

// FuzzFakeApplyScript feeds arbitrary bytes to the demo's batch path, which is
// the tokenizer and the statement applier the staging flow runs in --demo. What
// it must never do is panic or leave the in-memory ruleset in a shape the model
// cannot render — a batch that fails is undone, not half-applied.
func FuzzFakeApplyScript(f *testing.F) {
	for _, seed := range []string{
		"",
		"flush ruleset",
		"add rule inet tui input tcp dport 22 counter accept",
		"add rule inet tui input iifname \"wan0\" ct state established,related counter accept",
		"flush ruleset\nadd table inet tui\nadd chain inet tui input { type filter hook input priority 0 ; policy drop ; }",
		"{\"tables\":[{\"family\":\"inet\",\"name\":\"tui\"}]}",
		"delete table inet tui",
		"garbage that is not a statement at all",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		fake := NewFake()
		// A batch either applies whole or leaves the ruleset untouched; either
		// way the result must be a ruleset the model can render.
		_, _ = fake.Run(context.Background(),
			firewall.One(firewall.Command{Argv: []string{"nft", "-f", "-"}, Stdin: string(data)}))
		ruleset := fake.Ruleset()
		model := Model(ruleset)
		for _, group := range model.Groups {
			if group.Name == "" {
				t.Fatal("a batch left a group with no name")
			}
		}
		// countReferences must have stayed consistent: no negative counts.
		for _, table := range ruleset.Tables {
			for _, set := range table.Sets {
				if set.References < 0 {
					t.Fatalf("set %s has %d references after a batch",
						set.Name, set.References)
				}
			}
		}
	})
}

// structuralWords are nft's punctuation, which the builders emit as argv
// words of their own. Anywhere else in a word those characters would be an
// operand smuggling syntax past the parser.
var structuralWords = map[string]bool{"{": true, "}": true, ";": true}

// containsWord reports whether an argv holds a word.
func containsWord(argv []string, word string) bool {
	for _, w := range argv {
		if w == word {
			return true
		}
	}
	return false
}

// readSeed reads a fixture during corpus construction, skipping it rather
// than failing: a missing seed is a weaker corpus, not a broken target.
func readSeed(f *testing.F, name string) []byte {
	f.Helper()
	data, err := readTestdata(name)
	if err != nil {
		return nil
	}
	return data
}

// mustReadSeedBytes reads a fixture a target cannot run without.
func mustReadSeedBytes(f *testing.F, name string) []byte {
	f.Helper()
	data, err := readTestdata(name)
	if err != nil {
		f.Fatalf("reading %s: %v", name, err)
	}
	return data
}

// FuzzParseSpec drives the reader of the tool's own saved file. The file is
// root-owned and this tool wrote it, but "we wrote it" is a claim about the
// last process to touch it, not about the bytes on disk — and what comes out
// of it becomes an nft statement and a table row. The invariant is that
// whatever parses is safe to hand to both: every statement word is one nft
// operand or one closed quoted string, and nothing the table draws carries a
// control character that would break the layout of the screen rather than the
// cell.
func FuzzParseSpec(f *testing.F) {
	marker := specMarkerPrefix + SpecVersion + "\n"
	valid := `{"index":1,"expr":["tcp","dport","22","counter","drop"],` +
		`"rule":{"table":{"family":"inet","name":"tui"},"chain":"input",` +
		`"handle":7,"index":0,"match":{"dport":"22"},"raw":"tcp dport 22"}}`
	for _, seed := range []string{
		"",
		"table inet tui {\n}\n",
		marker,
		marker + disabledPrefix + valid,
		marker + disabledPrefix + "{}",
		marker + disabledPrefix + "null",
		marker + disabledPrefix + "[]",
		specMarkerPrefix + "v1\n",
		disabledPrefix + valid,
		marker + disabledPrefix + `{"index":0,"expr":["drop;flush ruleset"],` +
			`"rule":{"table":{"family":"inet","name":"tui"},"chain":"c","handle":1,"match":{},"raw":""}}`,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content string) {
		spec, err := ParseSpec(content)
		if err != nil {
			return
		}
		for _, entry := range spec.Disabled {
			if len(entry.Expr) == 0 {
				t.Fatalf("an accepted entry has nothing to put back: %+v", entry)
			}
			for _, word := range entry.Expr {
				if err := checkSpecWord(word); err != nil {
					t.Fatalf("an accepted statement word is not safe: %q (%v)", word, err)
				}
				if strings.ContainsAny(word, ";\n\r") {
					t.Fatalf("an accepted statement word can end the statement: %q", word)
				}
			}
			for _, name := range []string{
				entry.Rule.Table.Family, entry.Rule.Table.Name, entry.Rule.Chain,
			} {
				if err := checkSpecName(name); err != nil {
					t.Fatalf("an accepted name is not safe: %q (%v)", name, err)
				}
			}
			// Everything the row draws has been through the one-line pass.
			row := renderDisabled(entry, firewall.DirIn)
			for _, cell := range []string{
				string(row.Action), row.From, row.To, row.Ports, row.Proto,
				row.Comment, row.Raw, row.Extra[firewall.ExtraDetail],
				row.Extra[firewall.ExtraInIface], row.Extra[firewall.ExtraOutIface],
			} {
				if strings.ContainsAny(cell, "\n\r\t") {
					t.Fatalf("a drawn cell carries a control character: %q", cell)
				}
			}
			if !utf8.ValidString(row.Raw) {
				t.Fatalf("a drawn cell is not valid UTF-8: %q", row.Raw)
			}
		}
	})
}

// FuzzSaveFileRoundTrip asserts that anything this package writes, it reads
// back: a disabled rule that survived the guards must survive the file, or a
// save would quietly drop the rule it exists to preserve.
func FuzzSaveFileRoundTrip(f *testing.F) {
	f.Add("input", "10.0.0.0/8", "a comment", 3)
	f.Add("forward", "@lan_hosts", "", 0)
	f.Add("output", "", "quotes \" and ; semicolons", 1)

	f.Fuzz(func(t *testing.T, chain, saddr, comment string, index int) {
		if index < 0 {
			index = -index
		}
		entry := DisabledRule{
			Index: index,
			Expr:  []string{"counter", "drop"},
			Rule: Rule{
				Table: OwnTable, Chain: chain, Handle: 3, Comment: comment,
				Match: Match{Verdict: "drop", Saddr: saddr},
			},
		}
		spec := Spec{Disabled: []DisabledRule{sanitizeDisabled(entry)}}
		content, err := RenderSaveFile("table inet tui {\n}", spec)
		if err != nil {
			// A rule this package refuses to write is a rule it also refuses
			// to build, which is the guard doing its job.
			return
		}
		back, err := ParseSpec(content)
		if err != nil {
			t.Fatalf("what this package wrote, it must read: %v\n%s", err, content)
		}
		if back.Len() != 1 {
			t.Fatalf("wrote 1 disabled rule, read %d back:\n%s", back.Len(), content)
		}
		if back.Disabled[0].Index != index {
			t.Errorf("position %d came back as %d", index, back.Disabled[0].Index)
		}
	})
}
