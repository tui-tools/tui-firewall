package nftables

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures, and where they come from.
//
// `nft -j list ruleset` needs root, and this repository's tests do not have
// it. What they do have is nft itself: a user namespace with a network
// namespace of its own carries CAP_NET_ADMIN over that namespace's empty
// ruleset, so `unshare -rn nft ...` loads and lists a ruleset with the real
// binary while touching nothing on the host. Every fixture here was produced
// that way, with nftables v1.1.1, from the .nft source file of the same name
// that sits beside it:
//
//	unshare -rn sh -c 'nft -f router.nft && nft -j -a list ruleset' > router.json
//
// So the JSON is captured — nft wrote every byte of it — while the ruleset
// that produced it is constructed, except for empty.json, which is a real
// listing of a real empty ruleset and is constructed in no sense at all.
//
//   - empty.json      captured, nothing loaded: a machine with no firewall
//   - router.json     captured from router.nft: the shape the router profile
//     provisions, with the tool's own table, the three
//     filter chains, both NAT chains and three aliases
//   - firewalld.json  captured from firewalld.nft: the table and per-zone
//     chain tree firewalld installs on a machine it manages
//   - ufw.json        captured from ufw.nft: what ufw leaves behind, which is
//     the legacy filter tables of iptables-nft carrying
//     the chain names ufw generates
//
// The two manager fixtures are hand-built rather than taken off a running
// machine on purpose: a capture from this host would carry its interfaces and
// addresses, and a fixture is not the place for either.
// fixtures are the four rulesets every table test runs over.
var fixtures = []string{"empty", "router", "firewalld", "ufw"}

// readTestdata reads one fixture. It is the only place in these tests that
// opens a file, so the one path they build is built once.
func readTestdata(name string) ([]byte, error) {
	//nolint:gosec // the name comes from the fixture list in this file
	return os.ReadFile(filepath.Join("testdata", name+".json"))
}

// readFixture loads one fixture by name, failing the test when it cannot.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := readTestdata(name)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return data
}

// parseFixture parses one fixture by name.
func parseFixture(t *testing.T, name string) Ruleset {
	t.Helper()
	ruleset, err := ParseRuleset(readFixture(t, name))
	if err != nil {
		t.Fatalf("ParseRuleset(%s): %v", name, err)
	}
	return ruleset
}

func TestParseRulesetCounts(t *testing.T) {
	cases := []struct {
		fixture    string
		tables     int
		chains     int
		baseChains int
		sets       int
		rules      int
		version    string
	}{
		{fixture: "empty", version: "1.1.1"},
		{fixture: "router", tables: 1, chains: 6, baseChains: 5, sets: 3,
			rules: 19, version: "1.1.1"},
		{fixture: "firewalld", tables: 1, chains: 26, baseChains: 5, sets: 1,
			rules: 36, version: "1.1.1"},
		{fixture: "ufw", tables: 2, chains: 24, baseChains: 4, sets: 0,
			rules: 36, version: "1.1.1"},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			ruleset := parseFixture(t, tc.fixture)
			if got := len(ruleset.Tables); got != tc.tables {
				t.Errorf("tables = %d, want %d", got, tc.tables)
			}
			if ruleset.Version != tc.version {
				t.Errorf("version = %q, want %q", ruleset.Version, tc.version)
			}
			if ruleset.SchemaVersion != schemaVersion {
				t.Errorf("schema = %d, want %d", ruleset.SchemaVersion, schemaVersion)
			}
			chains, sets, rules := 0, 0, 0
			for _, table := range ruleset.Tables {
				chains += len(table.Chains)
				sets += len(table.Sets)
				for _, chain := range table.Chains {
					rules += len(chain.Rules)
				}
			}
			if chains != tc.chains {
				t.Errorf("chains = %d, want %d", chains, tc.chains)
			}
			if sets != tc.sets {
				t.Errorf("sets = %d, want %d", sets, tc.sets)
			}
			if rules != tc.rules {
				t.Errorf("rules = %d, want %d", rules, tc.rules)
			}
			if got := len(ruleset.BaseChains()); got != tc.baseChains {
				t.Errorf("base chains = %d, want %d", got, tc.baseChains)
			}
		})
	}
}

func TestParseRulesetBaseChainDetails(t *testing.T) {
	ruleset := parseFixture(t, "router")
	cases := []struct {
		chain    string
		kind     string
		hook     string
		priority int
		policy   string
		describe string
	}{
		{"input", "filter", "input", 0, PolicyDrop,
			"type filter hook input priority 0; policy drop"},
		{"output", "filter", "output", 0, PolicyAccept,
			"type filter hook output priority 0; policy accept"},
		{"forward", "filter", "forward", 0, PolicyDrop,
			"type filter hook forward priority 0; policy drop"},
		{"prerouting", "nat", "prerouting", -100, PolicyAccept,
			"type nat hook prerouting priority -100; policy accept"},
		{"postrouting", "nat", "postrouting", 100, PolicyAccept,
			"type nat hook postrouting priority 100; policy accept"},
	}
	for _, tc := range cases {
		t.Run(tc.chain, func(t *testing.T) {
			chain, ok := ruleset.Chain(OwnTable, tc.chain)
			if !ok {
				t.Fatalf("chain %s is missing", tc.chain)
			}
			if !chain.Base() {
				t.Error("chain should be a base chain")
			}
			if chain.Type != tc.kind || chain.Hook != tc.hook ||
				chain.Priority != tc.priority || chain.Policy != tc.policy {
				t.Errorf("chain = %+v, want type %s hook %s priority %d policy %s",
					chain, tc.kind, tc.hook, tc.priority, tc.policy)
			}
			if got := chain.Describe(); got != tc.describe {
				t.Errorf("Describe() = %q, want %q", got, tc.describe)
			}
		})
	}
}

func TestParseRulesetRegularChainHasNoPolicy(t *testing.T) {
	// The distinction the mutation guard turns on: a chain with no hook has
	// no policy, and nothing this backend writes may land in one.
	chain, ok := parseFixture(t, "router").Chain(OwnTable, "admin_services")
	if !ok {
		t.Fatal("admin_services is missing")
	}
	if chain.Base() {
		t.Error("admin_services has no hook and must not report as a base chain")
	}
	if chain.Policy != "" {
		t.Errorf("policy = %q, want empty on a regular chain", chain.Policy)
	}
	if got := chain.Describe(); !strings.Contains(got, "regular chain") {
		t.Errorf("Describe() = %q, want it to say the chain is regular", got)
	}
}

func TestParseRulesetSets(t *testing.T) {
	ruleset := parseFixture(t, "router")
	cases := []struct {
		name       string
		setType    string
		interval   bool
		elements   []string
		references int
		comment    string
	}{
		{
			name: "lan_hosts", setType: "ipv4_addr", interval: true,
			elements:   []string{"10.10.0.0/24", "192.168.50.10"},
			references: 3,
			comment:    "hosts allowed to reach the router services",
		},
		{
			name: "lan6_hosts", setType: "ipv6_addr", interval: false,
			elements:   []string{"fd00:10::5", "fd00:10::6"},
			references: 1,
			comment:    "the v6 half of the same list",
		},
		{
			name: "admin_ports", setType: "inet_service", interval: true,
			elements:   []string{"22", "9090-9095"},
			references: 1,
			comment:    "ports the admin network may reach",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set, ok := ruleset.Set(OwnTable, tc.name)
			if !ok {
				t.Fatalf("set %s is missing", tc.name)
			}
			if set.Type != tc.setType {
				t.Errorf("type = %q, want %q", set.Type, tc.setType)
			}
			if set.Interval() != tc.interval {
				t.Errorf("Interval() = %v, want %v", set.Interval(), tc.interval)
			}
			if got := strings.Join(set.Elements, ","); got != strings.Join(tc.elements, ",") {
				t.Errorf("elements = %v, want %v", set.Elements, tc.elements)
			}
			if set.References != tc.references {
				t.Errorf("references = %d, want %d", set.References, tc.references)
			}
			if set.Comment != tc.comment {
				t.Errorf("comment = %q, want %q", set.Comment, tc.comment)
			}
			if got := set.Ref(); got != "@"+tc.name {
				t.Errorf("Ref() = %q, want @%s", got, tc.name)
			}
		})
	}
}

func TestParseRulesetRuleColumns(t *testing.T) {
	ruleset := parseFixture(t, "router")
	cases := []struct {
		chain   string
		comment string
		want    Match
		raw     string
	}{
		{
			chain: "input", comment: "admin from lan",
			want: Match{
				Verdict: "accept", Proto: "tcp",
				Saddr: "@lan_hosts", DPort: "@admin_ports",
				Counter: &Counter{}, Sets: []string{"lan_hosts", "admin_ports"},
				family4: true,
			},
			raw: "ip saddr @lan_hosts tcp dport @admin_ports " +
				"counter packets 0 bytes 0 accept",
		},
		{
			chain: "input", comment: "no ssh from the wan",
			want: Match{
				Verdict: "drop", IIF: "wan0", Proto: "tcp", DPort: "22",
				Counter: &Counter{},
			},
			raw: "iifname wan0 tcp dport 22 counter packets 0 bytes 0 drop",
		},
		{
			chain: "forward", comment: "lan to wan",
			want: Match{
				Verdict: "accept", IIF: "lan0", OIF: "wan0", Counter: &Counter{},
			},
			raw: "iifname lan0 oifname wan0 counter packets 0 bytes 0 accept",
		},
		{
			chain: "output", comment: "no smtp out",
			want: Match{
				Verdict: "reject", OIF: "wan0", Proto: "tcp", DPort: "25",
				Counter: &Counter{},
			},
			raw: "oifname wan0 tcp dport 25 counter packets 0 bytes 0 " +
				"reject with tcp reset",
		},
		{
			chain: "prerouting", comment: "web port forward",
			want: Match{
				Verdict: "dnat", IIF: "wan0", Proto: "tcp", DPort: "8080",
				Counter: &Counter{},
				NAT:     &NAT{Kind: "dnat", Addr: "10.10.0.5", Port: "80"},
			},
			raw: "iifname wan0 tcp dport 8080 counter packets 0 bytes 0 " +
				"dnat to 10.10.0.5:80",
		},
		{
			chain: "postrouting", comment: "wan nat",
			want: Match{
				Verdict: "masquerade", OIF: "wan0", Counter: &Counter{},
				NAT: &NAT{Kind: "masquerade"},
			},
			raw: "oifname wan0 counter packets 0 bytes 0 masquerade",
		},
		{
			chain: "postrouting", comment: "static outbound address",
			want: Match{
				Verdict: "snat", OIF: "wan0", Saddr: "10.10.0.5",
				Counter: &Counter{},
				NAT:     &NAT{Kind: "snat", Addr: "203.0.113.9"},
				family4: true,
			},
			raw: "ip saddr 10.10.0.5 oifname wan0 counter packets 0 bytes 0 " +
				"snat to 203.0.113.9",
		},
	}
	for _, tc := range cases {
		t.Run(tc.chain+"/"+tc.comment, func(t *testing.T) {
			rule, ok := findRuleByComment(ruleset, tc.chain, tc.comment)
			if !ok {
				t.Fatalf("no rule commented %q in %s", tc.comment, tc.chain)
			}
			assertMatch(t, rule.Match, tc.want)
			if rule.Raw != tc.raw {
				t.Errorf("Raw =\n  %q\nwant\n  %q", rule.Raw, tc.raw)
			}
			if rule.Handle <= 0 {
				t.Errorf("handle = %d, want a positive nft handle", rule.Handle)
			}
		})
	}
}

func TestParseRulesetModelsCTState(t *testing.T) {
	// A ct state match is what makes a rule stateful; it reads back into a
	// column of its own so the UI can show "established,related" rather than
	// letting the match fall into the raw line unmodeled.
	rule, ok := findRuleByComment(parseFixture(t, "router"), "input", "keep state")
	if !ok {
		t.Fatal("the keep-state rule is missing")
	}
	if rule.Match.CTState != "established,related" {
		t.Errorf("CTState = %q, want established,related", rule.Match.CTState)
	}
	for _, u := range rule.Match.Unmodeled {
		if strings.Contains(u, "ct state") {
			t.Errorf("the ct state match is modeled, so it should not also be "+
				"unmodeled: %q", u)
		}
	}
	if !strings.Contains(rule.Raw, "ct state established,related") {
		t.Errorf("Raw = %q, want the ct state match in it", rule.Raw)
	}
}

func TestParseRulesetLogStatement(t *testing.T) {
	ruleset := parseFixture(t, "router")
	chain, _ := ruleset.Chain(OwnTable, "input")
	last := chain.Rules[len(chain.Rules)-1]
	if !last.Match.Log {
		t.Error("the last input rule logs and Match.Log should say so")
	}
	if last.Match.Verdict != "" {
		t.Errorf("verdict = %q, want empty: the rule logs and falls through",
			last.Match.Verdict)
	}
	if !strings.Contains(last.Raw, `log prefix "tui input drop " level info`) {
		t.Errorf("Raw = %q, want the log prefix and level", last.Raw)
	}
}

func TestParseRulesetFamilyPerRule(t *testing.T) {
	ruleset := parseFixture(t, "router")
	cases := map[string]string{
		"admin from lan":    "v4",
		"admin from lan v6": "v6",
		"keep state":        "",
	}
	for comment, want := range cases {
		rule, ok := findRuleByComment(ruleset, "input", comment)
		if !ok {
			t.Fatalf("no rule commented %q", comment)
		}
		if got := rule.Match.Family(); got != want {
			t.Errorf("%q: family = %q, want %q", comment, got, want)
		}
	}
}

func TestParseEmptyRuleset(t *testing.T) {
	ruleset := parseFixture(t, "empty")
	if !ruleset.Empty() {
		t.Error("an empty ruleset should report itself as empty")
	}
	if ruleset.Filtering() {
		t.Error("nothing is filtering when there is no chain at all")
	}
	if DetectManagement(ruleset).Managed() {
		t.Error("an empty ruleset is managed by nobody")
	}
}

func TestParseRulesetRejectsAnUnknownSchema(t *testing.T) {
	// A schema bump means nft changed the shape of what it prints. Guessing
	// at it would show rules that are not there, so the reader stops.
	data := []byte(`{"nftables":[{"metainfo":{"version":"9.9",` +
		`"json_schema_version":2}},{"table":{"family":"inet","name":"x"}}]}`)
	_, err := ParseRuleset(data)
	if err == nil {
		t.Fatal("expected an error for an unknown schema version")
	}
	for _, want := range []string{"schema version 2", "refusing"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

func TestParseRulesetRejectsGarbage(t *testing.T) {
	for _, input := range []string{"", "not json", "[]", "{", `{"nftables":3}`} {
		if _, err := ParseRuleset([]byte(input)); err == nil {
			t.Errorf("ParseRuleset(%q) should have failed", input)
		}
	}
}

func TestParseRulesetToleratesAnUnannouncedChain(t *testing.T) {
	// A rule whose chain nft never listed is kept rather than dropped: the
	// chain it lands in has no hook, so the mutation guard refuses to write
	// to it, and the rule is still visible.
	data := []byte(`{"nftables":[{"metainfo":{"json_schema_version":1}},` +
		`{"rule":{"family":"inet","table":"t","chain":"orphan","handle":7,` +
		`"expr":[{"accept":null}]}}]}`)
	ruleset, err := ParseRuleset(data)
	if err != nil {
		t.Fatalf("ParseRuleset: %v", err)
	}
	chain, ok := ruleset.Chain(TableID{Family: "inet", Name: "t"}, "orphan")
	if !ok {
		t.Fatal("the orphaned rule's chain should have been created")
	}
	if len(chain.Rules) != 1 || chain.Rules[0].Handle != 7 {
		t.Errorf("chain = %+v, want the one rule with handle 7", chain)
	}
	if err := ruleset.checkMutable(chain); err == nil {
		t.Error("a chain with no hook must not be writable")
	}
}

func TestParseSetElementShapes(t *testing.T) {
	cases := []struct {
		name string
		elem any
		want string
	}{
		{"plain string", "10.0.0.1", "10.0.0.1"},
		{"number", float64(22), "22"},
		{"prefix", map[string]any{
			"prefix": map[string]any{"addr": "10.0.0.0", "len": float64(8)},
		}, "10.0.0.0/8"},
		{"range", map[string]any{
			"range": []any{float64(9090), float64(9095)},
		}, "9090-9095"},
		{"concat", map[string]any{
			"concat": []any{"10.0.0.1", float64(80)},
		}, "10.0.0.1 . 80"},
		{"commented", map[string]any{
			"elem": map[string]any{"val": "10.0.0.1", "comment": "the gateway"},
		}, "10.0.0.1 # the gateway"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderElement(tc.elem); got != tc.want {
				t.Errorf("renderElement = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParsePriorityAcceptsBothSpellings(t *testing.T) {
	cases := []struct {
		raw   string
		value int
		name  string
	}{
		{`-100`, -100, ""},
		{`0`, 0, ""},
		{`"filter"`, 0, "filter"},
		{`"10"`, 10, ""},
		{``, 0, ""},
	}
	for _, tc := range cases {
		value, name := parsePriority([]byte(tc.raw))
		if value != tc.value || name != tc.name {
			t.Errorf("parsePriority(%q) = %d, %q; want %d, %q",
				tc.raw, value, name, tc.value, tc.name)
		}
	}
}

// findRuleByComment returns the rule of a chain carrying a given comment.
func findRuleByComment(rs Ruleset, chain, comment string) (Rule, bool) {
	for _, table := range rs.Tables {
		for _, c := range table.Chains {
			if c.Name != chain {
				continue
			}
			for _, rule := range c.Rules {
				if rule.Comment == comment {
					return rule, true
				}
			}
		}
	}
	return Rule{}, false
}

// assertMatch compares the columns of a decoded rule, field by field, so a
// failure names the column that is wrong rather than dumping two structs.
func assertMatch(t *testing.T, got, want Match) {
	t.Helper()
	fields := []struct {
		name      string
		got, want string
	}{
		{"verdict", got.Verdict, want.Verdict},
		{"iif", got.IIF, want.IIF},
		{"oif", got.OIF, want.OIF},
		{"proto", got.Proto, want.Proto},
		{"saddr", got.Saddr, want.Saddr},
		{"daddr", got.Daddr, want.Daddr},
		{"sport", got.SPort, want.SPort},
		{"dport", got.DPort, want.DPort},
		{"family", got.Family(), want.Family()},
		{"sets", strings.Join(got.Sets, ","), strings.Join(want.Sets, ",")},
	}
	for _, f := range fields {
		if f.got != f.want {
			t.Errorf("%s = %q, want %q", f.name, f.got, f.want)
		}
	}
	if (got.Counter == nil) != (want.Counter == nil) {
		t.Errorf("counter = %v, want %v", got.Counter, want.Counter)
	}
	switch {
	case (got.NAT == nil) != (want.NAT == nil):
		t.Errorf("nat = %v, want %v", got.NAT, want.NAT)
	case got.NAT != nil && *got.NAT != *want.NAT:
		t.Errorf("nat = %+v, want %+v", *got.NAT, *want.NAT)
	}
}
