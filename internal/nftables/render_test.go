package nftables

import (
	"encoding/json"
	"testing"
)

// decode is the shortcut every case here uses: the JSON nft prints for one
// expression list, decoded the way ParseRuleset decodes it.
func decode(t *testing.T, expressions string) (Match, string) {
	t.Helper()
	var exprs []any
	if err := json.Unmarshal([]byte(expressions), &exprs); err != nil {
		t.Fatalf("bad test input: %v", err)
	}
	return decodeExprs(exprs)
}

func TestRenderStatements(t *testing.T) {
	cases := []struct {
		name string
		json string
		raw  string
	}{
		{
			name: "an interface match loses the meta word nft omits",
			json: `[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},` +
				`"right":"wan0"}}]`,
			raw: "iifname wan0",
		},
		{
			name: "a meta key with no keyword keeps it",
			json: `[{"match":{"op":"==","left":{"meta":{"key":"mark"}},"right":1}}]`,
			// meta mark has no column of its own, so the operator stays: the
			// raw line has to read as the rule, not as a summary of it.
			raw: "meta mark == 1",
		},
		{
			name: "a reject says what it answers with",
			json: `[{"reject":{"type":"icmpx","expr":"admin-prohibited"}}]`,
			raw:  "reject with icmpx admin-prohibited",
		},
		{
			name: "a log keeps its prefix and level",
			json: `[{"log":{"prefix":"drop ","level":"warn"}}]`,
			raw:  `log prefix "drop " level warn`,
		},
		{
			name: "a jump names its target",
			json: `[{"jump":{"target":"filter_IN_public"}}]`,
			raw:  "jump filter_IN_public",
		},
		{
			name: "a set literal is rendered as nft spells it",
			json: `[{"match":{"op":"==","left":{"payload":{"protocol":"tcp",` +
				`"field":"dport"}},"right":{"set":[22,80,443]}}}]`,
			raw: "tcp dport { 22, 80, 443 }",
		},
		{
			name: "a prefix operand keeps its length",
			json: `[{"match":{"op":"==","left":{"payload":{"protocol":"ip6",` +
				`"field":"daddr"}},"right":{"prefix":{"addr":"fe80::","len":64}}}}]`,
			raw: "ip6 daddr fe80::/64",
		},
		{
			name: "a raw payload has no protocol to name",
			json: `[{"match":{"op":"==","left":{"payload":{"base":"th",` +
				`"offset":0,"len":16}},"right":22}}]`,
			raw: "@th,0,16 == 22",
		},
		{
			name: "an unmodeled statement keeps nft's own word for it",
			json: `[{"limit":{"rate":5,"per":"second"}}]`,
			raw:  `limit {"per":"second","rate":5}`,
		},
		{
			name: "a masquerade to a port range",
			json: `[{"masquerade":{"port":8080}}]`,
			raw:  "masquerade to :8080",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, raw := decode(t, tc.json)
			if raw != tc.raw {
				t.Errorf("raw = %q, want %q", raw, tc.raw)
			}
		})
	}
}

func TestRenderKeepsAnUnmodeledMatchOutOfTheColumns(t *testing.T) {
	// A negated interface match is not "this rule is about wan0": putting it
	// in the interface column would say the opposite of what the rule does.
	match, raw := decode(t, `[{"match":{"op":"!=","left":{"meta":`+
		`{"key":"iifname"}},"right":"wan0"}}]`)
	if match.IIF != "" {
		t.Errorf("iif = %q, want empty: the match is a negation", match.IIF)
	}
	if raw != "iifname != wan0" {
		t.Errorf("raw = %q", raw)
	}
	if len(match.Unmodeled) != 1 || match.Unmodeled[0] != raw {
		t.Errorf("Unmodeled = %v, want the negation", match.Unmodeled)
	}
}

func TestRenderFillsAColumnOnlyOnce(t *testing.T) {
	// Two destination port matches in one rule: the first fills the column,
	// and the second is still visible in the raw line rather than silently
	// replacing it.
	match, raw := decode(t, `[`+
		`{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},`+
		`{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":80}}]`)
	if match.DPort != "22" {
		t.Errorf("dport = %q, want the first match", match.DPort)
	}
	if want := "tcp dport 22 tcp dport == 80"; raw != want {
		t.Errorf("raw = %q, want %q", raw, want)
	}
}

func TestRenderProtocolComesFromThePayloadHeader(t *testing.T) {
	// nft spells a port match as `tcp dport 22`: the protocol is the payload
	// header, not a match of its own, and the column has to read it there.
	match, _ := decode(t, `[{"match":{"op":"==","left":{"payload":`+
		`{"protocol":"udp","field":"dport"}},"right":53}}]`)
	if match.Proto != "udp" || match.DPort != "53" {
		t.Errorf("proto/dport = %q/%q, want udp/53", match.Proto, match.DPort)
	}
}

func TestRenderCollectsSetReferences(t *testing.T) {
	match, _ := decode(t, `[`+
		`{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"@hosts"}},`+
		`{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":"@ports"}}]`)
	if len(match.Sets) != 2 || match.Sets[0] != "hosts" || match.Sets[1] != "ports" {
		t.Errorf("sets = %v, want [hosts ports]", match.Sets)
	}
}

func TestRenderCounter(t *testing.T) {
	match, raw := decode(t, `[{"counter":{"packets":1234,"bytes":2097152}}]`)
	if match.Counter == nil || match.Counter.Packets != 1234 {
		t.Fatalf("counter = %v", match.Counter)
	}
	if got := match.Counter.String(); got != "1234p/2.0M" {
		t.Errorf("Counter.String() = %q, want 1234p/2.0M", got)
	}
	if raw != "counter packets 1234 bytes 2097152" {
		t.Errorf("raw = %q", raw)
	}
}

func TestNATString(t *testing.T) {
	cases := []struct {
		nat  NAT
		want string
	}{
		{NAT{Kind: "masquerade"}, "masquerade"},
		{NAT{Kind: "snat", Addr: "203.0.113.9"}, "snat to 203.0.113.9"},
		{NAT{Kind: "dnat", Addr: "10.0.0.5", Port: "80"}, "dnat to 10.0.0.5:80"},
		{NAT{Kind: "redirect", Port: "8080"}, "redirect to :8080"},
	}
	for _, tc := range cases {
		if got := tc.nat.String(); got != tc.want {
			t.Errorf("NAT%+v.String() = %q, want %q", tc.nat, got, tc.want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[uint64]string{
		0: "0B", 512: "512B", 1024: "1.0K", 1536: "1.5K",
		1048576: "1.0M", 1073741824: "1.0G",
	}
	for input, want := range cases {
		if got := humanBytes(input); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", input, got, want)
		}
	}
}

func TestOneLineFlattensWhatGoesInACell(t *testing.T) {
	// Everything rendered here came from another program's output, and a
	// control character in a table cell breaks the table rather than the cell.
	cases := map[string]string{
		"plain":         "plain",
		" padded ":      "padded",
		"two\nlines":    "two lines",
		"tab\there":     "tab here",
		"bell\x07":      "bell",
		"del\x7fmiddle": "del middle",
	}
	for input, want := range cases {
		if got := oneLine(input); got != want {
			t.Errorf("oneLine(%q) = %q, want %q", input, got, want)
		}
	}
}
