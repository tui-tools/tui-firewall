package nftables

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// TestBuildFlowMatches covers the router-shaped matches phase 2 added to the
// add-rule builder: interface, connection state, and ICMP, on their own and
// together, in the family the table pins.
func TestBuildFlowMatches(t *testing.T) {
	ruleset := parseFixture(t, "router")
	cases := []struct {
		name string
		spec firewall.RuleSpec
		want string
	}{
		{
			name: "an input and output interface at once",
			spec: firewall.RuleSpec{Action: firewall.ActionAllow,
				InIface: "lan0", OutIface: "wan0"},
			want: `nft add rule inet tui input iifname "lan0" oifname "wan0" ` +
				"counter accept",
		},
		{
			name: "the stateful default leads the rule",
			spec: firewall.RuleSpec{Action: firewall.ActionAllow,
				CTStates: []string{"established", "related"}},
			want: "nft add rule inet tui input ct state established,related " +
				"counter accept",
		},
		{
			name: "an interface, a state and a port together",
			spec: firewall.RuleSpec{Action: firewall.ActionAllow, InIface: "lan0",
				CTStates: []string{"new"}, Proto: "tcp", Ports: "22"},
			want: `nft add rule inet tui input iifname "lan0" ct state new ` +
				"tcp dport 22 counter accept",
		},
		{
			name: "icmp with a type in an inet table",
			spec: firewall.RuleSpec{Action: firewall.ActionAllow, Proto: "icmp",
				ICMPType: "echo-request"},
			want: "nft add rule inet tui input ip protocol icmp " +
				"icmp type echo-request counter accept",
		},
		{
			name: "icmpv6 uses the v6 header",
			spec: firewall.RuleSpec{Action: firewall.ActionAllow, Proto: "icmpv6"},
			want: "nft add rule inet tui input ip6 nexthdr ipv6-icmp counter accept",
		},
		{
			name: "a v4 alias gets its family from the set type",
			spec: firewall.RuleSpec{Action: firewall.ActionAllow,
				Service: "@lan_hosts", Proto: "tcp", Ports: "443"},
			want: "nft add rule inet tui input ip saddr @lan_hosts " +
				"tcp dport 443 counter accept",
		},
		{
			name: "a v6 alias gets ip6 from the set type",
			spec: firewall.RuleSpec{Action: firewall.ActionAllow,
				Service: "@lan6_hosts", Proto: "tcp", Ports: "22"},
			want: "nft add rule inet tui input ip6 saddr @lan6_hosts " +
				"tcp dport 22 counter accept",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			change, err := ruleset.AddRule("inet tui / input", tc.spec)
			if err != nil {
				t.Fatalf("AddRule: %v", err)
			}
			if got := argvOf(t, change); got != tc.want {
				t.Errorf("argv =\n  %s\nwant\n  %s", got, tc.want)
			}
		})
	}
}

func TestBuildFlowMatchRefusals(t *testing.T) {
	ruleset := parseFixture(t, "router")
	cases := []struct {
		name string
		spec firewall.RuleSpec
		want string
	}{
		{"an unknown connection state",
			firewall.RuleSpec{Action: firewall.ActionAllow,
				CTStates: []string{"established", "flying"}},
			"a connection state is one of"},
		{"an ICMP type on a non-ICMP protocol",
			firewall.RuleSpec{Action: firewall.ActionAllow, Proto: "tcp",
				Ports: "22", ICMPType: "echo-request"},
			"only applies to the icmp"},
		{"a port on icmp",
			firewall.RuleSpec{Action: firewall.ActionAllow, Proto: "icmp",
				Ports: "22"},
			"carries no port"},
		{"a semicolon in an interface name",
			firewall.RuleSpec{Action: firewall.ActionAllow, InIface: "wan0; drop"},
			"nft would read as syntax"},
		{"a v4 and a v6 operand in one rule",
			firewall.RuleSpec{Action: firewall.ActionAllow, From: "10.0.0.1",
				To: "fd00::1"},
			"two"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ruleset.AddRule("inet tui / input", tc.spec)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestBuildIcmpFamilyGuards(t *testing.T) {
	// icmp is the v4 protocol and icmpv6 the v6 one; each is refused in a table
	// of the other family rather than accepted and rejected by nft.
	ip6 := Ruleset{Tables: []Table{{
		TableID: TableID{Family: "ip6", Name: "t"},
		Chains: []Chain{{Table: TableID{Family: "ip6", Name: "t"}, Name: "input",
			Type: "filter", Hook: "input", Policy: PolicyAccept}},
	}}}
	chain := ip6.Tables[0].Chains[0]
	if _, err := ip6.BuildAddRule(chain, firewall.RuleSpec{
		Action: firewall.ActionAllow, Proto: "icmp"}); err == nil ||
		!strings.Contains(err.Error(), "use icmpv6") {
		t.Fatalf("icmp in a v6 table should say use icmpv6, got %v", err)
	}
}

func TestBuildMasqueradeWithSource(t *testing.T) {
	ruleset := parseFixture(t, "router")
	post := routerChain(t, ruleset, "postrouting")

	change, err := ruleset.BuildMasquerade(post, "wan0", "10.10.0.0/24")
	if err != nil {
		t.Fatalf("BuildMasquerade: %v", err)
	}
	want := `nft add rule inet tui postrouting ip saddr 10.10.0.0/24 ` +
		`oifname "wan0" counter masquerade comment "masquerade 10.10.0.0/24 out wan0"`
	if got := argvOf(t, change); got != want {
		t.Errorf("argv =\n  %s\nwant\n  %s", got, want)
	}
}

func TestBuildDeleteChain(t *testing.T) {
	ruleset := parseFixture(t, "router")

	// An empty chain is one command; the admin_services chain has a rule, so an
	// unforced delete is refused with the count, and a forced one flushes first.
	rs := parseFixture(t, "router")
	for i := range rs.Tables[0].Chains {
		if rs.Tables[0].Chains[i].Name == "admin_services" {
			rs.Tables[0].Chains[i].Rules = nil
		}
	}
	emptyChain, _ := rs.Chain(OwnTable, "admin_services")
	change, err := rs.BuildDeleteChain(emptyChain, false)
	if err != nil {
		t.Fatalf("BuildDeleteChain empty: %v", err)
	}
	if got := argvOf(t, change); got != "nft delete chain inet tui admin_services" {
		t.Errorf("argv = %s", got)
	}

	withRule := routerChain(t, ruleset, "admin_services")
	if _, err := ruleset.BuildDeleteChain(withRule, false); err == nil ||
		!strings.Contains(err.Error(), "still holds") {
		t.Fatalf("a chain with rules should be refused unforced, got %v", err)
	}
	forced, err := ruleset.BuildDeleteChain(withRule, true)
	if err != nil {
		t.Fatalf("forced delete: %v", err)
	}
	if len(forced.Commands) != 2 {
		t.Fatalf("a forced delete flushes then deletes, got %d commands",
			len(forced.Commands))
	}
	if !strings.Contains(forced.Commands[0].String(), "flush chain") ||
		!strings.Contains(forced.Commands[1].String(), "delete chain") {
		t.Errorf("forced delete should flush then delete: %s", forced.String())
	}
}

func TestBuildDeleteTable(t *testing.T) {
	ruleset := parseFixture(t, "router")
	change, err := ruleset.BuildDeleteTable(OwnTable)
	if err != nil {
		t.Fatalf("BuildDeleteTable: %v", err)
	}
	if got := argvOf(t, change); got != "nft delete table inet tui" {
		t.Errorf("argv = %s", got)
	}
	if !change.Destructive {
		t.Error("deleting the table is destructive")
	}
}

func TestDeleteRefusesSomeoneElsesTable(t *testing.T) {
	// The guard that keeps this backend from writing to another tool's table
	// also keeps it from deleting one: firewalld's table and its chains are
	// read, never removed.
	ruleset := parseFixture(t, "firewalld")
	other := TableID{Family: "inet", Name: ManagerFirewalld}
	if _, err := ruleset.BuildDeleteTable(other); err == nil ||
		!strings.Contains(err.Error(), OwnTable.String()) {
		t.Fatalf("deleting another table should be refused, got %v", err)
	}
	table, ok := ruleset.Table(other)
	if !ok || len(table.Chains) == 0 {
		t.Skip("the firewalld fixture has no chain to try to delete")
	}
	if _, err := ruleset.BuildDeleteChain(table.Chains[0], true); err == nil ||
		!strings.Contains(err.Error(), OwnTable.String()) {
		t.Fatalf("deleting another table's chain should be refused, got %v", err)
	}
}

func TestExtrasOfferTheStructureDeletes(t *testing.T) {
	ruleset := parseFixture(t, "router")
	ids := map[string]bool{}
	for _, extra := range ruleset.Extras() {
		ids[extra.ID] = true
	}
	for _, want := range []string{ExtraDeleteChain, ExtraDeleteTable, ExtraMasquerade} {
		if !ids[want] {
			t.Errorf("the actions menu should offer %q", want)
		}
	}
	// A ruleset with no table this tool owns offers only creating it.
	empty := parseFixture(t, "empty")
	for _, extra := range empty.Extras() {
		if extra.ID == ExtraDeleteTable {
			t.Error("there is no table to delete when the tool owns none")
		}
	}
}

func TestBuildExtraDeletesThroughTheMenu(t *testing.T) {
	ruleset := parseFixture(t, "router")

	// Delete the table: no steps, straight to the command.
	change, err := ruleset.BuildExtra(ExtraDeleteTable, nil)
	if err != nil {
		t.Fatalf("BuildExtra delete table: %v", err)
	}
	if got := argvOf(t, change); got != "nft delete table inet tui" {
		t.Errorf("argv = %s", got)
	}

	// Masquerade with the optional source answered.
	change, err = ruleset.BuildExtra(ExtraMasquerade, []string{"wan0", "10.0.0.0/24"})
	if err != nil {
		t.Fatalf("BuildExtra masquerade: %v", err)
	}
	if !strings.Contains(change.String(), "ip saddr 10.0.0.0/24") {
		t.Errorf("the source network did not reach the command: %s", change.String())
	}

	// Masquerade with the source left blank stays interface-only.
	change, err = ruleset.BuildExtra(ExtraMasquerade, []string{"wan0", ""})
	if err != nil {
		t.Fatalf("BuildExtra masquerade no source: %v", err)
	}
	if strings.Contains(change.String(), "saddr") {
		t.Errorf("a blank source should not add an saddr match: %s", change.String())
	}
}
