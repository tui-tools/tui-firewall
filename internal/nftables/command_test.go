package nftables

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// argvOf returns the single command of a Change, failing when a builder
// produced anything but one.
func argvOf(t *testing.T, change firewall.Change) string {
	t.Helper()
	if len(change.Commands) != 1 {
		t.Fatalf("expected one command, got %d: %s",
			len(change.Commands), change.String())
	}
	return change.Commands[0].String()
}

// routerChain fetches a chain of the router fixture.
func routerChain(t *testing.T, rs Ruleset, name string) Chain {
	t.Helper()
	chain, ok := rs.Chain(OwnTable, name)
	if !ok {
		t.Fatalf("chain %s is missing from the fixture", name)
	}
	return chain
}

func TestBuildAddRule(t *testing.T) {
	ruleset := parseFixture(t, "router")
	cases := []struct {
		name string
		spec firewall.RuleSpec
		want string
	}{
		{
			name: "a port and a protocol",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, Proto: "tcp", Ports: "22",
				Comment: "ssh from anywhere",
			},
			want: `nft add rule inet tui input tcp dport 22 counter accept ` +
				`comment "ssh from anywhere"`,
		},
		{
			name: "a source network",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, From: "10.0.0.0/8",
				Proto: "tcp", Ports: "5432",
			},
			want: "nft add rule inet tui input ip saddr 10.0.0.0/8 " +
				"tcp dport 5432 counter accept",
		},
		{
			name: "a v6 source, read off the address",
			spec: firewall.RuleSpec{
				Action: firewall.ActionDeny, From: "fd00::/8", Proto: "udp",
				Ports: "53",
			},
			want: "nft add rule inet tui input ip6 saddr fd00::/8 " +
				"udp dport 53 counter drop",
		},
		{
			name: "a port list becomes a set",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, Proto: "tcp", Ports: "80,443",
			},
			want: "nft add rule inet tui input tcp dport { 80, 443 } counter accept",
		},
		{
			name: "a port range in the family's spelling becomes nft's",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, Proto: "udp", Ports: "2000:2100",
			},
			want: "nft add rule inet tui input udp dport 2000-2100 counter accept",
		},
		{
			name: "an alias as the source needs the family spelled out",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, Service: "@lan_hosts",
				Family: firewall.FamilyIPv4, Proto: "tcp", Ports: "22",
			},
			want: "nft add rule inet tui input ip saddr @lan_hosts " +
				"tcp dport 22 counter accept",
		},
		{
			name: "a protocol with no port",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, Proto: "icmp",
			},
			want: "nft add rule inet tui input meta l4proto icmp counter accept",
		},
		{
			name: "logging is a statement, before the counter",
			spec: firewall.RuleSpec{
				Action: firewall.ActionReject, Proto: "tcp", Ports: "25", Log: true,
			},
			want: "nft add rule inet tui input tcp dport 25 log counter reject",
		},
		{
			name: "a position inserts, counting from nft's zero",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, Proto: "tcp", Ports: "22",
				Position: 1,
			},
			want: "nft insert rule inet tui input index 0 tcp dport 22 counter accept",
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

func TestBuildAddRuleRefusals(t *testing.T) {
	ruleset := parseFixture(t, "router")
	cases := []struct {
		name string
		spec firewall.RuleSpec
		want string
	}{
		{"no action", firewall.RuleSpec{Proto: "tcp", Ports: "22"},
			"an action is required"},
		{"an action nft has no verdict for",
			firewall.RuleSpec{Action: firewall.ActionLimit, Ports: "22", Proto: "tcp"},
			"no verdict"},
		{"nothing to match at all",
			firewall.RuleSpec{Action: firewall.ActionAllow},
			"every packet the chain sees"},
		{"a port with no protocol",
			firewall.RuleSpec{Action: firewall.ActionAllow, Ports: "22"},
			"a port needs a protocol"},
		{"a direction the chain already decided",
			firewall.RuleSpec{Action: firewall.ActionAllow, Ports: "22",
				Proto: "tcp", Direction: firewall.DirOut},
			"the chain it lives in"},
		{"an alias and a source at once",
			firewall.RuleSpec{Action: firewall.ActionAllow, Service: "@lan_hosts",
				From: "10.0.0.1", Ports: "22", Proto: "tcp"},
			"not both"},
		{"an alias that is not there",
			firewall.RuleSpec{Action: firewall.ActionAllow, Service: "@nope",
				Ports: "22", Proto: "tcp"},
			"no alias"},
		{"an alias with no family to pin it to",
			firewall.RuleSpec{Action: firewall.ActionAllow, Service: "@lan_hosts",
				Ports: "22", Proto: "tcp"},
			"family field"},
		{"a comment with a newline in it",
			firewall.RuleSpec{Action: firewall.ActionAllow, Ports: "22",
				Proto: "tcp", Comment: "one\ntwo"},
			"one line"},
		{"a semicolon smuggled into an operand",
			firewall.RuleSpec{Action: firewall.ActionAllow, Proto: "tcp",
				Ports: "22 ; drop"},
			"nft would read as syntax"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ruleset.AddRule("inet tui / input", tc.spec)
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestMutationGuard(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		group   string
		want    string
	}{
		{
			name:    "a regular chain of our own table",
			fixture: "router", group: "inet tui / admin_services",
			want: "",
		},
		{
			name:    "a regular chain of somebody else's table",
			fixture: "firewalld", group: "inet firewalld / filter_IN_public_allow",
			want: "belongs to firewalld",
		},
		{
			name:    "a base chain of somebody else's table",
			fixture: "firewalld", group: "inet firewalld / filter_INPUT",
			want: "belongs to firewalld",
		},
		{
			name:    "a ufw chain",
			fixture: "ufw", group: "ip filter / ufw-user-input",
			want: "belongs to ufw",
		},
		{
			name:    "a base chain of our own table",
			fixture: "router", group: "inet tui / input",
			want: "",
		},
		{
			name:    "a chain that is no longer there",
			fixture: "router", group: "inet tui / gone",
			want: "no longer in table",
		},
		{
			name:    "a group name that is not a chain",
			fixture: "router", group: "not-a-chain",
			want: "is not a chain",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := parseFixture(t, tc.fixture).Writable(tc.group)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("expected the group to be writable, got: %v", err)
			case tc.want == "":
				return
			case err == nil:
				t.Fatal("expected a refusal")
			case !strings.Contains(err.Error(), tc.want):
				t.Errorf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestMutationGuardRefusesAChainWithNoPolicy(t *testing.T) {
	// A base chain of a table nobody manages, whose policy nft did not
	// report: writable by the table test above only because it is ours. Here
	// it is not, and the guard has to say what it cannot promise.
	ruleset := Ruleset{Tables: []Table{{
		TableID: TableID{Family: "inet", Name: "other"},
		Chains: []Chain{
			{Table: TableID{Family: "inet", Name: "other"}, Name: "in",
				Type: "filter", Hook: "input"},
			{Table: TableID{Family: "inet", Name: "other"}, Name: "helper"},
		},
	}}}
	err := ruleset.Writable("inet other / in")
	if err == nil || !strings.Contains(err.Error(), "no policy") {
		t.Errorf("a base chain with no policy should be refused, got: %v", err)
	}
	err = ruleset.Writable("inet other / helper")
	if err == nil || !strings.Contains(err.Error(), "regular chain") {
		t.Errorf("a regular chain should be refused, got: %v", err)
	}
}

func TestBuildDeleteRule(t *testing.T) {
	ruleset := parseFixture(t, "router")
	rule, ok := findRuleByComment(ruleset, "input", "no ssh from the wan")
	if !ok {
		t.Fatal("the fixture rule is missing")
	}
	model := Model(ruleset)
	group, _ := model.Group("inet tui / input")
	var row firewall.Rule
	for _, r := range group.Rules {
		if r.Comment == rule.Comment {
			row = r
		}
	}
	change, err := ruleset.DeleteRule("inet tui / input", row)
	if err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if !change.Destructive {
		t.Error("deleting a rule is destructive")
	}
	want := "nft delete rule inet tui input handle " + row.ID
	if got := argvOf(t, change); got != want {
		t.Errorf("argv = %s, want %s", got, want)
	}
}

func TestBuildDeleteRuleWithoutAHandle(t *testing.T) {
	_, err := parseFixture(t, "router").DeleteRule("inet tui / input",
		firewall.Rule{ID: ""})
	if err == nil || !strings.Contains(err.Error(), "no handle") {
		t.Errorf("expected a refusal naming the missing handle, got: %v", err)
	}
}

func TestBuildDeleteRuleFromTheNATView(t *testing.T) {
	// The NAT view mixes chains, so the row carries the chain its handle
	// belongs to and the delete has to follow it.
	ruleset := parseFixture(t, "router")
	group, ok := Model(ruleset).Group(GroupNAT)
	if !ok || len(group.Rules) == 0 {
		t.Fatal("the NAT view is empty")
	}
	row := group.Rules[0]
	change, err := ruleset.DeleteRule(GroupNAT, row)
	if err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if got := argvOf(t, change); !strings.Contains(got, "inet tui prerouting handle") {
		t.Errorf("argv = %s, want the prerouting chain the row came from", got)
	}
}

func TestBuildSetPolicy(t *testing.T) {
	ruleset := parseFixture(t, "router")
	change, err := ruleset.SetPolicy("inet tui / input", firewall.PolicyAllow)
	if err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	want := "nft chain inet tui input { policy accept ; }"
	if got := argvOf(t, change); got != want {
		t.Errorf("argv = %s, want %s", got, want)
	}
	if !change.Destructive {
		t.Error("changing a chain policy is destructive")
	}

	if _, err := ruleset.SetPolicy("inet tui / input", firewall.PolicyReject); err == nil {
		t.Error("nft has no reject policy and the builder should say so")
	}
	if _, err := ruleset.SetPolicy("inet tui / admin_services",
		firewall.PolicyDeny); err == nil {
		t.Error("a regular chain has no policy to change")
	}
}

func TestBuildAliasCommands(t *testing.T) {
	ruleset := parseFixture(t, "router")
	cases := []struct {
		name  string
		build func() (firewall.Change, error)
		want  string
	}{
		{
			name: "create",
			build: func() (firewall.Change, error) {
				return ruleset.BuildCreateSet(OwnTable, "vpn_peers", "ipv4_addr",
					true, "peers allowed in over wireguard")
			},
			want: `nft add set inet tui vpn_peers { type ipv4_addr ; ` +
				`flags interval ; comment "peers allowed in over wireguard" ; }`,
		},
		{
			name: "create without ranges",
			build: func() (firewall.Change, error) {
				return ruleset.BuildCreateSet(OwnTable, "single", "inet_service",
					false, "")
			},
			want: "nft add set inet tui single { type inet_service ; }",
		},
		{
			name: "add a member",
			build: func() (firewall.Change, error) {
				return ruleset.BuildAddElement(OwnTable, "lan_hosts", "10.20.0.0/24")
			},
			want: "nft add element inet tui lan_hosts { 10.20.0.0/24 }",
		},
		{
			name: "remove a member",
			build: func() (firewall.Change, error) {
				return ruleset.BuildRemoveElement(OwnTable, "lan_hosts", "192.168.50.10")
			},
			want: "nft delete element inet tui lan_hosts { 192.168.50.10 }",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			change, err := tc.build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if got := argvOf(t, change); got != tc.want {
				t.Errorf("argv =\n  %s\nwant\n  %s", got, tc.want)
			}
		})
	}
}

func TestBuildAliasRefusals(t *testing.T) {
	ruleset := parseFixture(t, "router")
	other := TableID{Family: "inet", Name: "firewalld"}
	cases := []struct {
		name  string
		build func() (firewall.Change, error)
		want  string
	}{
		{"a table that is not ours", func() (firewall.Change, error) {
			return ruleset.BuildCreateSet(other, "x", "ipv4_addr", true, "")
		}, "the table this tool owns"},
		{"a name nft would refuse", func() (firewall.Change, error) {
			return ruleset.BuildCreateSet(OwnTable, "bad name", "ipv4_addr", true, "")
		}, "letters, digits"},
		{"a name already taken", func() (firewall.Change, error) {
			return ruleset.BuildCreateSet(OwnTable, "lan_hosts", "ipv4_addr", true, "")
		}, "already has an alias"},
		{"a type an alias cannot hold", func() (firewall.Change, error) {
			return ruleset.BuildCreateSet(OwnTable, "x", "ifname", true, "")
		}, "an alias holds one of"},
		{"deleting an alias rules still use", func() (firewall.Change, error) {
			return ruleset.BuildDeleteSet(OwnTable, "lan_hosts")
		}, "used by 3 rules"},
		{"deleting an alias that is not there", func() (firewall.Change, error) {
			return ruleset.BuildDeleteSet(OwnTable, "nope")
		}, "no alias"},
		{"a range in an alias that holds single values", func() (firewall.Change, error) {
			return ruleset.BuildAddElement(OwnTable, "lan6_hosts", "fd00::/8")
		}, "holds single values"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.build()
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestBuildDeleteSetWhenNothingUsesIt(t *testing.T) {
	// The reference count is what makes the difference legible, so an alias
	// nothing refers to has to actually be deletable.
	ruleset := parseFixture(t, "router")
	for i := range ruleset.Tables[0].Sets {
		ruleset.Tables[0].Sets[i].References = 0
	}
	change, err := ruleset.BuildDeleteSet(OwnTable, "lan_hosts")
	if err != nil {
		t.Fatalf("BuildDeleteSet: %v", err)
	}
	if got := argvOf(t, change); got != "nft delete set inet tui lan_hosts" {
		t.Errorf("argv = %s", got)
	}
}

func TestBuildNATCommands(t *testing.T) {
	ruleset := parseFixture(t, "router")
	post := routerChain(t, ruleset, "postrouting")
	pre := routerChain(t, ruleset, "prerouting")

	change, err := ruleset.BuildMasquerade(post, "wan0")
	if err != nil {
		t.Fatalf("BuildMasquerade: %v", err)
	}
	want := `nft add rule inet tui postrouting oifname "wan0" counter ` +
		`masquerade comment "masquerade out wan0"`
	if got := argvOf(t, change); got != want {
		t.Errorf("masquerade argv =\n  %s\nwant\n  %s", got, want)
	}

	change, err = ruleset.BuildPortForward(pre, "wan0", "tcp", "8080", "10.10.0.5", "80")
	if err != nil {
		t.Fatalf("BuildPortForward: %v", err)
	}
	// In an inet table dnat has to name the family it translates to.
	want = `nft add rule inet tui prerouting iifname "wan0" tcp dport 8080 ` +
		`counter dnat ip to 10.10.0.5:80 comment "tcp 8080 to 10.10.0.5:80"`
	if got := argvOf(t, change); got != want {
		t.Errorf("dnat argv =\n  %s\nwant\n  %s", got, want)
	}

	change, err = ruleset.BuildPortForward(pre, "wan0", "udp", "51820", "fd00::9", "51820")
	if err != nil {
		t.Fatalf("BuildPortForward v6: %v", err)
	}
	if got := argvOf(t, change); !strings.Contains(got, "dnat ip6 to [fd00::9]:51820") {
		t.Errorf("a v6 target is bracketed and ip6-qualified, got: %s", got)
	}
}

func TestBuildNATRefusals(t *testing.T) {
	ruleset := parseFixture(t, "router")
	post := routerChain(t, ruleset, "postrouting")
	pre := routerChain(t, ruleset, "prerouting")
	filter := routerChain(t, ruleset, "input")

	cases := []struct {
		name  string
		build func() (firewall.Change, error)
		want  string
	}{
		{"masquerade in a filter chain", func() (firewall.Change, error) {
			return ruleset.BuildMasquerade(filter, "wan0")
		}, "only happens in a nat chain"},
		{"masquerade in the wrong hook", func() (firewall.Change, error) {
			return ruleset.BuildMasquerade(pre, "wan0")
		}, "hooked at postrouting"},
		{"a port forward in the wrong hook", func() (firewall.Change, error) {
			return ruleset.BuildPortForward(post, "wan0", "tcp", "80", "10.0.0.1", "80")
		}, "hooked at prerouting"},
		{"a protocol that has no ports", func() (firewall.Change, error) {
			return ruleset.BuildPortForward(pre, "wan0", "icmp", "80", "10.0.0.1", "80")
		}, "tcp or udp"},
		{"a port that is not a number", func() (firewall.Change, error) {
			return ruleset.BuildPortForward(pre, "wan0", "tcp", "http", "10.0.0.1", "80")
		}, "must be a number"},
		{"a target that is not an address", func() (firewall.Change, error) {
			return ruleset.BuildPortForward(pre, "wan0", "tcp", "80", "somehost", "80")
		}, "not an address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.build()
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestBuildExtraCreatesTheStructure(t *testing.T) {
	empty := parseFixture(t, "empty")

	change, err := empty.BuildExtra(ExtraCreateTable, nil)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	if got := argvOf(t, change); got != "nft add table inet tui" {
		t.Errorf("argv = %s", got)
	}

	// With the table present but no chains, both chain actions are offered
	// and each is one command per chain.
	withTable := Ruleset{Tables: []Table{{TableID: OwnTable}}}
	change, err = withTable.BuildExtra(ExtraCreateFilterChains, nil)
	if err != nil {
		t.Fatalf("create filter chains: %v", err)
	}
	if len(change.Commands) != 3 {
		t.Fatalf("expected three chains, got %d", len(change.Commands))
	}
	want := "nft add chain inet tui input { type filter hook input " +
		"priority 0 ; policy accept ; }"
	if got := change.Commands[0].String(); got != want {
		t.Errorf("argv =\n  %s\nwant\n  %s", got, want)
	}
	for _, cmd := range change.Commands {
		if !strings.Contains(cmd.String(), "policy accept") {
			t.Errorf("a chain created by this action must not start dropping: %s",
				cmd.String())
		}
	}

	change, err = withTable.BuildExtra(ExtraCreateNATChains, nil)
	if err != nil {
		t.Fatalf("create nat chains: %v", err)
	}
	if len(change.Commands) != 2 {
		t.Fatalf("expected two chains, got %d", len(change.Commands))
	}
	if !strings.Contains(change.Commands[0].String(), "priority -100") ||
		!strings.Contains(change.Commands[1].String(), "priority 100") {
		t.Errorf("the NAT chains need the translation priorities: %s", change.String())
	}
}

func TestExtrasFollowTheRuleset(t *testing.T) {
	// On a machine with nothing of ours, the only thing to offer is creating
	// the table: every other action writes into it.
	extras := parseFixture(t, "empty").Extras()
	if len(extras) != 1 || extras[0].ID != ExtraCreateTable {
		t.Fatalf("extras on an empty ruleset = %+v, want only create-table", extras)
	}

	// On the router fixture the structure is there, so the actions are the
	// ones that use it.
	ids := map[string]bool{}
	for _, extra := range parseFixture(t, "router").Extras() {
		ids[extra.ID] = true
		if extra.Label == "" {
			t.Errorf("extra %s has no label", extra.ID)
		}
	}
	for _, want := range []string{
		ExtraCreateAlias, ExtraAddElement, ExtraRemoveElement,
		ExtraMasquerade, ExtraPortForward,
	} {
		if !ids[want] {
			t.Errorf("extra %s should be offered on the router fixture", want)
		}
	}
	for _, unwanted := range []string{ExtraCreateTable, ExtraCreateFilterChains,
		ExtraCreateNATChains} {
		if ids[unwanted] {
			t.Errorf("extra %s should not be offered: it already exists", unwanted)
		}
	}
}

func TestBuildExtraChecksItsAnswers(t *testing.T) {
	ruleset := parseFixture(t, "router")
	if _, err := ruleset.BuildExtra(ExtraAddElement, []string{"lan_hosts"}); err == nil {
		t.Error("an action missing an answer should be refused")
	}
	if _, err := ruleset.BuildExtra("no-such-action", nil); err == nil {
		t.Error("an unknown action should be refused")
	}
}

func TestCapabilitiesSayWhatNftablesCannotDo(t *testing.T) {
	caps := Capabilities()
	if caps.SupportsEnable {
		t.Error("nftables has no on/off switch")
	}
	if caps.SupportsLogging {
		t.Error("nftables logs per rule, not by level")
	}
	if caps.SupportsReload {
		t.Error("an nft command takes effect as it runs; there is nothing to reload")
	}
	if !caps.SupportsLog || !caps.SupportsFamily || !caps.SupportsInsert ||
		!caps.SupportsComments {
		t.Errorf("capabilities = %+v, want per-rule logging, family, insert "+
			"and comments", caps)
	}
	if len(caps.Directions) != 0 {
		t.Error("a rule's direction is the chain it lives in")
	}
}
