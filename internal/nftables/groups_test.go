package nftables

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

func TestModelGroups(t *testing.T) {
	model := Model(parseFixture(t, "router"))
	if model.Backend != "nftables" {
		t.Errorf("backend = %q", model.Backend)
	}
	if !model.Enabled {
		t.Error("a ruleset with a dropping filter chain is filtering")
	}

	var names []string
	for _, group := range model.Groups {
		names = append(names, group.Name)
	}
	want := []string{
		"inet tui / input", "inet tui / forward", "inet tui / output",
		"inet tui / admin_services", GroupNAT, GroupAliases,
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("groups = %v\nwant %v", names, want)
	}
}

func TestModelGroupPolicySlots(t *testing.T) {
	model := Model(parseFixture(t, "router"))
	cases := []struct {
		group  string
		slot   firewall.PolicyDirection
		policy firewall.Policy
	}{
		{"inet tui / input", firewall.PolicyIncoming, firewall.PolicyDeny},
		{"inet tui / forward", firewall.PolicyRouted, firewall.PolicyDeny},
		{"inet tui / output", firewall.PolicyOutgoing, firewall.PolicyAllow},
	}
	for _, tc := range cases {
		t.Run(tc.group, func(t *testing.T) {
			group, ok := model.Group(tc.group)
			if !ok {
				t.Fatalf("group %s is missing", tc.group)
			}
			if len(group.PolicySlots) != 1 || group.PolicySlots[0] != tc.slot {
				t.Fatalf("slots = %v, want [%s]", group.PolicySlots, tc.slot)
			}
			if got := currentPolicyOf(group, tc.slot); got != tc.policy {
				t.Errorf("policy = %q, want %q", got, tc.policy)
			}
		})
	}

	// A regular chain has no policy, so it offers no slot to change.
	group, _ := model.Group("inet tui / admin_services")
	if len(group.PolicySlots) != 0 {
		t.Errorf("a regular chain offers no policy slot, got %v", group.PolicySlots)
	}
}

// currentPolicyOf reads the policy out of the slot a group filled.
func currentPolicyOf(g firewall.Group, slot firewall.PolicyDirection) firewall.Policy {
	switch slot {
	case firewall.PolicyIncoming:
		return g.Default.Incoming
	case firewall.PolicyOutgoing:
		return g.Default.Outgoing
	case firewall.PolicyRouted:
		return g.Default.Routed
	}
	return ""
}

func TestModelViews(t *testing.T) {
	model := Model(parseFixture(t, "router"))
	views := map[string]string{
		"inet tui / input": firewall.ViewRules,
		GroupNAT:           firewall.ViewNAT,
		GroupAliases:       firewall.ViewAliases,
	}
	for name, want := range views {
		group, ok := model.Group(name)
		if !ok {
			t.Fatalf("group %s is missing", name)
		}
		if group.View != want {
			t.Errorf("%s view = %q, want %q", name, group.View, want)
		}
	}
}

func TestModelNATView(t *testing.T) {
	group, ok := Model(parseFixture(t, "router")).Group(GroupNAT)
	if !ok {
		t.Fatal("the NAT view is missing")
	}
	if len(group.Rules) != 5 {
		t.Fatalf("NAT rules = %d, want 5", len(group.Rules))
	}
	cases := []struct {
		index  int
		kind   string
		target string
		note   string
	}{
		{0, "dnat", "dnat to 10.10.0.5:80", "inet tui / prerouting"},
		{2, "masquerade", "masquerade", "inet tui / postrouting"},
		{4, "snat", "snat to 203.0.113.9", "inet tui / postrouting"},
	}
	for _, tc := range cases {
		rule := group.Rules[tc.index]
		if rule.Kind != tc.kind {
			t.Errorf("rule %d kind = %q, want %q", tc.index, rule.Kind, tc.kind)
		}
		if got := rule.Extra[firewall.ExtraTarget]; got != tc.target {
			t.Errorf("rule %d target = %q, want %q", tc.index, got, tc.target)
		}
		// The row has to remember which chain its handle belongs to, or the
		// delete would go to the wrong one.
		if rule.Note != tc.note {
			t.Errorf("rule %d note = %q, want %q", tc.index, rule.Note, tc.note)
		}
		if rule.Index != tc.index+1 {
			t.Errorf("rule %d is numbered %d", tc.index, rule.Index)
		}
	}
}

func TestModelAliasView(t *testing.T) {
	group, ok := Model(parseFixture(t, "router")).Group(GroupAliases)
	if !ok {
		t.Fatal("the alias view is missing")
	}
	if len(group.Rules) != 3 {
		t.Fatalf("aliases = %d, want 3", len(group.Rules))
	}
	first := group.Rules[0]
	if first.Service != "lan_hosts" || first.ID != "lan_hosts" {
		t.Errorf("alias = %+v, want lan_hosts", first)
	}
	if got := first.Extra[firewall.ExtraReferences]; got != "3" {
		t.Errorf("references = %q, want 3", got)
	}
	if got := first.Extra[firewall.ExtraElements]; got != "2" {
		t.Errorf("elements = %q, want 2", got)
	}
	if got := first.Extra[firewall.ExtraFlags]; got != "interval" {
		t.Errorf("flags = %q, want interval", got)
	}
	if first.Note != "inet tui" {
		t.Errorf("table = %q, want inet tui", first.Note)
	}
}

func TestModelRuleColumns(t *testing.T) {
	group, _ := Model(parseFixture(t, "router")).Group("inet tui / input")
	byComment := map[string]firewall.Rule{}
	for _, rule := range group.Rules {
		byComment[rule.Comment] = rule
	}

	rule := byComment["no ssh from the wan"]
	if rule.Action != firewall.ActionDeny {
		t.Errorf("action = %q, want DENY", rule.Action)
	}
	if rule.Direction != firewall.DirIn {
		t.Errorf("direction = %q, want IN: the chain decides it", rule.Direction)
	}
	if rule.Extra[firewall.ExtraInIface] != "wan0" {
		t.Errorf("in = %q, want wan0", rule.Extra[firewall.ExtraInIface])
	}
	if rule.Ports != "22" || rule.Proto != "tcp" {
		t.Errorf("ports/proto = %q/%q, want 22/tcp", rule.Ports, rule.Proto)
	}
	if rule.From != "Anywhere" || rule.To != "Anywhere" {
		t.Errorf("from/to = %q/%q, want Anywhere", rule.From, rule.To)
	}
	if rule.Extra[firewall.ExtraCounter] != "0p/0B" {
		t.Errorf("counter = %q", rule.Extra[firewall.ExtraCounter])
	}

	// A rule that only logs still says what it does.
	if got := byComment[""].Action; got != "LOG" {
		t.Errorf("the log-only rule's action = %q, want LOG", got)
	}
	// The state match has no column, so it goes in the detail line.
	if got := byComment["keep state"].Extra[firewall.ExtraDetail]; !strings.Contains(got, "ct state") {
		t.Errorf("detail = %q, want the ct state match", got)
	}
}

func TestModelKeepsNftVerdictsItCannotTranslate(t *testing.T) {
	// firewalld's chain tree is all jumps and gotos. Showing those as ALLOW
	// would be a lie in the column the eye reads first.
	group, ok := Model(parseFixture(t, "firewalld")).Group("inet firewalld / filter_INPUT")
	if !ok {
		t.Fatal("filter_INPUT is missing")
	}
	found := false
	for _, rule := range group.Rules {
		if strings.HasPrefix(string(rule.Action), "JUMP ") {
			found = true
		}
	}
	if !found {
		t.Error("a jump should be shown as a jump")
	}
}

func TestModelWarnsOnAManagedRuleset(t *testing.T) {
	for _, fixture := range []string{"firewalld", "ufw"} {
		model := Model(parseFixture(t, fixture))
		if !strings.HasPrefix(model.Warning, "read-only:") {
			t.Errorf("%s: warning = %q, want a read-only banner", fixture, model.Warning)
		}
		if !strings.Contains(model.Warning, fixture) {
			t.Errorf("%s: the warning should name the manager, got %q",
				fixture, model.Warning)
		}
	}
	if got := Model(parseFixture(t, "router")).Warning; got != "" {
		t.Errorf("a ruleset nobody else manages needs no warning, got %q", got)
	}
}

func TestModelOffersOurAliasesToTheForm(t *testing.T) {
	// The alias picker in the add-rule form offers only the sets of the table
	// this backend writes rules into.
	model := Model(parseFixture(t, "router"))
	want := []string{"@admin_ports", "@lan6_hosts", "@lan_hosts"}
	if strings.Join(model.Services, ",") != strings.Join(want, ",") {
		t.Errorf("services = %v, want %v", model.Services, want)
	}
	if got := Model(parseFixture(t, "firewalld")).Services; len(got) != 0 {
		t.Errorf("a ruleset with no table of ours offers no aliases, got %v", got)
	}
}

func TestModelHidesEmptyScaffoldingChains(t *testing.T) {
	// firewalld leaves a dozen empty chains behind. A base chain is always
	// shown, because its policy is a fact; an empty regular chain says
	// nothing and would bury the ones that do.
	model := Model(parseFixture(t, "firewalld"))
	for _, group := range model.Groups {
		if group.Name == GroupNAT || group.Name == GroupAliases {
			continue
		}
		if len(group.Rules) == 0 && len(group.PolicySlots) == 0 {
			t.Errorf("group %s is empty and not a base chain", group.Name)
		}
	}
}

func TestModelMarksAReadOnlyGroup(t *testing.T) {
	group, ok := Model(parseFixture(t, "ufw")).Group("ip filter / ufw-user-input")
	if !ok {
		t.Fatal("ufw-user-input is missing")
	}
	if !strings.Contains(group.Description, "read-only") {
		t.Errorf("description = %q, want it to say the group is read-only",
			group.Description)
	}
}

func TestGroupNameRoundTrip(t *testing.T) {
	for _, fixture := range fixtures {
		ruleset := parseFixture(t, fixture)
		for _, table := range ruleset.Tables {
			for _, chain := range table.Chains {
				name := GroupName(chain)
				got, err := ruleset.ChainForGroup(name)
				if err != nil {
					t.Fatalf("%s: ChainForGroup(%q): %v", fixture, name, err)
				}
				if got.Name != chain.Name || got.Table != chain.Table {
					t.Errorf("%s: %q resolved to %s / %s",
						fixture, name, got.Table, got.Name)
				}
			}
		}
	}
}

func TestChainForGroupRefusesTheSpecialViews(t *testing.T) {
	ruleset := parseFixture(t, "router")
	for _, group := range []string{GroupNAT, GroupAliases} {
		if _, err := ruleset.ChainForGroup(group); err == nil {
			t.Errorf("%s is not a chain and should not resolve to one", group)
		}
	}
	if _, err := ruleset.AddRule(GroupNAT, firewall.RuleSpec{}); err == nil ||
		!strings.Contains(err.Error(), "actions menu") {
		t.Errorf("adding a rule to the NAT view should point at the actions "+
			"menu, got: %v", err)
	}
	if _, err := ruleset.AddRule(GroupAliases, firewall.RuleSpec{}); err == nil ||
		!strings.Contains(err.Error(), "actions menu") {
		t.Errorf("adding a rule to the alias view should point at the actions "+
			"menu, got: %v", err)
	}
}

func TestDeleteFromTheAliasView(t *testing.T) {
	ruleset := parseFixture(t, "router")
	group, _ := Model(ruleset).Group(GroupAliases)
	// lan_hosts is used by three rules; the alias view's delete has to say so
	// rather than build a command nft would reject.
	if _, err := ruleset.DeleteRule(GroupAliases, group.Rules[0]); err == nil ||
		!strings.Contains(err.Error(), "used by") {
		t.Errorf("expected the reference count in the refusal, got: %v", err)
	}
}

func TestModelOfEveryFixtureIsCoherent(t *testing.T) {
	// The invariant the fuzz target asserts too, checked here on every real
	// fixture: a group either resolves to the chain it names, or is one of
	// the two views that are not chains.
	for _, fixture := range fixtures {
		ruleset := parseFixture(t, fixture)
		model := Model(ruleset)
		seen := map[string]bool{}
		for _, group := range model.Groups {
			if seen[group.Name] {
				t.Errorf("%s: duplicate group %q", fixture, group.Name)
			}
			seen[group.Name] = true
			if group.Name == GroupNAT || group.Name == GroupAliases {
				continue
			}
			chain, err := ruleset.ChainForGroup(group.Name)
			if err != nil {
				t.Errorf("%s: group %q does not resolve: %v", fixture, group.Name, err)
				continue
			}
			if len(chain.Rules) != len(group.Rules) {
				t.Errorf("%s: group %q has %d rows for %d rules",
					fixture, group.Name, len(group.Rules), len(chain.Rules))
			}
		}
		if !seen[GroupNAT] || !seen[GroupAliases] {
			t.Errorf("%s: the NAT and alias views are always offered", fixture)
		}
	}
}
