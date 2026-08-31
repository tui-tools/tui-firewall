package nftables

import (
	"strings"
	"testing"
)

func TestDetectManagement(t *testing.T) {
	cases := []struct {
		fixture string
		manager string
		detail  string
	}{
		{"empty", "", ""},
		{"router", "", ""},
		{"firewalld", ManagerFirewalld, "table inet firewalld"},
		{"ufw", ManagerUFW, "table ip filter and table ip6 filter"},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			management := DetectManagement(parseFixture(t, tc.fixture))
			if management.Manager != tc.manager {
				t.Fatalf("manager = %q, want %q", management.Manager, tc.manager)
			}
			if tc.manager == "" {
				if management.Managed() {
					t.Error("Managed() should be false with no manager")
				}
				return
			}
			if !management.Managed() {
				t.Error("Managed() should be true")
			}
			if !strings.Contains(management.Detail, tc.detail) {
				t.Errorf("detail = %q, want it to name %q",
					management.Detail, tc.detail)
			}
			for _, id := range management.Tables {
				if !management.Owns(id) {
					t.Errorf("Owns(%s) should be true", id)
				}
			}
			if management.Owns(OwnTable) {
				t.Errorf("%s is ours and no manager owns it", OwnTable)
			}
		})
	}
}

func TestDetectManagementIsAboutTheRulesetNotTheHost(t *testing.T) {
	// The whole point of reading the ruleset: a table named firewalld means
	// firewalld is in charge here, whatever any service on the host says.
	ruleset := Ruleset{Tables: []Table{
		{TableID: OwnTable},
		{TableID: TableID{Family: "ip", Name: "firewalld"}},
	}}
	if got := DetectManagement(ruleset).Manager; got != ManagerFirewalld {
		t.Errorf("manager = %q, want firewalld", got)
	}
}

func TestDetectManagementFindsUFWByItsChainNames(t *testing.T) {
	// ufw does not name a table after itself: it drives iptables-nft, so what
	// it leaves behind is the legacy filter table with its own chains in it.
	filter := TableID{Family: "ip", Name: "filter"}
	ruleset := Ruleset{Tables: []Table{{
		TableID: filter,
		Chains: []Chain{
			{Table: filter, Name: "INPUT", Type: "filter", Hook: "input",
				Policy: PolicyDrop},
			{Table: filter, Name: "ufw-user-input"},
		},
	}}}
	management := DetectManagement(ruleset)
	if management.Manager != ManagerUFW {
		t.Fatalf("manager = %q, want ufw", management.Manager)
	}
	if !strings.Contains(management.Detail, "ufw's own chains") {
		t.Errorf("detail = %q, want it to say what it recognised",
			management.Detail)
	}
}

func TestDetectManagementIgnoresATableThatMerelyLooksLikeOne(t *testing.T) {
	// A chain called "ufwish" is not a ufw chain, and a plain filter table is
	// not evidence of anything.
	filter := TableID{Family: "ip", Name: "filter"}
	ruleset := Ruleset{Tables: []Table{{
		TableID: filter,
		Chains:  []Chain{{Table: filter, Name: "ufwish"}},
	}}}
	if DetectManagement(ruleset).Managed() {
		t.Error("a chain that merely starts with the letters is not evidence")
	}
}

func TestDescribeTables(t *testing.T) {
	cases := []struct {
		ids  []TableID
		want string
	}{
		{[]TableID{{"ip", "filter"}}, "table ip filter"},
		{[]TableID{{"ip", "filter"}, {"ip6", "filter"}},
			"table ip filter and table ip6 filter"},
		{[]TableID{{"ip", "a"}, {"ip", "b"}, {"ip", "c"}},
			"table ip a, table ip b and table ip c"},
	}
	for _, tc := range cases {
		if got := describeTables(tc.ids); got != tc.want {
			t.Errorf("describeTables(%v) = %q, want %q", tc.ids, got, tc.want)
		}
	}
}
