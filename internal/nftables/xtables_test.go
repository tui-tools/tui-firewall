package nftables

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// Two more fixtures, outside the table-test list because they are about the
// xtables tables rather than the shapes every view is checked over:
//
//   - iptables-nft.json  captured read-only (`nft -j list ruleset`) from an
//     Oracle Cloud Ubuntu 24.04 host whose firewall is iptables-nft with
//     iptables-persistent, docker and tailscale; addresses outside RFC 1918
//     and link-local were replaced with documentation ranges
//   - docker-nft.json    captured in a namespace by docker-nft.sh: a native
//     inet filter table that is the firewall, plus the plumbing docker writes
//     into table ip filter through iptables-nft

func TestXtablesTablesOfTheCloudImage(t *testing.T) {
	rs := parseFixture(t, "iptables-nft")
	var names []string
	for _, id := range XtablesTables(rs) {
		names = append(names, id.String())
	}
	want := "ip filter,ip6 filter,ip nat,ip6 nat,ip mangle,ip6 mangle"
	if strings.Join(names, ",") != want {
		t.Errorf("xtables tables = %v, want %s", names, want)
	}
	if native := NativeTables(rs); len(native) != 0 {
		t.Errorf("native tables = %v, want none", native)
	}
}

func TestDetectManagementSeesIptablesInCharge(t *testing.T) {
	management := DetectManagement(parseFixture(t, "iptables-nft"))
	if management.Manager != ManagerIptables {
		t.Fatalf("manager = %q, want iptables", management.Manager)
	}
	for _, part := range []string{"table ip filter", "iptables-nft", "rules of the operator's own"} {
		if !strings.Contains(management.Detail, part) {
			t.Errorf("detail %q should mention %q", management.Detail, part)
		}
	}
}

func TestNftablesRefusesToWriteIntoAnXtablesTable(t *testing.T) {
	// The bug 0.4.1 had on this host: ip filter / INPUT was listed as
	// writable, and an allow would have been appended after the REJECT as a
	// native rule iptables-save cannot print.
	rs := parseFixture(t, "iptables-nft")
	err := rs.Writable("ip filter / INPUT")
	if err == nil {
		t.Fatal("ip filter / INPUT must not be writable from the nftables backend")
	}
	for _, part := range []string{"iptables-nft", "iptables-save", "--backend iptables"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("refusal %q should mention %q", err, part)
		}
	}
	chain, _ := rs.Chain(TableID{Family: "ip", Name: "filter"}, "INPUT")
	if _, err := rs.BuildAddRule(chain, firewall.RuleSpec{
		Action: firewall.ActionAllow, Proto: "udp", Ports: "51820",
	}); err == nil {
		t.Error("BuildAddRule must refuse the xtables table too")
	}
	model := Model(rs)
	if !strings.Contains(model.Warning, "iptables is the firewall in charge") {
		t.Errorf("warning = %q", model.Warning)
	}
	group, _ := model.Group("ip filter / INPUT")
	if !strings.Contains(group.Description, "read-only") {
		t.Errorf("description = %q, want read-only", group.Description)
	}
}

func TestDockerOnANativeHostStaysNftables(t *testing.T) {
	// docker writes table ip filter through iptables-nft on a machine whose
	// firewall is a native table: that is plumbing, not a firewall, so nothing
	// claims the ruleset — and the xtables table is still refused.
	rs := parseFixture(t, "docker-nft")
	if management := DetectManagement(rs); management.Managed() {
		t.Fatalf("management = %+v, want none", management)
	}
	if err := rs.Writable("inet filter / input"); err != nil {
		t.Errorf("the native table must stay writable: %v", err)
	}
	if err := rs.Writable("ip filter / FORWARD"); err == nil ||
		!strings.Contains(err.Error(), "iptables-nft") {
		t.Errorf("docker's table must be refused: %v", err)
	}
	native := NativeTables(rs)
	if len(native) != 1 || native[0].String() != "inet filter" {
		t.Errorf("native = %v", native)
	}
}

func TestXtablesExpressionsAreRendered(t *testing.T) {
	rs := parseFixture(t, "iptables-nft")
	chain, _ := rs.Chain(TableID{Family: "ip", Name: "filter"}, "INPUT")
	last := chain.Rules[len(chain.Rules)-1]
	if len(last.Match.Xtables) != 1 || last.Match.Xtables[0] != "xt target REJECT" {
		t.Errorf("last rule xtables = %v, raw %q", last.Match.Xtables, last.Raw)
	}
}
