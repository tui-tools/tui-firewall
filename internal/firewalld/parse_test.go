package firewalld

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// The fixtures under testdata/ are the real output of firewall-cmd 2.3.2 on a
// Fedora 42 machine, with interface names replaced by generic ones. The layout
// — two-space keys, tab-indented continuations for forward-ports and rich
// rules, the "(default, active)" suffix — is exactly as firewalld printed it,
// which is the only part a parser can depend on.
//
// list-all-rich.txt is the one hand-written fixture: it carries the entries
// that host happened not to have (bound sources, forward ports, rich rules
// with logging), written in the syntax firewalld's own documentation uses.
func fixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(data)
}

func TestParseSectionsReadsEveryZone(t *testing.T) {
	sections := ParseSections(fixture(t, "list-all-zones.txt"))

	var names []string
	for _, s := range sections {
		names = append(names, s.Name)
	}
	want := []string{"FedoraWorkstation", "block", "docker", "libvirt", "trusted"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("zones = %q, want %q", names, want)
	}

	workstation := sections[0]
	if !workstation.Default || !workstation.Active {
		t.Errorf("FedoraWorkstation flags: default=%v active=%v, want both true",
			workstation.Default, workstation.Active)
	}
	if got := workstation.First(KeyTarget); got != "default" {
		t.Errorf("target = %q", got)
	}
	if got := workstation.Field(KeyServices); !reflect.DeepEqual(got,
		[]string{"dhcpv6-client", "mdns", "samba-client", "ssh"}) {
		t.Errorf("services = %q", got)
	}
	if got := workstation.Field(KeyPorts); !reflect.DeepEqual(got,
		[]string{"1025-65535/udp", "1025-65535/tcp"}) {
		t.Errorf("ports = %q", got)
	}
	if !workstation.Flag(KeyMasquerade) || !workstation.Flag(KeyForward) {
		t.Error("masquerade and forward should both read as yes")
	}

	// An empty key must still register, so the mapping can tell an absent
	// feature from an empty list.
	if !workstation.Has(KeySources) || len(workstation.Field(KeySources)) != 0 {
		t.Errorf("sources = %q, want present and empty", workstation.Field(KeySources))
	}
	if block := sections[1]; block.First(KeyTarget) != "%%REJECT%%" {
		t.Errorf("block target = %q", block.First(KeyTarget))
	}
}

func TestParseSectionsKeepsRichRulesWhole(t *testing.T) {
	sections := ParseSections(fixture(t, "list-all-zones.txt"))
	libvirt := sections[3]
	if libvirt.Name != "libvirt" {
		t.Fatalf("expected libvirt, got %q", libvirt.Name)
	}
	want := []string{`rule priority="32767" reject`}
	if !reflect.DeepEqual(libvirt.RichRules, want) {
		t.Errorf("rich rules = %q, want %q", libvirt.RichRules, want)
	}
	if got := libvirt.Field(KeyProtocols); !reflect.DeepEqual(got,
		[]string{"icmp", "ipv6-icmp"}) {
		t.Errorf("protocols = %q", got)
	}
}

func TestParseSectionsReadsContinuationLines(t *testing.T) {
	sections := ParseSections(fixture(t, "list-all-rich.txt"))
	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	dmz := sections[0]

	wantForward := []string{
		"port=80:proto=tcp:toport=8080",
		"port=443:proto=tcp:toport=8443:toaddr=10.20.0.9",
	}
	if got := dmz.Field(KeyForwardPorts); !reflect.DeepEqual(got, wantForward) {
		t.Errorf("forward-ports = %q, want %q", got, wantForward)
	}
	if got := len(dmz.RichRules); got != 4 {
		t.Fatalf("rich rules = %d, want 4", got)
	}
	// A rich rule carries colons and quotes; it must survive as one string,
	// because that string is its own delete argument.
	if got := dmz.RichRules[0]; got !=
		`rule family="ipv4" source address="10.20.0.0/16" service name="postgresql" `+
			`log prefix="pg: " level="info" limit value="3/m" accept` {
		t.Errorf("rich rule 1 = %q", got)
	}
	if got := dmz.Field(KeySources); !reflect.DeepEqual(got,
		[]string{"10.20.0.0/16", "fd00:dead:beef::/48", "ipset:office"}) {
		t.Errorf("sources = %q", got)
	}
}

func TestParseSectionsReadsASingleZoneListing(t *testing.T) {
	// `--list-all` prints one block in the same shape as `--list-all-zones`,
	// which is why one parser reads both.
	sections := ParseSections(fixture(t, "list-all.txt"))
	if len(sections) != 1 || sections[0].Name != "libvirt" {
		t.Fatalf("sections = %+v", sections)
	}
	if !sections[0].Active || sections[0].Default {
		t.Errorf("flags: active=%v default=%v", sections[0].Active, sections[0].Default)
	}
}

func TestParseSectionsReadsAPolicy(t *testing.T) {
	sections := ParseSections(fixture(t, "policy-list-all.txt"))
	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	policy := sections[0]
	if policy.Name != "allow-host-ipv6" || !policy.Active {
		t.Errorf("policy = %q active=%v", policy.Name, policy.Active)
	}
	if got := policy.First(KeyPriority); got != "-15000" {
		t.Errorf("priority = %q", got)
	}
	if got := policy.First(KeyTarget); got != "CONTINUE" {
		t.Errorf("target = %q", got)
	}
	if got := policy.Field(KeyIngressZones); !reflect.DeepEqual(got, []string{"ANY"}) {
		t.Errorf("ingress-zones = %q", got)
	}
	if got := len(policy.RichRules); got != 8 {
		t.Errorf("rich rules = %d, want 8", got)
	}
}

func TestParseActiveZones(t *testing.T) {
	zones := ParseActiveZones(fixture(t, "get-active-zones.txt"))
	if len(zones) != 3 {
		t.Fatalf("zones = %d, want 3", len(zones))
	}
	if zones[0].Name != "FedoraWorkstation" || !zones[0].Default {
		t.Errorf("first zone = %+v", zones[0])
	}
	if len(zones[0].Interfaces) != 12 {
		t.Errorf("interfaces = %d, want 12", len(zones[0].Interfaces))
	}
	if zones[2].Name != "libvirt" {
		t.Errorf("third zone = %q", zones[2].Name)
	}
}

func TestParseActiveZonesWithoutTheDefaultSuffix(t *testing.T) {
	// firewalld only started marking the default zone in this listing in
	// 2.0.6; before that the name was bare. The parser must read both, which
	// it does by not depending on the suffix at all.
	zones := ParseActiveZones("public\n  interfaces: eth0\n" +
		"internal\n  sources: 10.0.0.0/8\n")
	if len(zones) != 2 {
		t.Fatalf("zones = %d, want 2", len(zones))
	}
	if zones[0].Name != "public" || zones[0].Default {
		t.Errorf("first zone = %+v", zones[0])
	}
	if !reflect.DeepEqual(zones[1].Sources, []string{"10.0.0.0/8"}) {
		t.Errorf("sources = %q", zones[1].Sources)
	}
}

func TestParseList(t *testing.T) {
	if got := ParseList("  ssh http https \n"); !reflect.DeepEqual(got,
		[]string{"ssh", "http", "https"}) {
		t.Errorf("ParseList = %q", got)
	}
	if got := ParseList("\n"); got != nil {
		t.Errorf("ParseList of nothing = %q, want nil", got)
	}
}

func TestParseRichRule(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want RichRule
	}{
		{
			name: "service with logging",
			raw: `rule family="ipv4" source address="10.20.0.0/16" ` +
				`service name="postgresql" log prefix="pg: " level="info" accept`,
			want: RichRule{
				Family: "ipv4", Source: "10.20.0.0/16", Service: "postgresql",
				Verdict: "accept", Log: true, LogPrefix: "pg: ",
			},
		},
		{
			name: "port reject",
			raw:  `rule family="ipv6" source address="fd00::/8" port port="8443" protocol="tcp" reject`,
			want: RichRule{
				Family: "ipv6", Source: "fd00::/8", Port: "8443",
				Protocol: "tcp", Verdict: "reject",
			},
		},
		{
			name: "bare drop",
			raw:  `rule family="ipv4" source address="192.0.2.7" drop`,
			want: RichRule{Family: "ipv4", Source: "192.0.2.7", Verdict: "drop"},
		},
		{
			name: "destination",
			raw:  `rule family="ipv4" destination address="10.0.0.9" service name="dns" accept`,
			want: RichRule{
				Family: "ipv4", Destination: "10.0.0.9", Service: "dns",
				Verdict: "accept",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseRichRule(tc.raw)
			tc.want.Raw = tc.raw
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseRichRule\n got: %+v\nwant: %+v", got, tc.want)
			}
		})
	}
}

func TestDescribeForwardPort(t *testing.T) {
	ports, proto, to := describeForwardPort("port=443:proto=tcp:toport=8443:toaddr=10.20.0.9")
	if ports != "443" || proto != "tcp" || to != "10.20.0.9:8443" {
		t.Errorf("got %q %q %q", ports, proto, to)
	}
	// Without an address the port is forwarded to this machine.
	_, _, to = describeForwardPort("port=80:proto=tcp:toport=8080")
	if to != "localhost:8080" {
		t.Errorf("to = %q", to)
	}
}

func TestApplyRichFillsTheGenericColumns(t *testing.T) {
	rule := firewall.Rule{}
	applyRich(&rule, ParseRichRule(
		`rule family="ipv6" source address="fd00::/8" port port="8443" protocol="tcp" reject`))
	if rule.Action != firewall.ActionReject {
		t.Errorf("Action = %q, want REJECT", rule.Action)
	}
	if rule.Family != firewall.FamilyIPv6 {
		t.Errorf("Family = %q, want v6", rule.Family)
	}
	if rule.From != "fd00::/8" || rule.To != "8443/tcp" {
		t.Errorf("From/To = %q / %q", rule.From, rule.To)
	}
}
