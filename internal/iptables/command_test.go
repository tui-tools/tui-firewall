package iptables

import (
	"reflect"
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

const v4Input = "ip filter / INPUT"

func TestOpenPortsReadsTheCloudImageTheWayItDecides(t *testing.T) {
	// The acceptance case: 443/tcp, 41641/udp and 54203/tcp are open on the
	// captured host, 51820/udp is not.
	state := ociState(t)
	input, _ := state.V4.Chain(TableFilter, ChainInput)
	open, shadowed := input.OpenPorts()
	for _, want := range []string{"443/tcp", "41641/udp", "54203/tcp", "22/tcp"} {
		if !contains(open, want) {
			t.Errorf("open = %v, want %s", open, want)
		}
	}
	if contains(open, "51820/udp") || len(shadowed) != 0 {
		t.Errorf("open = %v, shadowed = %v: 51820/udp must not be open", open, shadowed)
	}
}

func TestOpenPortsFlagsAnAcceptAfterTheCatchAll(t *testing.T) {
	// What tui-firewall 0.4.1 would have produced through nft: the accept
	// appended after the REJECT, listed but never matching.
	chain := mustChain(t, "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A INPUT -j REJECT --reject-with icmp-host-prohibited",
		"-A INPUT -p udp -m udp --dport 51820 -j ACCEPT")
	open, shadowed := chain.OpenPorts()
	if !reflect.DeepEqual(open, []string{"22/tcp"}) ||
		!reflect.DeepEqual(shadowed, []string{"51820/udp"}) {
		t.Errorf("open = %v, shadowed = %v", open, shadowed)
	}
}

func TestBuildAddRuleInsertsBeforeTheCatchAll(t *testing.T) {
	state := ociState(t)
	change, err := state.BuildAddRule(v4Input, firewall.RuleSpec{
		Action: firewall.ActionAllow, Proto: "udp", Ports: "51820",
	})
	if err != nil {
		t.Fatalf("BuildAddRule: %v", err)
	}
	want := []string{"iptables", "-I", "INPUT", "9", "-p", "udp", "-m", "udp",
		"--dport", "51820", "-j", "ACCEPT"}
	if len(change.Commands) != 1 || !reflect.DeepEqual(change.Commands[0].Argv, want) {
		t.Fatalf("argv = %q, want %q", change.String(), strings.Join(want, " "))
	}
	for _, part := range []string{"position 9 of INPUT", "right before rule 9",
		"--reject-with icmp-host-prohibited", "never match", "W writes"} {
		if !strings.Contains(change.Note, part) {
			t.Errorf("note %q should say %q", change.Note, part)
		}
	}
}

func TestBuildAddRuleAppendsWhenThereIsNoCatchAll(t *testing.T) {
	state := ociState(t)
	change, err := state.BuildAddRule("ip6 filter / INPUT", firewall.RuleSpec{
		Action: firewall.ActionAllow, Proto: "tcp", Ports: "443",
		CTStates: []string{"new"},
	})
	if err != nil {
		t.Fatalf("BuildAddRule: %v", err)
	}
	if got := change.String(); got != "ip6tables -I INPUT 2 -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT" {
		t.Errorf("argv = %s", got)
	}
	if !strings.Contains(change.Note, "no catch-all") {
		t.Errorf("note = %q", change.Note)
	}
}

func TestBuildAddRuleRefusesAPositionAfterTheCatchAll(t *testing.T) {
	state := ociState(t)
	_, err := state.BuildAddRule(v4Input, firewall.RuleSpec{
		Action: firewall.ActionAllow, Proto: "udp", Ports: "51820", Position: 10,
	})
	if err == nil || !strings.Contains(err.Error(), "never match") {
		t.Errorf("err = %v, want a refusal naming the catch-all", err)
	}
	_, err = state.BuildAddRule(v4Input, firewall.RuleSpec{
		Action: firewall.ActionAllow, Proto: "udp", Ports: "51820", Position: 1,
	})
	if err != nil {
		t.Errorf("an explicit position above the catch-all must be honoured: %v", err)
	}
}

func TestBuildAddRuleWithEveryMatch(t *testing.T) {
	state := ociState(t)
	change, err := state.BuildAddRule("ip filter / FORWARD", firewall.RuleSpec{
		Action: firewall.ActionReject, Proto: "tcp", Ports: "80,443",
		From: "10.0.0.0/16", To: "192.0.2.10", InIface: "eth0", OutIface: "docker0",
		Comment: "web-block",
	})
	if err != nil {
		t.Fatalf("BuildAddRule: %v", err)
	}
	want := "iptables -I FORWARD 4 -p tcp -s 10.0.0.0/16 -d 192.0.2.10 -i eth0 " +
		"-o docker0 -m multiport --dports 80,443 -m comment --comment web-block -j REJECT"
	if got := change.String(); got != want {
		t.Errorf("argv =\n%s\nwant\n%s", got, want)
	}
}

func TestBuildAddRuleICMP(t *testing.T) {
	state := ociState(t)
	change, err := state.BuildAddRule("ip6 filter / INPUT", firewall.RuleSpec{
		Action: firewall.ActionAllow, Proto: "icmpv6", ICMPType: "echo-request",
	})
	if err != nil {
		t.Fatalf("BuildAddRule: %v", err)
	}
	if got := change.String(); got != "ip6tables -I INPUT 2 -p ipv6-icmp -m icmp6 --icmpv6-type echo-request -j ACCEPT" {
		t.Errorf("argv = %s", got)
	}
}

func TestBuildAddRuleRefusals(t *testing.T) {
	state := ociState(t)
	cases := map[string]struct {
		group string
		spec  firewall.RuleSpec
		want  string
	}{
		"v6 address in the v4 chain": {v4Input, firewall.RuleSpec{
			Action: firewall.ActionAllow, From: "2001:db8::1"}, "IPv6"},
		"comment with a double quote": {v4Input, firewall.RuleSpec{
			Action: firewall.ActionAllow, Comment: `say "hi"`}, "double quotes"},
		"comment with a newline": {v4Input, firewall.RuleSpec{
			Action: firewall.ActionAllow, Comment: "two\nlines"}, "one line"},
		"port without a protocol": {v4Input, firewall.RuleSpec{
			Action: firewall.ActionAllow, Ports: "22"}, "protocol"},
		"output interface on INPUT": {v4Input, firewall.RuleSpec{
			Action: firewall.ActionAllow, OutIface: "eth0"}, "output interface"},
		"a named service": {v4Input, firewall.RuleSpec{
			Action: firewall.ActionAllow, Service: "ssh"}, "services"},
		"docker's chain": {"ip filter / DOCKER-FORWARD", firewall.RuleSpec{
			Action: firewall.ActionAllow}, "docker"},
		"tailscale's chain": {"ip filter / ts-input", firewall.RuleSpec{
			Action: firewall.ActionAllow}, "tailscaled"},
		"a user chain": {"ip filter / InstanceServices", firewall.RuleSpec{
			Action: firewall.ActionAllow}, "user chain"},
		"the nat table": {"ip nat / POSTROUTING", firewall.RuleSpec{
			Action: firewall.ActionAllow}, "table nat"},
		"a bad port": {v4Input, firewall.RuleSpec{
			Action: firewall.ActionAllow, Proto: "tcp", Ports: "70000"}, "port"},
		"a bad interface": {v4Input, firewall.RuleSpec{
			Action: firewall.ActionAllow, InIface: "eth0;reboot"}, "interface"},
	}
	for name, tc := range cases {
		_, err := state.BuildAddRule(tc.group, tc.spec)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, tc.want)
		}
	}
}

func TestBuildDeleteRuleGoesBySpecification(t *testing.T) {
	state := ociState(t)
	model := Model(state)
	group, _ := model.Group(v4Input)
	var https firewall.Rule
	for _, r := range group.Rules {
		if r.Ports == "443" {
			https = r
		}
	}
	change, err := state.BuildDeleteRule(v4Input, https)
	if err != nil {
		t.Fatalf("BuildDeleteRule: %v", err)
	}
	want := "iptables -D INPUT -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT"
	if got := change.String(); got != want || !change.Destructive {
		t.Errorf("delete = %s (destructive %t), want %s", got, change.Destructive, want)
	}
	// A rule that is no longer there is refused rather than guessed at.
	https.ID = "-p tcp -m tcp --dport 8443 -j ACCEPT"
	if _, err := state.BuildDeleteRule(v4Input, https); err == nil {
		t.Error("deleting a rule that is not there must fail")
	}
}

func TestBuildDeleteOfTheCatchAllSaysWhatItMeans(t *testing.T) {
	state := ociState(t)
	group, _ := Model(state).Group(v4Input)
	last := group.Rules[len(group.Rules)-1]
	change, err := state.BuildDeleteRule(v4Input, last)
	if err != nil {
		t.Fatalf("BuildDeleteRule: %v", err)
	}
	if !strings.Contains(change.Note, "catch-all") {
		t.Errorf("note = %q", change.Note)
	}
}

func TestBuildSetPolicy(t *testing.T) {
	state := ociState(t)
	change, err := state.BuildSetPolicy(v4Input, firewall.PolicyDeny)
	if err != nil {
		t.Fatalf("BuildSetPolicy: %v", err)
	}
	if change.String() != "iptables -P INPUT DROP" || !change.Destructive {
		t.Errorf("policy = %s", change.String())
	}
	if _, err := state.BuildSetPolicy(v4Input, firewall.PolicyReject); err == nil {
		t.Error("a REJECT policy does not exist in iptables")
	}
	if _, err := state.BuildSetPolicy("ip filter / DOCKER", firewall.PolicyDeny); err == nil {
		t.Error("a user chain has no policy to set")
	}
}

func TestModelShapesTheCloudImage(t *testing.T) {
	model := Model(ociState(t))
	if model.Backend != "iptables" || !model.Enabled {
		t.Errorf("model = %s enabled %t", model.Backend, model.Enabled)
	}
	names := make([]string, 0, len(model.Groups))
	for _, g := range model.Groups {
		names = append(names, g.Name)
	}
	wantFirst := []string{"ip filter / INPUT", "ip6 filter / INPUT",
		"ip filter / FORWARD", "ip6 filter / FORWARD",
		"ip filter / OUTPUT", "ip6 filter / OUTPUT"}
	if !reflect.DeepEqual(names[:6], wantFirst) {
		t.Errorf("groups = %v", names)
	}
	input, _ := model.Group(v4Input)
	if !strings.Contains(input.Description, "catch-all REJECT at rule 9") {
		t.Errorf("INPUT description = %q", input.Description)
	}
	if input.Default.Incoming != firewall.PolicyAllow {
		t.Errorf("INPUT policy = %q", input.Default.Incoming)
	}
	if input.Rules[0].Action != "JUMP" || !strings.Contains(input.Rules[0].Extra[firewall.ExtraDetail], "ts-input") {
		t.Errorf("rule 1 = %+v, want a jump to ts-input", input.Rules[0])
	}
	if input.Rules[8].Action != firewall.ActionReject || input.Rules[8].Extra[firewall.ExtraCounter] == "" {
		t.Errorf("rule 9 = %+v", input.Rules[8])
	}
	docker, ok := model.Group("ip filter / DOCKER")
	if !ok || !strings.Contains(docker.Description, "read-only") {
		t.Errorf("DOCKER group = %+v", docker)
	}
}

func TestParseGroup(t *testing.T) {
	family, table, chain, err := ParseGroup("ip6 filter / INPUT")
	if err != nil || family != V6 || table != TableFilter || chain != ChainInput {
		t.Errorf("ParseGroup = %s %s %s %v", family, table, chain, err)
	}
	for _, bad := range []string{"INPUT", "inet filter / INPUT", "ip / INPUT"} {
		if _, _, _, err := ParseGroup(bad); err == nil {
			t.Errorf("ParseGroup(%q) should fail", bad)
		}
	}
}

// mustChain builds an INPUT chain from dump lines.
func mustChain(t *testing.T, lines ...string) Chain {
	t.Helper()
	dump, err := ParseSave(V4, "*filter\n:INPUT ACCEPT [0:0]\n"+strings.Join(lines, "\n")+"\nCOMMIT\n")
	if err != nil {
		t.Fatalf("ParseSave: %v", err)
	}
	chain, _ := dump.Chain(TableFilter, ChainInput)
	return chain
}

// contains reports whether a slice holds a value.
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
