package firewalld

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// argvs flattens a change into the argv lines it will run, which is what the
// preview shows and therefore the only thing worth asserting on.
func argvs(change firewall.Change) [][]string {
	out := make([][]string, 0, len(change.Commands))
	for _, cmd := range change.Commands {
		out = append(out, cmd.Argv)
	}
	return out
}

func TestBuildAddRule(t *testing.T) {
	tests := []struct {
		name  string
		group string
		spec  firewall.RuleSpec
		want  [][]string
	}{
		{
			name:  "a service, runtime and permanent",
			group: "public",
			spec:  firewall.RuleSpec{Action: firewall.ActionAllow, Service: "ssh"},
			want: [][]string{
				{Bin, "--zone=public", "--add-service=ssh"},
				{Bin, "--permanent", "--zone=public", "--add-service=ssh"},
			},
		},
		{
			name:  "a port",
			group: "public",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, Ports: "8080", Proto: "tcp",
			},
			want: [][]string{
				{Bin, "--zone=public", "--add-port=8080/tcp"},
				{Bin, "--permanent", "--zone=public", "--add-port=8080/tcp"},
			},
		},
		{
			name:  "a port range on a policy object",
			group: PolicyPrefix + "libvirt-to-host",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, Ports: "1000-2000", Proto: "udp",
			},
			want: [][]string{
				{Bin, "--policy=libvirt-to-host", "--add-port=1000-2000/udp"},
				{Bin, "--permanent", "--policy=libvirt-to-host", "--add-port=1000-2000/udp"},
			},
		},
		{
			name:  "a source turns the rule into a rich rule",
			group: "public",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, Service: "postgresql", From: "10.0.0.0/8",
			},
			want: [][]string{
				{Bin, "--zone=public", `--add-rich-rule=rule family="ipv4" ` +
					`source address="10.0.0.0/8" service name="postgresql" accept`},
				{Bin, "--permanent", "--zone=public", `--add-rich-rule=rule family="ipv4" ` +
					`source address="10.0.0.0/8" service name="postgresql" accept`},
			},
		},
		{
			name:  "a reject verdict needs a rich rule even without an address",
			group: "public",
			spec: firewall.RuleSpec{
				Action: firewall.ActionReject, Ports: "3306", Proto: "tcp",
			},
			want: [][]string{
				{Bin, "--zone=public",
					`--add-rich-rule=rule port port="3306" protocol="tcp" reject`},
				{Bin, "--permanent", "--zone=public",
					`--add-rich-rule=rule port port="3306" protocol="tcp" reject`},
			},
		},
		{
			name:  "an explicit family and logging",
			group: "public",
			spec: firewall.RuleSpec{
				Action: firewall.ActionDeny, Family: firewall.FamilyIPv6,
				Service: "http", Log: true,
			},
			want: [][]string{
				{Bin, "--zone=public", `--add-rich-rule=rule family="ipv6" ` +
					`service name="http" log level="info" limit value="10/m" drop`},
				{Bin, "--permanent", "--zone=public", `--add-rich-rule=rule family="ipv6" ` +
					`service name="http" log level="info" limit value="10/m" drop`},
			},
		},
		{
			name:  "an IPv6 source picks its own family",
			group: "public",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, From: "fd00::/8", Service: "dns",
			},
			want: [][]string{
				{Bin, "--zone=public", `--add-rich-rule=rule family="ipv6" ` +
					`source address="fd00::/8" service name="dns" accept`},
				{Bin, "--permanent", "--zone=public", `--add-rich-rule=rule family="ipv6" ` +
					`source address="fd00::/8" service name="dns" accept`},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			change, err := BuildAddRule(tc.group, tc.spec)
			if err != nil {
				t.Fatalf("BuildAddRule: %v", err)
			}
			if got := argvs(change); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("argv\n got: %q\nwant: %q", got, tc.want)
			}
			if change.Description == "" || change.Note == "" {
				t.Errorf("change should describe itself: %+v", change)
			}
		})
	}
}

func TestBuildAddRuleErrors(t *testing.T) {
	tests := []struct {
		name string
		spec firewall.RuleSpec
		want string
	}{
		{"nothing at all", firewall.RuleSpec{Action: firewall.ActionAllow},
			"service or a port"},
		{"a port without a protocol",
			firewall.RuleSpec{Action: firewall.ActionAllow, Ports: "80"},
			"needs a protocol"},
		{"an insert position",
			firewall.RuleSpec{Action: firewall.ActionAllow, Service: "ssh", Position: 2},
			"does not order"},
		{"a comment",
			firewall.RuleSpec{Action: firewall.ActionAllow, Service: "ssh", Comment: "why"},
			"no rule comments"},
		{"a limit verdict",
			firewall.RuleSpec{Action: firewall.ActionLimit, From: "10.0.0.1", Service: "ssh"},
			"no \"LIMIT\" verdict"},
		{"an unknown protocol",
			firewall.RuleSpec{Action: firewall.ActionAllow, Ports: "80", Proto: "sctpx"},
			"unknown protocol"},
		{"a source with a space in it",
			firewall.RuleSpec{Action: firewall.ActionAllow, Service: "ssh",
				From: "10.0.0.0/8 accept"},
			"must not contain spaces"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildAddRule("public", tc.spec)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestBuildDeleteRuleByKind(t *testing.T) {
	tests := []struct {
		kind string
		raw  string
		want string
	}{
		{firewall.KindService, "ssh", "--remove-service=ssh"},
		{firewall.KindPort, "8080/tcp", "--remove-port=8080/tcp"},
		{firewall.KindProtocol, "esp", "--remove-protocol=esp"},
		{firewall.KindSourcePort, "5353/udp", "--remove-source-port=5353/udp"},
		{firewall.KindICMPBlock, "echo-request", "--remove-icmp-block=echo-request"},
		{firewall.KindSource, "10.0.0.0/8", "--remove-source=10.0.0.0/8"},
		{firewall.KindInterface, "eth0", "--remove-interface=eth0"},
		{firewall.KindForwardPort, "port=80:proto=tcp:toport=8080",
			"--remove-forward-port=port=80:proto=tcp:toport=8080"},
		{firewall.KindRich, `rule family="ipv4" source address="192.0.2.7" drop`,
			`--remove-rich-rule=rule family="ipv4" source address="192.0.2.7" drop`},
	}

	for _, tc := range tests {
		t.Run(tc.kind, func(t *testing.T) {
			change, err := BuildDeleteRule("public", firewall.Rule{
				Kind: tc.kind, Raw: tc.raw,
				Extra: map[string]string{ExtraScope: ScopeBoth},
			})
			if err != nil {
				t.Fatalf("BuildDeleteRule: %v", err)
			}
			want := [][]string{
				{Bin, "--zone=public", tc.want},
				{Bin, "--permanent", "--zone=public", tc.want},
			}
			if got := argvs(change); !reflect.DeepEqual(got, want) {
				t.Errorf("argv\n got: %q\nwant: %q", got, want)
			}
			if !change.Destructive {
				t.Error("a delete must be marked destructive")
			}
		})
	}
}

func TestBuildDeleteRuleFollowsTheScope(t *testing.T) {
	// An entry that exists only in the runtime configuration is removed from
	// the runtime only: issuing the permanent form as well would just fail.
	runtimeOnly, err := BuildDeleteRule("public", firewall.Rule{
		Kind: firewall.KindPort, Raw: "9090/tcp",
		Extra: map[string]string{ExtraScope: ScopeRuntime},
	})
	if err != nil {
		t.Fatalf("BuildDeleteRule: %v", err)
	}
	want := [][]string{{Bin, "--zone=public", "--remove-port=9090/tcp"}}
	if got := argvs(runtimeOnly); !reflect.DeepEqual(got, want) {
		t.Errorf("runtime-only argv = %q, want %q", got, want)
	}

	permanentOnly, err := BuildDeleteRule("public", firewall.Rule{
		Kind: firewall.KindService, Raw: "https",
		Extra: map[string]string{ExtraScope: ScopePermanent},
	})
	if err != nil {
		t.Fatalf("BuildDeleteRule: %v", err)
	}
	want = [][]string{{Bin, "--permanent", "--zone=public", "--remove-service=https"}}
	if got := argvs(permanentOnly); !reflect.DeepEqual(got, want) {
		t.Errorf("permanent-only argv = %q, want %q", got, want)
	}
}

func TestBuildDeleteRuleForValuelessKinds(t *testing.T) {
	for kind, want := range map[string]string{
		firewall.KindMasquerade: "--remove-masquerade",
		firewall.KindForward:    "--remove-forward",
	} {
		change, err := BuildDeleteRule("public", firewall.Rule{
			Kind: kind, Raw: kind, Extra: map[string]string{ExtraScope: ScopeBoth},
		})
		if err != nil {
			t.Fatalf("BuildDeleteRule(%s): %v", kind, err)
		}
		if got := change.Commands[0].Argv[2]; got != want {
			t.Errorf("%s argv = %q, want %q", kind, got, want)
		}
	}

	if _, err := BuildDeleteRule("public", firewall.Rule{Raw: "x"}); err == nil {
		t.Error("an entry with no kind cannot be deleted")
	}
}

func TestBuildSetPolicyIsPermanentPlusReload(t *testing.T) {
	// firewalld has no runtime form for a zone target, so this is the one
	// change that reloads — and the change says so.
	change, err := BuildSetPolicy("public", firewall.PolicyTarget, TargetDrop)
	if err != nil {
		t.Fatalf("BuildSetPolicy: %v", err)
	}
	want := [][]string{
		{Bin, "--permanent", "--zone=public", "--set-target=DROP"},
		{Bin, "--reload"},
	}
	if got := argvs(change); !reflect.DeepEqual(got, want) {
		t.Errorf("argv\n got: %q\nwant: %q", got, want)
	}
	if !strings.Contains(change.Note, "reload") {
		t.Errorf("note = %q, want it to mention the reload", change.Note)
	}

	if _, err := BuildSetPolicy("public", firewall.PolicyIncoming, TargetDrop); err == nil {
		t.Error("firewalld has no incoming policy slot")
	}
	if _, err := BuildSetPolicy("public", firewall.PolicyTarget, "MAYBE"); err == nil {
		t.Error("an unknown target must be rejected")
	}
	if _, err := BuildSetPolicy(PolicyPrefix+"p1", firewall.PolicyTarget,
		TargetDrop); err == nil {
		t.Error("a policy object's target is not editable here")
	}
}

func TestBuildSetLogging(t *testing.T) {
	change, err := BuildSetLogging(LogAll)
	if err != nil {
		t.Fatalf("BuildSetLogging: %v", err)
	}
	want := [][]string{{Bin, "--set-log-denied=all"}}
	if got := argvs(change); !reflect.DeepEqual(got, want) {
		t.Errorf("argv = %q, want %q", got, want)
	}
	// It reloads the firewall to install the logging rules, so it is not a
	// harmless setting and must not be presented as one.
	if !change.Destructive {
		t.Error("set-log-denied reloads, so it is destructive")
	}
	if _, err := BuildSetLogging("verbose"); err == nil {
		t.Error("an unknown log-denied value must be rejected")
	}
}

func TestBuildSetEnabledRefuses(t *testing.T) {
	_, err := BuildSetEnabled(true)
	if err == nil {
		t.Fatal("firewalld must not be started from here")
	}
	if !strings.Contains(err.Error(), "systemctl") {
		t.Errorf("error = %v, want it to point at systemctl", err)
	}
}

func TestBuildReload(t *testing.T) {
	change, err := BuildReload()
	if err != nil {
		t.Fatalf("BuildReload: %v", err)
	}
	if got := argvs(change); !reflect.DeepEqual(got, [][]string{{Bin, "--reload"}}) {
		t.Errorf("argv = %q", got)
	}
	if !strings.Contains(change.Note, "runtime-only") {
		t.Errorf("note = %q, want the warning about runtime-only entries", change.Note)
	}
}

func TestBuildExtra(t *testing.T) {
	tests := []struct {
		id    string
		group string
		args  []string
		want  [][]string
	}{
		{
			id: ExtraSetDefaultZone, group: "public", args: []string{"internal"},
			want: [][]string{{Bin, "--set-default-zone=internal"}},
		},
		{
			id: ExtraChangeInterface, group: "public", args: []string{"eth1", "internal"},
			want: [][]string{
				{Bin, "--zone=internal", "--change-interface=eth1"},
				{Bin, "--permanent", "--zone=internal", "--change-interface=eth1"},
			},
		},
		{
			id: ExtraAddSource, group: "internal", args: []string{"10.0.0.0/8"},
			want: [][]string{
				{Bin, "--zone=internal", "--add-source=10.0.0.0/8"},
				{Bin, "--permanent", "--zone=internal", "--add-source=10.0.0.0/8"},
			},
		},
		{
			id: ExtraMasqueradeOn, group: "public",
			want: [][]string{
				{Bin, "--zone=public", "--add-masquerade"},
				{Bin, "--permanent", "--zone=public", "--add-masquerade"},
			},
		},
		{
			id: ExtraMasqueradeOff, group: "public",
			want: [][]string{
				{Bin, "--zone=public", "--remove-masquerade"},
				{Bin, "--permanent", "--zone=public", "--remove-masquerade"},
			},
		},
		{id: ExtraPanicOn, want: [][]string{{Bin, "--panic-on"}}},
		{id: ExtraPanicOff, want: [][]string{{Bin, "--panic-off"}}},
		{id: ExtraRuntimeToPermanent, want: [][]string{{Bin, "--runtime-to-permanent"}}},
	}

	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			change, err := BuildExtra(tc.group, tc.id, tc.args)
			if err != nil {
				t.Fatalf("BuildExtra: %v", err)
			}
			if got := argvs(change); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("argv\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}

	if _, err := BuildExtra("public", "reboot", nil); err == nil {
		t.Error("an unknown action must be rejected")
	}
	if _, err := BuildExtra("public", ExtraAddSource, []string{""}); err == nil {
		t.Error("an empty source must be rejected")
	}
}

func TestExtrasFollowTheState(t *testing.T) {
	fake := NewFake()
	model, _ := fake.Load(context.Background())

	ids := map[string]bool{}
	for _, extra := range fake.Extras(model, "public") {
		ids[extra.ID] = true
	}
	// public has masquerade off in the demo, so only "on" is offered.
	if !ids[ExtraMasqueradeOn] || ids[ExtraMasqueradeOff] {
		t.Errorf("public actions = %v", ids)
	}
	if !ids[ExtraPanicOn] || ids[ExtraPanicOff] {
		t.Errorf("panic mode is off, so only panic-on belongs: %v", ids)
	}

	ids = map[string]bool{}
	for _, extra := range fake.Extras(model, "internal") {
		ids[extra.ID] = true
	}
	if !ids[ExtraMasqueradeOff] || ids[ExtraMasqueradeOn] {
		t.Errorf("internal has masquerade on: %v", ids)
	}

	// A policy object is not somewhere an interface or a source can point.
	ids = map[string]bool{}
	for _, extra := range fake.Extras(model, PolicyPrefix+"libvirt-to-host") {
		ids[extra.ID] = true
	}
	if ids[ExtraChangeInterface] || ids[ExtraAddSource] {
		t.Errorf("policy actions = %v", ids)
	}
}

func TestExtrasOfferPanicOffWhilePanicking(t *testing.T) {
	model := BuildModel(Snapshot{Running: true, Panic: true})
	ids := map[string]bool{}
	for _, extra := range Extras(model, "public") {
		ids[extra.ID] = true
	}
	if !ids[ExtraPanicOff] || ids[ExtraPanicOn] {
		t.Errorf("actions = %v, want only panic-off", ids)
	}
}
