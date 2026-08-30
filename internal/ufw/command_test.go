package ufw

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// Both implementations must satisfy the generic interface.
var (
	_ firewall.Backend = (*Real)(nil)
	_ firewall.Backend = (*Fake)(nil)
)

func TestBuildAddRule(t *testing.T) {
	tests := []struct {
		name string
		spec firewall.RuleSpec
		want []string
	}{
		{
			name: "short form port and proto",
			spec: firewall.RuleSpec{Action: firewall.ActionAllow, Ports: "22", Proto: "tcp"},
			want: []string{"ufw", "allow", "22/tcp"},
		},
		{
			name: "port without proto",
			spec: firewall.RuleSpec{Action: firewall.ActionAllow, Ports: "8080"},
			want: []string{"ufw", "allow", "8080"},
		},
		{
			name: "direction in",
			spec: firewall.RuleSpec{
				Action: firewall.ActionDeny, Direction: firewall.DirIn,
				Ports: "3306", Proto: "tcp",
			},
			want: []string{"ufw", "deny", "in", "3306/tcp"},
		},
		{
			name: "direction out",
			spec: firewall.RuleSpec{
				Action: firewall.ActionReject, Direction: firewall.DirOut,
				Ports: "25", Proto: "tcp",
			},
			want: []string{"ufw", "reject", "out", "25/tcp"},
		},
		{
			name: "app profile short form",
			spec: firewall.RuleSpec{Action: firewall.ActionAllow, Service: "OpenSSH"},
			want: []string{"ufw", "allow", "OpenSSH"},
		},
		{
			name: "limit with comment",
			spec: firewall.RuleSpec{
				Action: firewall.ActionLimit, Ports: "22", Proto: "tcp",
				Comment: "ssh rate limit",
			},
			want: []string{"ufw", "limit", "22/tcp", "comment", "ssh rate limit"},
		},
		{
			name: "extended form with source CIDR",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, Direction: firewall.DirIn,
				From: "10.0.0.0/8", Ports: "5432", Proto: "tcp",
				Comment: "postgres from lan",
			},
			want: []string{"ufw", "allow", "in", "from", "10.0.0.0/8", "to", "any",
				"port", "5432", "proto", "tcp", "comment", "postgres from lan"},
		},
		{
			name: "extended form with destination only",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, To: "192.168.1.10", Ports: "443",
			},
			want: []string{"ufw", "allow", "from", "any", "to", "192.168.1.10",
				"port", "443"},
		},
		{
			name: "extended form with app profile",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, From: "10.0.0.0/8", Service: "Samba",
			},
			want: []string{"ufw", "allow", "from", "10.0.0.0/8", "to", "any",
				"app", "Samba"},
		},
		{
			name: "ipv6 source",
			spec: firewall.RuleSpec{
				Action: firewall.ActionReject, Direction: firewall.DirIn,
				From: "fd00::/8", Ports: "137,138", Proto: "udp",
			},
			want: []string{"ufw", "reject", "in", "from", "fd00::/8", "to", "any",
				"port", "137,138", "proto", "udp"},
		},
		{
			name: "route rule",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, Routed: true,
				From: "192.168.1.0/24", Comment: "lan forwarding",
			},
			want: []string{"ufw", "route", "allow", "from", "192.168.1.0/24",
				"to", "any", "comment", "lan forwarding"},
		},
		{
			name: "insert at position",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, Position: 2, Ports: "80", Proto: "tcp",
			},
			want: []string{"ufw", "insert", "2", "allow", "80/tcp"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			change, err := BuildAddRule(GroupName, tc.spec)
			if err != nil {
				t.Fatalf("BuildAddRule: %v", err)
			}
			// ufw applies a change in one invocation, so a change it builds
			// always holds exactly one command.
			if len(change.Commands) != 1 {
				t.Fatalf("Commands = %d, want 1", len(change.Commands))
			}
			if !reflect.DeepEqual(change.Commands[0].Argv, tc.want) {
				t.Errorf("Argv\n got: %q\nwant: %q", change.Commands[0].Argv, tc.want)
			}
			if change.Description == "" {
				t.Error("Description should not be empty")
			}
		})
	}
}

func TestBuildAddRuleErrors(t *testing.T) {
	tests := []struct {
		name string
		spec firewall.RuleSpec
	}{
		{name: "no action", spec: firewall.RuleSpec{Ports: "22"}},
		{name: "no target", spec: firewall.RuleSpec{Action: firewall.ActionAllow}},
		{
			name: "proto without port",
			spec: firewall.RuleSpec{Action: firewall.ActionAllow, Proto: "tcp"},
		},
		{
			name: "negative position",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, Ports: "22", Position: -1,
			},
		},
		{
			name: "multiline comment",
			spec: firewall.RuleSpec{
				Action: firewall.ActionAllow, Ports: "22", Comment: "a\nb",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildAddRule(GroupName, tc.spec); err == nil {
				t.Error("expected an error")
			}
		})
	}

	spec := firewall.RuleSpec{Action: firewall.ActionAllow, Ports: "22"}
	if _, err := BuildAddRule("zone-public", spec); err == nil {
		t.Error("expected an error for an unknown group")
	}
}

func TestBuildOtherCommands(t *testing.T) {
	del, err := BuildDeleteRule(GroupName, firewall.Rule{ID: "3"})
	if err != nil {
		t.Fatalf("BuildDeleteRule: %v", err)
	}
	if got := del.String(); got != "ufw --force delete 3" {
		t.Errorf("delete = %q", got)
	}
	if !del.Destructive {
		t.Error("delete should be marked destructive")
	}
	if _, err := BuildDeleteRule(GroupName, firewall.Rule{ID: ""}); err == nil {
		t.Error("expected an error for a rule without a number")
	}

	enable, _ := BuildSetEnabled(true)
	if got := enable.String(); got != "ufw --force enable" {
		t.Errorf("enable = %q", got)
	}
	disable, _ := BuildSetEnabled(false)
	if got := disable.String(); got != "ufw disable" {
		t.Errorf("disable = %q", got)
	}
	reload, _ := BuildReload()
	if got := reload.String(); got != "ufw reload" {
		t.Errorf("reload = %q", got)
	}

	policy, err := BuildSetPolicy(GroupName, firewall.PolicyIncoming, firewall.PolicyDeny)
	if err != nil {
		t.Fatalf("BuildSetPolicy: %v", err)
	}
	if got := policy.String(); got != "ufw default deny incoming" {
		t.Errorf("policy = %q", got)
	}
	if _, err := BuildSetPolicy(GroupName, firewall.PolicyTarget, firewall.PolicyDeny); err == nil {
		t.Error("expected an error for an unsupported policy slot")
	}
	if _, err := BuildSetPolicy(GroupName, firewall.PolicyIncoming, "drop"); err == nil {
		t.Error("expected an error for an unknown policy")
	}

	logging, err := BuildSetLogging(LogMedium)
	if err != nil {
		t.Fatalf("BuildSetLogging: %v", err)
	}
	if got := logging.String(); got != "ufw logging medium" {
		t.Errorf("logging = %q", got)
	}
	if _, err := BuildSetLogging("verbose"); err == nil {
		t.Error("expected an error for an unknown logging level")
	}
}

func TestFakeAppliesCommands(t *testing.T) {
	ctx := context.Background()
	f := NewFake()

	before, err := f.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	count := len(before.Groups[0].Rules)

	add, err := f.BuildAddRule(GroupName, firewall.RuleSpec{
		Action: firewall.ActionAllow, Ports: "8443", Proto: "tcp",
		Comment: "app",
	})
	if err != nil {
		t.Fatalf("BuildAddRule: %v", err)
	}
	if _, err := f.Run(ctx, add); err != nil {
		t.Fatalf("Run add: %v", err)
	}

	after, _ := f.Load(ctx)
	rules := after.Groups[0].Rules
	if len(rules) != count+1 {
		t.Fatalf("len(Rules) = %d, want %d", len(rules), count+1)
	}
	added := rules[len(rules)-1]
	if added.Ports != "8443" || added.Proto != "tcp" || added.Comment != "app" {
		t.Errorf("added rule = %+v", added)
	}
	if added.ID != "10" || added.Index != 10 {
		t.Errorf("added rule should be renumbered, got ID=%q Index=%d",
			added.ID, added.Index)
	}

	del, err := f.BuildDeleteRule(GroupName, added)
	if err != nil {
		t.Fatalf("BuildDeleteRule: %v", err)
	}
	if _, err := f.Run(ctx, del); err != nil {
		t.Fatalf("Run delete: %v", err)
	}
	after, _ = f.Load(ctx)
	if got := len(after.Groups[0].Rules); got != count {
		t.Errorf("len(Rules) = %d, want %d after delete", got, count)
	}

	if len(f.Log) != 2 {
		t.Errorf("len(Log) = %d, want 2", len(f.Log))
	}
}

func TestFakeInsertAndToggles(t *testing.T) {
	ctx := context.Background()
	f := NewFake()

	insert, err := f.BuildAddRule(GroupName, firewall.RuleSpec{
		Action: firewall.ActionDeny, Ports: "23", Proto: "tcp", Position: 1,
	})
	if err != nil {
		t.Fatalf("BuildAddRule: %v", err)
	}
	if _, err := f.Run(ctx, insert); err != nil {
		t.Fatalf("Run insert: %v", err)
	}
	model, _ := f.Load(ctx)
	if got := model.Groups[0].Rules[0]; got.Ports != "23" || got.Index != 1 {
		t.Errorf("inserted rule = %+v, want ports 23 at index 1", got)
	}

	disable, _ := f.BuildSetEnabled(false)
	if _, err := f.Run(ctx, disable); err != nil {
		t.Fatalf("Run disable: %v", err)
	}
	if model, _ = f.Load(ctx); model.Enabled {
		t.Error("Enabled = true after disable")
	}

	logging, _ := f.BuildSetLogging(LogFull)
	if _, err := f.Run(ctx, logging); err != nil {
		t.Fatalf("Run logging: %v", err)
	}
	if model, _ = f.Load(ctx); model.Logging != LogFull {
		t.Errorf("Logging = %q, want full", model.Logging)
	}

	policy, _ := f.BuildSetPolicy(GroupName, firewall.PolicyRouted, firewall.PolicyAllow)
	if _, err := f.Run(ctx, policy); err != nil {
		t.Fatalf("Run policy: %v", err)
	}
	model, _ = f.Load(ctx)
	if d := model.Groups[0].Default; d.Routed != firewall.PolicyAllow || d.RoutedDisabled {
		t.Errorf("routed default = %+v", d)
	}
}

func TestFakeLoadReturnsCopy(t *testing.T) {
	f := NewFake()
	model, _ := f.Load(context.Background())
	model.Groups[0].Rules[0].Comment = "mutated"

	fresh, _ := f.Load(context.Background())
	if fresh.Groups[0].Rules[0].Comment == "mutated" {
		t.Error("Load must return a copy of the state")
	}
}

func TestFakeRejectsUnknownCommand(t *testing.T) {
	_, err := NewFake().Run(context.Background(),
		firewall.One(firewall.Command{Argv: []string{"ufw", "show", "raw"}}))
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("err = %v, want an unsupported-command error", err)
	}
}
