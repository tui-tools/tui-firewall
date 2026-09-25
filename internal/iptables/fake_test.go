package iptables

import (
	"context"
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/nftables/staging"
)

// specAllowUDP is an allow for one UDP port.
func specAllowUDP(port string) firewall.RuleSpec {
	return firewall.RuleSpec{Action: firewall.ActionAllow, Proto: "udp", Ports: port}
}

func TestFakeAddPersistDeleteRoundTrip(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	change, err := f.BuildAddRule(v4Input, specAllowUDP("51820"))
	if err != nil {
		t.Fatalf("BuildAddRule: %v", err)
	}
	if !strings.HasPrefix(change.String(), "iptables -I INPUT 5 ") {
		t.Fatalf("demo add = %s, want position 5, before the REJECT", change.String())
	}
	if _, err := f.Run(ctx, change); err != nil {
		t.Fatalf("Run: %v", err)
	}
	input, _ := f.State().V4.Chain(TableFilter, ChainInput)
	if input.Rules[4].Match.DPort != "51820" || input.Rules[5].Match.Target != TargetReject {
		t.Fatalf("INPUT after the add:\n%s", Comparable(f.State().V4))
	}
	if drift := f.PersistState().Drift; drift.InSync {
		t.Fatalf("drift = %+v, want the add unsaved", drift)
	}

	persist, diff, err := f.PreparePersist(ctx)
	if err != nil {
		t.Fatalf("PreparePersist: %v", err)
	}
	if !strings.Contains(diff, "+-A INPUT -p udp -m udp --dport 51820 -j ACCEPT") {
		t.Errorf("persist diff =\n%s", diff)
	}
	if _, err := f.Run(ctx, persist); err != nil {
		t.Fatalf("persist: %v", err)
	}
	if drift := f.PersistState().Drift; !drift.InSync {
		t.Fatalf("drift after persist = %+v", drift)
	}

	group, _ := func() (firewall.Group, bool) {
		m, _ := f.Load(ctx)
		return m.Group(v4Input)
	}()
	del, err := f.BuildDeleteRule(v4Input, group.Rules[4])
	if err != nil {
		t.Fatalf("BuildDeleteRule: %v", err)
	}
	if _, err := f.Run(ctx, del); err != nil {
		t.Fatalf("delete: %v", err)
	}
	input, _ = f.State().V4.Chain(TableFilter, ChainInput)
	if len(input.Rules) != 5 {
		t.Errorf("INPUT has %d rules after the delete, want 5", len(input.Rules))
	}
}

func TestFakeRejectsWhatIptablesRejects(t *testing.T) {
	f := NewFake()
	_, err := f.Run(context.Background(), firewall.One(firewall.Command{
		Argv: []string{"iptables", "-I", "INPUT", "99", "-j", "ACCEPT"}}))
	if err == nil {
		t.Error("an insert past the end must fail, as iptables does")
	}
	_, err = f.Run(context.Background(), firewall.One(firewall.Command{
		Argv: []string{"iptables", "-D", "INPUT", "-p", "tcp", "--dport", "1", "-j", "ACCEPT"}}))
	if err == nil {
		t.Error("deleting a rule that is not there must fail")
	}
}

func TestDialectAppliesPerFamilyAndRollsBack(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	session := staging.NewWithDialect(0, f.StagingDialect())
	add4, _ := f.BuildAddRule(v4Input, specAllowUDP("51820"))
	add6, _ := f.BuildAddRule("ip6 filter / INPUT", specAllowUDP("51820"))
	for _, c := range []firewall.Change{add4, add6} {
		if err := session.Stage(c); err != nil {
			t.Fatalf("Stage: %v", err)
		}
	}
	preview := session.PreviewApply()
	for _, want := range []string{"# iptables-restore --noflush", "# ip6tables-restore --noflush",
		"-I INPUT 5 -p udp -m udp --dport 51820 -j ACCEPT", "COMMIT"} {
		if !strings.Contains(preview, want) {
			t.Errorf("preview should contain %q:\n%s", want, preview)
		}
	}
	snapshot, err := f.SnapshotRuleset(ctx)
	if err != nil {
		t.Fatalf("SnapshotRuleset: %v", err)
	}
	session.Snapshot(snapshot)
	apply, err := session.ApplyChange()
	if err != nil {
		t.Fatalf("ApplyChange: %v", err)
	}
	if len(apply.Commands) != 2 || apply.Commands[0].Argv[0] != "iptables-restore" ||
		apply.Commands[1].Argv[0] != "ip6tables-restore" {
		t.Fatalf("apply = %s", apply.String())
	}
	before := Comparable(f.State().V4)
	if _, err := f.Run(ctx, apply); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if Comparable(f.State().V4) == before {
		t.Fatal("the batch changed nothing")
	}
	if err := session.Arm(nil); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	rollback, err := session.RollbackChange()
	if err != nil {
		t.Fatalf("RollbackChange: %v", err)
	}
	if _, err := f.Run(ctx, rollback); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got := Comparable(f.State().V4); got != before {
		t.Errorf("rollback did not restore the filter table:\n%s", got)
	}
	// The nat table was not in the snapshot and must be untouched.
	if _, ok := f.State().V4.Table("nat"); !ok {
		t.Error("the rollback must not drop docker's nat table")
	}
}

func TestDialectIsAllOrNothing(t *testing.T) {
	f := NewFake()
	before := Comparable(f.State().V4)
	script := "*filter\n-I INPUT 5 -p udp -m udp --dport 51820 -j ACCEPT\n" +
		"-D INPUT -p tcp --dport 1 -j ACCEPT\nCOMMIT\n"
	_, err := f.Run(context.Background(), firewall.One(firewall.Command{
		Argv: []string{"iptables-restore", "--noflush"}, Stdin: script}))
	if err == nil {
		t.Fatal("a batch with a failing line must fail")
	}
	if Comparable(f.State().V4) != before {
		t.Error("a failed batch must change nothing")
	}
}

func TestDialectRefusesForeignCommands(t *testing.T) {
	_, err := Dialect{}.Apply([]firewall.Change{firewall.One(firewall.Command{
		Argv: []string{"netfilter-persistent", "save"}})})
	if err == nil {
		t.Error("a persist cannot join an iptables-restore batch")
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	v4, v6 := SplitSnapshot(JoinSnapshot("*filter\nCOMMIT\n", "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"))
	if v4 != "*filter\nCOMMIT\n" || !strings.Contains(v6, ":INPUT ACCEPT") {
		t.Errorf("split = %q / %q", v4, v6)
	}
}
