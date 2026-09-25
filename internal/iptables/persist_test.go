package iptables

import (
	"strings"
	"testing"
)

func TestDriftIgnoresTheChainsDaemonsRebuild(t *testing.T) {
	// The captured host: rules.v4 was saved before tailscaled added ts-input
	// and ts-forward. The running rules differ from the file only in chains
	// tailscaled rebuilds at start, which is not drift the operator caused.
	state := ociState(t)
	drift := state.Persistence.Drift
	if !drift.Known || !drift.InSync {
		t.Fatalf("drift = %+v, want in sync", drift)
	}
	if drift.Summary() != "in sync" {
		t.Errorf("summary = %q", drift.Summary())
	}
}

func TestDriftSeesAnUnsavedRule(t *testing.T) {
	state := ociState(t)
	change, err := state.BuildAddRule(v4Input, specAllowUDP("51820"))
	if err != nil {
		t.Fatalf("BuildAddRule: %v", err)
	}
	if err := applyCommand(&state.V4, change.Commands[0].Argv[1:]); err != nil {
		t.Fatalf("applying: %v", err)
	}
	drift := ComputeDrift(state)
	if drift.InSync || len(drift.RuntimeOnly) != 1 ||
		!strings.Contains(drift.RuntimeOnly[0], "--dport 51820") {
		t.Fatalf("drift = %+v, want the new rule as runtime-only", drift)
	}
	if !strings.Contains(drift.Summary(), "1 line not saved") {
		t.Errorf("summary = %q", drift.Summary())
	}
}

func TestDriftSeesAReorder(t *testing.T) {
	// Same rules, different order: for a firewall that is a different ruleset.
	running := mustDump(t, "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A INPUT -j REJECT --reject-with icmp-host-prohibited",
		"-A INPUT -p udp -m udp --dport 51820 -j ACCEPT")
	saved := mustDump(t, "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A INPUT -p udp -m udp --dport 51820 -j ACCEPT",
		"-A INPUT -j REJECT --reject-with icmp-host-prohibited")
	state := State{V4: running, Persistence: Persistence{
		Layout: netfilterPersistentLayout, SavedV4: &saved}}
	drift := ComputeDrift(state)
	if drift.InSync || len(drift.Reordered) != 1 || !strings.Contains(drift.Reordered[0], "INPUT") {
		t.Errorf("drift = %+v, want INPUT reordered", drift)
	}
}

func TestDriftUnknownWithoutASavedFile(t *testing.T) {
	state := ociState(t)
	state.Persistence.SavedV4 = nil
	if drift := ComputeDrift(state); drift.Known {
		t.Errorf("drift = %+v, want unknown", drift)
	}
	state.Persistence = Persistence{}
	if drift := ComputeDrift(state); drift.Known || drift.Summary() != "unknown" {
		t.Errorf("no layout: drift = %+v", drift)
	}
}

func TestBuildPersistDebian(t *testing.T) {
	state := ociState(t)
	change, err := BuildPersist(state)
	if err != nil {
		t.Fatalf("BuildPersist: %v", err)
	}
	if change.String() != "netfilter-persistent save" {
		t.Errorf("persist = %s", change.String())
	}
	for _, part := range []string{"/etc/iptables/rules.v4", "restores both at boot",
		"docker and tailscaled"} {
		if !strings.Contains(change.Note, part) {
			t.Errorf("note %q should mention %q", change.Note, part)
		}
	}
}

func TestBuildPersistRHEL(t *testing.T) {
	state := ociState(t)
	state.Persistence.Layout = iptablesServicesLayout
	change, err := BuildPersist(state)
	if err != nil {
		t.Fatalf("BuildPersist: %v", err)
	}
	want := "/usr/libexec/iptables/iptables.init save\n" +
		"/usr/libexec/iptables/ip6tables.init save"
	if change.String() != want {
		t.Errorf("persist = %q", change.String())
	}
	if !strings.Contains(change.Note, "systemctl enable iptables") {
		t.Errorf("a disabled unit must be called out: %q", change.Note)
	}
}

func TestBuildPersistRefusesWithoutALayer(t *testing.T) {
	state := ociState(t)
	state.Persistence = Persistence{}
	if _, err := BuildPersist(state); err == nil || !strings.Contains(err.Error(), "iptables-persistent") {
		t.Errorf("err = %v, want the install hint", err)
	}
}

func TestPersistDiffShowsTheUnsavedRule(t *testing.T) {
	state := ociState(t)
	if err := applyCommand(&state.V4, []string{"-I", "INPUT", "9", "-p", "udp",
		"-m", "udp", "--dport", "51820", "-j", "ACCEPT"}); err != nil {
		t.Fatalf("applying: %v", err)
	}
	diff := PersistDiff(state)
	if !strings.Contains(diff, "--- /etc/iptables/rules.v4") ||
		!strings.Contains(diff, "+-A INPUT -p udp -m udp --dport 51820 -j ACCEPT") {
		t.Errorf("diff =\n%s", diff)
	}
}

// mustDump builds a v4 dump whose filter INPUT holds the given lines.
func mustDump(t *testing.T, lines ...string) Dump {
	t.Helper()
	dump, err := ParseSave(V4, "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n"+
		":OUTPUT ACCEPT [0:0]\n"+strings.Join(lines, "\n")+"\nCOMMIT\n")
	if err != nil {
		t.Fatalf("ParseSave: %v", err)
	}
	return dump
}
