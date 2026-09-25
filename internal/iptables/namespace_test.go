package iptables

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/nftables/staging"
)

// TestAgainstRealIptables drives the builders, the staged apply and the
// rollback against a real iptables, in a private network namespace. It is
// skipped unless TUI_FW_NS_TEST is set, because it needs the CAP_NET_ADMIN an
// `unshare -rn` grants:
//
//	unshare -rn env TUI_FW_NS_TEST=1 go test -run TestAgainstRealIptables \
//	    -v ./internal/iptables/
//
// It is a test file, so it may exec iptables directly; the shipped code still
// starts every process through the runner. What it proves is that the argv
// the builders produce and the restore scripts the dialect produces are ones
// this iptables accepts, with the effect the preview describes.
func TestAgainstRealIptables(t *testing.T) {
	if os.Getenv("TUI_FW_NS_TEST") == "" {
		t.Skip("set TUI_FW_NS_TEST=1 and run under `unshare -rn` to drive real iptables")
	}
	// The cloud image's INPUT: established, ssh, and the catch-all REJECT.
	setup := "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n" +
		"-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n" +
		"-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT\n" +
		"-A INPUT -j REJECT --reject-with icmp-host-prohibited\nCOMMIT\n"
	runIpt(t, setup, "iptables-restore")

	state := readRealState(t)
	add, err := state.BuildAddRule(v4Input, firewall.RuleSpec{
		Action: firewall.ActionAllow, Proto: "udp", Ports: "51820",
		Comment: "wireguard",
	})
	if err != nil {
		t.Fatalf("BuildAddRule: %v", err)
	}
	runIpt(t, "", add.Commands[0].Argv...)
	listing := runIpt(t, "", "iptables", "-S", "INPUT")
	lines := strings.Split(strings.TrimSpace(listing), "\n")
	// -P INPUT ACCEPT, established, ssh, the new rule, REJECT.
	if len(lines) != 5 || !strings.Contains(lines[3], "--dport 51820") ||
		!strings.Contains(lines[4], "REJECT") {
		t.Fatalf("the rule did not land before the REJECT:\n%s", listing)
	}

	// Stage a second allow and the delete of the first, apply them as one
	// batch, then roll the batch back from the snapshot.
	state = readRealState(t)
	group, _ := Model(state).Group(v4Input)
	var wg firewall.Rule
	for _, r := range group.Rules {
		if r.Ports == "51820" {
			wg = r
		}
	}
	del, err := state.BuildDeleteRule(v4Input, wg)
	if err != nil {
		t.Fatalf("BuildDeleteRule: %v", err)
	}
	https, err := state.BuildAddRule(v4Input, firewall.RuleSpec{
		Action: firewall.ActionAllow, Proto: "tcp", Ports: "443", CTStates: []string{"new"},
	})
	if err != nil {
		t.Fatalf("BuildAddRule: %v", err)
	}
	session := staging.NewWithDialect(0, Dialect{HasV6: true})
	for _, c := range []firewall.Change{https, del} {
		if err := session.Stage(c); err != nil {
			t.Fatalf("Stage: %v", err)
		}
	}
	snapshot := JoinSnapshot(runIpt(t, "", "iptables-save", "-t", "filter"),
		runIpt(t, "", "ip6tables-save", "-t", "filter"))
	session.Snapshot(snapshot)
	apply, err := session.ApplyChange()
	if err != nil {
		t.Fatalf("ApplyChange: %v", err)
	}
	for _, cmd := range apply.Commands {
		runIpt(t, cmd.Stdin, cmd.Argv...)
	}
	listing = runIpt(t, "", "iptables", "-S", "INPUT")
	if strings.Contains(listing, "51820") || !strings.Contains(listing, "--dport 443") {
		t.Fatalf("the batch did not apply:\n%s", listing)
	}
	if err := session.Arm(nil); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	rollback, err := session.RollbackChange()
	if err != nil {
		t.Fatalf("RollbackChange: %v", err)
	}
	for _, cmd := range rollback.Commands {
		runIpt(t, cmd.Stdin, cmd.Argv...)
	}
	listing = runIpt(t, "", "iptables", "-S", "INPUT")
	if !strings.Contains(listing, "51820") || strings.Contains(listing, "--dport 443") {
		t.Fatalf("the rollback did not restore the snapshot:\n%s", listing)
	}

	// A batch iptables rejects changes nothing.
	before := runIpt(t, "", "iptables", "-S")
	bad := "*filter\n-I INPUT 1 -p udp -m udp --dport 5353 -j ACCEPT\n" +
		"-D INPUT -p tcp -m tcp --dport 1 -j ACCEPT\nCOMMIT\n"
	cmd := exec.Command("iptables-restore", "--noflush")
	cmd.Stdin = strings.NewReader(bad)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("a failing batch must fail: %s", out)
	}
	if after := runIpt(t, "", "iptables", "-S"); after != before {
		t.Errorf("a rejected batch changed the rules:\n%s", after)
	}
}

// readRealState reads the namespace's rules the way the backend does.
func readRealState(t *testing.T) State {
	t.Helper()
	v4, err := ParseSave(V4, runIpt(t, "", "iptables-save", "-c"))
	if err != nil {
		t.Fatalf("parsing iptables-save: %v", err)
	}
	v6, err := ParseSave(V6, runIpt(t, "", "ip6tables-save", "-c"))
	if err != nil {
		t.Fatalf("parsing ip6tables-save: %v", err)
	}
	return State{V4: v4, V6: v6, HasV6: true}
}

// runIpt runs one xtables command in the namespace and fails the test on error.
func runIpt(t *testing.T, stdin string, argv ...string) string {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // test-only, fixed binaries
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(argv, " "), err, out)
	}
	return string(out)
}
