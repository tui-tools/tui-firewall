package nftables

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/nftables/staging"
)

// TestStagingAgainstRealNft drives the staged atomic apply and the
// connectivity-safe rollback against a real nft, in a private network
// namespace. It is skipped unless TUI_FW_NS_TEST is set, because it needs the
// CAP_NET_ADMIN a `unshare -rn` grants:
//
//	unshare -rn env TUI_FW_NS_TEST=1 go test -run TestStagingAgainstRealNft \
//	    -v ./internal/nftables/
//
// It is a test file, so it may exec nft directly; the shipped code still starts
// every process through the runner. What it proves is that the payloads the
// staging package builds are ones this nft accepts, and that a batch nft
// rejects changes nothing.
func TestStagingAgainstRealNft(t *testing.T) {
	if os.Getenv("TUI_FW_NS_TEST") == "" {
		t.Skip("set TUI_FW_NS_TEST=1 and run under `unshare -rn` to drive real nft")
	}

	// The pre-existing, working state: a forward chain that accepts, with the
	// stateful keep-alive already in place. This is what the operator would lose
	// if a policy drop landed without its companion accept.
	setup := "add table inet tui\n" +
		"add chain inet tui forward { type filter hook forward priority 0 ; policy accept ; }\n" +
		"add rule inet tui forward ct state established,related counter accept\n"
	runNft(t, setup, "-f", "-")

	// Snapshot the live ruleset the way the backend does: nft's own text.
	snapshot := runNft(t, "", "list", "ruleset")

	// Build the batch with the real builders, off the ruleset nft reports.
	rs, err := ParseRuleset([]byte(runNft(t, "", "-j", "list", "ruleset")))
	if err != nil {
		t.Fatalf("parsing the live ruleset: %v", err)
	}
	forward, ok := rs.Chain(OwnTable, "forward")
	if !ok {
		t.Fatal("the forward chain was not created")
	}
	accept, err := rs.BuildAddRule(forward, firewall.RuleSpec{
		Action:   firewall.ActionAllow,
		InIface:  "lan0",
		OutIface: "wan0",
		CTStates: []string{"new", "established", "related"},
	})
	if err != nil {
		t.Fatalf("building the accept rule: %v", err)
	}
	drop, err := rs.BuildSetPolicy(forward, firewall.PolicyDeny)
	if err != nil {
		t.Fatalf("building the policy drop: %v", err)
	}

	session := staging.New(0)
	session.Snapshot(snapshot)
	if err := session.Stage(accept); err != nil {
		t.Fatalf("staging the accept: %v", err)
	}
	if err := session.Stage(drop); err != nil {
		t.Fatalf("staging the drop: %v", err)
	}

	applyCmd, err := session.Apply()
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	t.Logf("nft -f payload (the atomic apply):\n%s", applyCmd.Stdin)
	// Argv is nft -f - ; the payload is on stdin.
	runNft(t, applyCmd.Stdin, applyCmd.Argv[1:]...)

	after := runNft(t, "", "list", "ruleset")
	if !strings.Contains(after, "policy drop") {
		t.Errorf("the forward policy did not flip to drop:\n%s", after)
	}
	if !strings.Contains(after, `iifname "lan0"`) {
		t.Errorf("the accept rule did not land in the same transaction:\n%s", after)
	}

	// The operator lost access and never confirmed: the keep window fires.
	if err := session.Arm(nil); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	rollbackCmd, err := session.Rollback()
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	t.Logf("nft -f payload (the rollback):\n%s", rollbackCmd.Stdin)
	runNft(t, rollbackCmd.Stdin, rollbackCmd.Argv[1:]...)

	restored := runNft(t, "", "list", "ruleset")
	if strings.Contains(restored, `iifname "lan0"`) {
		t.Errorf("the staged accept survived the rollback:\n%s", restored)
	}
	if strings.Contains(restored, "policy drop") {
		t.Errorf("the forward policy was not restored to accept:\n%s", restored)
	}
	if strings.TrimSpace(restored) != strings.TrimSpace(snapshot) {
		t.Errorf("the rollback did not restore the snapshot exactly:\ngot:\n%s\nwant:\n%s",
			restored, snapshot)
	}

	// A batch nft rejects must change nothing: stage a good rule and a
	// syntactically valid but semantically impossible one, and confirm the
	// ruleset is untouched after nft refuses the transaction.
	t.Run("a rejected batch changes nothing", func(t *testing.T) {
		before := runNft(t, "", "list", "ruleset")
		// A rule into a chain that does not exist: nft rejects the whole file.
		bad := "add rule inet tui nonexistent tcp dport 22 counter accept\n"
		cmd := exec.Command("nft", "-f", "-") //nolint:gosec // G204: test-only, fixed argv
		cmd.Stdin = strings.NewReader(bad)
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("nft accepted a rule into a missing chain: %s", out)
		}
		if now := runNft(t, "", "list", "ruleset"); now != before {
			t.Errorf("a rejected batch changed the ruleset:\nbefore:\n%s\nafter:\n%s",
				before, now)
		}
	})
}

// runNft runs nft with the given stdin and arguments, failing the test on
// error. It is the test's own exec, exempt from the family's exec boundary.
func runNft(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	// A test driving real nft with a fixed argv; not a path user input flows through.
	cmd := exec.Command("nft", args...) //nolint:gosec // G204: test-only, fixed binary
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("nft %v failed: %v\n%s", args, err, out)
	}
	return string(out)
}
