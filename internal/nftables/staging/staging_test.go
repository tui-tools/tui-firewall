package staging

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// change is a one-command firewall.Change built from an argv, for tests that
// stage without pulling in the whole nftables backend (which would be a cycle).
func change(argv ...string) firewall.Change {
	return firewall.One(firewall.Command{Argv: argv, Description: strings.Join(argv, " ")})
}

// manualTimer is a countdown a test fires by hand, so the rollback path runs
// without waiting a real timeout.
type manualTimer struct {
	mu      sync.Mutex
	fn      func()
	stopped bool
}

func (m *manualTimer) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopped = true
}

// fire runs the callback unless the timer was already stopped, the way a real
// AfterFunc that has been Stop'd in time would not fire.
func (m *manualTimer) fire() {
	m.mu.Lock()
	stopped := m.stopped
	fn := m.fn
	m.mu.Unlock()
	if !stopped && fn != nil {
		fn()
	}
}

func TestApplyRendersOneAtomicTransaction(t *testing.T) {
	s := New(0)
	if got := s.Timeout(); got != DefaultTimeout {
		t.Fatalf("timeout = %s, want the default %s", got, DefaultTimeout)
	}
	changes := []firewall.Change{
		change("nft", "chain", "inet", "tui", "forward", "{", "policy", "drop", ";", "}"),
		change("nft", "add", "rule", "inet", "tui", "forward", "ct", "state",
			"established,related", "counter", "accept"),
	}
	for _, c := range changes {
		if err := s.Stage(c); err != nil {
			t.Fatalf("Stage: %v", err)
		}
	}
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}

	cmd, err := s.Apply()
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if strings.Join(cmd.Argv, " ") != "nft -f -" {
		t.Errorf("apply argv = %q, want `nft -f -`", cmd.Argv)
	}
	if !cmd.Destructive {
		t.Error("an atomic apply is destructive")
	}
	// The payload is the two changes as an nft script, in order, with the
	// leading "nft" dropped: one transaction nft reads all-or-nothing.
	wantStdin := "chain inet tui forward { policy drop ; }\n" +
		"add rule inet tui forward ct state established,related counter accept\n"
	if cmd.Stdin != wantStdin {
		t.Errorf("apply stdin =\n%q\nwant\n%q", cmd.Stdin, wantStdin)
	}
	// The dialog shows the payload, because a command line never carries stdin.
	if s.PreviewApply() != strings.TrimRight(wantStdin, "\n") {
		t.Errorf("PreviewApply =\n%q", s.PreviewApply())
	}
	// Apply does not itself change the phase; the caller arms after the run.
	if s.Phase() != Building {
		t.Errorf("phase = %d after Apply, want Building", s.Phase())
	}
}

func TestRollbackReplaysTheSnapshot(t *testing.T) {
	s := New(time.Minute)
	if err := s.Stage(change("nft", "add", "rule", "inet", "tui", "input",
		"tcp", "dport", "22", "counter", "accept")); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	snapshot := "table inet tui {\n\tchain input {\n\t\ttype filter hook input " +
		"priority 0; policy drop;\n\t}\n}"
	s.Snapshot(snapshot)
	if _, err := s.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := s.Arm(nil); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if !s.Awaiting() {
		t.Fatal("the session should be awaiting confirmation after Arm")
	}

	cmd, err := s.Rollback()
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if strings.Join(cmd.Argv, " ") != "nft -f -" {
		t.Errorf("rollback argv = %q", cmd.Argv)
	}
	// The restore flushes the whole ruleset first, then replays the snapshot,
	// so the machine ends exactly where it was, atomically.
	if !strings.HasPrefix(cmd.Stdin, "flush ruleset\n") {
		t.Errorf("rollback stdin does not start by flushing: %q", cmd.Stdin)
	}
	if !strings.Contains(cmd.Stdin, snapshot) {
		t.Error("rollback stdin does not carry the snapshot")
	}
	// Rollback resets the session.
	if s.Phase() != Building || s.Len() != 0 || s.SnapshotText() != "" {
		t.Error("Rollback should return the session to an empty Building state")
	}
}

func TestTimerRollsBackWhenKeepIsNeverGiven(t *testing.T) {
	// The connectivity-safe case: the operator lost access, never confirmed, and
	// the countdown fired. What must happen is the rollback callback runs.
	s := New(10 * time.Millisecond)
	var timer *manualTimer
	s.SetTimer(func(_ time.Duration, f func()) Timer {
		timer = &manualTimer{fn: f}
		return timer
	})

	if err := s.Stage(change("nft", "chain", "inet", "tui", "forward",
		"{", "policy", "drop", ";", "}")); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	s.Snapshot("table inet tui { }")
	if _, err := s.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	var rolledBack firewall.Command
	fired := false
	if err := s.Arm(func() {
		fired = true
		cmd, err := s.Rollback()
		if err != nil {
			t.Errorf("Rollback from the timer: %v", err)
		}
		rolledBack = cmd
	}); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if timer == nil {
		t.Fatal("Arm did not start a timer")
	}

	timer.fire()
	if !fired {
		t.Fatal("the keep-confirmation timeout did not roll back")
	}
	if !strings.HasPrefix(rolledBack.Stdin, "flush ruleset\n") {
		t.Errorf("the auto-rollback did not restore the snapshot: %q", rolledBack.Stdin)
	}
	if s.Phase() != Building {
		t.Error("after an auto-rollback the session is back to Building")
	}
}

func TestCommitStopsTheTimer(t *testing.T) {
	// The operator confirmed in time: the countdown must be stopped, and a late
	// fire must do nothing.
	s := New(time.Minute)
	var timer *manualTimer
	s.SetTimer(func(_ time.Duration, f func()) Timer {
		timer = &manualTimer{fn: f}
		return timer
	})
	if err := s.Stage(change("nft", "add", "rule", "inet", "tui", "input",
		"tcp", "dport", "22", "counter", "accept")); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	s.Snapshot("table inet tui { }")
	if _, err := s.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	expired := false
	if err := s.Arm(func() { expired = true }); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if !timer.stopped {
		t.Error("Commit should have stopped the countdown")
	}
	// A timer that fires after a commit must be a no-op: the phase check inside
	// fire is what guards a rollback of changes the operator already kept.
	timer.fire()
	if expired {
		t.Error("a fire after Commit rolled back a committed batch")
	}
	if s.Phase() != Building || s.Len() != 0 {
		t.Error("Commit should return the session to an empty Building state")
	}
}

func TestLifecycleRefusals(t *testing.T) {
	cases := []struct {
		name string
		run  func(*Session) error
		want string
	}{
		{"apply with nothing staged", func(s *Session) error {
			_, err := s.Apply()
			return err
		}, "nothing is staged"},
		{"an empty change is not staged", func(s *Session) error {
			return s.Stage(firewall.Change{})
		}, "nothing to apply"},
		{"rollback with nothing applied", func(s *Session) error {
			_, err := s.Rollback()
			return err
		}, "nothing was applied"},
		{"commit with nothing applied", func(s *Session) error {
			return s.Commit()
		}, "nothing is awaiting"},
		{"drop out of range", func(s *Session) error {
			return s.Drop(4)
		}, "no staged change"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(New(0)); err == nil ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestStagingRefusesWhileAwaiting(t *testing.T) {
	// Once a batch is applied and awaiting confirmation, the pending set is the
	// record of what has to be committed or rolled back; it cannot be edited.
	s := New(time.Minute)
	if err := s.Stage(change("nft", "add", "rule", "inet", "tui", "input",
		"tcp", "dport", "22", "counter", "accept")); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	s.Snapshot("table inet tui { }")
	if _, err := s.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := s.Arm(nil); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if err := s.Stage(change("nft", "add", "rule", "inet", "tui", "input",
		"udp", "dport", "53", "counter", "accept")); err == nil {
		t.Error("staging more while awaiting confirmation should be refused")
	}
	if err := s.Clear(); err == nil {
		t.Error("clearing an applied batch should be refused")
	}
	if err := s.Drop(0); err == nil {
		t.Error("dropping from an applied batch should be refused")
	}
}

func TestDropAndClear(t *testing.T) {
	s := New(0)
	for _, port := range []string{"22", "80", "443"} {
		if err := s.Stage(change("nft", "add", "rule", "inet", "tui", "input",
			"tcp", "dport", port, "counter", "accept")); err != nil {
			t.Fatalf("Stage: %v", err)
		}
	}
	if err := s.Drop(1); err != nil {
		t.Fatalf("Drop: %v", err)
	}
	pending := s.Pending()
	if len(pending) != 2 {
		t.Fatalf("Len = %d after Drop, want 2", len(pending))
	}
	if !strings.Contains(pending[1].Commands[0].String(), "443") {
		t.Errorf("Drop removed the wrong change: %v", pending[1])
	}
	// Pending returns a copy: mutating it must not touch the session.
	pending[0] = firewall.Change{}
	if s.Pending()[0].Empty() {
		t.Error("Pending returned the backing slice, not a copy")
	}
	if err := s.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if s.Len() != 0 {
		t.Error("Clear should empty the pending set")
	}
}
