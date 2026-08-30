// Package staging is the connectivity-safe apply for the nftables backend.
//
// Applying a router's rules one at a time can cut the operator off: a forward
// policy set to drop before the accept rule that keeps a session alive, a
// policy flipped before the rule that keeps SSH up. The whole point of staging
// is to make a set of changes one transaction — reviewed as a whole, applied
// all-or-nothing, and undone on its own if the operator does not confirm they
// still have access.
//
// The package holds no exec of its own on purpose: the exec boundary keeps
// every process start inside internal/nftables, so a Session builds the two
// runner.Commands the flow needs — the `nft -f` batch and the rollback — and
// the backend runs them. That is also what makes the flow testable without a
// terminal: a test stages changes, reads the exact payload, drives the timer by
// hand and asserts on what would have run.
package staging

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// DefaultTimeout is how long the applied batch waits for the operator to
// confirm they still have access before it rolls the ruleset back on its own.
// It mirrors the "apply, then keep or revert" of an OPNsense apply.
const DefaultTimeout = 60 * time.Second

// Phase is where a Session is in its lifecycle.
type Phase int

const (
	// Building: changes are being staged and reviewed; nothing has been
	// applied, and dropping a staged change or clearing the set is free.
	Building Phase = iota
	// Awaiting: the batch was applied and the Session is waiting for the
	// operator to confirm (Commit) they still have access before the timer
	// rolls it back (Rollback).
	Awaiting
)

// Timer is the part of a countdown a Session drives. A test swaps the real one
// for a timer it fires by hand, which is how the rollback path is exercised
// without waiting a real minute.
type Timer interface {
	// Stop cancels the countdown. It is safe to call more than once.
	Stop()
}

// NewTimer starts a countdown that calls f after d unless it is stopped first.
type NewTimer func(d time.Duration, f func()) Timer

// realTimer wraps time.Timer to satisfy Timer.
type realTimer struct{ t *time.Timer }

func (r realTimer) Stop() { r.t.Stop() }

// RealTimer is the production countdown: time.AfterFunc.
func RealTimer(d time.Duration, f func()) Timer {
	return realTimer{t: time.AfterFunc(d, f)}
}

// Session is a set of staged changes and the commit/rollback lifecycle around
// applying them as one transaction. The zero value is not usable; call New.
type Session struct {
	mu       sync.Mutex
	timeout  time.Duration
	newTimer NewTimer

	pending  []firewall.Change
	snapshot string
	phase    Phase
	timer    Timer
	onExpire func()
}

// New returns a Session with the given keep-confirmation timeout, or
// DefaultTimeout when it is zero or negative. It uses the real countdown; a
// test overrides it with SetTimer.
func New(timeout time.Duration) *Session {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Session{timeout: timeout, newTimer: RealTimer}
}

// SetTimer replaces the countdown factory, so a test can drive the timeout by
// hand. It must be called before Arm.
func (s *Session) SetTimer(f NewTimer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.newTimer = f
}

// Timeout is the keep-confirmation timeout in force.
func (s *Session) Timeout() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.timeout
}

// Stage adds a change to the pending set. A change with no commands is ignored:
// there is nothing to apply and nothing for the review to show.
func (s *Session) Stage(change firewall.Change) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != Building {
		return errors.New("staging: a batch is awaiting confirmation; " +
			"commit or roll it back before staging more")
	}
	if change.Empty() {
		return errors.New("staging: that change has nothing to apply")
	}
	s.pending = append(s.pending, change)
	return nil
}

// Pending returns a copy of the staged changes, in the order they were staged.
func (s *Session) Pending() []firewall.Change {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]firewall.Change, len(s.pending))
	copy(out, s.pending)
	return out
}

// Len is how many changes are staged.
func (s *Session) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// Phase reports where the Session is in its lifecycle.
func (s *Session) Phase() Phase {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.phase
}

// Awaiting reports whether an applied batch is waiting for confirmation.
func (s *Session) Awaiting() bool { return s.Phase() == Awaiting }

// Drop removes the staged change at index i.
func (s *Session) Drop(i int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != Building {
		return errors.New("staging: the batch is applied; there is nothing to drop")
	}
	if i < 0 || i >= len(s.pending) {
		return fmt.Errorf("staging: there is no staged change %d", i+1)
	}
	s.pending = append(s.pending[:i], s.pending[i+1:]...)
	return nil
}

// Clear discards every staged change. It refuses once a batch is applied,
// because the pending set is then the record of what has to be committed or
// rolled back.
func (s *Session) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != Building {
		return errors.New("staging: the batch is applied; commit or roll it back")
	}
	s.pending = nil
	return nil
}

// Snapshot records the ruleset captured before the batch is applied. It is the
// bytes `nft list ruleset` printed, which is exactly what the rollback replays.
func (s *Session) Snapshot(ruleset string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot = ruleset
}

// SnapshotText returns the recorded snapshot.
func (s *Session) SnapshotText() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot
}

// Apply renders the whole staged set as one `nft -f` transaction: a single
// command whose standard input is every staged change, in order, as an nft
// script. nft reads the file as one atomic transaction — if any line is
// rejected, none of it is applied — which is the all-or-nothing the flow needs.
//
// It does not run anything and it does not change the phase: the caller runs
// the returned command, and calls Arm once it succeeds.
func (s *Session) Apply() (firewall.Command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != Building {
		return firewall.Command{}, errors.New(
			"staging: a batch is already awaiting confirmation")
	}
	if len(s.pending) == 0 {
		return firewall.Command{}, errors.New("staging: nothing is staged to apply")
	}
	return firewall.Command{
		Argv:        []string{"nft", "-f", "-"},
		Description: fmt.Sprintf("Apply %s atomically", plural(len(s.pending), "staged change")),
		Destructive: true,
		Stdin:       batchScript(s.pending),
	}, nil
}

// PreviewApply renders the transaction the way the confirm dialog shows it: one
// nft script line per command, the same bytes Apply puts on nft's standard
// input. Stdin never appears in a command-line preview — a payload is not a
// command line — so the dialog shows this instead.
func (s *Session) PreviewApply() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.TrimRight(batchScript(s.pending), "\n")
}

// Arm records that the batch was applied and starts the keep-confirmation
// countdown. If the operator does not Commit before it fires, onExpire is
// called — the caller's cue to run the rollback command. A nil onExpire arms no
// timer: the caller drives the timeout itself (a TUI ticks its own clock) and
// still gets the Awaiting phase and the Rollback path.
func (s *Session) Arm(onExpire func()) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == Awaiting {
		return errors.New("staging: a batch is already awaiting confirmation")
	}
	if len(s.pending) == 0 {
		return errors.New("staging: nothing was applied to await")
	}
	s.phase = Awaiting
	s.onExpire = onExpire
	if onExpire != nil && s.newTimer != nil {
		s.timer = s.newTimer(s.timeout, s.fire)
	}
	return nil
}

// fire is the timer's callback: it rolls the phase forward to expired only if
// nothing committed in the meantime, then calls onExpire outside the lock.
func (s *Session) fire() {
	s.mu.Lock()
	if s.phase != Awaiting {
		s.mu.Unlock()
		return
	}
	cb := s.onExpire
	s.mu.Unlock()
	if cb != nil {
		cb()
	}
}

// Commit confirms the operator still has access: it stops the countdown, clears
// the applied batch, and returns to Building. The changes stay in the ruleset.
func (s *Session) Commit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != Awaiting {
		return errors.New("staging: nothing is awaiting confirmation")
	}
	s.reset()
	return nil
}

// Rollback builds the command that restores the pre-apply snapshot and resets
// the Session. The restore is itself one `nft -f` transaction: it flushes the
// whole ruleset and replays the snapshot, so the machine ends exactly where it
// was before the batch, in one atomic step.
func (s *Session) Rollback() (firewall.Command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != Awaiting {
		return firewall.Command{}, errors.New("staging: nothing was applied to roll back")
	}
	cmd := restoreCommand(s.snapshot)
	s.reset()
	return cmd, nil
}

// PreviewRollback renders the rollback transaction the way the dialog shows it.
func (s *Session) PreviewRollback() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return restoreCommand(s.snapshot).Stdin
}

// reset stops the timer and returns the Session to an empty Building state. The
// caller holds the lock.
func (s *Session) reset() {
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = nil
	s.onExpire = nil
	s.pending = nil
	s.snapshot = ""
	s.phase = Building
}

// restoreCommand builds the `nft -f` transaction that replays a snapshot. The
// leading `flush ruleset` is what makes it a restore rather than a merge: the
// ruleset is emptied and rebuilt from the captured bytes in one step.
func restoreCommand(snapshot string) firewall.Command {
	payload := "flush ruleset\n"
	if trimmed := strings.TrimRight(snapshot, "\n"); trimmed != "" {
		payload += trimmed + "\n"
	}
	return firewall.Command{
		Argv:        []string{"nft", "-f", "-"},
		Description: "Restore the ruleset snapshot taken before the staged apply",
		Destructive: true,
		Stdin:       payload,
	}
}

// batchScript renders the staged changes as an nft script: one line per
// command, the leading "nft" dropped because a script carries statements, not
// invocations. The quoting the builders put in — around a comment, an interface
// name — is nft's own grammar and reads the same in a script as on the command
// line, which is why the same Command value serves both.
func batchScript(changes []firewall.Change) string {
	var b strings.Builder
	for _, change := range changes {
		for _, cmd := range change.Commands {
			b.WriteString(scriptLine(cmd.Argv))
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// scriptLine renders one command as an nft script statement.
func scriptLine(argv []string) string {
	if len(argv) > 0 && argv[0] == "nft" {
		argv = argv[1:]
	}
	return strings.Join(argv, " ")
}

// plural renders a count with its noun.
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
