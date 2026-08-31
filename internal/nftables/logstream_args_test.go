package nftables

import (
	"slices"
	"testing"
)

// TestKernelLogArgsUsesValidJournalctlFlag pins the one detail a unit test can
// reach of an invocation the tests otherwise never run: they drive the Fake
// stream, so the real journalctl argv is exercised only on a machine. The
// kernel-only filter is -k / --dmesg; --kernel is not a journalctl option and
// made the live view exit 1 before a line was read.
func TestKernelLogArgsUsesValidJournalctlFlag(t *testing.T) {
	args := kernelLogArgs()
	if slices.Contains(args, "--kernel") {
		t.Fatalf("kernelLogArgs uses --kernel, which journalctl does not accept: %v", args)
	}
	if !slices.Contains(args, "--dmesg") {
		t.Errorf("kernelLogArgs should filter to kernel messages with --dmesg: %v", args)
	}
	for _, want := range []string{"--follow", "--lines=0"} {
		if !slices.Contains(args, want) {
			t.Errorf("kernelLogArgs missing %s: %v", want, args)
		}
	}
}

func TestFirstStderrLine(t *testing.T) {
	got := firstStderrLine("journalctl: unrecognized option '--kernel'\nmore\n")
	want := "journalctl: unrecognized option '--kernel'"
	if got != want {
		t.Errorf("firstStderrLine = %q, want %q", got, want)
	}
	if firstStderrLine("   \n  ") != "" {
		t.Errorf("blank stderr should yield the empty string")
	}
}

func TestCappedBufferStopsAtLimit(t *testing.T) {
	c := &cappedBuffer{limit: 8}
	n, err := c.Write([]byte("hello "))
	if err != nil || n != 6 {
		t.Fatalf("first write: n=%d err=%v", n, err)
	}
	// The writer always reports a full write, so the process never blocks, but
	// only what fits under the limit is retained.
	n, err = c.Write([]byte("world and more"))
	if err != nil || n != 14 {
		t.Fatalf("second write: n=%d err=%v", n, err)
	}
	if got := c.String(); got != "hello wo" {
		t.Errorf("cappedBuffer kept %q, want %q", got, "hello wo")
	}
}
