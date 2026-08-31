package main

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/nftables"
)

// selectRuleByComment moves the cursor onto the visible rule with the given
// comment, so a per-rule action acts on a known rule.
func selectRuleByComment(t *testing.T, a *app, comment string) {
	t.Helper()
	for i, rule := range a.visible {
		if rule.Comment == comment {
			a.cursor = i
			return
		}
	}
	t.Fatalf("no visible rule with comment %q", comment)
}

func TestToggleLogKeyPreviewsReplace(t *testing.T) {
	a, _ := newNftablesApp(t, 130, 30)
	// The input view is first; select the WAN ssh drop, which does not log.
	selectRuleByComment(t, a, "no ssh from the wan")
	send(t, a, "l")
	if a.mode != modeConfirm {
		t.Fatalf("l should preview a confirm, mode = %v", a.mode)
	}
	want := `replace rule inet tui input handle 14 iifname "wan0" tcp dport 22 ` +
		`log prefix "tui:input drop " counter drop`
	if !strings.Contains(a.confirm.Command, want) {
		t.Errorf("the preview is not the log toggle:\n%s", a.confirm.Command)
	}
}

func TestToggleLogKeyRefusedOnUfw(t *testing.T) {
	a, _ := newTestApp(t, 100, 30) // a ufw demo has no per-rule logging
	send(t, a, "l")
	if a.mode == modeConfirm {
		t.Fatal("ufw has no per-rule logging; l should not open a confirm")
	}
}

func TestLiveLogViewOpensAndAnimates(t *testing.T) {
	a, _ := newNftablesApp(t, 120, 30)
	send(t, a, "w")
	if a.mode != modeLog {
		t.Fatalf("w should open the live log, mode = %v", a.mode)
	}
	out := a.View()
	if !strings.Contains(out, "live log") {
		t.Errorf("the live view has no header:\n%s", out)
	}
	if !strings.Contains(out, "waiting for logged packets") {
		t.Errorf("an empty live view should say it is waiting:\n%s", out)
	}

	// Feed the view two events directly, as the stream would, so the test does
	// not wait on the demo's timer.
	a.Update(logEventMsg{ok: true, event: nftables.LogEvent{
		Direction: "in", Verdict: "drop", Src: "198.51.100.23",
		Dst: "203.0.113.9", Proto: "tcp", DPort: "22",
		Prefix: nftables.LogPrefixMarker + "input drop",
	}})
	a.Update(logEventMsg{ok: true, event: nftables.LogEvent{
		Direction: "fwd", Verdict: "accept", Src: "10.10.0.42",
		Dst: "140.82.112.3", Proto: "tcp", DPort: "443",
		Prefix: nftables.LogPrefixMarker + "forward accept",
	}})

	out = a.View()
	for _, want := range []string{"198.51.100.23", "DROP", "IN", "443", "FWD", "ACCEPT"} {
		if !strings.Contains(out, want) {
			t.Errorf("the live view is missing %q:\n%s", want, out)
		}
	}
	if a.live.total != 2 {
		t.Errorf("the view counted %d events, want 2", a.live.total)
	}

	// Pause freezes the feed; the header says so.
	send(t, a, " ")
	if !a.live.paused {
		t.Error("space should pause the feed")
	}
	if !strings.Contains(a.View(), "paused") {
		t.Error("a paused feed should say so in the header")
	}

	// Closing the view stops the stream and returns to the table.
	send(t, a, "q")
	if a.mode != modeTable {
		t.Fatalf("q should close the live log, mode = %v", a.mode)
	}
	if a.live.stream != nil {
		t.Error("closing the view should drop the stream")
	}
}

func TestLiveLogViewCapsRetainedLines(t *testing.T) {
	a, _ := newNftablesApp(t, 120, 30)
	send(t, a, "w")
	for i := 0; i < logCap+50; i++ {
		a.live.events = append(a.live.events, nftables.LogEvent{Verdict: "drop"})
	}
	// The handler trims to the cap on the next event.
	a.Update(logEventMsg{ok: true, event: nftables.LogEvent{Verdict: "drop"}})
	if len(a.live.events) > logCap {
		t.Errorf("retained %d events, cap is %d", len(a.live.events), logCap)
	}
	a.closeLogView()
}
