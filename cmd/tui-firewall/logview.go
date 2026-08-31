package main

import (
	"context"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/nftables"
	"github.com/tui-tools/tui-kit/ui"
)

// logCap bounds how many events the live view retains. A firewall under a scan
// logs faster than anyone reads, so the buffer is a ring: the newest logCap
// events, and the older ones are gone. Unbounded retention would be a memory
// leak dressed up as a feature.
const logCap = 2000

// logToggler is the part of the nftables backend the per-rule log key needs
// beyond the generic firewall.Backend: turning a rule's own logging on or off.
// Only the nftables backend and its demo implement it, which is what gates the
// key — ufw and firewalld log by level, not by rule.
type logToggler interface {
	BuildToggleLog(group string, rule firewall.Rule) (firewall.Change, error)
}

// logStreamer is the part of the nftables backend the live view needs: a
// read-only feed of firewall-log events. The real backend reads journald; the
// demo plays a synthetic script. ufw and firewalld implement neither.
type logStreamer interface {
	LogStream(ctx context.Context) (*nftables.LogStream, error)
}

// liveLog is the state of the live firewall-log view: the open stream, the
// events retained, and where in them the view is looking.
type liveLog struct {
	stream *nftables.LogStream
	events []nftables.LogEvent
	// total counts every event seen, the dropped ones included, so the header
	// can say more arrived than the ring kept.
	total int
	// paused freezes the view on the events already shown; the stream keeps
	// draining behind it so the producer never blocks.
	paused bool
	// anchor is the index one past the last event shown. While the view follows
	// the tail it tracks len(events); pausing pins it so new events pile up out
	// of sight until the view resumes.
	anchor int
}

// logEventMsg carries one event off the stream, or its close (ok == false).
type logEventMsg struct {
	event nftables.LogEvent
	ok    bool
}

// waitLog reads the next event from a stream. Reading a closed channel returns
// at once with ok false, which is how the view learns the stream ended.
func waitLog(stream *nftables.LogStream) tea.Cmd {
	events := stream.Events()
	return func() tea.Msg {
		event, ok := <-events
		return logEventMsg{event: event, ok: ok}
	}
}

// confirmToggleLog previews turning the selected rule's logging on or off.
func (a *app) confirmToggleLog() tea.Cmd {
	toggler, ok := a.backend.(logToggler)
	if !ok {
		a.setStatus(ui.StatusWarn,
			"per-rule logging is an nftables feature; this backend logs by "+
				"level, which L changes")
		return nil
	}
	if a.currentView() != firewall.ViewRules {
		a.setStatus(ui.StatusWarn,
			"logging is a statement on a filter rule; switch to a chain view "+
				"with [ ] or v, then pick the rule to log")
		return nil
	}
	rule, ok := a.selectedRule()
	if !ok {
		a.setStatus(ui.StatusWarn, "no rule selected")
		return nil
	}
	change, err := toggler.BuildToggleLog(a.group, rule)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	body := "Rule: " + describeRule(rule) + "\n" +
		"nft replaces the rule in place, keeping its handle and position; its " +
		"counter restarts at zero. Logged packets appear in the live view (w)."
	a.stageOrConfirm(change.Description, body, change)
	return nil
}

// openLogView starts the live firewall-log stream and switches to its screen.
func (a *app) openLogView() tea.Cmd {
	streamer, ok := a.backend.(logStreamer)
	if !ok {
		a.setStatus(ui.StatusWarn,
			"the live firewall log is an nftables feature: it streams the "+
				"kernel log the `log` statement writes")
		return nil
	}
	stream, err := streamer.LogStream(context.Background())
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.live = liveLog{stream: stream}
	a.mode = modeLog
	a.setStatusf(ui.StatusInfo, "live firewall log — %s", stream.Source())
	return waitLog(stream)
}

// closeLogView stops the stream and returns to the table.
func (a *app) closeLogView() {
	if a.live.stream != nil {
		a.live.stream.Close()
	}
	a.live = liveLog{}
	a.mode = modeTable
}

// handleLogEvent folds one streamed event into the buffer and asks for the
// next, or reports the stream ending.
func (a *app) handleLogEvent(msg logEventMsg) tea.Cmd {
	if a.live.stream == nil {
		// The view was closed while an event was in flight: drop it.
		return nil
	}
	if !msg.ok {
		if err := a.live.stream.Err(); err != nil {
			a.setStatusf(ui.StatusError, "the live log ended: %s", firstLine(err.Error()))
		} else {
			a.setStatus(ui.StatusInfo, "the live log ended")
		}
		a.live.stream = nil
		return nil
	}
	a.live.total++
	following := !a.live.paused && a.live.anchor >= len(a.live.events)
	a.live.events = append(a.live.events, msg.event)
	if len(a.live.events) > logCap {
		a.live.events = a.live.events[len(a.live.events)-logCap:]
	}
	if following {
		a.live.anchor = len(a.live.events)
	} else if a.live.anchor > len(a.live.events) {
		a.live.anchor = len(a.live.events)
	}
	return waitLog(a.live.stream)
}

// handleLogKey handles the live-log screen.
func (a *app) handleLogKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	height := a.tableHeight()
	switch msg.String() {
	case "q", "esc", "w":
		a.closeLogView()
		a.setStatus(ui.StatusInfo, "closed the live log")
		return a, nil
	case " ", "p":
		a.live.paused = !a.live.paused
		if a.live.paused {
			a.live.anchor = len(a.live.events)
		} else {
			a.live.anchor = len(a.live.events)
		}
		return a, nil
	case "c":
		a.live.events = nil
		a.live.anchor = 0
		return a, nil
	case "j", "down":
		a.live.paused = true
		a.live.anchor = min(a.live.anchor+1, len(a.live.events))
		return a, nil
	case "k", "up":
		a.live.paused = true
		a.live.anchor = max(a.live.anchor-1, min(height, len(a.live.events)))
		return a, nil
	case "g", "home":
		a.live.paused = true
		a.live.anchor = min(height, len(a.live.events))
		return a, nil
	case "G", "end":
		a.live.paused = false
		a.live.anchor = len(a.live.events)
		return a, nil
	}
	return a, nil
}

// visibleEvents returns the window of events the view shows, newest last.
func (l liveLog) visibleEvents(height int) []nftables.LogEvent {
	end := l.anchor
	if !l.paused || end > len(l.events) {
		end = len(l.events)
	}
	start := max(end-height, 0)
	return l.events[start:end]
}

// logView renders the live firewall-log screen: a header, a scrolling table of
// events with the newest at the bottom, a help bar and the status line.
func (a *app) logView() string {
	height := a.tableHeight()
	events := a.live.visibleEvents(height)

	columns := []ui.Column{
		{Title: "TIME", Width: 8},
		{Title: "DIR", Width: 4},
		{Title: "ACTION", Width: 7},
	}
	showProto := a.width >= 68
	showPrefix := a.width >= 104
	if showProto {
		columns = append(columns, ui.Column{Title: "PROTO", Width: 5})
	}
	columns = append(columns,
		ui.Column{Title: "SOURCE", Width: 16, Flex: true},
		ui.Column{Title: "DESTINATION", Width: 16, Flex: true},
		ui.Column{Title: "PORT", Width: 7})
	if showPrefix {
		columns = append(columns, ui.Column{Title: "PREFIX", Width: 18, Flex: true})
	}

	rows := make([][]string, 0, len(events))
	styles := make([]*lipgloss.Style, 0, len(events))
	for _, event := range events {
		row := []string{
			event.Time.Format("15:04:05"),
			orDash(strings.ToUpper(event.Direction)),
			orDash(strings.ToUpper(event.Verdict)),
		}
		if showProto {
			row = append(row, orDash(strings.ToUpper(event.Proto)))
		}
		row = append(row, orDash(event.Src), orDash(event.Dst), orDash(logPort(event)))
		if showPrefix {
			row = append(row, event.Prefix)
		}
		rows = append(rows, row)
		styles = append(styles, a.actionStyle(verdictAction(event.Verdict)))
	}

	table := ui.Table{
		Columns:  columns,
		Rows:     rows,
		Styles:   styles,
		Selected: -1,
		Offset:   0,
		Height:   height,
	}.Render(a.theme, a.width)

	if len(events) == 0 {
		table = ui.EmptyState(a.theme,
			"waiting for logged packets — mark a rule with l, then generate traffic",
			a.width, height+1)
	}

	header := a.logHeaderView()
	help := ui.HelpBar(a.theme, a.logHelpKeys(), a.width)
	status := ui.StatusLine(a.theme, a.statusKind, a.status, a.logDefaultStatus(), a.width)
	return strings.Join([]string{header, table, help, status}, "\n")
}

// logHeaderView renders the live view's header: where the feed comes from, how
// many events it has seen, and whether it is paused.
func (a *app) logHeaderView() string {
	t := a.theme
	facts := []ui.Fact{}
	if a.live.paused {
		style := t.Warn
		facts = append(facts, ui.Fact{Label: "feed", Value: "paused", Style: &style})
	} else {
		style := t.OK
		facts = append(facts, ui.Fact{Label: "feed", Value: "live", Style: &style})
	}
	facts = append(facts, ui.Fact{Label: "events", Value: strconv.Itoa(a.live.total)})
	if a.live.stream != nil {
		facts = append(facts, ui.Fact{Label: "prefix", Value: nftables.LogPrefixMarker})
	}
	subtitle := "the kernel firewall log, filtered to this tool's rules"
	if a.live.stream != nil {
		subtitle = a.live.stream.Source()
	}
	return ui.Header{Title: "tui-firewall — live log", Subtitle: subtitle, Facts: facts}.
		Render(t, a.width)
}

// logDefaultStatus is the hint the live view's status line falls back to.
func (a *app) logDefaultStatus() string {
	if a.live.paused {
		return "paused — space resumes, G jumps to newest  ·  q closes"
	}
	return "following the newest — space pauses, j/k scrolls  ·  q closes"
}

// logHelpKeys is the live view's help bar.
func (a *app) logHelpKeys() []ui.KeyHint {
	return []ui.KeyHint{
		{Key: "space", Desc: "pause/resume"},
		{Key: "j/k", Desc: "scroll"},
		{Key: "g/G", Desc: "oldest/newest"},
		{Key: "c", Desc: "clear"},
		{Key: "q", Desc: "close"},
	}
}

// logPort renders the port column of a log row: the destination port, with the
// source port when that is all there is.
func logPort(event nftables.LogEvent) string {
	switch {
	case event.DPort != "" && event.SPort != "":
		return event.SPort + "→" + event.DPort
	case event.DPort != "":
		return event.DPort
	case event.SPort != "":
		return "from " + event.SPort
	default:
		return ""
	}
}

// verdictAction maps a logged verdict onto the family's action vocabulary, so
// the live rows colour the way the rule rows do.
func verdictAction(verdict string) firewall.Action {
	switch verdict {
	case "accept":
		return firewall.ActionAllow
	case "drop":
		return firewall.ActionDeny
	case "reject":
		return firewall.ActionReject
	default:
		return firewall.Action(strings.ToUpper(verdict))
	}
}
