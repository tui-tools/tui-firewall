package nftables

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// LogEvent is one firewall-log line parsed into the fields the live view shows:
// when the packet was logged, which way it was going, what the rule did to it,
// and the addresses and ports it carried. It is what a rule's `log` statement
// produces once the kernel has written it and journald has carried it.
type LogEvent struct {
	// Time is the moment the kernel logged the packet, when the source line
	// carried a timestamp the reader could parse; otherwise it is zero and the
	// caller stamps it with the time the line arrived.
	Time time.Time `json:"time"`
	// Chain is the chain the logging rule lived in, read off the log prefix.
	Chain string `json:"chain,omitempty"`
	// Direction is "in", "out" or "fwd", derived from the chain or, failing
	// that, from which of IN=/OUT= the line carried.
	Direction string `json:"direction,omitempty"`
	// Verdict is the action the rule took, read off the log prefix ("drop",
	// "accept"); empty for a rule that only logs and falls through.
	Verdict string `json:"verdict,omitempty"`
	// Prefix is the whole log prefix the line carried, marker included.
	Prefix string `json:"prefix,omitempty"`
	// IIF and OIF are the input and output interfaces (IN=/OUT=).
	IIF string `json:"iif,omitempty"`
	OIF string `json:"oif,omitempty"`
	// Src and Dst are the addresses (SRC=/DST=).
	Src string `json:"src,omitempty"`
	Dst string `json:"dst,omitempty"`
	// Proto is the layer-4 protocol (PROTO=), lowercased.
	Proto string `json:"proto,omitempty"`
	// SPort and DPort are the source and destination ports (SPT=/DPT=).
	SPort string `json:"sport,omitempty"`
	DPort string `json:"dport,omitempty"`
	// Raw is the log message from the marker onward, kept for the detail line
	// and so nothing the columns dropped is lost.
	Raw string `json:"raw,omitempty"`
}

// DirectionForChain maps a chain name onto the traffic direction its packets
// travel, the same reading the rule views use. A chain the tool did not name
// gives an empty direction, and the parser then falls back to the interfaces.
func DirectionForChain(chain string) string {
	switch chain {
	case "input", "prerouting":
		return "in"
	case "output", "postrouting":
		return "out"
	case "forward":
		return "fwd"
	default:
		return ""
	}
}

// ParseKernelLogLine reads one kernel-log line into a LogEvent, reporting false
// for a line that is not one of this tool's own — one that does not carry the
// LogPrefixMarker. The line may be journald's short-iso rendering
// ("<iso-ts> host kernel: tui:… IN=…"), a raw /dev/kmsg body, or a bare kernel
// message; the parser keys off the marker and the KEY=VALUE fields the kernel
// log format uses, both of which are the same wherever the line came from.
func ParseKernelLogLine(line string) (LogEvent, bool) {
	line = oneLine(line)
	marker := strings.Index(line, LogPrefixMarker)
	if marker < 0 {
		return LogEvent{}, false
	}

	event := LogEvent{Time: leadingTimestamp(line)}
	message := line[marker:]
	event.Raw = message

	// After the marker come the chain, then the verdict words, then the
	// KEY=VALUE fields the kernel appended. The prefix is everything up to the
	// first KEY=VALUE.
	fields := strings.Fields(message[len(LogPrefixMarker):])
	var prefixWords []string
	rest := fields
	for i, word := range fields {
		if strings.Contains(word, "=") {
			rest = fields[i:]
			break
		}
		prefixWords = append(prefixWords, word)
		rest = nil
	}
	if len(prefixWords) > 0 {
		event.Chain = prefixWords[0]
		if len(prefixWords) > 1 {
			event.Verdict = strings.Join(prefixWords[1:], " ")
		}
	}
	event.Prefix = strings.TrimSpace(LogPrefixMarker + strings.Join(prefixWords, " "))

	for _, word := range rest {
		key, value, ok := strings.Cut(word, "=")
		if !ok {
			continue
		}
		switch key {
		case "IN":
			event.IIF = value
		case "OUT":
			event.OIF = value
		case "SRC":
			event.Src = value
		case "DST":
			event.Dst = value
		case "PROTO":
			event.Proto = strings.ToLower(value)
		case "SPT":
			event.SPort = value
		case "DPT":
			event.DPort = value
		}
	}

	event.Direction = DirectionForChain(event.Chain)
	if event.Direction == "" {
		event.Direction = directionFromInterfaces(event.IIF, event.OIF)
	}
	return event, true
}

// directionFromInterfaces is the fallback reading of a packet's direction when
// the chain did not name it: a packet with only an input interface is coming
// in, one with only an output interface is going out, one with both is being
// forwarded.
func directionFromInterfaces(in, out string) string {
	switch {
	case in != "" && out != "":
		return "fwd"
	case in != "":
		return "in"
	case out != "":
		return "out"
	default:
		return ""
	}
}

// isoLayouts are the timestamp shapes the log sources print. journald's
// short-iso is the first; the space-separated form is what a raw read can carry.
var isoLayouts = []string{
	"2006-01-02T15:04:05Z0700",
	"2006-01-02T15:04:05-0700",
	"2006-01-02 15:04:05",
}

// leadingTimestamp reads the timestamp a log line leads with, or the zero time
// when it carries none the reader knows.
func leadingTimestamp(line string) time.Time {
	token, _, ok := strings.Cut(line, " ")
	if !ok {
		return time.Time{}
	}
	for _, layout := range isoLayouts {
		if t, err := time.Parse(layout, token); err == nil {
			return t
		}
	}
	return time.Time{}
}

// LogStream is a live, read-only feed of firewall-log events. It owns the
// process (or the demo generator) behind it; Close stops that process and closes
// the channel. It is not a mutation and does not go through the preview/confirm
// contract: nothing it does changes the firewall.
type LogStream struct {
	events chan LogEvent
	source string
	cancel context.CancelFunc

	mu  sync.Mutex
	err error
}

// newLogStream builds an empty stream with a buffered channel, so a burst of
// packets does not block the reader on a UI that is mid-frame.
func newLogStream(source string) *LogStream {
	return &LogStream{events: make(chan LogEvent, 256), source: source}
}

// Events is the channel the UI ranges over. It closes when the stream ends.
func (s *LogStream) Events() <-chan LogEvent { return s.events }

// Source names where the events come from, for the live view's header.
func (s *LogStream) Source() string { return s.source }

// Close stops the stream. It is safe to call more than once.
func (s *LogStream) Close() {
	if s.cancel != nil {
		s.cancel()
	}
}

// Err returns the error the stream ended with, if any.
func (s *LogStream) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// setErr records why the stream ended.
func (s *LogStream) setErr(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

// send delivers an event unless the stream has been cancelled.
func (s *LogStream) send(ctx context.Context, event LogEvent) bool {
	select {
	case s.events <- event:
		return true
	case <-ctx.Done():
		return false
	}
}

// pumpReader scans a process's stdout line by line, forwarding the lines that
// are this tool's own, and closes the channel when the process ends.
func (s *LogStream) pumpReader(ctx context.Context, reader io.ReadCloser, wait func() error) {
	defer close(s.events)
	scanner := bufio.NewScanner(reader)
	// A kernel log line with a long MAC address and many fields is well within
	// this, and capping it keeps a pathological line from growing the buffer
	// without bound.
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for scanner.Scan() {
		event, ok := ParseKernelLogLine(scanner.Text())
		if !ok {
			continue
		}
		if event.Time.IsZero() {
			event.Time = time.Now()
		}
		if !s.send(ctx, event) {
			break
		}
	}
	_ = reader.Close()
	if err := wait(); err != nil && ctx.Err() == nil {
		s.setErr(err)
	}
}

// kernelLogArgs is the journalctl invocation the live view follows: the kernel
// log, from the tail forward, in the timestamp format the parser reads. The
// kernel-only filter is journalctl's -k, whose long form is --dmesg. There is
// no --kernel option; passing one makes journalctl exit at once, before a line
// is read, which the unit tests miss because they drive the Fake stream — so
// this stays one place a test can pin.
func kernelLogArgs() []string {
	// --lines=0 starts at the tail: the view shows packets logged from now on,
	// not a replay of the journal. short-iso is the timestamp the parser reads.
	return []string{
		"--dmesg", "--follow", "--lines=0", "--output=short-iso", "--no-pager",
	}
}

// cappedBuffer collects a process's stderr up to a fixed size and drops the
// rest, so a failing command's first diagnostic line survives without a
// misbehaving one growing the buffer without bound. It always reports a full
// write, so the process never blocks on a full stderr pipe.
type cappedBuffer struct {
	buf   []byte
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.limit - len(c.buf); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		c.buf = append(c.buf, p[:room]...)
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return string(c.buf) }

// firstStderrLine is the reason to show the operator: a process's first
// non-empty stderr line, trimmed.
func firstStderrLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// LogStream opens the live kernel-log feed, filtered to this tool's own log
// prefix. It reads journald — where the kernel `log` statement's output lands —
// with `journalctl --dmesg --follow`, escalating the same way the nft reads do
// because the kernel log needs privilege. A machine without journald is told so
// plainly rather than left with an empty screen.
func (r *Real) LogStream(ctx context.Context) (*LogStream, error) {
	path, err := exec.LookPath("journalctl")
	if err != nil {
		return nil, errorf(
			"the live firewall log reads the kernel log from journald, and " +
				"journalctl was not found on PATH; the nftables `log` statement " +
				"writes to the kernel log, which journald carries — install " +
				"systemd's journal, or read /dev/kmsg by hand")
	}
	journalArgs := kernelLogArgs()

	bin := path
	args := journalArgs
	if len(r.sudoPrefix) > 0 && os.Geteuid() != 0 {
		sudo, err := exec.LookPath(r.sudoPrefix[0])
		if err != nil {
			return nil, errorf(
				"the live firewall log reads the kernel log, which needs root, "+
					"and %q was not found; re-run as root or with a working "+
					"escalation prefix", r.sudoPrefix[0])
		}
		bin = sudo
		args = append(append([]string{}, r.sudoPrefix[1:]...),
			append([]string{path}, journalArgs...)...)
	}

	streamCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(streamCtx, bin, args...) //nolint:gosec // argv built here, never a shell string
	cmd.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, errorf("could not read journalctl's output: %v", err)
	}
	// Keep journalctl's own diagnostics. When it exits at once — an option it
	// does not know, a journal it cannot read — its first stderr line is the
	// reason, and discarding it would leave the view saying only "exit status
	// 1". Capped so a process that streams to stderr cannot grow it unbounded.
	errbuf := &cappedBuffer{limit: 4096}
	cmd.Stderr = errbuf
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, errorf("could not start journalctl: %v", err)
	}

	stream := newLogStream("journald kernel log · journalctl --dmesg --follow · " +
		LogPrefixMarker + " prefix")
	stream.cancel = cancel
	wait := func() error {
		werr := cmd.Wait()
		if werr != nil {
			if line := firstStderrLine(errbuf.String()); line != "" {
				return errorf("%s (%v)", line, werr)
			}
		}
		return werr
	}
	go stream.pumpReader(streamCtx, stdout, wait)
	return stream, nil
}

// LoggedRules counts the rules in the ruleset that log: total across every
// chain, and how many of those live in a chain this backend may write to, which
// is the number the live view and the lab acceptance actually care about — a
// logged rule the tool does not own is one it cannot have marked.
func (r Ruleset) LoggedRules() (owned, total int) {
	for _, table := range r.Tables {
		for _, chain := range table.Chains {
			mutable := r.checkMutable(chain) == nil
			for _, rule := range chain.Rules {
				if !rule.Match.Log {
					continue
				}
				total++
				if mutable {
					owned++
				}
			}
		}
	}
	return owned, total
}

// LogSourceProbe reports whether the live-log source can be read, for --check
// and --report. It is a fact about the machine — is journald here — rather than
// a stream: opening the follow would need root, which a report path may not
// have, so presence on PATH is what it answers.
func LogSourceProbe() (readable bool, source, detail string) {
	source = "journald kernel log (journalctl --dmesg)"
	if _, err := exec.LookPath("journalctl"); err != nil {
		return false, source, "journalctl not found on PATH: the live view " +
			"needs journald, which carries the kernel log the `log` statement writes"
	}
	return true, source, "journalctl present; reading the kernel log still needs " +
		"root or membership of the systemd-journal group"
}

// demoLogScript is the loop the --demo live view animates from: a couple of
// drops from one address probing SSH, an accepted forward, and an outbound
// reject — enough that the screen moves with nothing installed and no root.
var demoLogScript = []LogEvent{
	{Chain: "input", Verdict: "drop", Direction: "in", IIF: "wan0",
		Src: "198.51.100.23", Dst: "203.0.113.9", Proto: "tcp", SPort: "44210", DPort: "22",
		Prefix: LogPrefixMarker + "input drop"},
	{Chain: "input", Verdict: "drop", Direction: "in", IIF: "wan0",
		Src: "198.51.100.23", Dst: "203.0.113.9", Proto: "tcp", SPort: "44211", DPort: "23",
		Prefix: LogPrefixMarker + "input drop"},
	{Chain: "forward", Verdict: "accept", Direction: "fwd", IIF: "lan0", OIF: "wan0",
		Src: "10.10.0.42", Dst: "140.82.112.3", Proto: "tcp", SPort: "51002", DPort: "443",
		Prefix: LogPrefixMarker + "forward accept"},
	{Chain: "input", Verdict: "drop", Direction: "in", IIF: "wan0",
		Src: "203.0.113.77", Dst: "203.0.113.9", Proto: "udp", SPort: "6000", DPort: "1900",
		Prefix: LogPrefixMarker + "input drop"},
	{Chain: "output", Verdict: "reject", Direction: "out", OIF: "wan0",
		Src: "203.0.113.9", Dst: "192.0.2.25", Proto: "tcp", SPort: "39004", DPort: "25",
		Prefix: LogPrefixMarker + "output reject"},
}

// LogStream returns a synthetic live feed for --demo: it plays the demo script
// on a timer, so the live view animates with no journald, no root and nothing
// installed. It never reads the machine.
func (f *Fake) LogStream(ctx context.Context) (*LogStream, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	stream := newLogStream("demo firewall log (synthetic, nothing on this machine is read)")
	stream.cancel = cancel
	go func() {
		defer close(stream.events)
		ticker := time.NewTicker(900 * time.Millisecond)
		defer ticker.Stop()
		i := 0
		for {
			select {
			case <-streamCtx.Done():
				return
			case <-ticker.C:
				event := demoLogScript[i%len(demoLogScript)]
				event.Time = time.Now()
				event.Raw = event.Prefix + " IN=" + event.IIF + " OUT=" + event.OIF +
					" SRC=" + event.Src + " DST=" + event.Dst +
					" PROTO=" + strings.ToUpper(event.Proto) +
					" SPT=" + event.SPort + " DPT=" + event.DPort
				if !stream.send(streamCtx, event) {
					return
				}
				i++
			}
		}
	}()
	return stream, nil
}
