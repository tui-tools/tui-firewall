package nftables

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The kernel log lines below are the documented output of the netfilter log
// target — nftables `log` and iptables `-j LOG` write the same format through
// nf_log — as journald renders it with --output=short-iso: an ISO timestamp,
// the host, "kernel:", then this tool's own prefix and the packet's KEY=VALUE
// fields. They are captured from the format nf_log_ipv4/ipv6 produces, with the
// host and interface names scrubbed, and they are what the live view parses.
// Rootless netns does not deliver these to the kernel log (the rule fires and
// its counter increments, but nf_log needs the real kernel log), so the parser
// is proven on the documented format here rather than on a namespace capture.

const (
	// A drop of an inbound SSH probe from the WAN, prefix "tui:input drop ".
	logLineInDrop = `2026-08-30T14:03:11+0000 router kernel: tui:input drop ` +
		`IN=wan0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 ` +
		`SRC=198.51.100.23 DST=203.0.113.9 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ` +
		`ID=54321 DF PROTO=TCP SPT=44210 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0`

	// An accepted forward from LAN to WAN, prefix "tui:forward accept ".
	logLineForwardAccept = `2026-08-30T14:03:12+0000 router kernel: tui:forward accept ` +
		`IN=lan0 OUT=wan0 MAC=00:11:22:33:44:55 SRC=10.10.0.42 DST=140.82.112.3 ` +
		`LEN=52 TOS=0x00 PREC=0x00 TTL=63 ID=0 DF PROTO=TCP SPT=51002 DPT=443 ` +
		`WINDOW=502 RES=0x00 ACK URGP=0`

	// An outbound reject over IPv6, prefix "tui:output reject "; the v6 header
	// carries HOPLIMIT/FLOWLBL rather than TTL/ID, which the parser ignores.
	logLineOutRejectV6 = `2026-08-30T14:03:13+0000 router kernel: tui:output reject ` +
		`IN= OUT=wan0 SRC=2001:db8::9 DST=2001:db8::25 LEN=60 TC=0 HOPLIMIT=64 ` +
		`FLOWLBL=0 PROTO=TCP SPT=39004 DPT=25 WINDOW=64800 RES=0x00 SYN URGP=0`

	// A log-only rule with no verdict word: the prefix is just "tui:input ".
	logLineInLogOnly = `2026-08-30T14:03:14+0000 router kernel: tui:input ` +
		`IN=wan0 OUT= MAC=00:11:22 SRC=203.0.113.77 DST=203.0.113.9 LEN=32 ` +
		`TOS=0x00 PREC=0x00 TTL=118 ID=1234 PROTO=UDP SPT=6000 DPT=1900 LEN=12`

	// The same event as a bare kernel message, no journald wrapper — what a
	// /dev/kmsg read would carry once the priority/sequence header is gone.
	logLineBare = `tui:input drop IN=eth0 OUT= SRC=192.0.2.5 DST=192.0.2.9 ` +
		`PROTO=ICMP TYPE=8 CODE=0`
)

func TestParseKernelLogLine(t *testing.T) {
	cases := []struct {
		name string
		line string
		want LogEvent
	}{
		{
			name: "inbound drop",
			line: logLineInDrop,
			want: LogEvent{
				Chain: "input", Verdict: "drop", Direction: "in",
				Prefix: "tui:input drop", IIF: "wan0", OIF: "",
				Src: "198.51.100.23", Dst: "203.0.113.9",
				Proto: "tcp", SPort: "44210", DPort: "22",
			},
		},
		{
			name: "forward accept",
			line: logLineForwardAccept,
			want: LogEvent{
				Chain: "forward", Verdict: "accept", Direction: "fwd",
				Prefix: "tui:forward accept", IIF: "lan0", OIF: "wan0",
				Src: "10.10.0.42", Dst: "140.82.112.3",
				Proto: "tcp", SPort: "51002", DPort: "443",
			},
		},
		{
			name: "outbound reject v6",
			line: logLineOutRejectV6,
			want: LogEvent{
				Chain: "output", Verdict: "reject", Direction: "out",
				Prefix: "tui:output reject", IIF: "", OIF: "wan0",
				Src: "2001:db8::9", Dst: "2001:db8::25",
				Proto: "tcp", SPort: "39004", DPort: "25",
			},
		},
		{
			name: "log only, no verdict",
			line: logLineInLogOnly,
			want: LogEvent{
				Chain: "input", Verdict: "", Direction: "in",
				Prefix: "tui:input", IIF: "wan0", OIF: "",
				Src: "203.0.113.77", Dst: "203.0.113.9",
				Proto: "udp", SPort: "6000", DPort: "1900",
			},
		},
		{
			name: "bare message, direction from interfaces",
			line: logLineBare,
			want: LogEvent{
				Chain: "input", Verdict: "drop", Direction: "in",
				Prefix: "tui:input drop", IIF: "eth0", OIF: "",
				Src: "192.0.2.5", Dst: "192.0.2.9", Proto: "icmp",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseKernelLogLine(tc.line)
			if !ok {
				t.Fatalf("line was not recognised as ours: %q", tc.line)
			}
			// Time is checked separately: the fixtures carry a real timestamp,
			// so it must parse to a non-zero moment.
			if got.Time.IsZero() && strings.HasPrefix(tc.line, "2026") {
				t.Errorf("timestamp did not parse from %q", tc.line)
			}
			got.Time = tc.want.Time
			got.Raw = tc.want.Raw
			if got != tc.want {
				t.Errorf("parsed\n  %+v\nwant\n  %+v", got, tc.want)
			}
		})
	}
}

func TestParseKernelLogLineNotOurs(t *testing.T) {
	for _, line := range []string{
		"",
		"2026-08-30T14:03:11+0000 router kernel: usb 1-1: new high-speed USB device",
		"random text with no marker",
		"IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP DPT=22",
	} {
		if _, ok := ParseKernelLogLine(line); ok {
			t.Errorf("line without the marker was taken as ours: %q", line)
		}
	}
}

func TestDirectionForChain(t *testing.T) {
	cases := map[string]string{
		"input": "in", "prerouting": "in",
		"output": "out", "postrouting": "out",
		"forward": "fwd", "admin_services": "", "": "",
	}
	for chain, want := range cases {
		if got := DirectionForChain(chain); got != want {
			t.Errorf("DirectionForChain(%q) = %q, want %q", chain, got, want)
		}
	}
}

func TestLogStatementRoundTrip(t *testing.T) {
	// The reader decodes the prefix and level of the fixture's tail log rule,
	// keeping the prefix's own trailing space so it round-trips to nft.
	ruleset := parseFixture(t, "router")
	chain, _ := ruleset.Chain(OwnTable, "input")
	last := chain.Rules[len(chain.Rules)-1]
	if !last.Match.Log {
		t.Fatal("the tail rule logs and Match.Log should say so")
	}
	if last.Match.LogPrefix != "tui:input drop " {
		t.Errorf("LogPrefix = %q, want the prefix with its trailing space",
			last.Match.LogPrefix)
	}
	if last.Match.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", last.Match.LogLevel)
	}
}

func TestLoggedRules(t *testing.T) {
	ruleset := parseFixture(t, "router")
	owned, total := ruleset.LoggedRules()
	if total != 1 {
		t.Errorf("total logged rules = %d, want 1", total)
	}
	// The one logging rule is in the tool's own input chain, so it is owned.
	if owned != 1 {
		t.Errorf("owned logged rules = %d, want 1", owned)
	}
}

func TestLogSourceProbe(t *testing.T) {
	// The probe reports a source and a detail whatever the machine looks like;
	// what it must never do is claim readable with no explanation.
	readable, source, detail := LogSourceProbe()
	if source == "" {
		t.Error("the probe named no source")
	}
	if detail == "" {
		t.Error("the probe gave no detail")
	}
	_ = readable
}

func FuzzParseKernelLogLine(f *testing.F) {
	for _, seed := range []string{
		logLineInDrop, logLineForwardAccept, logLineOutRejectV6,
		logLineInLogOnly, logLineBare,
		"", "tui:", "tui: ", "tui:input", "tui:input drop",
		"tui:x IN= OUT= SRC= DST= PROTO= SPT= DPT=",
		"prefix with the marker tui: in the middle IN=eth0 SRC=1.2.3.4",
		"tui:input drop IN=\x00\x01 SRC=\n DST=\t PROTO=TCP",
		"2026-08-30T14:03:11+0000 h kernel: tui:input drop IN=eth0 DPT=22",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, line string) {
		event, ok := ParseKernelLogLine(line)
		if !ok {
			// A line that is not ours yields the zero event; it must not have
			// been half-filled.
			if event != (LogEvent{}) {
				t.Fatalf("a rejected line still filled %+v", event)
			}
			return
		}
		// Every field the live view puts in a single-line table cell has to be
		// one line and valid UTF-8, whatever bytes the kernel log carried.
		for name, value := range map[string]string{
			"chain": event.Chain, "direction": event.Direction,
			"verdict": event.Verdict, "prefix": event.Prefix,
			"iif": event.IIF, "oif": event.OIF, "src": event.Src,
			"dst": event.Dst, "proto": event.Proto,
			"sport": event.SPort, "dport": event.DPort,
		} {
			if strings.ContainsAny(value, "\n\r") {
				t.Fatalf("%s spans lines: %q", name, value)
			}
			if !utf8.ValidString(value) {
				t.Fatalf("%s is not valid UTF-8: %q", name, value)
			}
		}
		// A recognised line always carries the marker in its prefix, and the
		// direction is one of the three the view knows, or empty.
		if !strings.Contains(event.Prefix, LogPrefixMarker) {
			t.Fatalf("prefix %q lost the marker", event.Prefix)
		}
		switch event.Direction {
		case "", "in", "out", "fwd":
		default:
			t.Fatalf("direction = %q, want in, out, fwd or empty", event.Direction)
		}
		// Parsing is a pure function of the input.
		again, _ := ParseKernelLogLine(line)
		again.Time = event.Time
		if again != event {
			t.Fatal("parsing the same line twice gave two answers")
		}
	})
}
