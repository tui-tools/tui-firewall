package iptables

import "strings"

// Match is what a rule's argv decomposes into: the columns the rule list
// shows. Everything this package does not model is kept as text in Unmodeled
// rather than dropped, because a rule the tool shows half of is worse than a
// rule it shows verbatim.
//
// A negated selector keeps iptables' own "!" in front of its value, so
// "! -i docker0" reads as "!docker0" in the interface column.
type Match struct {
	Proto    string `json:"proto,omitempty"`
	Src      string `json:"src,omitempty"`
	Dst      string `json:"dst,omitempty"`
	InIface  string `json:"in,omitempty"`
	OutIface string `json:"out,omitempty"`
	SPort    string `json:"sport,omitempty"`
	DPort    string `json:"dport,omitempty"`
	// CTState is the connection-tracking state, from either the conntrack
	// match (--ctstate) or the older state match (--state), as iptables
	// spells it: "RELATED,ESTABLISHED".
	CTState  string `json:"ctState,omitempty"`
	ICMPType string `json:"icmpType,omitempty"`
	Comment  string `json:"comment,omitempty"`
	// Target is what -j (or -g) names: a verdict, an extension target, or a
	// user chain. It is empty for a rule that only counts.
	Target string `json:"target,omitempty"`
	// Goto reports that the target was reached with -g rather than -j.
	Goto bool `json:"goto,omitempty"`
	// TargetArgs are the target's own options ("--reject-with …").
	TargetArgs []string `json:"targetArgs,omitempty"`
	// Unmodeled holds every option the columns above have no room for, each
	// rendered as the words iptables-save printed.
	Unmodeled []string `json:"unmodeled,omitempty"`
}

// Unconditional reports whether the rule matches every packet that reaches
// it. A comment does not narrow anything, so it does not count.
func (m Match) Unconditional() bool {
	return m.Proto == "" && m.Src == "" && m.Dst == "" && m.InIface == "" &&
		m.OutIface == "" && m.SPort == "" && m.DPort == "" && m.CTState == "" &&
		m.ICMPType == "" && len(m.Unmodeled) == 0
}

// Terminal reports whether the target ends the packet's walk through the
// table: a verdict rather than a jump, a log or a mark.
func (m Match) Terminal() bool {
	switch m.Target {
	case TargetAccept, TargetDrop, TargetReject:
		return true
	default:
		return false
	}
}

// TargetDetail renders the target with its options, as the dump spells it.
func (m Match) TargetDetail() string {
	if m.Target == "" {
		return ""
	}
	flag := "-j "
	if m.Goto {
		flag = "-g "
	}
	return strings.TrimSpace(flag + m.Target + " " + strings.Join(m.TargetArgs, " "))
}

// modulesImplied are matches whose options this decoder reads into columns,
// so the "-m name" that loads them says nothing on its own.
var modulesImplied = map[string]bool{
	"tcp": true, "udp": true, "multiport": true, "conntrack": true,
	"state": true, "comment": true, "icmp": true, "icmp6": true,
	"icmpv6": true,
}

// decodeArgs folds a rule's argv into a Match. It walks the words once;
// an option this decoder knows fills a column, and anything else — with the
// value words that follow it — is kept as one Unmodeled entry.
func decodeArgs(args []string) Match {
	var m Match
	negate := false
	// take returns the value after the option at i, prefixed with "!" when
	// the option was negated, and advances past it.
	take := func(i *int) string {
		value := ""
		if *i+1 < len(args) {
			*i++
			value = args[*i]
		}
		if negate {
			value = "!" + value
		}
		return value
	}
	for i := 0; i < len(args); i++ {
		word := args[i]
		if word == "!" {
			negate = true
			continue
		}
		switch word {
		case "-p", "--protocol":
			m.Proto = take(&i)
		case "-s", "--source":
			m.Src = take(&i)
		case "-d", "--destination":
			m.Dst = take(&i)
		case "-i", "--in-interface":
			m.InIface = take(&i)
		case "-o", "--out-interface":
			m.OutIface = take(&i)
		case "--dport", "--destination-port", "--dports", "--destination-ports":
			m.DPort = take(&i)
		case "--sport", "--source-port", "--sports", "--source-ports":
			m.SPort = take(&i)
		case "--ctstate", "--state":
			m.CTState = take(&i)
		case "--icmp-type", "--icmpv6-type":
			m.ICMPType = take(&i)
		case "--comment":
			m.Comment = take(&i)
		case "-m", "--match":
			name := take(&i)
			if !modulesImplied[strings.TrimPrefix(name, "!")] {
				m.Unmodeled = append(m.Unmodeled, "-m "+name)
			}
		case "-j", "--jump", "-g", "--goto":
			m.Goto = word == "-g" || word == "--goto"
			m.Target = take(&i)
			// Everything after the target is the target's own options.
			m.TargetArgs = append([]string(nil), args[i+1:]...)
			i = len(args)
		default:
			// An option with no column: keep it with its value words, the
			// ones up to the next option.
			parts := []string{word}
			if negate {
				parts = []string{"!", word}
			}
			for i+1 < len(args) && !isOption(args[i+1]) {
				i++
				parts = append(parts, QuoteArg(args[i]))
			}
			m.Unmodeled = append(m.Unmodeled, strings.Join(parts, " "))
		}
		negate = false
	}
	return m
}

// isOption reports whether an argv word starts a new option (or negates the
// next one), which is where an unmodeled option's values end.
func isOption(word string) bool {
	return word == "!" || (strings.HasPrefix(word, "-") && len(word) > 1 &&
		!isNumber(word[1:]))
}

// isNumber reports whether a word is all digits, so a negative-looking value
// is not taken for an option.
func isNumber(word string) bool {
	if word == "" {
		return false
	}
	for _, r := range word {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
