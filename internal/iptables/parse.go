// Package iptables drives iptables and ip6tables, for a machine whose filter
// tables are written through the xtables tools — iptables-nft or the legacy
// iptables — and usually restored at boot by iptables-persistent (Debian,
// Ubuntu) or iptables-services (Fedora, RHEL).
//
// The source of truth is iptables-save and ip6tables-save, the dump format the
// persistence packages themselves write and restore. Every change is one
// `iptables` or `ip6tables` invocation with an argv this package builds,
// previewed before it runs; writing the running rules to disk is a separate,
// previewed step, because on these machines "applied" and "survives a reboot"
// are two different facts.
package iptables

import (
	"fmt"
	"strconv"
	"strings"
)

// Family is the address family a dump belongs to. iptables keeps the two
// families in separate tables, driven by separate binaries.
type Family string

// The two families.
const (
	V4 Family = "v4"
	V6 Family = "v6"
)

// Families lists both, in the order the UI shows them.
func Families() []Family { return []Family{V4, V6} }

// Binary is the command that changes rules of this family.
func (f Family) Binary() string {
	if f == V6 {
		return "ip6tables"
	}
	return "iptables"
}

// SaveBinary is the command that dumps this family's rules.
func (f Family) SaveBinary() string { return f.Binary() + "-save" }

// RestoreBinary is the command that loads a dump of this family.
func (f Family) RestoreBinary() string { return f.Binary() + "-restore" }

// NftFamily is the nft table family the same rules live in when the xtables
// tools are the nf_tables variant: iptables-nft writes table ip filter.
func (f Family) NftFamily() string {
	if f == V6 {
		return "ip6"
	}
	return "ip"
}

// The tables and chains this backend knows by name.
const (
	TableFilter = "filter"

	ChainInput   = "INPUT"
	ChainForward = "FORWARD"
	ChainOutput  = "OUTPUT"
)

// The targets that decide a packet's fate.
const (
	TargetAccept = "ACCEPT"
	TargetDrop   = "DROP"
	TargetReject = "REJECT"
	TargetReturn = "RETURN"
)

// Counter is the packet and byte count iptables-save -c prints.
type Counter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// String renders the counter the way the rule list column shows it.
func (c Counter) String() string {
	return strconv.FormatUint(c.Packets, 10) + "p/" + humanBytes(c.Bytes)
}

// Rule is one `-A CHAIN …` line of a dump.
type Rule struct {
	Chain string `json:"chain"`
	// Index is the 1-based position in its chain. Unlike an nft handle it is
	// not an identity: it is what `iptables -I CHAIN N` means, and what shifts
	// as soon as anything is inserted above.
	Index int `json:"index"`
	// Spec is everything after "-A CHAIN ", exactly as iptables-save printed
	// it, quotes included. It is the rule's identity for a delete, which goes
	// by specification rather than by number.
	Spec string `json:"spec"`
	// Args is Spec split into the argv words iptables takes.
	Args []string `json:"args"`
	// Counter is the rule's counter when the dump carried one.
	Counter *Counter `json:"counter,omitempty"`
	Match   Match    `json:"match"`
}

// Line renders the rule as the dump line it came from, without a counter.
func (r Rule) Line() string { return "-A " + r.Chain + " " + r.Spec }

// Chain is one chain of a table.
type Chain struct {
	Name string `json:"name"`
	// Policy is ACCEPT or DROP on a built-in chain and empty on a user chain,
	// which iptables-save prints as "-".
	Policy string `json:"policy,omitempty"`
	Rules  []Rule `json:"rules"`
}

// Builtin reports whether the chain is one the kernel hooks into the packet
// path, which in a dump is exactly the chains with a policy.
func (c Chain) Builtin() bool { return c.Policy != "" }

// CatchAll returns the 1-based position of the first rule that rejects or
// drops everything that reaches it, or 0 when the chain has none. That rule is
// where a chain really ends: anything after it never matches, which is why a
// new rule is inserted in front of it rather than appended.
func (c Chain) CatchAll() (int, Rule) {
	for _, rule := range c.Rules {
		if rule.Match.Unconditional() && (rule.Match.Target == TargetReject ||
			rule.Match.Target == TargetDrop) {
			return rule.Index, rule
		}
	}
	return 0, Rule{}
}

// Table is one `*name … COMMIT` section of a dump.
type Table struct {
	Name   string  `json:"name"`
	Chains []Chain `json:"chains"`
}

// Chain returns the named chain.
func (t Table) Chain(name string) (Chain, bool) {
	for _, c := range t.Chains {
		if c.Name == name {
			return c, true
		}
	}
	return Chain{}, false
}

// Dump is one iptables-save or ip6tables-save output, decoded.
type Dump struct {
	Family Family `json:"family"`
	// Version is the xtables version that printed the dump ("1.8.10"), and
	// Variant which kernel interface it drove: "nf_tables" or "legacy".
	Version string  `json:"version,omitempty"`
	Variant string  `json:"variant,omitempty"`
	Tables  []Table `json:"tables"`
	// Warnings are the "# Warning:" lines the tool printed about itself, such
	// as iptables-nft noticing legacy tables loaded beside it.
	Warnings []string `json:"warnings,omitempty"`
}

// Table returns the named table.
func (d Dump) Table(name string) (Table, bool) {
	for _, t := range d.Tables {
		if t.Name == name {
			return t, true
		}
	}
	return Table{}, false
}

// Chain returns the named chain of the named table.
func (d Dump) Chain(table, chain string) (Chain, bool) {
	t, ok := d.Table(table)
	if !ok {
		return Chain{}, false
	}
	return t.Chain(chain)
}

// Empty reports a dump with no tables, which is what a family nothing has
// ever touched looks like.
func (d Dump) Empty() bool { return len(d.Tables) == 0 }

// ParseSave decodes the output of iptables-save or ip6tables-save, with or
// without -c. It is strict about structure — a rule outside a table, or a
// chain line it cannot read, is an error rather than a silently shorter list —
// and tolerant about content: a match it has no column for is kept as text.
func ParseSave(family Family, text string) (Dump, error) {
	dump := Dump{Family: family}
	var table *Table
	for n, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		lineNo := n + 1
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "# Generated by "):
			dump.Version, dump.Variant = parseGenerated(line)
		case strings.HasPrefix(line, "# Warning:"):
			dump.Warnings = append(dump.Warnings,
				strings.TrimSpace(strings.TrimPrefix(line, "# Warning:")))
		case strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "*"):
			if table != nil {
				return Dump{}, errorf("line %d: table %s starts before %s was committed",
					lineNo, line[1:], table.Name)
			}
			dump.Tables = append(dump.Tables, Table{Name: strings.TrimSpace(line[1:])})
			table = &dump.Tables[len(dump.Tables)-1]
		case line == "COMMIT":
			if table == nil {
				return Dump{}, errorf("line %d: COMMIT outside a table", lineNo)
			}
			table = nil
		case strings.HasPrefix(line, ":"):
			if table == nil {
				return Dump{}, errorf("line %d: chain outside a table", lineNo)
			}
			chain, err := parseChainLine(line)
			if err != nil {
				return Dump{}, errorf("line %d: %v", lineNo, err)
			}
			table.Chains = append(table.Chains, chain)
		default:
			if table == nil {
				return Dump{}, errorf("line %d: rule outside a table", lineNo)
			}
			if err := addRuleLine(table, line); err != nil {
				return Dump{}, errorf("line %d: %v", lineNo, err)
			}
		}
	}
	if table != nil {
		return Dump{}, errorf("table %s was never committed; the dump is truncated",
			table.Name)
	}
	return dump, nil
}

// parseGenerated reads the version and the variant out of the header line
// "# Generated by iptables-save v1.8.10 (nf_tables) on …".
func parseGenerated(line string) (version, variant string) {
	fields := strings.Fields(line)
	for i, f := range fields {
		if strings.HasPrefix(f, "v") && i > 0 && strings.HasSuffix(fields[i-1], "-save") {
			version = strings.TrimPrefix(f, "v")
			if i+1 < len(fields) && strings.HasPrefix(fields[i+1], "(") {
				variant = strings.Trim(fields[i+1], "()")
			}
			return version, variant
		}
	}
	return "", ""
}

// parseChainLine reads ":NAME POLICY [packets:bytes]".
func parseChainLine(line string) (Chain, error) {
	fields := strings.Fields(strings.TrimPrefix(line, ":"))
	if len(fields) < 2 || fields[0] == "" {
		return Chain{}, fmt.Errorf("cannot read chain line %q", line)
	}
	chain := Chain{Name: fields[0]}
	if fields[1] != "-" {
		chain.Policy = fields[1]
	}
	return chain, nil
}

// addRuleLine reads "[packets:bytes] -A CHAIN spec…" into its chain.
func addRuleLine(table *Table, line string) error {
	var counter *Counter
	if strings.HasPrefix(line, "[") {
		end := strings.IndexByte(line, ']')
		if end < 0 {
			return fmt.Errorf("unterminated counter in %q", line)
		}
		c, err := parseCounter(line[1:end])
		if err != nil {
			return err
		}
		counter = &c
		line = strings.TrimSpace(line[end+1:])
	}
	if !strings.HasPrefix(line, "-A ") {
		return fmt.Errorf("expected an -A rule, got %q", line)
	}
	rest := strings.TrimSpace(line[3:])
	name, spec, _ := strings.Cut(rest, " ")
	if name == "" {
		return fmt.Errorf("rule with no chain: %q", line)
	}
	spec = strings.TrimSpace(spec)
	args, err := SplitArgs(spec)
	if err != nil {
		return err
	}
	index := -1
	for i := range table.Chains {
		if table.Chains[i].Name == name {
			index = i
			break
		}
	}
	if index < 0 {
		// A rule whose chain was never declared: keep it, in a user chain,
		// which the mutation guard refuses to write to anyway.
		table.Chains = append(table.Chains, Chain{Name: name})
		index = len(table.Chains) - 1
	}
	chain := &table.Chains[index]
	chain.Rules = append(chain.Rules, Rule{
		Chain:   name,
		Index:   len(chain.Rules) + 1,
		Spec:    spec,
		Args:    args,
		Counter: counter,
		Match:   decodeArgs(args),
	})
	return nil
}

// parseCounter reads "packets:bytes".
func parseCounter(text string) (Counter, error) {
	p, b, ok := strings.Cut(text, ":")
	if !ok {
		return Counter{}, fmt.Errorf("cannot read counter %q", text)
	}
	packets, err := strconv.ParseUint(p, 10, 64)
	if err != nil {
		return Counter{}, fmt.Errorf("cannot read counter %q", text)
	}
	bytes, err := strconv.ParseUint(b, 10, 64)
	if err != nil {
		return Counter{}, fmt.Errorf("cannot read counter %q", text)
	}
	return Counter{Packets: packets, Bytes: bytes}, nil
}

// SplitArgs splits a rule specification into argv words the way
// iptables-restore does: whitespace separates, double quotes group, and a
// backslash inside quotes escapes the next character. iptables-save quotes a
// comment that carries a space, and that comment must come back as one word.
func SplitArgs(spec string) ([]string, error) {
	var args []string
	var word strings.Builder
	inWord, quoted := false, false
	for i := 0; i < len(spec); i++ {
		ch := spec[i]
		switch {
		case quoted && ch == '\\' && i+1 < len(spec):
			i++
			word.WriteByte(spec[i])
		case ch == '"':
			quoted = !quoted
			inWord = true
		case !quoted && (ch == ' ' || ch == '\t'):
			if inWord {
				args = append(args, word.String())
				word.Reset()
				inWord = false
			}
		default:
			word.WriteByte(ch)
			inWord = true
		}
	}
	if quoted {
		return nil, fmt.Errorf("unterminated quote in %q", spec)
	}
	if inWord {
		args = append(args, word.String())
	}
	return args, nil
}

// QuoteArg renders one argv word the way a dump line needs it: bare when it
// is safe, double-quoted with escapes when it carries a space or a quote.
func QuoteArg(arg string) string {
	if arg != "" && !strings.ContainsAny(arg, " \t\"\\'") {
		return arg
	}
	escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(arg)
	return `"` + escaped + `"`
}

// JoinArgs renders argv words as one dump-line specification.
func JoinArgs(args []string) string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		out = append(out, QuoteArg(a))
	}
	return strings.Join(out, " ")
}

// errorf is the package's one error constructor, so every message reads the
// same way: what it refused, and why.
func errorf(format string, args ...any) error {
	return fmt.Errorf("iptables: "+format, args...)
}

// humanBytes renders a byte count the way a table column can afford.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatUint(n, 10) + "B"
	}
	value, exp := float64(n), 0
	for value >= unit && exp < 4 {
		value /= unit
		exp++
	}
	return strconv.FormatFloat(value, 'f', 1, 64) + string("KMGT"[exp-1])
}
