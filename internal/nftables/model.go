// Package nftables drives nft directly, for a machine whose ruleset is not
// managed by ufw or firewalld.
//
// The source of truth is `nft -j list ruleset`, the JSON nft itself emits.
// Nothing is ever parsed out of nft's human-readable output, and nothing is
// written through a generated file: every change is one `nft` invocation with
// an argv this package builds, previewed before it runs.
package nftables

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// TableID names a table. nft addresses everything by family and name, and the
// pair is what makes a table unique: `inet filter` and `ip filter` are two
// different tables.
type TableID struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

// String renders the table the way nft's own command line spells it.
func (t TableID) String() string { return t.Family + " " + t.Name }

// Args returns the two argv words that address the table.
func (t TableID) Args() []string { return []string{t.Family, t.Name} }

// Counter is the packet and byte count of a rule that carries one.
type Counter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// String renders the counter the way the rule list column shows it.
func (c Counter) String() string {
	return strconv.FormatUint(c.Packets, 10) + "p/" + humanBytes(c.Bytes)
}

// NAT is the address translation a rule performs.
type NAT struct {
	// Kind is "masquerade", "dnat", "snat" or "redirect".
	Kind string `json:"kind"`
	// Addr and Port are the translation target; both empty for masquerade.
	Addr string `json:"addr,omitempty"`
	Port string `json:"port,omitempty"`
}

// String renders the translation as the NAT view's target column.
func (n NAT) String() string {
	switch {
	case n.Addr == "" && n.Port == "":
		return n.Kind
	case n.Port == "":
		return n.Kind + " to " + n.Addr
	case n.Addr == "":
		return n.Kind + " to :" + n.Port
	default:
		return n.Kind + " to " + n.Addr + ":" + n.Port
	}
}

// Match is what a rule's expression list decomposes into: the columns the
// rule list shows. Every expression this package does not model is rendered
// textually into Unmodeled instead of being dropped, because a rule the tool
// shows half of is worse than a rule it shows verbatim.
type Match struct {
	// Verdict is the terminal statement: accept, drop, reject, return, or a
	// "jump chain" / "goto chain".
	Verdict string `json:"verdict,omitempty"`
	// IIF and OIF are the input and output interface the rule matches.
	IIF string `json:"iif,omitempty"`
	OIF string `json:"oif,omitempty"`
	// Proto is the layer 4 protocol ("tcp", "udp", "icmp", …).
	Proto string `json:"proto,omitempty"`
	// CTState is the connection-tracking state the rule matches, rendered the
	// way nft spells it ("established,related"). It is what makes a rule
	// stateful, and the column a router user reads first.
	CTState string `json:"ctState,omitempty"`
	// ICMPType is the ICMP message type the rule narrows to ("echo-request").
	ICMPType string `json:"icmpType,omitempty"`
	// Saddr and Daddr are the address selectors, "@name" for a set reference.
	Saddr string `json:"saddr,omitempty"`
	Daddr string `json:"daddr,omitempty"`
	// SPort and DPort are the port selectors, "@name" for a set reference.
	SPort string `json:"sport,omitempty"`
	DPort string `json:"dport,omitempty"`
	// Counter is the rule's counter, when it carries one.
	Counter *Counter `json:"counter,omitempty"`
	// NAT is the translation the rule performs, when it performs one.
	NAT *NAT `json:"nat,omitempty"`
	// Log reports that the rule logs what it matches.
	Log bool `json:"log,omitempty"`
	// Sets lists every named set this rule refers to, in order. It is what
	// the alias reference count is computed from.
	Sets []string `json:"sets,omitempty"`
	// Unmodeled holds the textual rendering of every expression the columns
	// above have no room for — a ct state match, a meta mark, a limit.
	Unmodeled []string `json:"unmodeled,omitempty"`

	// family4 and family6 record which address header the rule matched on,
	// which is how a rule in an `inet` table says which family it is about.
	// They are unexported because they are an observation about the
	// expressions, not a field nft ever printed.
	family4, family6 bool
}

// Family reports the address family the rule's own matches pin it to: "v4",
// "v6", or empty when the rule applies to both.
func (m Match) Family() string {
	switch {
	case m.family4 && !m.family6:
		return "v4"
	case m.family6 && !m.family4:
		return "v6"
	default:
		return ""
	}
}

// Rule is one rule of one chain.
type Rule struct {
	Table TableID `json:"table"`
	Chain string  `json:"chain"`
	// Handle is nft's own identifier, and the only safe way to delete a rule:
	// positions shift as soon as anything else is inserted.
	Handle int `json:"handle"`
	// Index is the 1-based position in its chain, for display only.
	Index   int    `json:"index"`
	Comment string `json:"comment,omitempty"`
	Match   Match  `json:"match"`
	// Raw is the whole expression list rendered as one line, which is what
	// the detail view shows and what the filter matches against.
	Raw string `json:"raw"`
}

// Chain is one chain of one table.
type Chain struct {
	Table TableID `json:"table"`
	Name  string  `json:"name"`
	// Handle is nft's identifier for the chain.
	Handle int `json:"handle"`
	// Type is "filter", "nat" or "route"; empty on a regular chain.
	Type string `json:"type,omitempty"`
	// Hook is "input", "output", "forward", "prerouting" or "postrouting";
	// empty on a regular chain, which is only reached by a jump.
	Hook string `json:"hook,omitempty"`
	// Priority is the hook priority; PriorityName is nft's word for it when
	// it has one ("filter", "srcnat").
	Priority     int    `json:"priority"`
	PriorityName string `json:"priorityName,omitempty"`
	// Policy is the verdict for a packet no rule matched: "accept" or "drop".
	// It is empty on a regular chain, and that emptiness is what the mutation
	// guard reads.
	Policy string `json:"policy,omitempty"`
	Rules  []Rule `json:"rules"`
}

// Base reports whether the chain is hooked into the packet path. A regular
// chain has no hook, no policy and no direction of its own.
func (c Chain) Base() bool { return c.Hook != "" }

// Describe renders the chain's own header line, the way nft prints it.
func (c Chain) Describe() string {
	if !c.Base() {
		return "regular chain, reached by jump or goto"
	}
	priority := c.PriorityName
	if priority == "" {
		priority = strconv.Itoa(c.Priority)
	}
	line := "type " + c.Type + " hook " + c.Hook + " priority " + priority
	if c.Policy != "" {
		line += "; policy " + c.Policy
	}
	return line
}

// Set is a named set: what this tool calls an alias.
type Set struct {
	Table TableID `json:"table"`
	Name  string  `json:"name"`
	// Handle is nft's identifier for the set.
	Handle int `json:"handle"`
	// Type is the element type: "ipv4_addr", "ipv6_addr", "inet_service", or
	// the concatenation of several joined by " . ".
	Type string `json:"type"`
	// Flags are nft's set flags: "interval", "timeout", "constant".
	Flags   []string `json:"flags,omitempty"`
	Comment string   `json:"comment,omitempty"`
	// Elements are the members, each rendered as nft would print it.
	Elements []string `json:"elements"`
	// References counts the rules in this ruleset that name the set. An alias
	// nothing refers to is safe to delete; one that is referenced is not, and
	// the count is the only way the UI can say which is which.
	References int `json:"references"`
}

// Ref is how a rule spells a reference to this set.
func (s Set) Ref() string { return "@" + s.Name }

// Interval reports whether the set stores ranges rather than single values.
func (s Set) Interval() bool {
	for _, f := range s.Flags {
		if f == "interval" {
			return true
		}
	}
	return false
}

// Table is one nft table with the chains and sets it holds.
type Table struct {
	TableID
	Handle int     `json:"handle"`
	Chains []Chain `json:"chains"`
	Sets   []Set   `json:"sets"`
}

// Ruleset is the whole `nft -j list ruleset` output, decoded.
type Ruleset struct {
	// Version is what nft reported about itself in the metainfo object.
	Version string `json:"version"`
	// SchemaVersion is the JSON schema version nft emitted. The reader
	// refuses a version it was not written against rather than guessing.
	SchemaVersion int     `json:"schemaVersion"`
	Tables        []Table `json:"tables"`
}

// Table returns the table with the given family and name.
func (r Ruleset) Table(id TableID) (Table, bool) {
	for _, t := range r.Tables {
		if t.TableID == id {
			return t, true
		}
	}
	return Table{}, false
}

// Chain returns the chain with the given table and name.
func (r Ruleset) Chain(table TableID, name string) (Chain, bool) {
	t, ok := r.Table(table)
	if !ok {
		return Chain{}, false
	}
	for _, c := range t.Chains {
		if c.Name == name {
			return c, true
		}
	}
	return Chain{}, false
}

// Set returns the set with the given table and name.
func (r Ruleset) Set(table TableID, name string) (Set, bool) {
	t, ok := r.Table(table)
	if !ok {
		return Set{}, false
	}
	for _, s := range t.Sets {
		if s.Name == name {
			return s, true
		}
	}
	return Set{}, false
}

// Empty reports a ruleset with no tables at all, which is what a machine with
// no firewall looks like.
func (r Ruleset) Empty() bool { return len(r.Tables) == 0 }

// BaseChains returns every hooked chain, in the order tables were listed.
func (r Ruleset) BaseChains() []Chain {
	var chains []Chain
	for _, t := range r.Tables {
		for _, c := range t.Chains {
			if c.Base() {
				chains = append(chains, c)
			}
		}
	}
	return chains
}

// Filtering reports whether anything in this ruleset actually filters: a
// hooked filter chain that either drops by default or carries a rule. It is
// what the header's enabled/disabled fact is read from, because nftables has
// no on/off switch of its own to ask.
func (r Ruleset) Filtering() bool {
	for _, c := range r.BaseChains() {
		if c.Type != "filter" {
			continue
		}
		if c.Policy == PolicyDrop || len(c.Rules) > 0 {
			return true
		}
	}
	return false
}

// The chain policies nft accepts on a base chain.
const (
	PolicyAccept = "accept"
	PolicyDrop   = "drop"
)

// countReferences fills Set.References by walking every rule of the ruleset.
// A set is counted once per rule that names it, however many times that rule
// mentions it: what the user needs to know is how many rules break if the
// alias goes away.
func (r *Ruleset) countReferences() {
	counts := map[string]int{}
	for _, t := range r.Tables {
		for _, c := range t.Chains {
			for _, rule := range c.Rules {
				for _, name := range unique(rule.Match.Sets) {
					counts[t.String()+"/"+name]++
				}
			}
		}
	}
	for ti := range r.Tables {
		for si := range r.Tables[ti].Sets {
			set := &r.Tables[ti].Sets[si]
			set.References = counts[set.Table.String()+"/"+set.Name]
		}
	}
}

// unique returns the distinct values of a slice, order preserved.
func unique(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// humanBytes renders a byte count the way a table column can afford: three
// significant figures and a unit.
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

// sortedSetNames returns the set names of a table in a stable order, for the
// pickers that offer an alias to act on.
func sortedSetNames(sets []Set) []string {
	names := make([]string, 0, len(sets))
	for _, s := range sets {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return names
}

// errorf is the package's one error constructor, so every message this
// package produces reads the same way: what it refused, and why.
func errorf(format string, args ...any) error {
	return fmt.Errorf("nftables: "+format, args...)
}

// jsonNumber renders a JSON number the way nft would have printed it, which
// for a port or a protocol number means without a decimal point.
func jsonNumber(f float64) string {
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// oneLine makes a value safe to put in a table cell. Everything this package
// renders comes from bytes another program produced, and a control character
// in one of them would break the table's own layout rather than just its own
// cell — so they become spaces, and the surrounding whitespace goes.
func oneLine(value string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' || (r >= 0 && r < 0x20) || r == 0x7f {
			return ' '
		}
		return r
	}, value))
}

// compactJSON renders a decoded value back to one line of JSON. It is the
// last-resort rendering for an expression this package does not model: the
// user sees exactly what nft reported, rather than a blank cell.
func compactJSON(v any) string {
	out, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return strings.TrimSpace(string(out))
}
