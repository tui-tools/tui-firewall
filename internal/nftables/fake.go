package nftables

import (
	"context"
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"
	"sync"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// demoRuleset is the sample router --demo starts from: the same fixture the
// parser tests read, so the demo cannot drift away from a ruleset nft really
// printed.
//
//go:embed testdata/router.json
var demoRuleset []byte

// Fake is an in-memory nftables backend used by --demo and by the tests. It
// builds its commands with the very same builders the real backend uses, and
// then applies them to a ruleset it holds itself, so every preview the demo
// shows is a command the real backend would have run.
type Fake struct {
	mu      sync.Mutex
	ruleset Ruleset
	// nextHandle is the handle the next created object gets, the way the
	// kernel hands them out: increasing, never reused.
	nextHandle int
	// Log records every command that was run, in order.
	Log []firewall.Command
	// FailWith, when set, makes the next Run fail with this error.
	FailWith error
}

// NewFake returns a Fake preloaded with the sample router ruleset.
func NewFake() *Fake {
	ruleset, err := ParseRuleset(demoRuleset)
	if err != nil {
		// The fixture is embedded from this repository and parsed by this
		// package's own tests; an error here is a build that should not have
		// shipped rather than a condition to handle.
		panic("nftables: the embedded demo ruleset does not parse: " + err.Error())
	}
	return &Fake{ruleset: ruleset, nextHandle: highestHandle(ruleset) + 1}
}

// highestHandle finds the largest handle in a ruleset, so the fake can carry
// on numbering where nft left off.
func highestHandle(rs Ruleset) int {
	highest := 0
	for _, table := range rs.Tables {
		highest = max(highest, table.Handle)
		for _, set := range table.Sets {
			highest = max(highest, set.Handle)
		}
		for _, chain := range table.Chains {
			highest = max(highest, chain.Handle)
			for _, rule := range chain.Rules {
				highest = max(highest, rule.Handle)
			}
		}
	}
	return highest
}

// Name identifies the backend.
func (f *Fake) Name() string { return "demo" }

// Describe names the backend for the status line.
func (f *Fake) Describe() string { return "demo nftables (no changes are applied)" }

// Capabilities mirrors the real nftables backend.
func (f *Fake) Capabilities() firewall.Capabilities { return capabilities }

// Preview renders the change as the real backend would, without a privilege
// prefix: the demo never escalates.
func (f *Fake) Preview(change firewall.Change) string { return change.String() }

// Load returns the in-memory ruleset as the UI model.
func (f *Fake) Load(_ context.Context) (firewall.Model, error) {
	return Model(f.Ruleset()), nil
}

// Ruleset returns a copy of the in-memory ruleset.
func (f *Fake) Ruleset() Ruleset {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ruleset
}

// Run applies a change to the in-memory ruleset, one command at a time.
func (f *Fake) Run(_ context.Context, change firewall.Change) (string, error) {
	var outputs []string
	for _, cmd := range change.Commands {
		out, err := f.runOne(cmd)
		if out != "" {
			outputs = append(outputs, out)
		}
		if err != nil {
			return strings.Join(outputs, "\n"), err
		}
	}
	return strings.Join(outputs, "\n"), nil
}

// runOne applies a single command.
func (f *Fake) runOne(cmd firewall.Command) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.FailWith != nil {
		err := f.FailWith
		f.FailWith = nil
		return "", err
	}
	f.Log = append(f.Log, cmd)

	args := cmd.Argv
	if len(args) > 0 && args[0] == "nft" {
		args = args[1:]
	}
	if len(args) == 0 {
		return "", errorf("empty command")
	}

	// `nft -f -` is the one batch form: the whole staged transaction, or a
	// snapshot restore, arrives on standard input. The demo applies it so
	// staging behaves in --demo exactly as it does against a real nft.
	if args[0] == "-f" {
		return f.applyScript(cmd.Stdin)
	}
	return f.applyStatement(args)
}

// applyStatement dispatches one nft statement (the argv with the leading "nft"
// already stripped). It is shared by the single-command path and the batch
// path, so a staged change and its immediate-apply twin take the same route
// through the in-memory ruleset.
func (f *Fake) applyStatement(args []string) (string, error) {
	if len(args) == 0 {
		return "", errorf("empty statement")
	}
	verb := args[0]
	rest := args[1:]
	// `chain <family> <table> <name> { policy … }` has no verb of its own:
	// naming an object that already exists is how nft spells a change to it.
	if verb == "chain" {
		return f.setPolicy(rest)
	}
	if verb == "flush" && len(rest) > 0 && rest[0] == "ruleset" {
		f.ruleset = Ruleset{}
		return "ruleset flushed", nil
	}
	if len(rest) == 0 {
		return "", errorf("%q needs something to act on", verb)
	}

	object, operands := rest[0], rest[1:]
	switch verb + " " + object {
	case "add table":
		return f.addTable(operands)
	case "add chain":
		return f.addChain(operands)
	case "add rule", "insert rule":
		return f.addRule(operands, verb == "insert")
	case "delete rule":
		return f.deleteRule(operands)
	case "add set":
		return f.addSet(operands)
	case "delete set":
		return f.deleteSet(operands)
	case "delete chain":
		return f.deleteChain(operands)
	case "flush chain":
		return f.flushChain(operands)
	case "delete table":
		return f.deleteTable(operands)
	case "add element":
		return f.changeElement(operands, true)
	case "delete element":
		return f.changeElement(operands, false)
	default:
		return "", errorf("%s %s is not something the demo applies", verb, object)
	}
}

// SnapshotRuleset serialises the in-memory ruleset so the demo can restore it
// on a staged rollback. It is JSON rather than nft text — the demo has no nft
// to print human syntax — and the batch path below reads it back. The real
// backend captures nft's own text instead, which is what a real rollback needs.
func (f *Fake) SnapshotRuleset(_ context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := json.Marshal(f.ruleset)
	if err != nil {
		return "", errorf("snapshotting the demo ruleset: %v", err)
	}
	return string(data), nil
}

// applyScript applies a batch that arrived on standard input: the staged
// transaction, or a snapshot restore. A `flush ruleset` line empties the state;
// a JSON object is a snapshot to load whole; anything else is one nft statement.
// nft is all-or-nothing, so the batch is applied to a copy that only replaces
// the live ruleset if every line succeeded.
func (f *Fake) applyScript(stdin string) (string, error) {
	original := f.ruleset
	applied := 0
	for _, line := range strings.Split(stdin, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "flush ruleset" {
			f.ruleset = Ruleset{}
			continue
		}
		if strings.HasPrefix(line, "{") {
			var restored Ruleset
			if err := json.Unmarshal([]byte(line), &restored); err != nil {
				f.ruleset = original
				return "", errorf("restoring the snapshot: %v", err)
			}
			restored.countReferences()
			f.ruleset = restored
			applied++
			continue
		}
		if _, err := f.applyStatement(tokenizeScript(line)); err != nil {
			// All-or-nothing: a rejected line undoes the whole batch, the way
			// nft -f would have left the ruleset untouched.
			f.ruleset = original
			return "", err
		}
		applied++
	}
	return "batch of " + strconv.Itoa(applied) + " applied atomically", nil
}

// tokenizeScript splits one nft script line into the words the statement
// handlers expect, keeping a double-quoted run — a comment, an interface name —
// as a single word the way the argv builders produced it.
func tokenizeScript(line string) []string {
	var words []string
	var current strings.Builder
	inQuote := false
	flush := func() {
		if current.Len() > 0 {
			words = append(words, current.String())
			current.Reset()
		}
	}
	for _, r := range line {
		switch {
		case r == '"':
			inQuote = !inQuote
			current.WriteRune(r)
		case r == ' ' && !inQuote:
			flush()
		default:
			current.WriteRune(r)
		}
	}
	flush()
	return words
}

// take reads the family, table and remaining operands off an argv tail.
func take(operands []string) (TableID, []string, error) {
	if len(operands) < 2 {
		return TableID{}, nil, errorf("a command needs a family and a table")
	}
	return TableID{Family: operands[0], Name: operands[1]}, operands[2:], nil
}

// table returns a pointer to a table, creating nothing.
func (f *Fake) table(id TableID) (*Table, error) {
	for i := range f.ruleset.Tables {
		if f.ruleset.Tables[i].TableID == id {
			return &f.ruleset.Tables[i], nil
		}
	}
	return nil, errorf("no table %s", id)
}

// chain returns a pointer to a chain of a table.
func (f *Fake) chain(id TableID, name string) (*Chain, error) {
	table, err := f.table(id)
	if err != nil {
		return nil, err
	}
	if chain := findChain(table, name); chain != nil {
		return chain, nil
	}
	return nil, errorf("table %s has no chain %s", id, name)
}

// handle hands out the next handle.
func (f *Fake) handle() int {
	f.nextHandle++
	return f.nextHandle - 1
}

// addTable creates a table.
func (f *Fake) addTable(operands []string) (string, error) {
	id, _, err := take(operands)
	if err != nil {
		return "", err
	}
	if _, err := f.table(id); err == nil {
		return "", nil
	}
	f.ruleset.Tables = append(f.ruleset.Tables,
		Table{TableID: id, Handle: f.handle()})
	return "table " + id.String() + " created", nil
}

// addChain creates a chain, reading its type, hook, priority and policy out
// of the braced block the command carries.
func (f *Fake) addChain(operands []string) (string, error) {
	id, rest, err := take(operands)
	if err != nil {
		return "", err
	}
	table, err := f.table(id)
	if err != nil {
		return "", err
	}
	if len(rest) == 0 {
		return "", errorf("a chain needs a name")
	}
	name := rest[0]
	if findChain(table, name) != nil {
		return "", nil
	}
	chain := Chain{Table: id, Name: name, Handle: f.handle()}
	for i, word := range rest {
		if i+1 >= len(rest) {
			break
		}
		switch word {
		case "type":
			chain.Type = rest[i+1]
		case "hook":
			chain.Hook = rest[i+1]
		case "priority":
			chain.Priority, _ = strconv.Atoi(rest[i+1])
		case "policy":
			chain.Policy = strings.TrimSuffix(rest[i+1], ";")
		}
	}
	table.Chains = append(table.Chains, chain)
	return "chain " + name + " created", nil
}

// setPolicy applies `nft chain <family> <table> <name> { policy X ; }`.
func (f *Fake) setPolicy(operands []string) (string, error) {
	id, rest, err := take(operands)
	if err != nil {
		return "", err
	}
	if len(rest) == 0 {
		return "", errorf("a chain needs a name")
	}
	chain, err := f.chain(id, rest[0])
	if err != nil {
		return "", err
	}
	for i, word := range rest {
		if word == "policy" && i+1 < len(rest) {
			chain.Policy = strings.TrimSuffix(rest[i+1], ";")
			return "policy of " + chain.Name + " is now " + chain.Policy, nil
		}
	}
	return "", errorf("no policy in this command")
}

// addRule appends or inserts a rule, reconstructed from the argv the builders
// produced. It is a reader of this backend's own command shapes rather than a
// general nft parser: what it has to get right is that the row the demo shows
// afterwards is the rule the preview described.
func (f *Fake) addRule(operands []string, insert bool) (string, error) {
	id, rest, err := take(operands)
	if err != nil {
		return "", err
	}
	if len(rest) == 0 {
		return "", errorf("a rule needs a chain")
	}
	chain, err := f.chain(id, rest[0])
	if err != nil {
		return "", err
	}
	expr := rest[1:]

	position := len(chain.Rules)
	if insert && len(expr) >= 2 && expr[0] == "index" {
		if n, err := strconv.Atoi(expr[1]); err == nil && n >= 0 && n <= position {
			position = n
		}
		expr = expr[2:]
	}

	rule := Rule{Table: id, Chain: chain.Name, Handle: f.handle()}
	rule.Match, rule.Comment = matchFromArgs(expr)
	rule.Raw = strings.Join(stripQuotes(expr), " ")

	chain.Rules = append(chain.Rules, Rule{})
	copy(chain.Rules[position+1:], chain.Rules[position:])
	chain.Rules[position] = rule
	renumber(chain)
	f.ruleset.countReferences()
	return "rule added with handle " + strconv.Itoa(rule.Handle), nil
}

// deleteRule removes a rule by handle.
func (f *Fake) deleteRule(operands []string) (string, error) {
	id, rest, err := take(operands)
	if err != nil {
		return "", err
	}
	if len(rest) < 3 || rest[1] != "handle" {
		return "", errorf("a rule is deleted by handle")
	}
	chain, err := f.chain(id, rest[0])
	if err != nil {
		return "", err
	}
	handle, err := strconv.Atoi(rest[2])
	if err != nil {
		return "", errorf("%q is not a handle", rest[2])
	}
	for i, rule := range chain.Rules {
		if rule.Handle != handle {
			continue
		}
		chain.Rules = append(chain.Rules[:i], chain.Rules[i+1:]...)
		renumber(chain)
		f.ruleset.countReferences()
		return "rule " + rest[2] + " deleted", nil
	}
	return "", errorf("chain %s has no rule with handle %d", chain.Name, handle)
}

// addSet creates a named set.
func (f *Fake) addSet(operands []string) (string, error) {
	id, rest, err := take(operands)
	if err != nil {
		return "", err
	}
	table, err := f.table(id)
	if err != nil {
		return "", err
	}
	if len(rest) == 0 {
		return "", errorf("a set needs a name")
	}
	set := Set{Table: id, Name: rest[0], Handle: f.handle(), Elements: []string{}}
	for i, word := range rest {
		if i+1 >= len(rest) {
			break
		}
		switch word {
		case "type":
			set.Type = strings.TrimSuffix(rest[i+1], ";")
		case "flags":
			set.Flags = append(set.Flags, strings.TrimSuffix(rest[i+1], ";"))
		case "comment":
			set.Comment = strings.Trim(rest[i+1], "\"")
		}
	}
	table.Sets = append(table.Sets, set)
	return "set " + set.Name + " created", nil
}

// deleteSet removes a named set.
func (f *Fake) deleteSet(operands []string) (string, error) {
	id, rest, err := take(operands)
	if err != nil {
		return "", err
	}
	table, err := f.table(id)
	if err != nil {
		return "", err
	}
	if len(rest) == 0 {
		return "", errorf("a set needs a name")
	}
	for i, set := range table.Sets {
		if set.Name != rest[0] {
			continue
		}
		table.Sets = append(table.Sets[:i], table.Sets[i+1:]...)
		return "set " + rest[0] + " deleted", nil
	}
	return "", errorf("table %s has no set %s", id, rest[0])
}

// deleteChain removes a chain of a table. nft refuses one that still holds
// rules, and so does the builder, so a chain that reaches here empty is the
// normal case; a forced delete flushes it first, which the fake sees as a
// separate command.
func (f *Fake) deleteChain(operands []string) (string, error) {
	id, rest, err := take(operands)
	if err != nil {
		return "", err
	}
	table, err := f.table(id)
	if err != nil {
		return "", err
	}
	if len(rest) == 0 {
		return "", errorf("a chain needs a name")
	}
	for i, chain := range table.Chains {
		if chain.Name != rest[0] {
			continue
		}
		if len(chain.Rules) > 0 {
			return "", errorf("chain %s still holds %d rules",
				chain.Name, len(chain.Rules))
		}
		table.Chains = append(table.Chains[:i], table.Chains[i+1:]...)
		return "chain " + rest[0] + " deleted", nil
	}
	return "", errorf("table %s has no chain %s", id, rest[0])
}

// flushChain empties a chain, the way `nft flush chain` does.
func (f *Fake) flushChain(operands []string) (string, error) {
	id, rest, err := take(operands)
	if err != nil {
		return "", err
	}
	if len(rest) == 0 {
		return "", errorf("a chain needs a name")
	}
	chain, err := f.chain(id, rest[0])
	if err != nil {
		return "", err
	}
	chain.Rules = nil
	f.ruleset.countReferences()
	return "chain " + rest[0] + " flushed", nil
}

// deleteTable drops a whole table with everything in it.
func (f *Fake) deleteTable(operands []string) (string, error) {
	id, _, err := take(operands)
	if err != nil {
		return "", err
	}
	for i := range f.ruleset.Tables {
		if f.ruleset.Tables[i].TableID != id {
			continue
		}
		f.ruleset.Tables = append(f.ruleset.Tables[:i], f.ruleset.Tables[i+1:]...)
		f.ruleset.countReferences()
		return "table " + id.String() + " deleted", nil
	}
	return "", errorf("no table %s", id)
}

// changeElement adds or removes one member of a set.
func (f *Fake) changeElement(operands []string, add bool) (string, error) {
	id, rest, err := take(operands)
	if err != nil {
		return "", err
	}
	table, err := f.table(id)
	if err != nil {
		return "", err
	}
	if len(rest) < 3 {
		return "", errorf("an element command needs a set and a value")
	}
	value := strings.Trim(strings.Join(rest[1:], " "), "{} ")
	for i := range table.Sets {
		set := &table.Sets[i]
		if set.Name != rest[0] {
			continue
		}
		if add {
			set.Elements = append(set.Elements, value)
			return value + " added to " + set.Name, nil
		}
		for j, element := range set.Elements {
			if element != value {
				continue
			}
			set.Elements = append(set.Elements[:j], set.Elements[j+1:]...)
			return value + " removed from " + set.Name, nil
		}
		return "", errorf("set %s has no element %s", set.Name, value)
	}
	return "", errorf("table %s has no set %s", id, rest[0])
}

// renumber restores contiguous 1-based positions after an insert or a delete.
func renumber(chain *Chain) {
	for i := range chain.Rules {
		chain.Rules[i].Index = i + 1
	}
}

// stripQuotes removes the nft quoting from every word, for the raw rendering.
func stripQuotes(words []string) []string {
	out := make([]string, 0, len(words))
	for _, w := range words {
		out = append(out, strings.Trim(w, "\""))
	}
	return out
}

// matchFromArgs reconstructs the columns of a rule from the argv that created
// it, which is enough for the demo table to show what the command did.
func matchFromArgs(args []string) (Match, string) {
	var m Match
	var comment string
	value := func(i int) string {
		if i+1 < len(args) {
			return strings.Trim(args[i+1], "\"")
		}
		return ""
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "iifname", "iif":
			m.IIF = value(i)
		case "oifname", "oif":
			m.OIF = value(i)
		case "saddr":
			m.Saddr = value(i)
			m.noteArgFamily(args, i)
		case "daddr":
			m.Daddr = value(i)
			m.noteArgFamily(args, i)
		case "dport":
			m.DPort = portFromArgs(args, i+1)
			if i > 0 {
				m.Proto = args[i-1]
			}
		case "sport":
			m.SPort = portFromArgs(args, i+1)
			if i > 0 {
				m.Proto = args[i-1]
			}
		case "l4proto":
			m.Proto = value(i)
		case "protocol":
			// `ip protocol icmp`: the header word before it was ip.
			m.Proto = value(i)
		case "nexthdr":
			// `ip6 nexthdr ipv6-icmp` is how nft spells icmpv6 in a v6 header.
			if value(i) == "ipv6-icmp" {
				m.Proto = "icmpv6"
			} else {
				m.Proto = value(i)
			}
		case "state":
			if i > 0 && args[i-1] == "ct" {
				m.CTState = value(i)
			}
		case "type":
			// `icmp type echo-request` / `icmpv6 type echo-request`.
			if i > 0 && (args[i-1] == "icmp" || args[i-1] == "icmpv6") {
				m.ICMPType = value(i)
			}
		case "counter":
			m.Counter = &Counter{}
		case "log":
			m.Log = true
		case "accept", "drop", "reject", "return", "continue":
			m.Verdict = args[i]
		case "masquerade":
			m.Verdict, m.NAT = "masquerade", &NAT{Kind: "masquerade"}
		case "dnat", "snat", "redirect":
			m.Verdict = args[i]
			m.NAT = natFromArgs(args[i], args[i+1:])
		case "comment":
			comment = value(i)
		}
	}
	for _, selector := range []string{m.Saddr, m.Daddr, m.DPort, m.SPort} {
		m.collectSets(selector)
	}
	return m, comment
}

// noteArgFamily records the address family off the header word in front of an
// address match: `ip saddr` or `ip6 saddr`.
func (m *Match) noteArgFamily(args []string, at int) {
	if at == 0 {
		return
	}
	switch args[at-1] {
	case "ip":
		m.family4 = true
	case "ip6":
		m.family6 = true
	}
}

// portFromArgs reads a port operand, which is one word or a braced list.
func portFromArgs(args []string, at int) string {
	if at >= len(args) {
		return ""
	}
	if args[at] != "{" {
		return args[at]
	}
	var items []string
	for _, word := range args[at+1:] {
		if word == "}" {
			break
		}
		items = append(items, strings.TrimSuffix(word, ","))
	}
	return "{ " + strings.Join(items, ", ") + " }"
}

// natFromArgs reads the target of a dnat, snat or redirect out of the argv.
func natFromArgs(kind string, rest []string) *NAT {
	nat := &NAT{Kind: kind}
	for i, word := range rest {
		if word != "to" || i+1 >= len(rest) {
			continue
		}
		target := rest[i+1]
		// A v6 target is bracketed; a v4 one is not, and neither has to
		// carry a port.
		if strings.HasPrefix(target, "[") {
			addr, port, _ := strings.Cut(strings.TrimPrefix(target, "["), "]:")
			nat.Addr, nat.Port = addr, port
			return nat
		}
		addr, port, found := strings.Cut(target, ":")
		nat.Addr = addr
		if found {
			nat.Port = port
		}
		return nat
	}
	return nat
}

// BuildAddRule creates a rule.
func (f *Fake) BuildAddRule(group string, spec firewall.RuleSpec) (firewall.Change, error) {
	return f.Ruleset().AddRule(group, spec)
}

// BuildDeleteRule removes the selected row.
func (f *Fake) BuildDeleteRule(group string, rule firewall.Rule) (firewall.Change, error) {
	return f.Ruleset().DeleteRule(group, rule)
}

// BuildSetEnabled always refuses: nftables has no on/off switch.
func (f *Fake) BuildSetEnabled(bool) (firewall.Change, error) {
	return firewall.Change{}, errorf("%s", capabilities.EnableHint)
}

// BuildReload always refuses, for the reason the real backend gives.
func (f *Fake) BuildReload() (firewall.Change, error) {
	return (&Real{}).BuildReload()
}

// BuildSetPolicy changes the policy of the chain a group shows.
func (f *Fake) BuildSetPolicy(group string, _ firewall.PolicyDirection,
	policy firewall.Policy) (firewall.Change, error) {
	return f.Ruleset().SetPolicy(group, policy)
}

// BuildSetLogging always refuses, for the reason the real backend gives.
func (f *Fake) BuildSetLogging(level string) (firewall.Change, error) {
	return (&Real{}).BuildSetLogging(level)
}

// Extras lists the nftables-specific actions.
func (f *Fake) Extras(_ firewall.Model, _ string) []firewall.Extra {
	return f.Ruleset().Extras()
}

// BuildExtra turns a collected action into its commands.
func (f *Fake) BuildExtra(_, id string, args []string) (firewall.Change, error) {
	return f.Ruleset().BuildExtra(id, args)
}
