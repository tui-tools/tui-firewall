package nftables

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// capabilities describes what the nftables backend supports. It is shared by
// the real and the fake backend so --demo behaves exactly like the real thing.
//
// Three of them are off for reasons worth stating. nftables has no on/off
// switch: a ruleset is either loaded or it is not, and loading and flushing
// one is not something a rule editor should be doing behind a single key.
// There is no global logging level either — logging in nftables is a
// statement on a rule. And a rule's direction is the chain it lives in, so
// the form does not ask for one.
var capabilities = firewall.Capabilities{
	Actions: []firewall.Action{
		firewall.ActionAllow, firewall.ActionDeny, firewall.ActionReject,
	},
	Policies:           []firewall.Policy{firewall.PolicyAllow, firewall.PolicyDeny},
	SupportsInsert:     true,
	SupportsComments:   true,
	SupportsFamily:     true,
	SupportsLog:        true,
	SupportsInterfaces: true,
	SupportsConntrack:  true,
	SupportsICMP:       true,
	SupportsEnable:     false,
	EnableHint: "nftables has no on/off switch: change a chain policy with p, " +
		"or load and flush the ruleset with your own nft commands",
	SupportsLogging: false,
	ServiceLabel:    "Alias (source)",
	GroupLabel:      "View",
}

// Capabilities reports what the nftables backend supports.
func Capabilities() firewall.Capabilities { return capabilities }

// verdictFor maps a family action onto the nft verdict that expresses it.
func verdictFor(action firewall.Action) (string, error) {
	switch action {
	case firewall.ActionAllow:
		return "accept", nil
	case firewall.ActionDeny:
		return "drop", nil
	case firewall.ActionReject:
		return "reject", nil
	case "":
		return "", errorf("an action is required")
	default:
		return "", errorf("nft has no verdict for %q; use %s, %s or %s",
			action, firewall.ActionAllow, firewall.ActionDeny, firewall.ActionReject)
	}
}

// policyWord maps a family policy onto the nft chain policy.
func policyWord(policy firewall.Policy) (string, error) {
	switch policy {
	case firewall.PolicyAllow:
		return PolicyAccept, nil
	case firewall.PolicyDeny:
		return PolicyDrop, nil
	default:
		return "", errorf("a base chain policy is %s or %s, not %q",
			firewall.PolicyAllow, firewall.PolicyDeny, policy)
	}
}

// checkMutable is the guard the spec turns on: this backend writes to a base
// chain whose policy nft actually reported, or to the table it owns, and
// nowhere else.
//
// The two exclusions are different refusals. A regular chain has no hook and
// no policy: a rule added there runs only if something else jumps to it, and
// this tool cannot see whether anything does, so it would be adding a rule
// whose effect it cannot describe. A table another tool manages is legible
// but not ours: the change would work and then be undone by the next reload
// of whatever wrote it.
func (r Ruleset) checkMutable(chain Chain) error {
	if chain.Table == OwnTable {
		return nil
	}
	management := DetectManagement(r)
	if management.Owns(chain.Table) {
		return errorf(
			"table %s belongs to %s: a rule added here is lost the next time "+
				"%s reloads, so this backend reads it and does not write to it",
			chain.Table, management.Manager, management.Manager)
	}
	if !chain.Base() {
		return errorf(
			"chain %s of table %s is a regular chain: it has no hook and no "+
				"policy, so a rule added here only runs if some other rule "+
				"jumps to it, which this backend cannot promise",
			chain.Name, chain.Table)
	}
	if chain.Policy == "" {
		return errorf(
			"nft reported no policy for base chain %s of table %s, so this "+
				"backend cannot say what happens to a packet the new rule "+
				"does not match", chain.Name, chain.Table)
	}
	return nil
}

// checkOwnTable is the guard for everything that is not a rule. Aliases and
// the chains that hold them are structure rather than policy, and this
// backend creates structure only inside the table it owns.
func (r Ruleset) checkOwnTable(id TableID) error {
	if id == OwnTable {
		return nil
	}
	return errorf(
		"aliases are created in %s, the table this tool owns, not in table "+
			"%s: a set added to somebody else's table outlives the rules "+
			"that used it and nothing would clean it up", OwnTable, id)
}

// BuildAddRule turns a RuleSpec into one `nft add rule` (or `nft insert
// rule`) invocation in the chain the group names.
func (r Ruleset) BuildAddRule(chain Chain, spec firewall.RuleSpec) (firewall.Change, error) {
	if err := r.checkMutable(chain); err != nil {
		return firewall.Change{}, err
	}
	expr, err := r.ruleExpression(chain, spec)
	if err != nil {
		return firewall.Change{}, err
	}

	verb, description := "add", "Add a rule to "+chain.Name
	argv := []string{"nft", verb, "rule"}
	argv = append(argv, chain.Table.Args()...)
	argv = append(argv, chain.Name)
	if spec.Position > 0 {
		// nft counts insert positions from zero, and the form asks for the
		// 1-based position the list shows.
		argv[1] = "insert"
		argv = append(argv, "index", strconv.Itoa(spec.Position-1))
		description = fmt.Sprintf("Insert a rule at position %d of %s",
			spec.Position, chain.Name)
	}
	argv = append(argv, expr...)

	return firewall.One(firewall.Command{Argv: argv, Description: description}), nil
}

// ruleExpression assembles the match and the statements of a new rule, in the
// order nft prints them, so the preview reads like the rule the list will
// show afterwards.
func (r Ruleset) ruleExpression(chain Chain, spec firewall.RuleSpec) ([]string, error) {
	verdict, err := verdictFor(spec.Action)
	if err != nil {
		return nil, err
	}
	if spec.Service != "" && spec.From != "" {
		return nil, errorf("give an alias or a source address, not both")
	}
	if spec.Direction != firewall.DirAny {
		return nil, errorf(
			"a rule's direction in nftables is the chain it lives in; " +
				"switch to the input, output or forward view instead of " +
				"setting a direction here")
	}
	if strings.ContainsAny(spec.Comment, "\n\r\"") {
		return nil, errorf("a comment is one line and carries no quotes")
	}

	source := spec.From
	if spec.Service != "" {
		if _, ok := r.Set(chain.Table, strings.TrimPrefix(spec.Service, "@")); !ok {
			return nil, errorf("table %s has no alias %s", chain.Table, spec.Service)
		}
		source = spec.Service
	}

	var expr []string
	// Interface matches lead the rule, the way nft prints them, so "SSH only
	// from the LAN side" reads left to right.
	ifaces, err := interfaceSelectors(spec.InIface, spec.OutIface)
	if err != nil {
		return nil, err
	}
	expr = append(expr, ifaces...)
	// The conntrack state comes next: a stateful rule is read "established,
	// related first, then what it lets through".
	ctState, err := ctStateSelector(spec.CTStates)
	if err != nil {
		return nil, err
	}
	expr = append(expr, ctState...)

	family, err := r.addressFamily(chain, spec.Family, source, spec.To)
	if err != nil {
		return nil, err
	}
	if source != "" {
		selector, err := addressSelector(family, "saddr", source)
		if err != nil {
			return nil, err
		}
		expr = append(expr, selector...)
	}
	if spec.To != "" {
		selector, err := addressSelector(family, "daddr", spec.To)
		if err != nil {
			return nil, err
		}
		expr = append(expr, selector...)
	}
	l4, err := protoSelector(chain, spec.Proto, spec.Ports, spec.ICMPType)
	if err != nil {
		return nil, err
	}
	expr = append(expr, l4...)
	if len(expr) == 0 {
		return nil, errorf(
			"give at least a port, an address, an alias, an interface, a " +
				"protocol or a connection state: a rule with no match at all " +
				"applies to every packet the chain sees")
	}

	if spec.Log {
		expr = append(expr, "log")
	}
	// Every rule this backend writes carries a counter. It costs a few
	// instructions per packet and it is the only way the rule list can answer
	// "is this rule doing anything", which is the first question anybody asks
	// of a firewall they did not write.
	expr = append(expr, "counter", verdict)
	if spec.Comment != "" {
		expr = append(expr, "comment", quote(spec.Comment))
	}
	return expr, nil
}

// LogPrefixMarker is the leader every log prefix this tool writes begins with.
// It is what the live log view greps the kernel log for, so it has to be short,
// stable and unlikely to collide with anything else's logging. The chain name
// and the verdict follow it, which is how the live view reads a packet's
// direction and the action the rule took off the prefix alone.
const LogPrefixMarker = "tui:"

// logPrefix builds the prefix a logged rule carries: the marker, the chain the
// rule lives in, and — when the rule decides — the verdict it applies. nft
// appends the packet's own fields straight after the prefix, so the trailing
// space keeps "tui:input drop" from running into "IN=eth0".
func logPrefix(chain, verdict string) string {
	prefix := LogPrefixMarker + chain + " "
	if verdict != "" {
		prefix += verdict + " "
	}
	return prefix
}

// BuildToggleLog turns per-rule logging on or off for a rule this backend owns.
//
// nftables rules are immutable: a statement cannot be added to one in place, so
// the only way to add or remove a log statement is to replace the whole rule.
// `nft replace rule … handle H …` does exactly that, keeping the handle and the
// position, and the replacement is rebuilt from the rule's own modelled match
// so the preview shows precisely the rule that will stand afterwards. A rule the
// model does not hold in full — one carrying a match this package renders only
// as text, a NAT translation, or a verdict other than accept/drop/reject — is
// refused rather than rebuilt from a rendering that might drop half of it.
func (r Ruleset) BuildToggleLog(chain Chain, target Rule) (firewall.Change, error) {
	if err := r.checkMutable(chain); err != nil {
		return firewall.Change{}, err
	}
	if target.Handle <= 0 {
		return firewall.Change{}, errorf(
			"this rule has no handle, so there is no safe way to name it to nft; " +
				"re-read the ruleset with R")
	}
	expr, err := logToggleExpr(chain, target)
	if err != nil {
		return firewall.Change{}, err
	}

	argv := []string{"nft", "replace", "rule"}
	argv = append(argv, chain.Table.Args()...)
	argv = append(argv, chain.Name, "handle", strconv.Itoa(target.Handle))
	argv = append(argv, expr...)

	action := "Log matches of"
	if target.Match.Log {
		action = "Stop logging"
	}
	return firewall.One(firewall.Command{
		Argv: argv,
		Description: fmt.Sprintf("%s rule handle %d in %s",
			action, target.Handle, chain.Name),
		// Replacing a rule resets its counter; that is a change worth the danger
		// colour even though it neither opens nor closes the firewall.
		Destructive: true,
	}), nil
}

// logToggleExpr rebuilds a rule's whole expression with its logging flipped:
// the log statement added when the rule does not log, removed when it does. The
// statements come out in the order nft prints them, the same order the add-rule
// builder uses, so the replacement reads like the rule the list will show.
func logToggleExpr(chain Chain, rule Rule) ([]string, error) {
	m := rule.Match
	if m.NAT != nil {
		return nil, errorf(
			"rule handle %d translates addresses; logging is toggled from the "+
				"filter views, not the NAT one", rule.Handle)
	}
	if len(m.Unmodeled) > 0 {
		return nil, errorf(
			"rule handle %d carries a match this tool shows only as text (%s), so "+
				"it cannot be rebuilt safely to toggle logging; edit it with nft "+
				"directly", rule.Handle, strings.Join(m.Unmodeled, "; "))
	}
	switch m.Verdict {
	case "accept", "drop", "reject", "":
	default:
		return nil, errorf(
			"per-rule logging is toggled on accept, drop and reject rules; rule "+
				"handle %d is a %q rule", rule.Handle, m.Verdict)
	}

	var expr []string
	ifaces, err := interfaceSelectors(m.IIF, m.OIF)
	if err != nil {
		return nil, err
	}
	expr = append(expr, ifaces...)
	if m.CTState != "" {
		expr = append(expr, "ct", "state", m.CTState)
	}

	addrs, err := addressExprs(chain, m)
	if err != nil {
		return nil, err
	}
	expr = append(expr, addrs...)

	l4, err := protoExprs(chain, m)
	if err != nil {
		return nil, err
	}
	expr = append(expr, l4...)

	// The toggle: add the log statement when the rule does not log, drop it when
	// it does. A rule that logs and nothing else keeps its bare counter.
	if !m.Log {
		expr = append(expr, "log", "prefix", quote(logPrefix(chain.Name, m.Verdict)))
	}
	expr = append(expr, "counter")

	verdict, err := verdictExpr(m)
	if err != nil {
		return nil, err
	}
	expr = append(expr, verdict...)

	if rule.Comment != "" {
		if strings.ContainsAny(rule.Comment, "\n\r\"") {
			return nil, errorf("rule handle %d has a comment nft would not "+
				"round-trip", rule.Handle)
		}
		expr = append(expr, "comment", quote(rule.Comment))
	}
	if len(expr) == 0 {
		return nil, errorf(
			"rule handle %d has no match this tool models, so toggling its log "+
				"would rewrite it as a match-everything rule", rule.Handle)
	}
	return expr, nil
}

// addressExprs rebuilds the saddr and daddr matches of a modelled rule, with
// the address-family header nft prints in front of each.
func addressExprs(chain Chain, m Match) ([]string, error) {
	var expr []string
	for _, addr := range []struct {
		field string
		value string
	}{{"saddr", m.Saddr}, {"daddr", m.Daddr}} {
		if addr.value == "" {
			continue
		}
		header := addrHeader(chain, m)
		if header == "" {
			return nil, errorf(
				"could not tell which address family %q belongs to, so the rule "+
					"cannot be rebuilt to toggle its log", addr.value)
		}
		selector, err := addressSelector(header, addr.field, addr.value)
		if err != nil {
			return nil, err
		}
		expr = append(expr, selector...)
	}
	return expr, nil
}

// addrHeader picks the `ip`/`ip6` header word a rebuilt address match needs:
// the table's own family when it has one, otherwise the family the rule's
// operands pinned it to.
func addrHeader(chain Chain, m Match) string {
	switch chain.Table.Family {
	case "ip":
		return "ip"
	case "ip6":
		return "ip6"
	}
	switch m.Family() {
	case "v4":
		return "ip"
	case "v6":
		return "ip6"
	}
	return ""
}

// protoExprs rebuilds the layer-4 match of a modelled rule: the ICMP forms, a
// port match, or a bare protocol.
func protoExprs(chain Chain, m Match) ([]string, error) {
	switch m.Proto {
	case "icmp", "icmpv6":
		return icmpSelector(chain, m.Proto, "", m.ICMPType)
	}
	if m.ICMPType != "" {
		return nil, errorf("an ICMP type only applies to the icmp and icmpv6 protocols")
	}
	if m.DPort != "" {
		return portMatchExpr(m.Proto, "dport", m.DPort)
	}
	if m.SPort != "" {
		return portMatchExpr(m.Proto, "sport", m.SPort)
	}
	if m.Proto != "" {
		if err := checkOperand(m.Proto); err != nil {
			return nil, err
		}
		return []string{"meta", "l4proto", m.Proto}, nil
	}
	return nil, nil
}

// portMatchExpr rebuilds a `tcp dport …` match from the port the model holds,
// whichever shape nft printed it in: a single value, a range, an alias, or the
// braced set the reader renders as "{ 80, 443 }".
func portMatchExpr(proto, field, port string) ([]string, error) {
	if proto == "" {
		return nil, errorf("a port match needs a protocol")
	}
	if err := checkOperand(proto); err != nil {
		return nil, err
	}
	value := strings.TrimSpace(port)
	if inner, ok := strings.CutPrefix(value, "{"); ok {
		// A braced set the reader rendered as "{ 80, 443 }" is rebuilt element
		// by element, each a word of its own the way the add-rule builder emits
		// them, so no operand can smuggle nft syntax through.
		inner = strings.TrimSuffix(inner, "}")
		argv := []string{proto, field, "{"}
		items := strings.Split(inner, ",")
		for i, item := range items {
			item = strings.TrimSpace(item)
			if item == "" {
				return nil, errorf("empty value in port set %q", port)
			}
			if err := checkOperand(item); err != nil {
				return nil, err
			}
			if i < len(items)-1 {
				item += ","
			}
			argv = append(argv, item)
		}
		return append(argv, "}"), nil
	}
	if err := checkOperand(value); err != nil {
		return nil, err
	}
	return []string{proto, field, value}, nil
}

// verdictExpr rebuilds a rule's terminal statement. A reject keeps the answer
// it sends, which is why RejectWith is modelled at all.
func verdictExpr(m Match) ([]string, error) {
	switch m.Verdict {
	case "accept", "drop":
		return []string{m.Verdict}, nil
	case "reject":
		expr := []string{"reject"}
		for _, word := range strings.Fields(m.RejectWith) {
			if err := checkOperand(word); err != nil {
				return nil, err
			}
			expr = append(expr, word)
		}
		return expr, nil
	case "":
		// A rule that only logs has no verdict of its own; it falls through to
		// the chain policy, which is what the fixture's tail log rule does.
		return nil, nil
	default:
		return nil, errorf("cannot rebuild a %q verdict", m.Verdict)
	}
}

// addressFamily decides which header a rule's address matches read from. In
// an `inet` table both families share one chain, so an address match has to
// say which one it means; in an `ip` or `ip6` table the table has already
// said it.
//
// When the family was not asked for, it is read off the operands themselves:
// a literal address carries its family, and an alias carries it in the set's
// own element type (ipv4_addr → ip, ipv6_addr → ip6). Only a rule whose only
// address operand is a port set or a concatenation — neither of which names a
// family — still has to be told.
func (r Ruleset) addressFamily(chain Chain, requested firewall.Family, from, to string) (string, error) {
	switch chain.Table.Family {
	case "ip":
		return "ip", nil
	case "ip6":
		return "ip6", nil
	}
	switch requested {
	case firewall.FamilyIPv4:
		return "ip", nil
	case firewall.FamilyIPv6:
		return "ip6", nil
	}
	// Nothing was asked for: read it off the operands. A rule that mixes a v4
	// and a v6 operand cannot be one address match, and saying so beats letting
	// nft reject the second half.
	seen := firewall.FamilyAny
	for _, operand := range []string{from, to} {
		f := r.operandFamily(chain.Table, operand)
		if f == firewall.FamilyAny {
			continue
		}
		if seen != firewall.FamilyAny && seen != f {
			return "", errorf(
				"this rule matches a v4 operand and a v6 one, which is two "+
					"rules; %q and %q cannot share one", from, to)
		}
		seen = f
	}
	switch seen {
	case firewall.FamilyIPv6:
		return "ip6", nil
	case firewall.FamilyIPv4:
		return "ip", nil
	}
	if from == "" && to == "" {
		return "", nil
	}
	return "", errorf(
		"table %s holds both address families, so an alias of ports or a "+
			"concatenation needs the family field set to v4 or v6", chain.Table)
}

// operandFamily reads the address family off one operand: a set's own element
// type when it is an alias, the literal's family otherwise.
func (r Ruleset) operandFamily(table TableID, operand string) firewall.Family {
	if name, ok := strings.CutPrefix(operand, "@"); ok {
		if set, found := r.Set(table, name); found {
			switch set.Type {
			case "ipv4_addr":
				return firewall.FamilyIPv4
			case "ipv6_addr":
				return firewall.FamilyIPv6
			}
		}
		return firewall.FamilyAny
	}
	return inferFamily(operand)
}

// interfaceSelectors renders `iifname "wan0"` and `oifname "lan0"`. nft matches
// an interface by name with iifname/oifname, which — unlike iif/oif — do not
// need the interface to exist when the rule is written.
func interfaceSelectors(in, out string) ([]string, error) {
	var expr []string
	for _, iface := range []struct {
		keyword string
		value   string
	}{{"iifname", in}, {"oifname", out}} {
		if iface.value == "" {
			continue
		}
		if err := checkOperand(iface.value); err != nil {
			return nil, err
		}
		expr = append(expr, iface.keyword, quote(iface.value))
	}
	return expr, nil
}

// ctStates are the connection-tracking states nft accepts. untracked is left
// out of the form on purpose: it means "no conntrack entry", which is a rule
// for a machine that has turned conntrack off, not the stateful firewall the
// form is for.
var ctStates = []string{"established", "related", "new", "invalid"}

// ctStateSelector renders `ct state established,related`. The states are joined
// with a comma into one operand, which is nft's own spelling for a set of
// states, so the preview reads exactly like the rule the list shows afterwards.
func ctStateSelector(states []string) ([]string, error) {
	if len(states) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	ordered := make([]string, 0, len(states))
	for _, state := range states {
		state = strings.TrimSpace(state)
		if state == "" {
			continue
		}
		if !contains(ctStates, state) {
			return nil, errorf("a connection state is one of %s, not %q",
				strings.Join(ctStates, ", "), state)
		}
		if seen[state] {
			continue
		}
		seen[state] = true
		ordered = append(ordered, state)
	}
	if len(ordered) == 0 {
		return nil, nil
	}
	return []string{"ct", "state", strings.Join(ordered, ",")}, nil
}

// protoSelector renders the layer-4 match: a port for tcp and udp, the ICMP
// forms for icmp and icmpv6, and `meta l4proto` for anything else with no port.
func protoSelector(chain Chain, proto, ports, icmpType string) ([]string, error) {
	switch proto {
	case "icmp", "icmpv6":
		return icmpSelector(chain, proto, ports, icmpType)
	}
	if icmpType != "" {
		return nil, errorf("an ICMP type only applies to the icmp and icmpv6 protocols")
	}
	return portSelector(proto, ports)
}

// icmpSelector renders `ip protocol icmp` / `ip6 nexthdr ipv6-icmp`, with an
// optional `icmp type echo-request`. The header word is the family's own, so
// the match is refused in a table of the other family rather than accepted and
// then rejected by nft.
func icmpSelector(chain Chain, proto, ports, icmpType string) ([]string, error) {
	if ports != "" {
		return nil, errorf("%s carries no port; leave the port field empty", proto)
	}
	var expr []string
	var typeKeyword string
	switch proto {
	case "icmp":
		if family := chain.Table.Family; family == "ip6" {
			return nil, errorf(
				"icmp is the v4 protocol; table %s is v6, so use icmpv6", chain.Table)
		}
		expr, typeKeyword = []string{"ip", "protocol", "icmp"}, "icmp"
	case "icmpv6":
		if family := chain.Table.Family; family == "ip" {
			return nil, errorf(
				"icmpv6 is the v6 protocol; table %s is v4, so use icmp", chain.Table)
		}
		expr, typeKeyword = []string{"ip6", "nexthdr", "ipv6-icmp"}, "icmpv6"
	}
	if icmpType != "" {
		if err := checkOperand(icmpType); err != nil {
			return nil, err
		}
		expr = append(expr, typeKeyword, "type", icmpType)
	}
	return expr, nil
}

// inferFamily reads an address family off a literal address or prefix.
func inferFamily(address string) firewall.Family {
	if address == "" || strings.HasPrefix(address, "@") {
		return firewall.FamilyAny
	}
	literal, _, found := strings.Cut(address, "/")
	if !found {
		literal = address
	}
	ip := net.ParseIP(literal)
	switch {
	case ip == nil:
		return firewall.FamilyAny
	case ip.To4() != nil:
		return firewall.FamilyIPv4
	default:
		return firewall.FamilyIPv6
	}
}

// addressSelector renders `ip saddr X` / `ip6 daddr @alias`.
func addressSelector(family, field, address string) ([]string, error) {
	if family == "" {
		return nil, errorf("could not tell which address family %q is", address)
	}
	if err := checkOperand(address); err != nil {
		return nil, err
	}
	return []string{family, field, address}, nil
}

// portSelector renders `tcp dport 22`, or the set form for a list.
func portSelector(proto, ports string) ([]string, error) {
	switch {
	case ports == "" && proto == "":
		return nil, nil
	case ports == "" && proto != "":
		// A protocol with no port is still a rule worth writing.
		if err := checkOperand(proto); err != nil {
			return nil, err
		}
		return []string{"meta", "l4proto", proto}, nil
	case proto == "":
		return nil, errorf("a port needs a protocol: pick tcp or udp")
	}
	if err := checkOperand(proto); err != nil {
		return nil, err
	}
	if err := checkOperand(ports); err != nil {
		return nil, err
	}
	// nft spells a range with a dash and a list with braces; the form takes
	// the family's own spelling ("2000:2100", "80,443") and this is where it
	// is translated.
	value := strings.ReplaceAll(ports, ":", "-")
	if strings.Contains(value, ",") {
		items := strings.Split(value, ",")
		argv := []string{proto, "dport", "{"}
		for i, item := range items {
			item = strings.TrimSpace(item)
			if item == "" {
				return nil, errorf("empty port in %q", ports)
			}
			if i < len(items)-1 {
				item += ","
			}
			argv = append(argv, item)
		}
		return append(argv, "}"), nil
	}
	return []string{proto, "dport", value}, nil
}

// checkOperand refuses anything that would end the statement early or hide a
// second command inside one argv word. nft joins its arguments into one
// buffer and parses that, so a semicolon or a newline in an operand is the
// nftables equivalent of a shell injection.
func checkOperand(value string) error {
	if value == "" {
		return errorf("empty value")
	}
	if strings.ContainsAny(value, ";\n\r\"'{}\\") {
		return errorf("%q contains a character nft would read as syntax", value)
	}
	return nil
}

// quote wraps a value in the double quotes nft's own grammar wants. The quotes
// are part of the argv word because nft concatenates its arguments and parses
// the result: an unquoted comment with a space in it is a syntax error, not a
// comment.
func quote(value string) string { return "\"" + value + "\"" }

// BuildDeleteRule removes a rule by its handle, which is the only identifier
// that survives another rule being inserted above it.
func (r Ruleset) BuildDeleteRule(chain Chain, rule firewall.Rule) (firewall.Change, error) {
	if err := r.checkMutable(chain); err != nil {
		return firewall.Change{}, err
	}
	handle, err := strconv.Atoi(rule.ID)
	if err != nil || handle <= 0 {
		return firewall.Change{}, errorf(
			"this rule has no handle (%q), so there is no safe way to name it "+
				"to nft; re-read the ruleset with R", rule.ID)
	}
	argv := []string{"nft", "delete", "rule"}
	argv = append(argv, chain.Table.Args()...)
	argv = append(argv, chain.Name, "handle", strconv.Itoa(handle))
	return firewall.One(firewall.Command{
		Argv:        argv,
		Description: fmt.Sprintf("Delete rule handle %d from %s", handle, chain.Name),
		Destructive: true,
	}), nil
}

// BuildSetPolicy changes the policy of a base chain. nft takes the change on
// its own: the chain keeps the type, hook and priority it already has.
func (r Ruleset) BuildSetPolicy(chain Chain, policy firewall.Policy) (firewall.Change, error) {
	if err := r.checkMutable(chain); err != nil {
		return firewall.Change{}, err
	}
	if !chain.Base() {
		return firewall.Change{}, errorf(
			"chain %s has no hook, so it has no policy to change", chain.Name)
	}
	word, err := policyWord(policy)
	if err != nil {
		return firewall.Change{}, err
	}
	argv := []string{"nft", "chain"}
	argv = append(argv, chain.Table.Args()...)
	argv = append(argv, chain.Name, "{", "policy", word, ";", "}")
	return firewall.One(firewall.Command{
		Argv: argv,
		Description: fmt.Sprintf("Set the policy of %s to %s",
			chain.Name, word),
		Destructive: true,
	}), nil
}

// BuildCreateTable creates the table this tool owns, which is what has to
// exist before it can create an alias or a NAT rule of its own.
func BuildCreateTable() firewall.Change {
	argv := append([]string{"nft", "add", "table"}, OwnTable.Args()...)
	return firewall.One(firewall.Command{
		Argv:        argv,
		Description: "Create table " + OwnTable.String(),
	})
}

// The set types this backend offers, which are the ones an alias means:
// addresses of either family, and service ports.
var setTypes = []string{"ipv4_addr", "ipv6_addr", "inet_service"}

// BuildCreateSet creates a named set: an alias.
func (r Ruleset) BuildCreateSet(table TableID, name, setType string,
	interval bool, comment string) (firewall.Change, error) {
	if err := r.checkOwnTable(table); err != nil {
		return firewall.Change{}, err
	}
	if _, ok := r.Table(table); !ok {
		return firewall.Change{}, errorf(
			"table %s does not exist yet; create it first with the "+
				"\"Create table\" action", table)
	}
	if err := checkSetName(name); err != nil {
		return firewall.Change{}, err
	}
	if _, exists := r.Set(table, name); exists {
		return firewall.Change{}, errorf("table %s already has an alias %q",
			table, name)
	}
	if !contains(setTypes, setType) {
		return firewall.Change{}, errorf("an alias holds one of %s, not %q",
			strings.Join(setTypes, ", "), setType)
	}
	if strings.ContainsAny(comment, "\n\r\"") {
		return firewall.Change{}, errorf("a comment is one line and carries no quotes")
	}

	argv := []string{"nft", "add", "set"}
	argv = append(argv, table.Args()...)
	argv = append(argv, name, "{", "type", setType, ";")
	if interval {
		// Without the interval flag a set holds single values only, and
		// "10.0.0.0/8" or "9090-9095" is refused on the first element.
		argv = append(argv, "flags", "interval", ";")
	}
	if comment != "" {
		argv = append(argv, "comment", quote(comment), ";")
	}
	argv = append(argv, "}")

	return firewall.One(firewall.Command{
		Argv:        argv,
		Description: fmt.Sprintf("Create alias %s in %s", name, table),
	}), nil
}

// BuildDeleteSet removes an alias. A set that rules still refer to is refused:
// nft would refuse it too, and saying so before the command runs is the point
// of counting the references in the first place.
func (r Ruleset) BuildDeleteSet(table TableID, name string) (firewall.Change, error) {
	if err := r.checkOwnTable(table); err != nil {
		return firewall.Change{}, err
	}
	set, ok := r.Set(table, name)
	if !ok {
		return firewall.Change{}, errorf("table %s has no alias %q", table, name)
	}
	if set.References > 0 {
		return firewall.Change{}, errorf(
			"alias %s is used by %s; delete those first",
			name, plural(set.References, "rule"))
	}
	argv := []string{"nft", "delete", "set"}
	argv = append(argv, table.Args()...)
	argv = append(argv, name)
	return firewall.One(firewall.Command{
		Argv:        argv,
		Description: "Delete alias " + name,
		Destructive: true,
	}), nil
}

// BuildAddElement adds one member to an alias.
func (r Ruleset) BuildAddElement(table TableID, name, element string) (firewall.Change, error) {
	return r.buildElement(table, name, element, "add")
}

// BuildRemoveElement removes one member from an alias.
func (r Ruleset) BuildRemoveElement(table TableID, name, element string) (firewall.Change, error) {
	return r.buildElement(table, name, element, "delete")
}

// buildElement is the shared half of the two element commands.
func (r Ruleset) buildElement(table TableID, name, element, verb string) (firewall.Change, error) {
	if err := r.checkOwnTable(table); err != nil {
		return firewall.Change{}, err
	}
	set, ok := r.Set(table, name)
	if !ok {
		return firewall.Change{}, errorf("table %s has no alias %q", table, name)
	}
	element = strings.TrimSpace(element)
	if err := checkOperand(element); err != nil {
		return firewall.Change{}, err
	}
	if !set.Interval() && strings.ContainsAny(element, "/-") {
		return firewall.Change{}, errorf(
			"alias %s holds single values: it was created without the "+
				"interval flag, so it cannot hold %q", name, element)
	}

	argv := []string{"nft", verb, "element"}
	argv = append(argv, table.Args()...)
	argv = append(argv, name, "{", element, "}")

	description := "Add " + element + " to alias " + name
	if verb == "delete" {
		description = "Remove " + element + " from alias " + name
	}
	return firewall.One(firewall.Command{
		Argv:        argv,
		Description: description,
		Destructive: verb == "delete",
	}), nil
}

// BuildMasquerade adds a masquerade rule for an outgoing interface: every
// packet leaving through it is rewritten to the router's own address. An
// optional source network scopes it to one subnet, so a router that
// masquerades one LAN and routes another cleanly does not have to.
func (r Ruleset) BuildMasquerade(chain Chain, iface, source string) (firewall.Change, error) {
	if err := r.checkNATChain(chain, "postrouting"); err != nil {
		return firewall.Change{}, err
	}
	if err := checkOperand(iface); err != nil {
		return firewall.Change{}, err
	}
	argv := []string{"nft", "add", "rule"}
	argv = append(argv, chain.Table.Args()...)
	comment := "masquerade out " + iface
	if source != "" {
		family, err := r.addressFamily(chain, "", source, "")
		if err != nil {
			return firewall.Change{}, err
		}
		selector, err := addressSelector(family, "saddr", source)
		if err != nil {
			return firewall.Change{}, err
		}
		argv = append(argv, chain.Name)
		argv = append(argv, selector...)
		argv = append(argv, "oifname", quote(iface))
		comment = "masquerade " + source + " out " + iface
	} else {
		argv = append(argv, chain.Name, "oifname", quote(iface))
	}
	argv = append(argv, "counter", "masquerade", "comment", quote(comment))
	description := "Masquerade everything leaving " + iface
	if source != "" {
		description = "Masquerade " + source + " leaving " + iface
	}
	return firewall.One(firewall.Command{
		Argv:        argv,
		Description: description,
		Destructive: true,
	}), nil
}

// BuildDeleteChain removes a chain of the table this tool owns. nft refuses to
// delete a chain that still holds rules, so a chain with rules is refused here
// too — with the count, so the user knows what they would be dropping — unless
// the caller has already confirmed the cascade with force.
func (r Ruleset) BuildDeleteChain(chain Chain, force bool) (firewall.Change, error) {
	if err := r.checkOwnTable(chain.Table); err != nil {
		return firewall.Change{}, err
	}
	found, ok := r.Chain(chain.Table, chain.Name)
	if !ok {
		return firewall.Change{}, errorf("table %s has no chain %s",
			chain.Table, chain.Name)
	}
	var commands []firewall.Command
	note := ""
	if len(found.Rules) > 0 {
		if !force {
			return firewall.Change{}, errorf(
				"chain %s still holds %s; delete those first, or confirm the "+
					"cascade", chain.Name, plural(len(found.Rules), "rule"))
		}
		// nft will not delete a chain with rules in it, so a forced delete
		// flushes the chain first. Both lines are shown; both run in order.
		flush := []string{"nft", "flush", "chain"}
		flush = append(flush, chain.Table.Args()...)
		flush = append(flush, chain.Name)
		commands = append(commands, firewall.Command{
			Argv:        flush,
			Description: "Flush the rules of " + chain.Name,
			Destructive: true,
		})
		note = "the chain holds " + plural(len(found.Rules), "rule") +
			", flushed first because nft will not delete a chain that has any"
	}
	del := []string{"nft", "delete", "chain"}
	del = append(del, chain.Table.Args()...)
	del = append(del, chain.Name)
	commands = append(commands, firewall.Command{
		Argv:        del,
		Description: "Delete chain " + chain.Name + " from " + chain.Table.String(),
		Destructive: true,
	})
	return firewall.Change{
		Description: "Delete chain " + chain.Name,
		Destructive: true,
		Commands:    commands,
		Note:        note,
	}, nil
}

// BuildDeleteTable drops the whole table this tool owns, with every chain, set
// and rule in it. It is refused for any other table: a table this backend did
// not create is one it reads and never removes.
func (r Ruleset) BuildDeleteTable(id TableID) (firewall.Change, error) {
	if err := r.checkOwnTable(id); err != nil {
		return firewall.Change{}, err
	}
	if _, ok := r.Table(id); !ok {
		return firewall.Change{}, errorf("there is no table %s to delete", id)
	}
	argv := []string{"nft", "delete", "table"}
	argv = append(argv, id.Args()...)
	return firewall.One(firewall.Command{
		Argv: argv,
		Description: "Delete table " + id.String() +
			" and everything in it",
		Destructive: true,
	}), nil
}

// BuildPortForward adds a DNAT rule: a port on the router's own address is
// answered by a host behind it.
func (r Ruleset) BuildPortForward(chain Chain, iface, proto, port,
	toAddr, toPort string) (firewall.Change, error) {
	if err := r.checkNATChain(chain, "prerouting"); err != nil {
		return firewall.Change{}, err
	}
	if proto != "tcp" && proto != "udp" {
		return firewall.Change{}, errorf("a port forward is tcp or udp, not %q", proto)
	}
	for _, value := range []string{iface, port, toAddr, toPort} {
		if err := checkOperand(value); err != nil {
			return firewall.Change{}, err
		}
	}
	if _, err := strconv.Atoi(port); err != nil {
		return firewall.Change{}, errorf("the incoming port must be a number, not %q", port)
	}
	if _, err := strconv.Atoi(toPort); err != nil {
		return firewall.Change{}, errorf("the target port must be a number, not %q", toPort)
	}
	family := inferFamily(toAddr)
	if family == firewall.FamilyAny {
		return firewall.Change{}, errorf("%q is not an address a packet can be sent to", toAddr)
	}
	target := toAddr + ":" + toPort
	if family == firewall.FamilyIPv6 {
		// nft wants the brackets around a v6 address that carries a port.
		target = "[" + toAddr + "]:" + toPort
	}

	argv := []string{"nft", "add", "rule"}
	argv = append(argv, chain.Table.Args()...)
	argv = append(argv, chain.Name, "iifname", quote(iface), proto, "dport", port,
		"counter", "dnat")
	// In an inet table dnat has to say which family it translates to; in an
	// ip or ip6 table the table has already said it, and repeating it is a
	// syntax error.
	if chain.Table.Family == "inet" {
		argv = append(argv, familyWord(family))
	}
	argv = append(argv, "to", target, "comment",
		quote(proto+" "+port+" to "+toAddr+":"+toPort))

	return firewall.One(firewall.Command{
		Argv: argv,
		Description: fmt.Sprintf("Forward %s/%s on %s to %s",
			port, proto, iface, target),
		Destructive: true,
	}), nil
}

// familyWord is nft's word for an address family.
func familyWord(f firewall.Family) string {
	if f == firewall.FamilyIPv6 {
		return "ip6"
	}
	return "ip"
}

// checkNATChain applies the mutation guard and then makes sure the chain is
// the NAT hook the caller meant: a masquerade in prerouting and a dnat in
// postrouting are both accepted by nft and neither does anything.
func (r Ruleset) checkNATChain(chain Chain, hook string) error {
	if err := r.checkMutable(chain); err != nil {
		return err
	}
	if chain.Type != "nat" {
		return errorf("chain %s of table %s is a %s chain, and address "+
			"translation only happens in a nat chain",
			chain.Name, chain.Table, orRegular(chain.Type))
	}
	if chain.Hook != hook {
		return errorf("this belongs in a nat chain hooked at %s, and %s is "+
			"hooked at %s", hook, chain.Name, chain.Hook)
	}
	return nil
}

// orRegular names a chain with no type at all.
func orRegular(kind string) string {
	if kind == "" {
		return "regular"
	}
	return kind
}

// contains reports whether a slice holds a value.
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// plural renders a count with its noun.
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// checkSetName refuses a name nft would not take, before the command is built.
func checkSetName(name string) error {
	if name == "" {
		return errorf("an alias needs a name")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return errorf(
				"an alias name holds letters, digits, underscores and "+
					"dashes; %q does not", name)
		}
	}
	return nil
}
