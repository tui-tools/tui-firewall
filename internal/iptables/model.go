package iptables

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// State is everything one Load reads: the running rules of both families,
// and what the persistence layer would restore at boot.
type State struct {
	V4 Dump `json:"v4"`
	// V6 is empty when ip6tables is not installed or has nothing loaded.
	V6 Dump `json:"v6"`
	// HasV6 reports whether ip6tables-save could be read at all.
	HasV6       bool        `json:"hasV6"`
	Persistence Persistence `json:"persistence"`
}

// Dump returns the running dump of a family.
func (s State) Dump(family Family) Dump {
	if family == V6 {
		return s.V6
	}
	return s.V4
}

// groupSeparator divides the table from the chain in a group name. A chain
// name cannot carry a space, so the split is unambiguous.
const groupSeparator = " / "

// GroupName is the identifier of the group that shows one chain. It spells
// the table the way nft does — "ip filter / INPUT" — because on an
// iptables-nft machine that is literally the nft table the rules live in, and
// the nftables backend names the same chain the same way.
func GroupName(family Family, table, chain string) string {
	return family.NftFamily() + " " + table + groupSeparator + chain
}

// ParseGroup splits a group name back into its family, table and chain.
func ParseGroup(group string) (Family, string, string, error) {
	head, chain, ok := strings.Cut(group, groupSeparator)
	if !ok || chain == "" {
		return "", "", "", errorf("%q is not a chain of this backend", group)
	}
	fam, table, ok := strings.Cut(head, " ")
	if !ok || table == "" {
		return "", "", "", errorf("%q is not a chain of this backend", group)
	}
	switch fam {
	case "ip":
		return V4, table, chain, nil
	case "ip6":
		return V6, table, chain, nil
	default:
		return "", "", "", errorf("%q is not a chain of this backend", group)
	}
}

// builtinOrder is the order the filter chains are shown in: what arrives,
// what is routed through, what leaves.
var builtinOrder = []string{ChainInput, ChainForward, ChainOutput}

// Model renders the state as the picture the UI draws: one group per
// built-in filter chain of each family, then every other chain that holds a
// rule, read-only.
func Model(state State) firewall.Model {
	model := firewall.Model{
		Backend: "iptables",
		Enabled: state.filtering(),
	}
	families := []Family{V4}
	if state.HasV6 {
		families = append(families, V6)
	}
	// The built-in filter chains first, v4 and v6 side by side: they are
	// where this backend writes, and the pair is what a reader compares.
	for _, name := range builtinOrder {
		for _, family := range families {
			dump := state.Dump(family)
			chain, ok := dump.Chain(TableFilter, name)
			if !ok {
				// A family with no filter table yet still has the chain as
				// far as the kernel is concerned: empty, policy ACCEPT.
				chain = Chain{Name: name, Policy: TargetAccept}
			}
			model.Groups = append(model.Groups, chainGroup(family, TableFilter, chain))
		}
	}
	// Then every other chain that holds a rule, filter first.
	for _, family := range families {
		dump := state.Dump(family)
		for _, table := range orderedTables(dump) {
			for _, chain := range table.Chains {
				if table.Name == TableFilter && isFilterBuiltin(chain.Name) {
					continue
				}
				if len(chain.Rules) == 0 {
					continue
				}
				model.Groups = append(model.Groups, chainGroup(family, table.Name, chain))
			}
		}
	}
	model.Warning = state.warning()
	return model
}

// orderedTables returns the tables of a dump with filter first, the rest in
// the order the dump listed them.
func orderedTables(d Dump) []Table {
	out := make([]Table, 0, len(d.Tables))
	if t, ok := d.Table(TableFilter); ok {
		out = append(out, t)
	}
	for _, t := range d.Tables {
		if t.Name != TableFilter {
			out = append(out, t)
		}
	}
	return out
}

// isFilterBuiltin reports whether a chain is one of the three built-in chains
// of the filter table, which are the only chains this backend writes to.
func isFilterBuiltin(name string) bool {
	return name == ChainInput || name == ChainForward || name == ChainOutput
}

// filtering reports whether anything filters at all: a built-in filter chain
// that drops by default or carries a rule. iptables has no on/off switch, so
// this is what the header's status fact is read from.
func (s State) filtering() bool {
	for _, family := range []Family{V4, V6} {
		table, ok := s.Dump(family).Table(TableFilter)
		if !ok {
			continue
		}
		for _, chain := range table.Chains {
			if !chain.Builtin() {
				continue
			}
			if chain.Policy == TargetDrop || len(chain.Rules) > 0 {
				return true
			}
		}
	}
	return false
}

// warning is the banner the state wants shown: legacy tables loaded beside
// the nf_tables ones, which filter packets this backend neither shows nor
// changes, or a saved file that could not be read.
func (s State) warning() string {
	var parts []string
	for _, family := range []Family{V4, V6} {
		for _, w := range s.Dump(family).Warnings {
			if strings.Contains(w, "legacy tables present") {
				parts = append(parts, "this host also has iptables-legacy tables "+
					"loaded ("+family.Binary()+"-legacy-save lists them): they "+
					"filter packets too, and this backend neither shows nor changes them")
				break
			}
		}
	}
	if s.Persistence.ReadErr != "" {
		parts = append(parts, s.Persistence.ReadErr)
	}
	return strings.Join(parts, "  ·  ")
}

// chainGroup renders one chain as a group.
func chainGroup(family Family, table string, chain Chain) firewall.Group {
	title := chain.Name + " (" + family.Binary()
	if table != TableFilter {
		title += " " + table
	}
	title += ")"
	group := firewall.Group{
		Name:        GroupName(family, table, chain.Name),
		Title:       title,
		Description: describeChain(table, chain),
		View:        firewall.ViewRules,
	}
	if table == TableFilter {
		if slot := policySlot(chain.Name); slot != "" && chain.Builtin() {
			group.PolicySlots = []firewall.PolicyDirection{slot}
			setPolicy(&group.Default, slot, chain.Policy)
		}
	}
	if err := checkWritable(table, chain); err != nil {
		group.Description += "  ·  read-only: " + strings.TrimPrefix(err.Error(), "iptables: ")
	}
	direction := directionOf(chain.Name)
	for _, rule := range chain.Rules {
		group.Rules = append(group.Rules, renderRule(family, rule, direction))
	}
	return group
}

// describeChain is the one-line header of a chain view: its policy, and where
// a new rule would land.
func describeChain(table string, chain Chain) string {
	if !chain.Builtin() {
		line := "user chain, reached by a jump"
		if daemon := DaemonOf(chain.Name); daemon != "" {
			line += "; created by " + daemon
		}
		return line
	}
	line := "policy " + chain.Policy
	if table != TableFilter {
		return line
	}
	if at, rule := chain.CatchAll(); at > 0 {
		line += fmt.Sprintf("; catch-all %s at rule %d, new rules go before it",
			rule.Match.Target, at)
	}
	return line
}

// policySlot maps a built-in filter chain onto the policy slot the header
// shows it in.
func policySlot(chain string) firewall.PolicyDirection {
	switch chain {
	case ChainInput:
		return firewall.PolicyIncoming
	case ChainOutput:
		return firewall.PolicyOutgoing
	case ChainForward:
		return firewall.PolicyRouted
	default:
		return ""
	}
}

// setPolicy writes a chain policy into the slot it belongs to.
func setPolicy(policies *firewall.Policies, slot firewall.PolicyDirection, policy string) {
	value := firewall.PolicyAllow
	if policy == TargetDrop {
		value = firewall.PolicyDeny
	}
	switch slot {
	case firewall.PolicyIncoming:
		policies.Incoming = value
	case firewall.PolicyOutgoing:
		policies.Outgoing = value
	case firewall.PolicyRouted:
		policies.Routed = value
	}
}

// directionOf reads a rule's direction off the chain it lives in.
func directionOf(chain string) firewall.Direction {
	switch chain {
	case ChainInput, "PREROUTING":
		return firewall.DirIn
	case ChainOutput, "POSTROUTING":
		return firewall.DirOut
	case ChainForward:
		return firewall.DirForward
	default:
		return firewall.DirAny
	}
}

// renderRule maps one dump rule onto the row the table shows.
func renderRule(family Family, rule Rule, direction firewall.Direction) firewall.Rule {
	m := rule.Match
	out := firewall.Rule{
		// The specification is the identity: a delete names the rule by it,
		// so a rule another daemon inserted above it meanwhile cannot shift
		// the delete onto its neighbour.
		ID:        rule.Spec,
		Index:     rule.Index,
		Action:    actionOf(m),
		Direction: direction,
		Proto:     m.Proto,
		Ports:     portsOf(m),
		From:      orAny(m.Src),
		To:        orAny(m.Dst),
		Comment:   m.Comment,
		Family:    firewall.Family(family),
		Raw:       rule.Line(),
		Extra: map[string]string{
			firewall.ExtraInIface:  m.InIface,
			firewall.ExtraOutIface: m.OutIface,
			firewall.ExtraDetail:   ruleDetail(m),
		},
	}
	if rule.Counter != nil {
		out.Extra[firewall.ExtraCounter] = rule.Counter.String()
	}
	if m.Target == "LOG" || m.Target == "NFLOG" {
		out.Extra[firewall.ExtraLog] = "LOG"
	}
	return out
}

// actionOf maps a target onto the family's vocabulary where there is one, and
// says JUMP for a user chain: showing a jump as an allow would be a lie in the
// most load-bearing column of the screen.
func actionOf(m Match) firewall.Action {
	switch m.Target {
	case TargetAccept:
		return firewall.ActionAllow
	case TargetDrop:
		return firewall.ActionDeny
	case TargetReject:
		return firewall.ActionReject
	case "":
		return ""
	}
	if isExtensionTarget(m.Target) {
		return firewall.Action(m.Target)
	}
	if m.Goto {
		return "GOTO"
	}
	return "JUMP"
}

// isExtensionTarget reports whether a target is an xtables extension (RETURN,
// LOG, MARK, MASQUERADE …) rather than a user chain. Extension targets are
// spelled in capitals; a user chain can be too, but then it is also declared
// in the dump, which is what the model checks where it matters.
func isExtensionTarget(target string) bool {
	switch target {
	case TargetReturn, "LOG", "NFLOG", "MARK", "CONNMARK", "MASQUERADE", "SNAT",
		"DNAT", "REDIRECT", "TCPMSS", "CT", "NOTRACK", "TRACE", "QUEUE", "NFQUEUE",
		"AUDIT", "CHECKSUM", "CLASSIFY", "TPROXY", "SET", "ULOG":
		return true
	}
	return false
}

// ruleDetail renders the one-line note beside a rule: where it jumps, the
// state it matches, the target's options, then whatever had no column.
func ruleDetail(m Match) string {
	var parts []string
	if m.Target != "" && !m.Terminal() {
		parts = append(parts, m.TargetDetail())
	}
	if m.CTState != "" {
		parts = append(parts, "state "+m.CTState)
	}
	if m.ICMPType != "" {
		parts = append(parts, "icmp type "+m.ICMPType)
	}
	if m.Terminal() && len(m.TargetArgs) > 0 {
		parts = append(parts, strings.Join(m.TargetArgs, " "))
	}
	parts = append(parts, m.Unmodeled...)
	return strings.Join(parts, "; ")
}

// portsOf renders the port column: the destination port a rule matches, or
// the source port when that is all it has.
func portsOf(m Match) string {
	switch {
	case m.DPort != "" && m.SPort != "":
		return m.SPort + " → " + m.DPort
	case m.DPort != "":
		return m.DPort
	case m.SPort != "":
		return "from " + m.SPort
	default:
		return ""
	}
}

// orAny renders an empty address selector the way the rest of the family
// spells "no restriction".
func orAny(value string) string {
	if value == "" {
		return "Anywhere"
	}
	return value
}

// plural renders a count with its noun.
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// OpenPorts lists the ports a chain accepts, as "443/tcp" (with " from …"
// when the rule is narrowed to a source), and separately the accepts that sit
// after the catch-all, which never match. It answers "is this port open" the
// way the chain actually decides it, which is by position.
func (c Chain) OpenPorts() (open, shadowed []string) {
	catchAt, _ := c.CatchAll()
	for _, rule := range c.Rules {
		m := rule.Match
		if m.Target != TargetAccept || m.DPort == "" || m.Proto == "" {
			continue
		}
		port := m.DPort + "/" + m.Proto
		if m.Src != "" {
			port += " from " + m.Src
		}
		if m.InIface != "" {
			port += " on " + m.InIface
		}
		if catchAt > 0 && rule.Index > catchAt {
			shadowed = append(shadowed, port)
			continue
		}
		open = append(open, port)
	}
	return open, shadowed
}
