package nftables

import (
	"sort"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// The names of the two groups that are not a chain. A chain group always
// carries the separator below, so neither can collide with one.
const (
	GroupNAT     = "NAT"
	GroupAliases = "Aliases"
)

// groupSeparator divides the table from the chain in a chain group's name.
// The name is what the UI hands back to the backend, so it has to survive the
// round trip; nft allows no spaces in a table or chain name, which is what
// makes the split unambiguous.
const groupSeparator = " / "

// GroupName is the identifier of the group that shows one chain.
func GroupName(chain Chain) string {
	return chain.Table.String() + groupSeparator + chain.Name
}

// Model renders a whole ruleset as the picture the UI draws: one group per
// chain worth showing, one for address translation, one for the aliases.
func Model(rs Ruleset) firewall.Model {
	management := DetectManagement(rs)

	model := firewall.Model{
		Backend: "nftables",
		Enabled: rs.Filtering(),
		Groups:  append(chainGroups(rs), natGroup(rs), aliasGroup(rs)),
	}
	if management.Managed() {
		model.Warning = "read-only: " + management.Detail
	}
	// The alias picker in the add-rule form offers the sets of the table this
	// tool owns, which is the only table it writes rules with an alias into.
	if table, ok := rs.Table(OwnTable); ok {
		for _, name := range sortedSetNames(table.Sets) {
			model.Services = append(model.Services, "@"+name)
		}
	}
	return model
}

// chainGroups builds one group per chain worth showing: every base chain,
// because its policy is a fact even when it holds no rules, and every regular
// chain that actually carries one. The empty scaffolding chains a manager
// like firewalld leaves behind are left out; there are dozens of them and
// none of them says anything.
func chainGroups(rs Ruleset) []firewall.Group {
	var groups []firewall.Group
	for _, table := range rs.Tables {
		for _, chain := range table.Chains {
			if chain.Type == "nat" {
				// Address translation has a view of its own: the columns that
				// matter there are the target and the interface, not the
				// verdict.
				continue
			}
			if !chain.Base() && len(chain.Rules) == 0 {
				continue
			}
			groups = append(groups, chainGroup(rs, chain))
		}
	}
	sort.SliceStable(groups, func(i, j int) bool {
		return hookRank(groups[i].Description) < hookRank(groups[j].Description)
	})
	return groups
}

// hookRank orders the chain groups the way a reader thinks about them: what
// arrives, what is routed, what leaves, and then the chains that are only
// reached by a jump.
func hookRank(description string) int {
	switch {
	case strings.Contains(description, "hook input"):
		return 0
	case strings.Contains(description, "hook forward"):
		return 1
	case strings.Contains(description, "hook output"):
		return 2
	case strings.Contains(description, "hook"):
		return 3
	default:
		return 4
	}
}

// chainGroup renders one chain as a group.
func chainGroup(rs Ruleset, chain Chain) firewall.Group {
	group := firewall.Group{
		Name:        GroupName(chain),
		Title:       chain.Name + " (" + chain.Table.String() + ")",
		Description: chain.Describe(),
		View:        firewall.ViewRules,
	}
	if slot := policySlot(chain); slot != "" {
		group.PolicySlots = []firewall.PolicyDirection{slot}
		setPolicy(&group.Default, slot, chain.Policy)
	}
	// A chain this backend will refuse to write to says so in its own
	// description, rather than letting the user find out at the confirm
	// dialog.
	if err := rs.checkMutable(chain); err != nil {
		group.Description += "  ·  read-only: " +
			strings.TrimPrefix(err.Error(), "nftables: ")
	}
	direction := directionOf(chain)
	for _, rule := range chain.Rules {
		group.Rules = append(group.Rules, renderRule(rule, direction))
	}
	return group
}

// policySlot maps a chain's hook onto the policy slot the header shows it in.
func policySlot(chain Chain) firewall.PolicyDirection {
	if chain.Policy == "" {
		return ""
	}
	switch chain.Hook {
	case "input", "prerouting":
		return firewall.PolicyIncoming
	case "output", "postrouting":
		return firewall.PolicyOutgoing
	case "forward":
		return firewall.PolicyRouted
	default:
		return ""
	}
}

// setPolicy writes a chain policy into the slot it belongs to.
func setPolicy(policies *firewall.Policies, slot firewall.PolicyDirection, policy string) {
	value := firewall.PolicyAllow
	if policy == PolicyDrop {
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

// directionOf reads a rule's direction off the chain it lives in, which is
// where nftables keeps it.
func directionOf(chain Chain) firewall.Direction {
	switch chain.Hook {
	case "input", "prerouting":
		return firewall.DirIn
	case "output", "postrouting":
		return firewall.DirOut
	case "forward":
		return firewall.DirForward
	default:
		return firewall.DirAny
	}
}

// renderRule maps one nft rule onto the row the table shows.
func renderRule(rule Rule, direction firewall.Direction) firewall.Rule {
	match := rule.Match
	out := firewall.Rule{
		ID:        strconv.Itoa(rule.Handle),
		Index:     rule.Index,
		Action:    actionOf(match.Verdict),
		Direction: direction,
		Proto:     match.Proto,
		Ports:     portsOf(match),
		From:      orAny(match.Saddr),
		To:        orAny(match.Daddr),
		Comment:   rule.Comment,
		Family:    firewall.Family(match.Family()),
		Raw:       rule.Raw,
		Extra: map[string]string{
			firewall.ExtraInIface:  match.IIF,
			firewall.ExtraOutIface: match.OIF,
			firewall.ExtraDetail:   ruleDetail(match),
		},
	}
	if out.Action == "" && match.Log {
		// A rule that logs and does not decide is still doing something, and
		// an empty verdict column would say it is not.
		out.Action = "LOG"
	}
	if match.Counter != nil {
		out.Extra[firewall.ExtraCounter] = match.Counter.String()
	}
	if match.NAT != nil {
		out.Kind = match.NAT.Kind
		out.Extra[firewall.ExtraTarget] = match.NAT.String()
	}
	return out
}

// ruleDetail renders the one-line note the flow table shows beside a rule: the
// state match that makes it stateful, the ICMP type it narrows to, and then
// whatever the columns had no room for.
func ruleDetail(m Match) string {
	parts := make([]string, 0, len(m.Unmodeled)+2)
	if m.CTState != "" {
		parts = append(parts, "ct state "+m.CTState)
	}
	if m.ICMPType != "" {
		parts = append(parts, "icmp type "+m.ICMPType)
	}
	parts = append(parts, m.Unmodeled...)
	return strings.Join(parts, "; ")
}

// actionOf maps an nft verdict onto the family's vocabulary where there is
// one, and keeps nft's own word where there is not: a jump is not an allow
// and showing it as one would be a lie in the most load-bearing column of the
// screen.
func actionOf(verdict string) firewall.Action {
	switch verdict {
	case "accept":
		return firewall.ActionAllow
	case "drop":
		return firewall.ActionDeny
	case "reject":
		return firewall.ActionReject
	case "":
		return ""
	default:
		return firewall.Action(strings.ToUpper(verdict))
	}
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

// natGroup collects every rule of every nat chain into one view. Address
// translation is one subject even when the kernel splits it across two hooks,
// and a reader looking for "what does this router rewrite" should not have to
// know which of them a rule lives in.
func natGroup(rs Ruleset) firewall.Group {
	group := firewall.Group{
		Name:  GroupNAT,
		Title: "NAT",
		Description: "address translation: masquerade on the way out, " +
			"port forwards on the way in",
		View: firewall.ViewNAT,
	}
	var chains []string
	for _, table := range rs.Tables {
		for _, chain := range table.Chains {
			if chain.Type != "nat" {
				continue
			}
			chains = append(chains, chain.Name+" ("+chain.Table.String()+")")
			direction := directionOf(chain)
			for _, rule := range chain.Rules {
				row := renderRule(rule, direction)
				// A NAT rule's row is read back by the delete path, which
				// needs to know which chain the handle belongs to.
				row.Note = GroupName(chain)
				group.Rules = append(group.Rules, row)
			}
		}
	}
	if len(chains) > 0 {
		group.Description += "  ·  " + strings.Join(chains, ", ")
	} else {
		group.Description += "  ·  no nat chain in this ruleset"
	}
	for i := range group.Rules {
		group.Rules[i].Index = i + 1
	}
	return group
}

// aliasGroup renders every named set of the ruleset as an alias, with the
// number of rules that use it. The count is the whole point: an alias nobody
// refers to is dead weight, and one that three rules refer to is three rules
// you are about to change when you edit it.
func aliasGroup(rs Ruleset) firewall.Group {
	group := firewall.Group{
		Name:  GroupAliases,
		Title: "Aliases",
		Description: "named sets of addresses and ports, and how many rules " +
			"use each",
		View: firewall.ViewAliases,
	}
	index := 0
	for _, table := range rs.Tables {
		for _, set := range table.Sets {
			index++
			group.Rules = append(group.Rules, firewall.Rule{
				ID:      set.Name,
				Index:   index,
				Kind:    set.Type,
				Service: set.Name,
				Note:    set.Table.String(),
				To:      strings.Join(set.Elements, ", "),
				Comment: set.Comment,
				Raw:     set.Ref() + " = { " + strings.Join(set.Elements, ", ") + " }",
				Extra: map[string]string{
					firewall.ExtraElements:   strconv.Itoa(len(set.Elements)),
					firewall.ExtraReferences: strconv.Itoa(set.References),
					firewall.ExtraFlags:      strings.Join(set.Flags, ","),
				},
			})
		}
	}
	return group
}

// ChainForGroup resolves a group name back to the chain it names. It is the
// other half of GroupName, and the reason group names are built rather than
// numbered: a group the UI is still showing after a reload has to resolve to
// the same chain, and a chain that is gone has to resolve to a refusal rather
// than to whatever is now in its position.
func (r Ruleset) ChainForGroup(group string) (Chain, error) {
	table, name, found := strings.Cut(group, groupSeparator)
	if !found {
		return Chain{}, errorf(
			"%q is not a chain: pick the view of the chain to change with "+
				"[ and ], and use the actions menu for the NAT and alias "+
				"views", group)
	}
	family, tableName, found := strings.Cut(table, " ")
	if !found {
		return Chain{}, errorf("%q does not name a table", table)
	}
	chain, ok := r.Chain(TableID{Family: family, Name: tableName}, name)
	if !ok {
		return Chain{}, errorf(
			"chain %s is no longer in table %s; press R to re-read the ruleset",
			name, table)
	}
	return chain, nil
}
