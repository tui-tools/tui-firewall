package iptables

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// capabilities is what the iptables backend offers the UI.
var capabilities = firewall.Capabilities{
	Actions: []firewall.Action{
		firewall.ActionAllow, firewall.ActionDeny, firewall.ActionReject,
	},
	Policies:           []firewall.Policy{firewall.PolicyAllow, firewall.PolicyDeny},
	SupportsInsert:     true,
	InsertHint:         "empty: just before the chain's catch-all REJECT/DROP",
	SupportsComments:   true,
	SupportsInterfaces: true,
	SupportsConntrack:  true,
	SupportsICMP:       true,
	SupportsEnable:     false,
	EnableHint: "iptables has no on/off switch: change a chain policy with p, " +
		"or delete the catch-all REJECT with d",
	// ServiceLabel is empty: iptables has no named services, so the form
	// offers ports and protocols only.
	GroupLabel: "Chain",
}

// Capabilities reports what the iptables backend supports.
func Capabilities() firewall.Capabilities { return capabilities }

// targetFor maps a family action onto the iptables target that expresses it.
func targetFor(action firewall.Action) (string, error) {
	switch action {
	case firewall.ActionAllow:
		return TargetAccept, nil
	case firewall.ActionDeny:
		return TargetDrop, nil
	case firewall.ActionReject:
		return TargetReject, nil
	case "":
		return "", errorf("an action is required")
	default:
		return "", errorf("iptables has no target for %q; use %s, %s or %s",
			action, firewall.ActionAllow, firewall.ActionDeny, firewall.ActionReject)
	}
}

// checkWritable is the mutation guard: this backend writes rules only into the
// three built-in chains of the filter table. Everything else is read and
// shown, and a write to it is refused with the reason.
func checkWritable(table string, chain Chain) error {
	if table != TableFilter {
		return errorf("table %s is shown, not changed: this backend writes filter "+
			"rules into INPUT, FORWARD and OUTPUT only", table)
	}
	if isFilterBuiltin(chain.Name) {
		return nil
	}
	if daemon := DaemonOf(chain.Name); daemon != "" {
		return errorf("chain %s belongs to %s, which rebuilds it every time it "+
			"starts: a rule added here would be lost, so it is not written to",
			chain.Name, daemon)
	}
	return errorf("chain %s is a user chain: a rule here only runs if some "+
		"other rule jumps to it, which this backend cannot promise; it writes to "+
		"INPUT, FORWARD and OUTPUT", chain.Name)
}

// Writable reports whether this backend would accept a rule in the group, and
// says why not when it would not. --check reports it; the UI puts the reason in
// the chain's description.
func (s State) Writable(group string) error {
	_, _, err := s.chainFor(group)
	return err
}

// chainFor resolves a group to its family and chain and checks the guard.
func (s State) chainFor(group string) (Family, Chain, error) {
	family, table, name, err := ParseGroup(group)
	if err != nil {
		return "", Chain{}, err
	}
	if family == V6 && !s.HasV6 {
		return "", Chain{}, errorf("ip6tables is not available on this machine")
	}
	chain, ok := s.Dump(family).Chain(table, name)
	if !ok {
		if table == TableFilter && isFilterBuiltin(name) {
			// The table was never loaded, so the kernel's chain is empty with
			// policy ACCEPT; writing to it creates the table.
			chain = Chain{Name: name, Policy: TargetAccept}
		} else {
			return "", Chain{}, errorf("chain %s of table %s is not loaded; "+
				"re-read the rules with R", name, table)
		}
	}
	if err := checkWritable(table, chain); err != nil {
		return "", Chain{}, err
	}
	return family, chain, nil
}

// Placement is where a new rule lands and the sentence saying why, which the
// confirm dialog shows beside the command.
type Placement struct {
	Position int
	Why      string
}

// Place decides the position of a new rule in a chain. An explicit position
// is honoured unless it lands after the catch-all, where nothing reaches it.
// Without one, the rule goes right in front of the catch-all REJECT or DROP —
// the point where the chain really ends — or, when the chain has none, at the
// end, where the policy decides what nothing matched.
func Place(chain Chain, requested int) (Placement, error) {
	last := len(chain.Rules) + 1
	catchAt, catchRule := chain.CatchAll()
	if requested > 0 {
		if requested > last {
			return Placement{}, errorf("%s has %s, so a rule can go at position "+
				"1 to %d, not %d", chain.Name, plural(len(chain.Rules), "rule"),
				last, requested)
		}
		if catchAt > 0 && requested > catchAt {
			return Placement{}, errorf("position %d is after rule %d of %s (%s), "+
				"which rejects everything that reaches it: a rule there would never "+
				"match; use %d or lower", requested, catchAt, chain.Name,
				catchRule.Match.TargetDetail(), catchAt)
		}
		return Placement{Position: requested,
			Why: fmt.Sprintf("inserted at position %d of %s, as asked", requested,
				chain.Name)}, nil
	}
	if catchAt > 0 {
		return Placement{Position: catchAt, Why: fmt.Sprintf(
			"inserted at position %d of %s, right before rule %d (%s): that rule "+
				"catches everything, so a rule appended after it would never match",
			catchAt, chain.Name, catchAt, catchRule.Match.TargetDetail())}, nil
	}
	policy := chain.Policy
	if policy == "" {
		policy = "the caller's"
	}
	return Placement{Position: last, Why: fmt.Sprintf(
		"inserted at position %d of %s, the end: the chain has no catch-all "+
			"REJECT or DROP, so its policy %s decides what no rule matched",
		last, chain.Name, policy)}, nil
}

// persistReminder ends the note of every change: a rule applied here is in the
// running kernel only, and the next boot restores the saved file.
const persistReminder = "runtime only until persisted: W writes the running " +
	"rules to the file restored at boot"

// BuildAddRule turns a RuleSpec into one `iptables -I CHAIN N …` (or
// ip6tables) invocation in the chain the group names.
func (s State) BuildAddRule(group string, spec firewall.RuleSpec) (firewall.Change, error) {
	family, chain, err := s.chainFor(group)
	if err != nil {
		return firewall.Change{}, err
	}
	matchArgs, err := specArgs(family, chain.Name, spec)
	if err != nil {
		return firewall.Change{}, err
	}
	placement, err := Place(chain, spec.Position)
	if err != nil {
		return firewall.Change{}, err
	}
	argv := []string{family.Binary(), "-I", chain.Name, strconv.Itoa(placement.Position)}
	argv = append(argv, matchArgs...)
	description := fmt.Sprintf("Insert a rule at position %d of %s (%s)",
		placement.Position, chain.Name, family.Binary())
	return firewall.Change{
		Description: description,
		Note:        placement.Why + "; " + persistReminder,
		Commands: []firewall.Command{{
			Argv:        argv,
			Description: description,
		}},
	}, nil
}

// BuildDeleteRule removes the selected rule by its specification.
func (s State) BuildDeleteRule(group string, rule firewall.Rule) (firewall.Change, error) {
	family, chain, err := s.chainFor(group)
	if err != nil {
		return firewall.Change{}, err
	}
	var found *Rule
	for i := range chain.Rules {
		if chain.Rules[i].Spec == rule.ID {
			found = &chain.Rules[i]
			break
		}
	}
	if found == nil {
		return firewall.Change{}, errorf("that rule is no longer in %s; re-read "+
			"the rules with R", chain.Name)
	}
	argv := append([]string{family.Binary(), "-D", chain.Name}, found.Args...)
	description := fmt.Sprintf("Delete rule %d of %s (%s)", found.Index,
		chain.Name, family.Binary())
	note := "deleted by its specification rather than its number, so a rule " +
		"another daemon inserted meanwhile cannot shift the delete onto a " +
		"neighbour"
	if at, _ := chain.CatchAll(); at == found.Index {
		note = "this is the catch-all of " + chain.Name + ": without it, the " +
			"policy " + chain.Policy + " decides every packet no rule matched; " + note
	}
	return firewall.Change{
		Description: description,
		Destructive: true,
		Note:        note + "; " + persistReminder,
		Commands: []firewall.Command{{
			Argv:        argv,
			Description: description,
			Destructive: true,
		}},
	}, nil
}

// BuildSetPolicy changes the policy of the built-in chain a group shows.
func (s State) BuildSetPolicy(group string, policy firewall.Policy) (firewall.Change, error) {
	family, chain, err := s.chainFor(group)
	if err != nil {
		return firewall.Change{}, err
	}
	var target string
	switch policy {
	case firewall.PolicyAllow:
		target = TargetAccept
	case firewall.PolicyDeny:
		target = TargetDrop
	default:
		return firewall.Change{}, errorf("a built-in chain's policy is ACCEPT or "+
			"DROP; %q has no equivalent (add a REJECT rule instead)", policy)
	}
	description := fmt.Sprintf("Set the policy of %s (%s) to %s", chain.Name,
		family.Binary(), target)
	note := persistReminder
	if target == TargetDrop {
		note = "every packet no rule accepts is dropped from the moment this " +
			"runs: make sure a rule above accepts your own session; " + note
	}
	return firewall.Change{
		Description: description,
		Destructive: target == TargetDrop,
		Note:        note,
		Commands: []firewall.Command{{
			Argv:        []string{family.Binary(), "-P", chain.Name, target},
			Description: description,
			Destructive: target == TargetDrop,
		}},
	}, nil
}

// ifaceName is what Linux accepts as an interface name, plus the "+"
// wildcard iptables allows at the end.
var ifaceName = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,15}\+?$`)

// commentWord is what a comment may carry. It is one word on purpose: the
// preview renders argv words joined by spaces, and a comment with a space in
// it would read as two words there while running as one.
var commentWord = regexp.MustCompile(`^[A-Za-z0-9_.:/@+,=-]{1,64}$`)

// icmpTypeName is an ICMP type as iptables names it, or a number.
var icmpTypeName = regexp.MustCompile(`^[a-z0-9-]{1,32}(/[0-9]{1,3})?$`)

// specArgs builds the match and target words of a rule from a spec. It
// validates every value, because each one becomes an argv word the kernel
// sees.
func specArgs(family Family, chain string, spec firewall.RuleSpec) ([]string, error) {
	target, err := targetFor(spec.Action)
	if err != nil {
		return nil, err
	}
	if spec.Service != "" {
		return nil, errorf("iptables has no named services; give the port and " +
			"protocol instead")
	}
	if spec.Log {
		return nil, errorf("iptables logs with a separate LOG rule, which this " +
			"backend does not add")
	}
	if spec.Routed && chain != ChainForward {
		return nil, errorf("a forwarding rule belongs in FORWARD; switch to that chain")
	}
	if spec.Family != firewall.FamilyAny && string(spec.Family) != string(family) {
		return nil, errorf("this is the %s chain; switch to the %s one for a %s rule",
			family.Binary(), otherFamily(family).Binary(), spec.Family)
	}

	var args []string
	proto := strings.ToLower(strings.TrimSpace(spec.Proto))
	switch proto {
	case "", "tcp", "udp":
	case "icmp", "icmpv6", "ipv6-icmp":
		if family == V6 {
			proto = "ipv6-icmp"
		} else if proto != "icmp" {
			return nil, errorf("icmpv6 is an ip6tables protocol; this is the iptables chain")
		}
	default:
		return nil, errorf("protocol %q is not offered; use tcp, udp or icmp", spec.Proto)
	}
	if proto != "" {
		args = append(args, "-p", proto)
	}
	for _, sel := range []struct {
		flag, value, label string
	}{
		{"-s", spec.From, "source"},
		{"-d", spec.To, "destination"},
	} {
		value := strings.TrimSpace(sel.value)
		if value == "" || strings.EqualFold(value, "any") || strings.EqualFold(value, "anywhere") {
			continue
		}
		if err := checkAddress(family, value, sel.label); err != nil {
			return nil, err
		}
		args = append(args, sel.flag, value)
	}
	if iface := strings.TrimSpace(spec.InIface); iface != "" {
		if chain == ChainOutput {
			return nil, errorf("OUTPUT sees packets this host sends: there is no " +
				"input interface to match")
		}
		if !ifaceName.MatchString(iface) {
			return nil, errorf("%q is not an interface name", iface)
		}
		args = append(args, "-i", iface)
	}
	if iface := strings.TrimSpace(spec.OutIface); iface != "" {
		if chain == ChainInput {
			return nil, errorf("INPUT sees packets for this host: there is no " +
				"output interface to match")
		}
		if !ifaceName.MatchString(iface) {
			return nil, errorf("%q is not an interface name", iface)
		}
		args = append(args, "-o", iface)
	}
	portArgs, err := portMatch(proto, spec.Ports)
	if err != nil {
		return nil, err
	}
	args = append(args, portArgs...)
	if icmp := strings.TrimSpace(spec.ICMPType); icmp != "" && proto != "tcp" && proto != "udp" && proto != "" {
		if !icmpTypeName.MatchString(icmp) {
			return nil, errorf("%q is not an ICMP type", icmp)
		}
		if family == V6 {
			args = append(args, "-m", "icmp6", "--icmpv6-type", icmp)
		} else {
			args = append(args, "-m", "icmp", "--icmp-type", icmp)
		}
	}
	if len(spec.CTStates) > 0 {
		states := make([]string, 0, len(spec.CTStates))
		for _, st := range spec.CTStates {
			st = strings.ToUpper(strings.TrimSpace(st))
			switch st {
			case "NEW", "ESTABLISHED", "RELATED", "INVALID", "UNTRACKED":
				states = append(states, st)
			default:
				return nil, errorf("%q is not a connection state", st)
			}
		}
		args = append(args, "-m", "conntrack", "--ctstate", strings.Join(states, ","))
	}
	if comment := strings.TrimSpace(spec.Comment); comment != "" {
		if !commentWord.MatchString(comment) {
			return nil, errorf("a comment here is one word of letters, digits " +
				"and ._:/@+,=- (no spaces), so the preview reads exactly as it runs")
		}
		args = append(args, "-m", "comment", "--comment", comment)
	}
	return append(args, "-j", target), nil
}

// portMatch renders the port selector: --dport for one port or a range, the
// multiport match for a list.
func portMatch(proto, ports string) ([]string, error) {
	ports = strings.ReplaceAll(strings.TrimSpace(ports), " ", "")
	if ports == "" {
		return nil, nil
	}
	if proto != "tcp" && proto != "udp" {
		return nil, errorf("a port needs a protocol: pick tcp or udp")
	}
	parts := strings.Split(ports, ",")
	for _, part := range parts {
		if err := checkPortOrRange(part); err != nil {
			return nil, err
		}
	}
	if len(parts) == 1 {
		return []string{"-m", proto, "--dport", ports}, nil
	}
	if len(parts) > 15 {
		return nil, errorf("the multiport match takes at most 15 ports")
	}
	return []string{"-m", "multiport", "--dports", ports}, nil
}

// checkPortOrRange validates "22" or "2000:2100".
func checkPortOrRange(value string) error {
	lo, hi, isRange := strings.Cut(value, ":")
	if isRange {
		a, errA := parsePort(lo)
		b, errB := parsePort(hi)
		if errA != nil || errB != nil || a > b {
			return errorf("%q is not a port range (low:high)", value)
		}
		return nil
	}
	if _, err := parsePort(value); err != nil {
		return errorf("%q is not a port (1-65535)", value)
	}
	return nil
}

// parsePort reads one port number.
func parsePort(value string) (int, error) {
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("bad port")
	}
	return n, nil
}

// checkAddress validates an address or a prefix of the chain's family.
func checkAddress(family Family, value, label string) error {
	var addr netip.Addr
	if prefix, err := netip.ParsePrefix(value); err == nil {
		addr = prefix.Addr()
	} else if a, err := netip.ParseAddr(value); err == nil {
		addr = a
	} else {
		return errorf("%q is not an address or a prefix for the %s", value, label)
	}
	if addr.Is4() != (family == V4) {
		return errorf("%s is an IPv%s address, and this is the %s chain; switch "+
			"to the %s one", value, map[bool]string{true: "4", false: "6"}[addr.Is4()],
			family.Binary(), otherFamily(family).Binary())
	}
	return nil
}

// otherFamily returns the family that is not this one.
func otherFamily(f Family) Family {
	if f == V6 {
		return V4
	}
	return V6
}
