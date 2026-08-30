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
	Policies:         []firewall.Policy{firewall.PolicyAllow, firewall.PolicyDeny},
	SupportsInsert:   true,
	SupportsComments: true,
	SupportsFamily:   true,
	SupportsLog:      true,
	SupportsEnable:   false,
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
	family, err := addressFamily(chain, spec.Family, source, spec.To)
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
	ports, err := portSelector(spec.Proto, spec.Ports)
	if err != nil {
		return nil, err
	}
	expr = append(expr, ports...)
	if len(expr) == 0 {
		return nil, errorf(
			"give at least a port, an address or an alias: a rule with no " +
				"match at all applies to every packet the chain sees")
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

// addressFamily decides which header a rule's address matches read from. In
// an `inet` table both families share one chain, so an address match has to
// say which one it means; in an `ip` or `ip6` table the table has already
// said it.
func addressFamily(chain Chain, requested firewall.Family, from, to string) (string, error) {
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
	// Nothing was asked for: read it off the addresses themselves.
	for _, address := range []string{from, to} {
		switch inferFamily(address) {
		case firewall.FamilyIPv6:
			return "ip6", nil
		case firewall.FamilyIPv4:
			return "ip", nil
		}
	}
	if from == "" && to == "" {
		return "", nil
	}
	return "", errorf(
		"table %s holds both address families, so an alias needs the family "+
			"field set to v4 or v6", chain.Table)
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
// packet leaving through it is rewritten to the router's own address.
func (r Ruleset) BuildMasquerade(chain Chain, iface string) (firewall.Change, error) {
	if err := r.checkNATChain(chain, "postrouting"); err != nil {
		return firewall.Change{}, err
	}
	if err := checkOperand(iface); err != nil {
		return firewall.Change{}, err
	}
	argv := []string{"nft", "add", "rule"}
	argv = append(argv, chain.Table.Args()...)
	argv = append(argv, chain.Name, "oifname", quote(iface), "counter",
		"masquerade", "comment", quote("masquerade out "+iface))
	return firewall.One(firewall.Command{
		Argv:        argv,
		Description: "Masquerade everything leaving " + iface,
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
