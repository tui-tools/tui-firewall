package ufw

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// InactiveMarker is the firewall.ExtraDisabled value a rule carries while ufw
// is inactive: the rule is saved and will be applied on `ufw enable`, but the
// firewall is not filtering anything with it yet.
const InactiveMarker = "inactive"

// addedPrefix starts every rule line of `ufw show added`.
const addedPrefix = "ufw "

// commentMarker separates a rule from its comment in `ufw show added`. ufw
// prints the comment last and wraps it in single quotes without escaping
// anything inside, so it is cut off the end of the line rather than tokenised.
const commentMarker = " comment '"

// ParseAdded parses `ufw show added`, the one read that still lists the user
// rules while ufw is inactive (`ufw status` then prints only "Status:
// inactive"). Each line is a rule in ufw's own command syntax ("ufw allow
// 22/tcp", "ufw route allow in on eth0 out on eth1"), one line per rule: the
// IPv4 and IPv6 halves ufw keeps for a rule that applies to both families are
// printed once.
//
// The rules carry no number. ufw numbers rules only in `status numbered`,
// which an inactive firewall does not print, and the order of this listing is,
// in ufw's own words, an approximation of the order the rules were added. The
// rule text itself is the ID: it is what `ufw delete RULE` takes.
func ParseAdded(output string) []firewall.Rule {
	var rules []firewall.Rule
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.ReplaceAll(scanner.Text(), "\r", " "))
		if !strings.HasPrefix(line, addedPrefix) {
			continue
		}
		if rule, ok := parseAddedLine(strings.TrimSpace(line[len(addedPrefix):])); ok {
			rules = append(rules, rule)
		}
	}
	return rules
}

// addedRule is one `ufw show added` line taken apart.
type addedRule struct {
	routed    bool
	action    string
	direction string
	inIface   string
	outIface  string
	src, dst  string
	sport     string
	dport     string
	sapp      string
	dapp      string
	proto     string
	comment   string
}

// parseAddedLine turns the text after "ufw " into a Rule. It returns false for
// a line it cannot read, which is then left out rather than shown wrong.
func parseAddedLine(text string) (firewall.Rule, bool) {
	tokens, err := splitAdded(text)
	if err != nil || len(tokens) == 0 {
		return firewall.Rule{}, false
	}
	parsed, ok := readAdded(tokens)
	if !ok {
		return firewall.Rule{}, false
	}
	rule := parsed.toRule()
	rule.ID = text
	rule.Raw = text
	rule.Extra = map[string]string{firewall.ExtraDisabled: InactiveMarker}
	return rule, true
}

// splitAdded splits a `ufw show added` rule into argv the way ufw's own
// parser would have received it: words separated by spaces, a single-quoted
// group ('Nginx Full') kept as one word, and the comment, which ufw prints
// last and quotes without escaping, kept whole.
func splitAdded(text string) ([]string, error) {
	head, comment, hasComment := text, "", false
	if idx := strings.Index(text, commentMarker); idx >= 0 && strings.HasSuffix(text, "'") &&
		len(text) >= idx+len(commentMarker)+1 {
		head = text[:idx]
		comment = text[idx+len(commentMarker) : len(text)-1]
		hasComment = true
	}
	var tokens []string
	var current strings.Builder
	inQuote, started := false, false
	for _, r := range head {
		switch {
		case r == '\'':
			inQuote = !inQuote
			started = true
		case r == ' ' && !inQuote:
			if started {
				tokens = append(tokens, current.String())
				current.Reset()
				started = false
			}
		default:
			current.WriteRune(r)
			started = true
		}
	}
	if inQuote {
		return nil, fmt.Errorf("ufw: unbalanced quote in %q", text)
	}
	if started {
		tokens = append(tokens, current.String())
	}
	if hasComment {
		tokens = append(tokens, "comment", comment)
	}
	return tokens, nil
}

// readAdded walks the argv of one rule, in the order ufw's get_command writes
// it: [route] ACTION [in|out] [on IFACE] [out on IFACE] [log|log-all], then
// either the short form (one port or app profile) or the extended one (from
// ... to ... proto ...), and a trailing comment.
func readAdded(tokens []string) (addedRule, bool) {
	r := addedRule{direction: "in", src: "any", dst: "any", proto: "any"}
	i := 0
	next := func() (string, bool) {
		if i >= len(tokens) {
			return "", false
		}
		i++
		return tokens[i-1], true
	}
	peek := func() string {
		if i >= len(tokens) {
			return ""
		}
		return tokens[i]
	}

	if peek() == "route" {
		r.routed = true
		i++
	}
	action, ok := next()
	if !ok || !knownAction(action) {
		return addedRule{}, false
	}
	r.action = action

	// Direction and interfaces: "in", "out", "in on eth0", "out on eth1", and
	// on a routed rule both.
	for peek() == "in" || peek() == "out" {
		dir, _ := next()
		if peek() == "on" {
			i++
			iface, ok := next()
			if !ok {
				return addedRule{}, false
			}
			if dir == "in" {
				r.inIface = iface
			} else {
				r.outIface = iface
			}
		}
		if !r.routed {
			r.direction = dir
		}
	}
	if peek() == "log" || peek() == "log-all" {
		i++
	}

	// A rule with interfaces and nothing else ("route allow in on eth0 out on
	// eth1") has no target at all; ufw marks the extended form only when no
	// interface does.
	extended := peek() == "from" || peek() == "to"
	bare := (peek() == "" || peek() == "comment") && (r.inIface != "" || r.outIface != "")
	if !extended && !bare {
		// Short form: exactly one target, a port expression or a profile.
		target, ok := next()
		if !ok {
			return addedRule{}, false
		}
		if m := portProtoRe.FindStringSubmatch(target); m != nil {
			r.dport = m[1]
			if m[2] != "" {
				r.proto = m[2]
			}
		} else {
			r.dapp = target
		}
	}
	for i < len(tokens) {
		word, _ := next()
		value, ok := next()
		if !ok {
			return addedRule{}, false
		}
		switch word {
		case "from":
			r.src = value
			if !readEndpointQualifier(&i, tokens, &r.sport, &r.sapp) {
				return addedRule{}, false
			}
		case "to":
			r.dst = value
			if !readEndpointQualifier(&i, tokens, &r.dport, &r.dapp) {
				return addedRule{}, false
			}
		case "proto":
			r.proto = value
		case "comment":
			r.comment = value
		default:
			return addedRule{}, false
		}
	}
	return r, true
}

// readEndpointQualifier consumes the optional "port P" or "app A" after a from
// or to address.
func readEndpointQualifier(i *int, tokens []string, port, app *string) bool {
	if *i >= len(tokens) {
		return true
	}
	switch tokens[*i] {
	case "port", "app":
		if *i+1 >= len(tokens) {
			return false
		}
		if tokens[*i] == "port" {
			*port = tokens[*i+1]
		} else {
			*app = tokens[*i+1]
		}
		*i += 2
	}
	return true
}

// knownAction reports one of ufw's rule verbs.
func knownAction(action string) bool {
	switch action {
	case "allow", "deny", "reject", "limit":
		return true
	}
	return false
}

// toRule renders the parsed command in the shape `ufw status` gives a rule, so
// a rule looks the same whether the firewall is active or not.
func (r addedRule) toRule() firewall.Rule {
	rule := firewall.Rule{
		Action:  firewall.Action(strings.ToUpper(r.action)),
		Comment: r.comment,
		Service: r.dapp,
	}
	switch {
	case r.routed:
		rule.Direction = firewall.DirForward
	case r.direction == "out":
		rule.Direction = firewall.DirOut
	default:
		rule.Direction = firewall.DirIn
	}
	if r.dport != "" {
		rule.Ports = r.dport
		if r.proto != "any" {
			rule.Proto = r.proto
		}
	}
	rule.To = endpoint(r.dst, r.dport, r.dapp, r.proto)
	rule.From = endpoint(r.src, r.sport, r.sapp, r.proto)
	// ufw prints an interface on the side it filters: the incoming one with
	// the destination of an ordinary rule, each on its own side on a routed
	// one.
	switch {
	case r.routed:
		rule.To = withIface(rule.To, r.outIface)
		rule.From = withIface(rule.From, r.inIface)
	default:
		rule.To = withIface(rule.To, r.inIface+r.outIface)
	}
	rule.Family = addressFamily(r.src, r.dst)
	return rule
}

// endpoint renders one side of a rule the way the status table does:
// "Anywhere", "192.0.2.0/24", "22/tcp", "192.0.2.1 22/tcp", "OpenSSH".
func endpoint(addr, port, app, proto string) string {
	target := app
	if target == "" && port != "" {
		target = port
		if proto != "any" {
			target += "/" + proto
		}
	}
	if addr == "any" || addr == "" {
		if target == "" {
			return "Anywhere"
		}
		return target
	}
	if target == "" {
		return addr
	}
	return addr + " " + target
}

// withIface appends ufw's "on IFACE" qualifier.
func withIface(side, iface string) string {
	if iface == "" {
		return side
	}
	return side + " on " + iface
}

// addressFamily is the family ufw restricts a rule to: an IPv6 address makes
// it IPv6 only, an IPv4 address IPv4 only, and "any" on both sides leaves it
// on both.
func addressFamily(addrs ...string) firewall.Family {
	for _, addr := range addrs {
		switch {
		case addr == "any" || addr == "":
		case strings.Contains(addr, ":"):
			return firewall.FamilyIPv6
		default:
			return firewall.FamilyIPv4
		}
	}
	return firewall.FamilyAny
}

// deleteByRuleArgs builds `ufw --force delete RULE` (or `ufw --force route
// delete RULE`) from a rule read off `ufw show added`. Deleting by rule rather
// than by number is the only form that works while ufw is inactive without
// guessing a numbering ufw does not print, and it removes the IPv4 and IPv6
// halves together, which is what the single listed line stands for.
func deleteByRuleArgs(text string) ([]string, error) {
	tokens, err := splitAdded(text)
	if err != nil {
		return nil, err
	}
	if _, ok := readAdded(tokens); !ok {
		return nil, fmt.Errorf("ufw: cannot read rule %q", text)
	}
	args := []string{"ufw", "--force"}
	if tokens[0] == "route" {
		return append(append(args, "route", "delete"), tokens[1:]...), nil
	}
	return append(append(args, "delete"), tokens...), nil
}
