// Package ufw implements firewall.Backend on top of the Uncomplicated
// Firewall. It parses `ufw status` output into the generic model and builds
// the exact `ufw` argv used to change it. Nothing here mutates the system
// implicitly: callers build a Command, show it to the user, and only then call
// Run.
package ufw

import (
	"bufio"
	"regexp"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// GroupName is the single group ufw exposes; it carries the global default
// policies. A firewalld backend uses one group per zone instead.
const GroupName = "rules"

var (
	// numberedPrefixRe matches the "[ 1] " prefix of `ufw status numbered`.
	numberedPrefixRe = regexp.MustCompile(`^\[\s*(\d+)\]\s+`)
	// verdictRe locates the Action/Direction column that splits a rule line
	// into its "To" (left) and "From" (right) halves.
	verdictRe = regexp.MustCompile(`\s(ALLOW|DENY|REJECT|LIMIT)(?:\s+(IN|OUT|FWD))?\s{2,}`)
	// portProtoRe matches "22/tcp", "80,443/tcp", "2000:2100/udp" and "22".
	portProtoRe = regexp.MustCompile(`^(\d+(?:[:,]\d+)*(?:,\d+)*)(?:/(tcp|udp))?$`)
	// appSuffixRe matches the "(Nginx Full)" suffix ufw appends to rules
	// created from an application profile.
	appSuffixRe = regexp.MustCompile(`\s+\(([^)]+)\)$`)
	// defaultsRe reads the "Default: deny (incoming), ..." line.
	defaultsRe = regexp.MustCompile(`\b(\w+)\s+\((incoming|outgoing|routed)\)`)
	// loggingRe reads the "Logging: on (low)" line.
	loggingRe = regexp.MustCompile(`^Logging:\s+(on|off)(?:\s+\(([a-z]+)\))?`)
)

// status is the intermediate result of parsing one `ufw status` invocation.
// It is assembled into a firewall.Model by buildModel.
type status struct {
	enabled   bool
	logging   string
	loggingOn bool
	defaults  firewall.Policies
	rules     []firewall.Rule
}

// ParseStatus parses the output of `ufw status verbose` or
// `ufw status numbered`. Both formats share the rule table, so a single parser
// handles them; fields absent from the given output stay at their zero value
// and are merged in by BuildModel.
func ParseStatus(output string) firewall.Model {
	return buildModel(parseStatus(output), nil)
}

// parseStatus does the line-by-line work.
func parseStatus(output string) status {
	st := status{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t")
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			continue
		case strings.HasPrefix(trimmed, "Status:"):
			// "inactive" contains "active", so test the negative form first.
			st.enabled = !strings.Contains(trimmed, "inactive") &&
				strings.Contains(trimmed, "active")
		case strings.HasPrefix(trimmed, "Logging:"):
			st.loggingOn, st.logging = parseLogging(trimmed)
		case strings.HasPrefix(trimmed, "Default:"):
			st.defaults = parseDefaults(trimmed)
		case strings.HasPrefix(trimmed, "New profiles:"):
			continue
		case isTableHeader(trimmed):
			continue
		default:
			if rule, ok := parseRuleLine(line); ok {
				st.rules = append(st.rules, rule)
			}
		}
	}
	return st
}

// buildModel wraps a parsed status into the generic model, with ufw's single
// rule group.
func buildModel(st status, services []string) firewall.Model {
	return firewall.Model{
		Backend:   "ufw",
		Enabled:   st.enabled,
		Logging:   st.logging,
		LoggingOn: st.loggingOn,
		Services:  services,
		Groups: []firewall.Group{{
			Name:    GroupName,
			Title:   "Rules",
			Default: st.defaults,
			PolicySlots: []firewall.PolicyDirection{
				firewall.PolicyIncoming,
				firewall.PolicyOutgoing,
				firewall.PolicyRouted,
			},
			Rules: st.rules,
		}},
	}
}

// MergeModels combines the verbose output (which carries defaults and logging
// but no rule numbers) with the numbered output (which carries the numbers).
// Rules always come from the numbered listing when it has any.
func MergeModels(verbose, numbered firewall.Model) firewall.Model {
	merged := verbose
	if !merged.Enabled {
		merged.Enabled = numbered.Enabled
	}
	if len(numbered.Groups) > 0 && len(numbered.Groups[0].Rules) > 0 &&
		len(merged.Groups) > 0 {
		merged.Groups[0].Rules = numbered.Groups[0].Rules
	}
	return merged
}

// isTableHeader reports the "To  Action  From" header and its dashed underline.
func isTableHeader(line string) bool {
	if strings.HasPrefix(line, "--") {
		return true
	}
	return strings.HasPrefix(line, "To") && strings.Contains(line, "Action") &&
		strings.Contains(line, "From")
}

// parseLogging reads a "Logging: on (low)" line.
func parseLogging(line string) (on bool, level string) {
	m := loggingRe.FindStringSubmatch(line)
	if m == nil {
		return false, ""
	}
	on = m[1] == "on"
	if !on {
		return false, LogOff
	}
	return true, m[2]
}

// parseDefaults reads a "Default: deny (incoming), allow (outgoing), disabled
// (routed)" line.
func parseDefaults(line string) firewall.Policies {
	d := firewall.Policies{}
	for _, m := range defaultsRe.FindAllStringSubmatch(line, -1) {
		verdict, where := m[1], m[2]
		policy := firewall.Policy(verdict)
		disabled := verdict == "disabled"
		switch where {
		case "incoming":
			d.Incoming = policy
		case "outgoing":
			d.Outgoing = policy
		case "routed":
			d.RoutedDisabled = disabled
			if !disabled {
				d.Routed = policy
			}
		}
	}
	return d
}

// parseRuleLine turns one table row into a Rule. It returns false for lines
// that do not carry a verdict column (headers, notes, blank separators).
func parseRuleLine(line string) (firewall.Rule, bool) {
	r := firewall.Rule{}
	body := line

	if m := numberedPrefixRe.FindStringSubmatch(body); m != nil {
		r.Index, _ = strconv.Atoi(m[1])
		r.ID = m[1]
		body = body[len(m[0]):]
	}
	body = strings.TrimLeft(body, " ")

	// The regex needs a leading space to anchor the verdict column, so it runs
	// against a padded copy.
	padded := " " + body
	loc := verdictRe.FindStringSubmatchIndex(padded)
	if loc == nil {
		return firewall.Rule{}, false
	}
	m := verdictRe.FindStringSubmatch(padded)
	to := strings.TrimSpace(padded[:loc[0]])
	from := strings.TrimSpace(padded[loc[1]:])

	r.Action = firewall.Action(m[1])
	r.Direction = firewall.Direction(m[2])

	from, r.Comment = splitComment(from)
	to, toV6 := stripV6(to)
	from, fromV6 := stripV6(from)
	if toV6 || fromV6 {
		r.Family = firewall.FamilyIPv6
	}

	r.To = to
	r.From = from
	r.Ports, r.Proto, r.Service = describeTarget(to)
	r.Raw = strings.TrimSpace(body)
	return r, true
}

// splitComment separates ufw's trailing "# comment" from the From column.
func splitComment(from string) (rest, comment string) {
	idx := strings.Index(from, "#")
	if idx < 0 {
		return from, ""
	}
	return strings.TrimSpace(from[:idx]), strings.TrimSpace(from[idx+1:])
}

// stripV6 removes the "(v6)" tag ufw appends to IPv6 rules.
func stripV6(s string) (rest string, v6 bool) {
	if strings.HasSuffix(s, "(v6)") {
		return strings.TrimSpace(strings.TrimSuffix(s, "(v6)")), true
	}
	return s, false
}

// describeTarget extracts ports, protocol and application profile from the
// "To" column. Only one of (ports/proto) and profile is usually present, but a
// rule created from a profile shows both ("80,443/tcp (Nginx Full)").
func describeTarget(to string) (ports, proto, profile string) {
	target := to
	if m := appSuffixRe.FindStringSubmatch(target); m != nil {
		profile = m[1]
		target = strings.TrimSpace(strings.TrimSuffix(target, m[0]))
	}
	// Drop the "on <iface>" qualifier, it is not part of the target.
	if idx := strings.Index(target, " on "); idx >= 0 {
		target = strings.TrimSpace(target[:idx])
	}
	fields := strings.Fields(target)
	if len(fields) == 0 {
		return "", "", profile
	}
	last := fields[len(fields)-1]
	if m := portProtoRe.FindStringSubmatch(last); m != nil {
		return m[1], m[2], profile
	}
	// A single non-address, non-"Anywhere" token is an application profile
	// name that ufw did not expand.
	if profile == "" && len(fields) == 1 && isProfileName(last) {
		profile = last
	}
	return "", "", profile
}

// isProfileName reports a token that looks like an app profile rather than an
// address ("OpenSSH" yes, "Anywhere" no, "192.168.0.0/24" no).
func isProfileName(s string) bool {
	if s == "" || s == "Anywhere" {
		return false
	}
	if strings.ContainsAny(s, ".:/") {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

// ParseAppList parses the output of `ufw app list`.
func ParseAppList(output string) []string {
	var profiles []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	seenHeader := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Available applications") {
			seenHeader = true
			continue
		}
		if !seenHeader {
			continue
		}
		profiles = append(profiles, line)
	}
	return profiles
}
