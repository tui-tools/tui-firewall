package ufw

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// Fake is an in-memory backend used by --demo and by the tests. It applies the
// same commands the real backend would run, so the UI cannot tell them apart.
type Fake struct {
	mu    sync.Mutex
	model firewall.Model
	// Log records every command that was run, in order.
	Log []firewall.Command
	// FailWith, when set, makes the next Run fail with this error.
	FailWith error
}

// NewFake returns a Fake preloaded with a realistic rule set.
func NewFake() *Fake { return &Fake{model: demoModel()} }

// rule is a small helper keeping demoModel readable.
func rule(index int, action firewall.Action, dir firewall.Direction,
	to, from, ports, proto, service, comment string, family firewall.Family) firewall.Rule {
	return firewall.Rule{
		ID: strconv.Itoa(index), Index: index, Action: action, Direction: dir,
		To: to, From: from, Ports: ports, Proto: proto, Service: service,
		Comment: comment, Family: family,
	}
}

// demoModel is the sample firewall shown by --demo.
func demoModel() firewall.Model {
	v4, v6 := firewall.FamilyIPv4, firewall.FamilyIPv6
	in, out := firewall.DirIn, firewall.DirOut
	rules := []firewall.Rule{
		rule(1, firewall.ActionLimit, in, "22/tcp", "Anywhere", "22", "tcp", "",
			"ssh rate limit", v4),
		rule(2, firewall.ActionAllow, in, "80,443/tcp (Nginx Full)", "Anywhere",
			"80,443", "tcp", "Nginx Full", "", v4),
		rule(3, firewall.ActionAllow, in, "5432/tcp", "10.0.0.0/8", "5432", "tcp", "",
			"postgres from lan", v4),
		rule(4, firewall.ActionDeny, in, "3306/tcp", "Anywhere", "3306", "tcp", "", "", v4),
		rule(5, firewall.ActionAllow, firewall.DirForward, "Anywhere",
			"192.168.1.0/24", "", "", "", "lan forwarding", v4),
		rule(6, firewall.ActionAllow, out, "2000:2100/udp", "Anywhere",
			"2000:2100", "udp", "", "", v4),
		rule(7, firewall.ActionLimit, in, "22/tcp", "Anywhere", "22", "tcp", "",
			"ssh rate limit", v6),
		rule(8, firewall.ActionAllow, in, "80,443/tcp (Nginx Full)", "Anywhere",
			"80,443", "tcp", "Nginx Full", "", v6),
		rule(9, firewall.ActionReject, in, "137,138/udp (Samba)", "fd00::/8",
			"137,138", "udp", "Samba", "", v6),
	}
	return firewall.Model{
		Backend:   "ufw",
		Enabled:   true,
		LoggingOn: true,
		Logging:   LogLow,
		Services: []string{
			"CUPS", "Nginx Full", "Nginx HTTP", "Nginx HTTPS", "OpenSSH", "Samba",
		},
		Groups: []firewall.Group{{
			Name:  GroupName,
			Title: "Rules",
			Default: firewall.Policies{
				Incoming:       firewall.PolicyDeny,
				Outgoing:       firewall.PolicyAllow,
				RoutedDisabled: true,
			},
			PolicySlots: []firewall.PolicyDirection{
				firewall.PolicyIncoming, firewall.PolicyOutgoing, firewall.PolicyRouted,
			},
			Rules: rules,
		}},
	}
}

// Name identifies the backend.
func (f *Fake) Name() string { return "demo" }

// Describe names the backend for the status line.
func (f *Fake) Describe() string { return "demo (no changes are applied)" }

// Capabilities mirrors the real ufw backend.
func (f *Fake) Capabilities() firewall.Capabilities { return capabilities }

// Preview renders the change as the real backend would, without a privilege
// prefix: the demo never escalates.
func (f *Fake) Preview(change firewall.Change) string { return change.String() }

// Load returns a copy of the in-memory state.
func (f *Fake) Load(_ context.Context) (firewall.Model, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshot(), nil
}

// snapshot copies the state so callers cannot mutate it behind our back. The
// caller must hold f.mu.
func (f *Fake) snapshot() firewall.Model {
	m := f.model
	m.Groups = append([]firewall.Group(nil), f.model.Groups...)
	for i := range m.Groups {
		m.Groups[i].Rules = append([]firewall.Rule(nil), f.model.Groups[i].Rules...)
	}
	m.Services = append([]string(nil), f.model.Services...)
	return m
}

// rules returns a pointer to the single demo rule group.
func (f *Fake) rules() *[]firewall.Rule { return &f.model.Groups[0].Rules }

// Run applies a change to the in-memory state, one command at a time.
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
	if len(args) > 0 && args[0] == "ufw" {
		args = args[1:]
	}
	// Skip the flags the real ufw takes before the verb.
	for len(args) > 0 && strings.HasPrefix(args[0], "--") {
		args = args[1:]
	}
	if len(args) == 0 {
		return "", fmt.Errorf("ufw: empty command")
	}

	switch args[0] {
	case "enable":
		f.model.Enabled = true
		return "Firewall is active and enabled on system startup", nil
	case "disable":
		f.model.Enabled = false
		return "Firewall stopped and disabled on system startup", nil
	case "reload":
		return "Firewall reloaded", nil
	case "status", "app":
		return "", nil
	case "delete":
		return f.deleteRule(args)
	case "logging":
		return f.setLogging(args)
	case "default":
		return f.setDefault(args)
	case "insert", "allow", "deny", "reject", "limit", "route":
		f.addRule(args)
		return "Rule added", nil
	default:
		return "", fmt.Errorf("ufw: unsupported command %q in demo mode", args[0])
	}
}

// deleteRule removes a rule by number and renumbers the rest.
func (f *Fake) deleteRule(args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("ufw: delete needs a rule number")
	}
	rules := f.rules()
	n, err := strconv.Atoi(args[1])
	if err != nil || n <= 0 || n > len(*rules) {
		return "", fmt.Errorf("ufw: could not delete non-existent rule %s", args[1])
	}
	*rules = append((*rules)[:n-1], (*rules)[n:]...)
	f.renumber()
	return "Rule deleted", nil
}

// setLogging applies `ufw logging <level>`.
func (f *Fake) setLogging(args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("ufw: logging needs a level")
	}
	f.model.Logging = args[1]
	f.model.LoggingOn = args[1] != LogOff
	return "Logging " + args[1], nil
}

// setDefault applies `ufw default <policy> <slot>`.
func (f *Fake) setDefault(args []string) (string, error) {
	if len(args) < 3 {
		return "", fmt.Errorf("ufw: default needs a policy and a direction")
	}
	policy := firewall.Policy(args[1])
	defaults := &f.model.Groups[0].Default
	switch firewall.PolicyDirection(args[2]) {
	case firewall.PolicyIncoming:
		defaults.Incoming = policy
	case firewall.PolicyOutgoing:
		defaults.Outgoing = policy
	case firewall.PolicyRouted:
		defaults.Routed = policy
		defaults.RoutedDisabled = false
	default:
		return "", fmt.Errorf("ufw: unknown direction %q", args[2])
	}
	return "Default policy changed", nil
}

// addRule appends (or inserts) a rule reconstructed from the argv, which is
// enough for the demo table to show the effect of the command.
func (f *Fake) addRule(args []string) {
	newRule := ruleFromArgs(args)
	rules := f.rules()
	position := len(*rules)
	if args[0] == "insert" && len(args) > 1 {
		if n, err := strconv.Atoi(args[1]); err == nil && n >= 1 && n <= position+1 {
			position = n - 1
		}
	}
	*rules = append(*rules, firewall.Rule{})
	copy((*rules)[position+1:], (*rules)[position:])
	(*rules)[position] = newRule
	f.renumber()
}

// ruleFromArgs is a small argv reader: enough to display what was added.
func ruleFromArgs(args []string) firewall.Rule {
	r := firewall.Rule{
		From: "Anywhere", To: "Anywhere",
		Direction: firewall.DirIn, Family: firewall.FamilyIPv4,
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "insert":
			i++
		case "route":
			r.Direction = firewall.DirForward
		case "allow", "deny", "reject", "limit":
			r.Action = firewall.Action(strings.ToUpper(args[i]))
		case "in":
			r.Direction = firewall.DirIn
		case "out":
			r.Direction = firewall.DirOut
		case "from", "to", "port", "proto", "app", "comment":
			key := args[i]
			i++
			if i < len(args) {
				assignRuleField(&r, key, args[i])
			}
		default:
			// The short form: a bare "22/tcp" target or an app profile name.
			if r.Action != "" && r.Ports == "" && r.Service == "" {
				r.Ports, r.Proto, r.Service = describeTarget(args[i])
			}
		}
	}
	if r.Ports != "" {
		r.To = portArg(r.Ports, r.Proto)
	} else if r.Service != "" && r.To == "Anywhere" {
		r.To = r.Service
	}
	return r
}

// assignRuleField sets the field named by a `ufw` keyword.
func assignRuleField(r *firewall.Rule, key, value string) {
	switch key {
	case "from":
		r.From = value
	case "to":
		r.To = value
	case "port":
		r.Ports = value
	case "proto":
		r.Proto = value
	case "app":
		r.Service = value
	case "comment":
		r.Comment = value
	}
}

// renumber restores contiguous 1-based rule numbers.
func (f *Fake) renumber() {
	rules := f.rules()
	for i := range *rules {
		(*rules)[i].Index = i + 1
		(*rules)[i].ID = strconv.Itoa(i + 1)
	}
}

// BuildAddRule creates a rule.
func (f *Fake) BuildAddRule(group string, spec firewall.RuleSpec) (firewall.Change, error) {
	return BuildAddRule(group, spec)
}

// BuildDeleteRule removes a rule.
func (f *Fake) BuildDeleteRule(group string, r firewall.Rule) (firewall.Change, error) {
	return BuildDeleteRule(group, r)
}

// BuildSetEnabled turns the firewall on or off.
func (f *Fake) BuildSetEnabled(enabled bool) (firewall.Change, error) {
	return BuildSetEnabled(enabled)
}

// BuildReload re-applies the rule set.
func (f *Fake) BuildReload() (firewall.Change, error) { return BuildReload() }

// BuildSetPolicy changes one default policy.
func (f *Fake) BuildSetPolicy(group string, slot firewall.PolicyDirection,
	policy firewall.Policy) (firewall.Change, error) {
	return BuildSetPolicy(group, slot, policy)
}

// BuildSetLogging changes the logging level.
func (f *Fake) BuildSetLogging(level string) (firewall.Change, error) {
	return BuildSetLogging(level)
}

// Extras reports that ufw has no actions beyond the common set.
func (f *Fake) Extras(_ firewall.Model, _ string) []firewall.Extra { return nil }

// BuildExtra always fails: ufw offers no extra actions.
func (f *Fake) BuildExtra(_, id string, _ []string) (firewall.Change, error) {
	return firewall.Change{}, fmt.Errorf("ufw: no extra action %q", id)
}
