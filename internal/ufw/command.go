package ufw

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/edimarlnx/tui-tools/internal/firewall"
)

// The `ufw logging` levels.
const (
	LogOff    = "off"
	LogLow    = "low"
	LogMedium = "medium"
	LogHigh   = "high"
	LogFull   = "full"
)

// capabilities describes what the ufw backend supports. It is shared by the
// real and the fake backend so the demo behaves exactly like the real thing.
var capabilities = firewall.Capabilities{
	Actions: []firewall.Action{
		firewall.ActionAllow, firewall.ActionDeny,
		firewall.ActionReject, firewall.ActionLimit,
	},
	Directions: []firewall.Direction{firewall.DirIn, firewall.DirOut},
	Policies: []firewall.Policy{
		firewall.PolicyAllow, firewall.PolicyDeny, firewall.PolicyReject,
	},
	LogLevels:        []string{LogOff, LogLow, LogMedium, LogHigh, LogFull},
	SupportsInsert:   true,
	SupportsComments: true,
	SupportsRouted:   true,
	SupportsLogging:  true,
	ServiceLabel:     "App profile",
	GroupLabel:       "Rules",
}

// Capabilities reports what the ufw backend supports.
func Capabilities() firewall.Capabilities { return capabilities }

// checkGroup rejects any group other than the single one ufw exposes.
func checkGroup(group string) error {
	if group != "" && group != GroupName {
		return fmt.Errorf("ufw: unknown rule group %q", group)
	}
	return nil
}

// BuildAddRule turns a RuleSpec into an `ufw` command. It returns an error
// when the spec is incomplete, so the form can refuse to open the confirm
// dialog.
func BuildAddRule(group string, spec firewall.RuleSpec) (firewall.Command, error) {
	if err := checkGroup(group); err != nil {
		return firewall.Command{}, err
	}
	args, err := ruleArgs(spec)
	if err != nil {
		return firewall.Command{}, err
	}
	description := "Add rule"
	if spec.Position > 0 {
		description = fmt.Sprintf("Insert rule at position %d", spec.Position)
	}
	return firewall.Command{Argv: args, Description: description}, nil
}

// ruleArgs assembles the argv shared by add and insert.
func ruleArgs(spec firewall.RuleSpec) ([]string, error) {
	if spec.Action == "" {
		return nil, fmt.Errorf("an action is required")
	}
	if spec.Service == "" && spec.Ports == "" && spec.From == "" && spec.To == "" {
		return nil, fmt.Errorf("give at least a port, an app profile or an address")
	}
	if spec.Position < 0 {
		return nil, fmt.Errorf("position must be positive")
	}
	if spec.Proto != "" && spec.Ports == "" && spec.Service == "" {
		return nil, fmt.Errorf("a protocol needs a port")
	}
	if strings.ContainsAny(spec.Comment, "\n\r") {
		return nil, fmt.Errorf("comment must be a single line")
	}

	args := []string{"ufw"}
	if spec.Position > 0 {
		args = append(args, "insert", strconv.Itoa(spec.Position))
	}
	if spec.Routed {
		args = append(args, "route")
	}
	args = append(args, spec.Action.Arg())
	if spec.Direction != firewall.DirAny {
		args = append(args, spec.Direction.Arg())
	}

	// The short form ("ufw allow 22/tcp", "ufw allow OpenSSH") only works
	// without from/to selectors; anything else needs the extended syntax.
	extended := spec.From != "" || spec.To != ""
	switch {
	case spec.Service != "" && !extended:
		args = append(args, spec.Service)
	case !extended:
		args = append(args, portArg(spec.Ports, spec.Proto))
	default:
		args = append(args, "from", orAny(spec.From), "to", orAny(spec.To))
		if spec.Service != "" {
			args = append(args, "app", spec.Service)
		} else if spec.Ports != "" {
			args = append(args, "port", spec.Ports)
			if spec.Proto != "" {
				args = append(args, "proto", spec.Proto)
			}
		}
	}

	if spec.Comment != "" {
		args = append(args, "comment", spec.Comment)
	}
	return args, nil
}

// portArg renders "22/tcp" or plain "22".
func portArg(ports, proto string) string {
	if proto == "" {
		return ports
	}
	return ports + "/" + proto
}

// orAny defaults an empty selector to ufw's "any" keyword.
func orAny(s string) string {
	if s == "" {
		return "any"
	}
	return s
}

// BuildDeleteRule removes a rule by its number in `ufw status numbered`.
func BuildDeleteRule(group string, rule firewall.Rule) (firewall.Command, error) {
	if err := checkGroup(group); err != nil {
		return firewall.Command{}, err
	}
	number, err := strconv.Atoi(rule.ID)
	if err != nil || number <= 0 {
		return firewall.Command{}, fmt.Errorf("ufw: rule has no usable number (%q)", rule.ID)
	}
	return firewall.Command{
		Argv:        []string{"ufw", "--force", "delete", strconv.Itoa(number)},
		Description: fmt.Sprintf("Delete rule %d", number),
		Destructive: true,
	}, nil
}

// BuildSetEnabled turns the firewall on or off. `--force` skips ufw's own SSH
// prompt, which a TUI cannot answer; fwall asks for confirmation itself.
func BuildSetEnabled(enabled bool) (firewall.Command, error) {
	if enabled {
		return firewall.Command{
			Argv:        []string{"ufw", "--force", "enable"},
			Description: "Enable the firewall",
			Destructive: true,
		}, nil
	}
	return firewall.Command{
		Argv:        []string{"ufw", "disable"},
		Description: "Disable the firewall (all traffic allowed)",
		Destructive: true,
	}, nil
}

// BuildReload re-applies the rule set without dropping connections.
func BuildReload() (firewall.Command, error) {
	return firewall.Command{
		Argv:        []string{"ufw", "reload"},
		Description: "Reload the firewall",
	}, nil
}

// BuildSetPolicy sets one of the three default policies.
func BuildSetPolicy(group string, slot firewall.PolicyDirection,
	policy firewall.Policy) (firewall.Command, error) {
	if err := checkGroup(group); err != nil {
		return firewall.Command{}, err
	}
	switch slot {
	case firewall.PolicyIncoming, firewall.PolicyOutgoing, firewall.PolicyRouted:
	default:
		return firewall.Command{}, fmt.Errorf("ufw: unsupported policy slot %q", slot)
	}
	if !validPolicy(policy) {
		return firewall.Command{}, fmt.Errorf("ufw: unknown policy %q", policy)
	}
	return firewall.Command{
		Argv:        []string{"ufw", "default", string(policy), string(slot)},
		Description: fmt.Sprintf("Set default %s policy to %s", slot, policy),
		Destructive: true,
	}, nil
}

// validPolicy reports whether p is one of the accepted default policies.
func validPolicy(p firewall.Policy) bool {
	for _, known := range capabilities.Policies {
		if p == known {
			return true
		}
	}
	return false
}

// BuildSetLogging sets the logging level.
func BuildSetLogging(level string) (firewall.Command, error) {
	for _, known := range capabilities.LogLevels {
		if level == known {
			return firewall.Command{
				Argv:        []string{"ufw", "logging", level},
				Description: fmt.Sprintf("Set logging to %s", level),
			}, nil
		}
	}
	return firewall.Command{}, fmt.Errorf("ufw: unknown logging level %q", level)
}
