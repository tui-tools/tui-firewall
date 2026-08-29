// Package firewall defines the backend-agnostic model tui-firewall renders and the
// interface every firewall implementation satisfies. The UI knows only these
// types: it never builds a ufw or firewall-cmd argv itself. Mutations are
// Command values produced by the backend, shown in a preview dialog and only
// then executed.
package firewall

import (
	"context"
	"strings"

	"github.com/tui-tools/tui-kit/runner"
)

// Action is the verdict a rule applies to matching traffic.
type Action string

// The verdicts common to the supported backends. LIMIT is ufw-specific; a
// backend advertises what it supports through Capabilities.
const (
	ActionAllow  Action = "ALLOW"
	ActionDeny   Action = "DENY"
	ActionReject Action = "REJECT"
	ActionLimit  Action = "LIMIT"
)

// Arg returns the lowercase form backends use on the command line.
func (a Action) Arg() string { return strings.ToLower(string(a)) }

// Direction is the traffic direction a rule matches.
type Direction string

// The directions a rule can carry. DirAny means the backend does not qualify
// the rule by direction.
const (
	DirAny     Direction = ""
	DirIn      Direction = "IN"
	DirOut     Direction = "OUT"
	DirForward Direction = "FWD"
)

// Arg returns the lowercase form backends use on the command line.
func (d Direction) Arg() string { return strings.ToLower(string(d)) }

// Family is the address family a rule applies to.
type Family string

// The address families a rule can carry.
const (
	FamilyAny  Family = ""
	FamilyIPv4 Family = "v4"
	FamilyIPv6 Family = "v6"
)

// Policy is a default policy verdict for a group.
type Policy string

// The default policies backends accept.
const (
	PolicyAllow  Policy = "allow"
	PolicyDeny   Policy = "deny"
	PolicyReject Policy = "reject"
)

// PolicyDirection names one of the default policies of a Group.
type PolicyDirection string

// The default policy slots a group can expose.
const (
	PolicyIncoming PolicyDirection = "incoming"
	PolicyOutgoing PolicyDirection = "outgoing"
	PolicyRouted   PolicyDirection = "routed"
	// PolicyTarget is the single target of a firewalld zone.
	PolicyTarget PolicyDirection = "target"
)

// Rule is one entry of a Group, in backend-neutral terms.
type Rule struct {
	// ID identifies the rule for deletion. It is opaque to the UI: ufw uses
	// the rule number, firewalld will use the rule's own textual form.
	ID string
	// Index is the 1-based display position within its group; 0 when the
	// backend does not order rules.
	Index int

	Action    Action
	Direction Direction
	// Proto is "tcp", "udp" or empty for any.
	Proto string
	// Ports is the port expression as the backend prints it: "22",
	// "80,443", "2000:2100".
	Ports string
	// From and To are the source and destination selectors.
	From string
	To   string
	// Service is the named service (firewalld) or application profile (ufw).
	Service string
	Comment string
	Family  Family
	// Raw is the backend's own rendering of the rule, kept for the detail view
	// and for backends whose rules do not decompose cleanly.
	Raw string
	// Extra carries backend-specific attributes the generic model has no field
	// for (firewalld rich-rule parts, ufw interface qualifiers, …).
	Extra map[string]string
}

// Policies are the default verdicts of a Group. A backend fills only the slots
// it exposes (see Group.PolicySlots).
type Policies struct {
	Incoming Policy
	Outgoing Policy
	Routed   Policy
	// RoutedDisabled reports that forwarding is off entirely.
	RoutedDisabled bool
	// Target is the firewalld zone target; unused by ufw.
	Target string
}

// Group is a named set of rules with its own default policies. ufw exposes a
// single group ("rules") carrying the global policies; firewalld will expose
// one group per zone.
type Group struct {
	// Name is the stable identifier passed back to the backend.
	Name string
	// Title is the human label shown in the UI; defaults to Name.
	Title string
	// Description is an optional one-line note (a zone's interfaces, say).
	Description string
	// Default holds the group's default policies.
	Default Policies
	// PolicySlots lists which Default fields this group actually uses, in the
	// order the policy dialog should offer them.
	PolicySlots []PolicyDirection
	Rules       []Rule
}

// Label returns Title when set, otherwise Name.
func (g Group) Label() string {
	if g.Title != "" {
		return g.Title
	}
	return g.Name
}

// Model is the whole picture tui-firewall renders.
type Model struct {
	// Backend names the implementation that produced this model.
	Backend string
	Enabled bool
	// Logging is the current log level; empty when unknown.
	Logging string
	// LoggingOn reports whether logging is active at all.
	LoggingOn bool
	Groups    []Group
	// Services lists the named services or app profiles offered by the picker.
	Services []string
}

// Group returns the group with the given name.
func (m Model) Group(name string) (Group, bool) {
	for _, g := range m.Groups {
		if g.Name == name {
			return g, true
		}
	}
	return Group{}, false
}

// Command is a single privileged invocation the user is about to run. Argv
// excludes any privilege wrapper: the backend adds it when executing.
//
// It is an alias rather than a type of its own: the preview/confirm/run
// contract belongs to the whole tui-tools family and lives in the kit, and an
// alias means a backend can hand its Command straight to a runner.Runner with
// no conversion in between — which is precisely what guarantees that the
// command shown in the dialog is the command that executes.
type Command = runner.Command

// RuleSpec describes a rule the user wants to create. Backends translate it
// into their own syntax; unsupported fields are rejected with a clear error.
type RuleSpec struct {
	Action    Action
	Direction Direction
	// Service is the named service or app profile; it replaces Ports/Proto.
	Service string
	Ports   string
	Proto   string
	From    string
	To      string
	Comment string
	// Routed asks for a forwarding rule.
	Routed bool
	// Position, when > 0, inserts the rule at that 1-based position.
	Position int
}

// Capabilities tells the UI which options a backend supports, so menus and
// forms are built from the backend instead of being hardcoded.
type Capabilities struct {
	Actions    []Action
	Directions []Direction
	Policies   []Policy
	LogLevels  []string
	// SupportsInsert reports whether RuleSpec.Position is honoured.
	SupportsInsert bool
	// SupportsComments reports whether RuleSpec.Comment is honoured.
	SupportsComments bool
	// SupportsRouted reports whether RuleSpec.Routed is honoured.
	SupportsRouted bool
	// SupportsLogging reports whether SetLogging is available.
	SupportsLogging bool
	// ServiceLabel names the service concept in the UI ("App profile",
	// "Service").
	ServiceLabel string
	// GroupLabel names the group concept in the UI ("Rules", "Zone").
	GroupLabel string
}

// Backend is the boundary between the UI and the machine. Load reads state;
// the Build* methods turn user intent into a previewable Command; Run executes
// a Command the user confirmed. Nothing else may mutate the system.
type Backend interface {
	// Name is the backend identifier ("ufw", "firewalld", "demo").
	Name() string
	// Describe is the one-line summary shown in the status line.
	Describe() string
	// Capabilities reports what this backend supports.
	Capabilities() Capabilities

	// Preview renders the exact command line that Run will execute, including
	// any privilege wrapper. This is the text shown in the confirm dialog.
	Preview(cmd Command) string

	// Load reads the current firewall state.
	Load(ctx context.Context) (Model, error)
	// Run executes a previously previewed command.
	Run(ctx context.Context, cmd Command) (string, error)

	// BuildAddRule creates a rule in the named group.
	BuildAddRule(group string, spec RuleSpec) (Command, error)
	// BuildDeleteRule removes an existing rule from the named group.
	BuildDeleteRule(group string, rule Rule) (Command, error)
	// BuildSetEnabled turns the firewall on or off.
	BuildSetEnabled(enabled bool) (Command, error)
	// BuildReload re-applies the rule set.
	BuildReload() (Command, error)
	// BuildSetPolicy changes one default policy of a group.
	BuildSetPolicy(group string, slot PolicyDirection, policy Policy) (Command, error)
	// BuildSetLogging changes the logging level.
	BuildSetLogging(level string) (Command, error)
}
