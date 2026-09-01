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

// Kind names what sort of entry a Rule is, for backends whose groups hold more
// than one species. ufw has a single kind and leaves it empty; firewalld fills
// it, because a zone mixes services, ports, rich rules, bound sources and
// assigned interfaces, and deleting each takes a different argument.
//
// The UI only ever displays a kind and passes it back; it never branches on
// the value, which is why the list is open rather than an enum.
const (
	KindService     = "service"
	KindPort        = "port"
	KindProtocol    = "protocol"
	KindSourcePort  = "source-port"
	KindForwardPort = "forward-port"
	KindRich        = "rich"
	KindSource      = "source"
	KindInterface   = "interface"
	KindMasquerade  = "masquerade"
	KindForward     = "forward"
	KindICMPBlock   = "icmp-block"
)

// View names the column layout a Group wants. A backend whose groups all hold
// the same species of entry leaves it empty and gets the rule table; one
// whose groups do not — the nftables backend shows filter rules, address
// translation and named sets, and no single set of columns fits all three —
// names the layout each group needs.
//
// It is a hint about presentation and nothing more: the UI picks columns from
// it and never branches on it for behaviour, which is why an unknown value
// falls back to the rule table rather than failing.
const (
	ViewRules   = ""
	ViewNAT     = "nat"
	ViewAliases = "aliases"
)

// The Rule.Extra keys the UI knows how to put in a column. A backend fills
// the ones it has; the columns appear only for a group whose view asks for
// them.
const (
	// ExtraInIface and ExtraOutIface are the interfaces a rule matches.
	ExtraInIface  = "in"
	ExtraOutIface = "out"
	// ExtraCounter is the rule's packet and byte counter, already rendered.
	ExtraCounter = "counter"
	// ExtraTarget is what an address translation rewrites to.
	ExtraTarget = "target"
	// ExtraElements is the member count of a named set, ExtraReferences the
	// number of rules that use it, and ExtraFlags its nft flags.
	ExtraElements   = "elements"
	ExtraReferences = "references"
	ExtraFlags      = "flags"
	// ExtraDetail is a one-line rendering of everything the columns of this
	// view had no room for.
	ExtraDetail = "detail"
	// ExtraLog marks a rule that logs the packets it matches, so the row can
	// carry a LOG tag. Its value is the log prefix when the rule has one.
	ExtraLog = "log"
	// ExtraDisabled marks a rule the backend holds but the firewall is not
	// applying, so the row can be greyed out and marked. It is set by a
	// backend that keeps its own record of a rule it took out of the running
	// configuration — nftables, which has no disabled state of its own.
	ExtraDisabled = "disabled"
)

// Rule is one entry of a Group, in backend-neutral terms.
type Rule struct {
	// ID identifies the rule for deletion. It is opaque to the UI: ufw uses
	// the rule number, firewalld uses the entry's own textual form.
	ID string
	// Index is the 1-based display position within its group; 0 when the
	// backend does not order rules.
	Index int
	// Kind names the species of entry (see the Kind* constants); empty on a
	// backend whose group holds only one.
	Kind string
	// Note is a short backend-supplied annotation shown beside the rule —
	// firewalld uses it to mark an entry that exists only in the runtime
	// configuration or only in the permanent one.
	Note string

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
	// View names the column layout this group wants; see the View constants.
	View string
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
	// Warning is a banner the backend wants shown about the current state.
	// firewalld uses it for panic mode, in which every packet is dropped.
	Warning string
	Groups  []Group
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

// Change is everything one confirmation applies: an ordered list of commands,
// with the description and the danger flag the dialog is painted from.
//
// It exists because not every backend expresses a change in one invocation.
// firewalld keeps a runtime configuration and a permanent one, and applying a
// change to both means running the same command twice, once with
// `--permanent`. Making that a list rather than a hidden second exec keeps the
// promise intact: every line the dialog shows is a line that runs, and nothing
// else does.
//
// Commands run in order and stop at the first failure.
type Change struct {
	// Description is the title of the confirm dialog.
	Description string
	// Destructive paints the dialog in the danger colour.
	Destructive bool
	// Note is one line explaining how the change is applied, shown in the
	// dialog above the commands ("applied to the running firewall and to the
	// permanent configuration; no reload, so connections are not dropped").
	Note string
	// Commands is what will run, in order.
	Commands []Command
}

// One wraps a single Command as a Change, carrying its description and danger
// flag up to the dialog. It is what a backend with nothing to sequence uses.
func One(cmd Command) Change {
	return Change{
		Description: cmd.Description,
		Destructive: cmd.Destructive,
		Commands:    []Command{cmd},
	}
}

// Empty reports a Change with nothing to run.
func (c Change) Empty() bool { return len(c.Commands) == 0 }

// String renders every command, one per line, with no privilege prefix. It is
// the backend-independent rendering; a preview adds the prefix the runner will
// really use.
func (c Change) String() string {
	lines := make([]string, 0, len(c.Commands))
	for _, cmd := range c.Commands {
		lines = append(lines, cmd.String())
	}
	return strings.Join(lines, "\n")
}

// PreviewChange renders every command of a Change, one per line, exactly as
// the given runner would execute it. Backends delegate their Preview here so
// the dialog and the execution loop below cannot drift apart.
func PreviewChange(r runner.Interface, change Change) string {
	lines := make([]string, 0, len(change.Commands))
	for _, cmd := range change.Commands {
		lines = append(lines, r.Preview(cmd))
	}
	return strings.Join(lines, "\n")
}

// RunChange executes a Change through a runner, in order, and stops at the
// first command that fails — a half-applied change is reported as such rather
// than pressed on with.
func RunChange(ctx context.Context, r runner.Interface, change Change) (string, error) {
	var outputs []string
	for _, cmd := range change.Commands {
		out, err := r.Run(ctx, cmd)
		if out = strings.TrimSpace(out); out != "" {
			outputs = append(outputs, out)
		}
		if err != nil {
			return strings.Join(outputs, "\n"), err
		}
	}
	return strings.Join(outputs, "\n"), nil
}

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
	// InIface and OutIface restrict the rule to an input or output interface.
	// nftables matches them with iifname/oifname; backends that cannot express
	// an interface match reject a non-empty value.
	InIface  string
	OutIface string
	// CTStates lists the connection-tracking states the rule matches
	// ("established", "related", "new", "invalid"). A stateful firewall reads
	// these first; a backend that has no conntrack match rejects a non-empty
	// value.
	CTStates []string
	// ICMPType, when Proto is "icmp" or "icmpv6", narrows the rule to one ICMP
	// message type ("echo-request", …). It is ignored for any other protocol.
	ICMPType string
	// Family restricts the rule to one address family. Backends that cannot
	// express it (ufw derives it from the addresses) reject a non-empty value.
	Family Family
	// Log asks the backend to log packets the rule matches.
	Log bool
	// Routed asks for a forwarding rule.
	Routed bool
	// Position, when > 0, inserts the rule at that 1-based position.
	Position int
}

// ExtraStep is one answer an Extra needs before its command can be built. The
// UI asks for the steps in order: a picker when Options is set, a text prompt
// otherwise.
type ExtraStep struct {
	// Prompt is the dialog title.
	Prompt string
	// Options are the choices; empty asks for free text instead.
	Options []string
	// Placeholder hints at the expected free-text answer.
	Placeholder string
	// Current preselects an option, or prefills the text field.
	Current string
}

// Extra is an action a backend offers beyond the set every firewall shares.
// The UI lists them in a menu, collects the steps and previews the resulting
// Change exactly like any other mutation — so a backend can add an operation
// without the UI learning what it means, let alone which binary provides it.
type Extra struct {
	// ID is passed back to BuildExtra; it is never shown.
	ID string
	// Label is the menu entry.
	Label string
	// Steps are the answers to collect, in order.
	Steps []ExtraStep
	// Danger paints the confirm dialog in the danger colour.
	Danger bool
	// Warning is an extra line shown in the confirm dialog, for an action
	// whose consequences deserve spelling out.
	Warning string
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
	// SupportsReload reports whether the rule set can be re-applied. nftables
	// cannot: an nft command takes effect as it runs, and re-reading a file
	// on disk would replace the ruleset on screen with one the tool has not
	// shown.
	SupportsReload bool
	// SupportsFamily reports whether RuleSpec.Family is honoured.
	SupportsFamily bool
	// SupportsLog reports whether RuleSpec.Log is honoured.
	SupportsLog bool
	// SupportsInterfaces reports whether RuleSpec.InIface and OutIface are
	// honoured: an nftables rule can match the interface a packet arrived or
	// leaves on, which is how a router says "SSH only from the LAN side".
	SupportsInterfaces bool
	// SupportsConntrack reports whether RuleSpec.CTStates is honoured: the
	// established/related/new/invalid match a stateful firewall is built on.
	SupportsConntrack bool
	// SupportsICMP reports whether the protocol choice includes icmp and
	// icmpv6 and RuleSpec.ICMPType is honoured.
	SupportsICMP bool
	// SupportsEnable reports whether the firewall can be turned on and off
	// through this backend. firewalld cannot: it is a system service, and
	// starting services is not this tool's job.
	SupportsEnable bool
	// EnableHint explains what to do instead when SupportsEnable is false.
	EnableHint string
	// ServiceLabel names the service concept in the UI ("App profile",
	// "Service").
	ServiceLabel string
	// GroupLabel names the group concept in the UI ("Rules", "Zone").
	GroupLabel string
	// LoggingLabel names the logging concept in the UI ("Logging level",
	// "Log denied").
	LoggingLabel string
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

	// Preview renders the exact command lines that Run will execute, one per
	// line, including any privilege wrapper. This is the text shown in the
	// confirm dialog.
	Preview(change Change) string

	// Load reads the current firewall state.
	Load(ctx context.Context) (Model, error)
	// Run executes a previously previewed change, in order, stopping at the
	// first command that fails.
	Run(ctx context.Context, change Change) (string, error)

	// BuildAddRule creates a rule in the named group.
	BuildAddRule(group string, spec RuleSpec) (Change, error)
	// BuildDeleteRule removes an existing rule from the named group.
	BuildDeleteRule(group string, rule Rule) (Change, error)
	// BuildSetEnabled turns the firewall on or off.
	BuildSetEnabled(enabled bool) (Change, error)
	// BuildReload re-applies the rule set.
	BuildReload() (Change, error)
	// BuildSetPolicy changes one default policy of a group.
	BuildSetPolicy(group string, slot PolicyDirection, policy Policy) (Change, error)
	// BuildSetLogging changes the logging level.
	BuildSetLogging(level string) (Change, error)

	// Extras lists the backend-specific actions offered for the given group,
	// given the state that was last loaded. A backend with none returns nil.
	Extras(model Model, group string) []Extra
	// BuildExtra turns an Extra and its collected answers into a Change.
	BuildExtra(group, id string, args []string) (Change, error)
}
