package firewalld

import (
	"fmt"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// Name is the backend identifier.
const Name = "firewalld"

// Bin is the binary this backend drives. It appears as Argv[0] of every
// command, which is what the runner replaces with the resolved path.
const Bin = "firewall-cmd"

// The `--set-log-denied` values firewalld accepts.
const (
	LogOff       = "off"
	LogAll       = "all"
	LogUnicast   = "unicast"
	LogBroadcast = "broadcast"
	LogMulticast = "multicast"
)

// The zone targets `--set-target` accepts.
const (
	TargetDefault = "default"
	TargetAccept  = "ACCEPT"
	TargetReject  = "%%REJECT%%"
	TargetDrop    = "DROP"
)

// bothNote is the sentence the confirm dialog carries on a change applied to
// the running firewall and to the permanent configuration.
//
// This is the choice the backend makes and states plainly, because the two
// obvious ways to make a firewalld change stick behave differently: running
// the command twice — once as it is, once with `--permanent` — leaves every
// established connection alone, while `--permanent` followed by `--reload`
// rebuilds the rule set and can drop connections that depended on it. Neither
// is hidden: both lines are in the preview.
const bothNote = "applied to the running firewall and to the permanent " +
	"configuration; no reload, so no connection is dropped"

// runtimeNote and permanentNote describe a change that exists in one
// configuration only, and is therefore removed from that one only.
const (
	runtimeNote   = "this entry exists only in the running firewall"
	permanentNote = "this entry exists only in the permanent configuration"
)

// reloadNote explains the one change firewalld has no runtime form for.
const reloadNote = "firewalld can only set a zone target permanently, so this " +
	"change is written to the permanent configuration and applied with a reload"

// capabilities describes what the firewalld backend supports. It is shared by
// the real backend and the demo so the two behave identically.
var capabilities = firewall.Capabilities{
	Actions: []firewall.Action{
		firewall.ActionAllow, firewall.ActionReject, firewall.ActionDeny,
	},
	Directions: []firewall.Direction{firewall.DirIn},
	Policies: []firewall.Policy{
		TargetDefault, TargetAccept, TargetReject, TargetDrop,
	},
	LogLevels: []string{LogOff, LogAll, LogUnicast, LogBroadcast, LogMulticast},
	// firewalld does not order the entries of a zone, and neither comments
	// nor a routed flag exist: a rich rule carries the equivalent detail.
	SupportsInsert:   false,
	SupportsComments: false,
	SupportsRouted:   false,
	SupportsLogging:  true,
	SupportsReload:   true,
	SupportsFamily:   true,
	SupportsLog:      true,
	SupportsEnable:   false,
	EnableHint: "firewalld runs as a system service; start or stop it with " +
		"systemctl, or use panic mode from the actions menu to drop everything now",
	ServiceLabel: "Service",
	GroupLabel:   "Zone",
	LoggingLabel: "Log denied",
}

// Capabilities reports what the firewalld backend supports.
func Capabilities() firewall.Capabilities { return capabilities }

// scopeArgs turns a group name into the `--zone=` or `--policy=` selector
// every zone-scoped command needs.
func scopeArgs(group string) ([]string, error) {
	name, isPolicy := ZoneName(group)
	if err := checkAtom("zone", name); err != nil {
		return nil, err
	}
	if isPolicy {
		return []string{"--policy=" + name}, nil
	}
	return []string{"--zone=" + name}, nil
}

// checkAtom rejects a value that cannot be a firewall-cmd argument. Nothing is
// ever passed through a shell, so this is about catching a typo before it
// reaches the machine rather than about quoting.
func checkAtom(what, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("a %s is required", what)
	}
	if strings.ContainsAny(value, " \t\n\r") {
		return fmt.Errorf("%s %q must not contain spaces", what, value)
	}
	if strings.HasPrefix(value, "-") {
		return fmt.Errorf("%s %q must not start with a dash", what, value)
	}
	return nil
}

// pair builds a change from one operation, applying it to the running firewall
// and to the permanent configuration — the two lines the preview shows.
func pair(description string, destructive bool, argv []string) firewall.Change {
	runtime := append([]string{Bin}, argv...)
	permanent := append([]string{Bin, "--permanent"}, argv...)
	return firewall.Change{
		Description: description,
		Destructive: destructive,
		Note:        bothNote,
		Commands: []firewall.Command{
			{Argv: runtime, Description: description},
			{Argv: permanent, Description: description + " (permanent)"},
		},
	}
}

// single builds a change from one command that has no permanent counterpart.
func single(description, note string, destructive bool, argv ...string) firewall.Change {
	return firewall.Change{
		Description: description,
		Destructive: destructive,
		Note:        note,
		Commands: []firewall.Command{{
			Argv:        append([]string{Bin}, argv...),
			Description: description,
			Destructive: destructive,
		}},
	}
}

// BuildAddRule turns a RuleSpec into the firewall-cmd operation that expresses
// it. A spec that only names a service or a port becomes `--add-service` or
// `--add-port`; anything that qualifies the traffic — an address, an address
// family, logging, or a verdict other than allow — becomes a rich rule,
// because that is the only firewalld syntax that carries those.
func BuildAddRule(group string, spec firewall.RuleSpec) (firewall.Change, error) {
	scope, err := scopeArgs(group)
	if err != nil {
		return firewall.Change{}, err
	}
	if spec.Position > 0 {
		return firewall.Change{}, fmt.Errorf(
			"firewalld does not order the entries of a zone, so there is no position")
	}
	if spec.Comment != "" {
		return firewall.Change{}, fmt.Errorf(
			"firewalld has no rule comments; a rich rule log prefix is the closest thing")
	}

	if needsRichRule(spec) {
		rule, err := RichRuleText(spec)
		if err != nil {
			return firewall.Change{}, err
		}
		return pair("Add rich rule", false,
			append(scope, "--add-rich-rule="+rule)), nil
	}

	switch {
	case spec.Service != "":
		if err := checkAtom("service", spec.Service); err != nil {
			return firewall.Change{}, err
		}
		return pair("Add service "+spec.Service, false,
			append(scope, "--add-service="+spec.Service)), nil
	case spec.Ports != "":
		port, err := portArg(spec.Ports, spec.Proto)
		if err != nil {
			return firewall.Change{}, err
		}
		return pair("Add port "+port, false,
			append(scope, "--add-port="+port)), nil
	default:
		return firewall.Change{}, fmt.Errorf("give at least a service or a port")
	}
}

// needsRichRule reports a spec that only a rich rule can express.
func needsRichRule(spec firewall.RuleSpec) bool {
	return spec.From != "" || spec.To != "" || spec.Family != firewall.FamilyAny ||
		spec.Log || (spec.Action != "" && spec.Action != firewall.ActionAllow)
}

// portArg renders firewalld's "80/tcp", rejecting a port with no protocol:
// firewalld has no default for it, and guessing one would be a rule the user
// never asked for.
func portArg(ports, proto string) (string, error) {
	if err := checkAtom("port", ports); err != nil {
		return "", err
	}
	switch proto {
	case "tcp", "udp", "sctp", "dccp":
	case "":
		return "", fmt.Errorf("firewalld needs a protocol with a port (tcp or udp)")
	default:
		return "", fmt.Errorf("unknown protocol %q", proto)
	}
	return ports + "/" + proto, nil
}

// RichRuleText renders a RuleSpec as firewalld rich rule syntax. It is
// exported because it is the one piece of this backend a test wants to read
// on its own: everything the guided form can produce ends up in this string.
func RichRuleText(spec firewall.RuleSpec) (string, error) {
	family := string(familyFor(spec))
	if (spec.From != "" || spec.To != "") && family == "" {
		return "", fmt.Errorf("an address needs an address family")
	}

	parts := []string{"rule"}
	if family != "" {
		parts = append(parts, `family="`+family+`"`)
	}
	if spec.From != "" {
		if err := checkAtom("source", spec.From); err != nil {
			return "", err
		}
		parts = append(parts, `source address="`+spec.From+`"`)
	}
	if spec.To != "" {
		if err := checkAtom("destination", spec.To); err != nil {
			return "", err
		}
		parts = append(parts, `destination address="`+spec.To+`"`)
	}

	switch {
	case spec.Service != "":
		if err := checkAtom("service", spec.Service); err != nil {
			return "", err
		}
		parts = append(parts, `service name="`+spec.Service+`"`)
	case spec.Ports != "":
		port, err := portArg(spec.Ports, spec.Proto)
		if err != nil {
			return "", err
		}
		ports, proto := splitPort(port)
		parts = append(parts, `port port="`+ports+`" protocol="`+proto+`"`)
	}

	if spec.Log {
		parts = append(parts, `log level="info" limit value="10/m"`)
	}

	verdict, err := verdictFor(spec.Action)
	if err != nil {
		return "", err
	}
	parts = append(parts, verdict)
	return strings.Join(parts, " "), nil
}

// familyFor resolves the address family, deriving it from the addresses when
// the form left it empty: firewalld requires one as soon as an address is
// given, and a colon in an address means IPv6.
func familyFor(spec firewall.RuleSpec) firewall.Family {
	switch spec.Family {
	case firewall.FamilyIPv4:
		return "ipv4"
	case firewall.FamilyIPv6:
		return "ipv6"
	}
	for _, address := range []string{spec.From, spec.To} {
		if address == "" {
			continue
		}
		if strings.Contains(address, ":") {
			return "ipv6"
		}
		return "ipv4"
	}
	return ""
}

// verdictFor maps a generic action to a rich rule verdict.
func verdictFor(action firewall.Action) (string, error) {
	switch action {
	case firewall.ActionAllow, "":
		return "accept", nil
	case firewall.ActionReject:
		return "reject", nil
	case firewall.ActionDeny:
		return "drop", nil
	default:
		return "", fmt.Errorf("firewalld has no %q verdict", action)
	}
}

// removeArgs is the operation that removes one entry, by kind.
func removeArgs(rule firewall.Rule) ([]string, string, error) {
	value := rule.Raw
	flag := map[string]string{
		firewall.KindService:     "--remove-service=",
		firewall.KindPort:        "--remove-port=",
		firewall.KindProtocol:    "--remove-protocol=",
		firewall.KindSourcePort:  "--remove-source-port=",
		firewall.KindForwardPort: "--remove-forward-port=",
		firewall.KindICMPBlock:   "--remove-icmp-block=",
		firewall.KindSource:      "--remove-source=",
		firewall.KindInterface:   "--remove-interface=",
		firewall.KindRich:        "--remove-rich-rule=",
	}[rule.Kind]

	switch rule.Kind {
	case firewall.KindMasquerade:
		return []string{"--remove-masquerade"}, "Disable masquerade", nil
	case firewall.KindForward:
		return []string{"--remove-forward"}, "Disable intra-zone forwarding", nil
	case "":
		return nil, "", fmt.Errorf("this entry cannot be removed: it has no kind")
	}
	if flag == "" {
		return nil, "", fmt.Errorf("firewalld: cannot remove an entry of kind %q", rule.Kind)
	}
	if strings.TrimSpace(value) == "" {
		return nil, "", fmt.Errorf("firewalld: the %s entry has no value", rule.Kind)
	}
	return []string{flag + value}, "Remove " + rule.Kind + " " + firstWords(value), nil
}

// firstWords keeps a description to a readable length: a rich rule can be very
// long, and the full text is in the preview anyway.
func firstWords(value string) string {
	if len(value) <= 48 {
		return value
	}
	return value[:45] + "…"
}

// BuildDeleteRule removes one entry, from whichever configurations hold it.
// An entry the tool showed as "runtime only" is removed from the runtime only:
// issuing the permanent form as well would fail, and hiding that failure would
// be worse than not issuing it.
func BuildDeleteRule(group string, rule firewall.Rule) (firewall.Change, error) {
	scope, err := scopeArgs(group)
	if err != nil {
		return firewall.Change{}, err
	}
	argv, description, err := removeArgs(rule)
	if err != nil {
		return firewall.Change{}, err
	}
	argv = append(scope, argv...)

	switch rule.Extra[ExtraScope] {
	case ScopeRuntime:
		change := single(description, runtimeNote, true, argv...)
		return change, nil
	case ScopePermanent:
		change := single(description, permanentNote, true,
			append([]string{"--permanent"}, argv...)...)
		return change, nil
	default:
		change := pair(description, true, argv)
		return change, nil
	}
}

// BuildSetEnabled reports that firewalld cannot be turned on and off here.
// Starting and stopping a system service is a different tool's job, and doing
// it silently from a firewall UI is exactly the kind of surprise this family
// exists to avoid.
func BuildSetEnabled(_ bool) (firewall.Change, error) {
	return firewall.Change{}, fmt.Errorf("%s", capabilities.EnableHint)
}

// BuildReload re-applies the permanent configuration.
func BuildReload() (firewall.Change, error) {
	return single("Reload the firewall",
		"the permanent configuration replaces the running one; "+
			"runtime-only entries are lost and connections may be dropped",
		true, "--reload"), nil
}

// BuildSetPolicy sets a zone target. firewalld has no runtime form for it, so
// this is the one change written permanently and applied with a reload.
func BuildSetPolicy(group string, slot firewall.PolicyDirection,
	policy firewall.Policy) (firewall.Change, error) {
	if slot != firewall.PolicyTarget {
		return firewall.Change{}, fmt.Errorf(
			"firewalld zones have a single target, not a %q policy", slot)
	}
	name, isPolicy := ZoneName(group)
	if isPolicy {
		return firewall.Change{}, fmt.Errorf(
			"the target of a policy object is not editable here")
	}
	if err := checkAtom("zone", name); err != nil {
		return firewall.Change{}, err
	}
	if !validTarget(policy) {
		return firewall.Change{}, fmt.Errorf("unknown zone target %q", policy)
	}

	description := fmt.Sprintf("Set the target of zone %s to %s", name, policy)
	return firewall.Change{
		Description: description,
		Destructive: true,
		Note:        reloadNote,
		Commands: []firewall.Command{
			{Argv: []string{Bin, "--permanent", "--zone=" + name,
				"--set-target=" + string(policy)}, Description: description},
			{Argv: []string{Bin, "--reload"}, Description: "Reload", Destructive: true},
		},
	}, nil
}

// validTarget reports whether a target is one firewalld accepts.
func validTarget(policy firewall.Policy) bool {
	for _, known := range capabilities.Policies {
		if policy == known {
			return true
		}
	}
	return false
}

// BuildSetLogging sets the global log-denied value. It is a single command:
// firewalld writes it to its configuration and applies it at once.
func BuildSetLogging(level string) (firewall.Change, error) {
	for _, known := range capabilities.LogLevels {
		if level == known {
			return single("Set log-denied to "+level,
				"a runtime and permanent change; firewalld reloads itself to "+
					"install the logging rules, which can drop connections", true,
				"--set-log-denied="+level), nil
		}
	}
	return firewall.Change{}, fmt.Errorf("firewalld: unknown log-denied value %q", level)
}
