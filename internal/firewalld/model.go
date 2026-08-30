package firewalld

import (
	"sort"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// PolicyPrefix marks a group that is a firewalld policy object rather than a
// zone. Group names reach the command builders unchanged, and this is how they
// know whether to say `--zone=` or `--policy=`.
const PolicyPrefix = "policy/"

// ZoneName strips PolicyPrefix, returning the firewalld object name and
// whether it is a policy.
func ZoneName(group string) (name string, isPolicy bool) {
	if rest, ok := strings.CutPrefix(group, PolicyPrefix); ok {
		return rest, true
	}
	return group, false
}

// Scope says where an entry exists. firewalld keeps two configurations — the
// one enforced right now and the one that survives a reload or a reboot — and
// they routinely differ: an interface NetworkManager assigned, a port someone
// added without `--permanent`, a change made permanently and not yet reloaded.
// Showing which is which is most of the value of reading both.
const (
	ScopeBoth      = "both"
	ScopeRuntime   = "runtime"
	ScopePermanent = "permanent"
)

// The Rule.Extra keys this backend fills.
const (
	ExtraScope = "scope"
	ExtraZone  = "zone"
)

// PanicWarning is the banner a firewall in panic mode carries. It is a
// constant because the actions menu keys off it: the only thing to offer a
// machine dropping every packet is a way to stop.
const PanicWarning = "panic mode is on: every incoming and outgoing packet is dropped"

// noteForScope is the annotation shown beside a rule.
func noteForScope(scope string) string {
	switch scope {
	case ScopeRuntime:
		return "runtime only"
	case ScopePermanent:
		return "permanent only"
	default:
		return ""
	}
}

// Snapshot is everything one Load read from the host, before it is folded into
// the generic model. Keeping the reads and the mapping apart is what lets the
// mapping be tested against captured output with no firewalld anywhere near.
type Snapshot struct {
	// Running reports `firewall-cmd --state`.
	Running bool
	// DefaultZone is `--get-default-zone`.
	DefaultZone string
	// Active is `--get-active-zones`.
	Active []ActiveZone
	// Zones and PermanentZones are `--list-all-zones` and the same with
	// `--permanent`.
	Zones          []Section
	PermanentZones []Section
	// Policies and PermanentPolicies are the policy objects, empty on a
	// firewalld that has none or does not have the feature.
	Policies          []Section
	PermanentPolicies []Section
	// Services is `--get-services`, the picker's service list.
	Services []string
	// LogDenied is `--get-log-denied`.
	LogDenied string
	// Panic reports `--query-panic`: every packet dropped.
	Panic bool
	// Lockdown reports `--query-lockdown`, on the firewalld versions that
	// still have the feature (it was removed in 2.2).
	Lockdown bool
}

// entry is one line of a zone or policy, in firewalld's own terms. The pair
// (kind, value) is exactly what the add and remove commands take, so it is
// also the rule's identity.
type entry struct {
	kind  string
	value string
}

// kindOrder is the order entries are listed in, chosen to read top-down from
// "what is this zone attached to" to "what does it let through".
var kindOrder = []string{
	firewall.KindInterface,
	firewall.KindSource,
	firewall.KindService,
	firewall.KindPort,
	firewall.KindProtocol,
	firewall.KindSourcePort,
	firewall.KindForwardPort,
	firewall.KindMasquerade,
	firewall.KindForward,
	firewall.KindICMPBlock,
	firewall.KindRich,
}

// keyForKind maps a rule kind back to the section key it was read from.
var keyForKind = map[string]string{
	firewall.KindInterface:   KeyInterfaces,
	firewall.KindSource:      KeySources,
	firewall.KindService:     KeyServices,
	firewall.KindPort:        KeyPorts,
	firewall.KindProtocol:    KeyProtocols,
	firewall.KindSourcePort:  KeySourcePorts,
	firewall.KindForwardPort: KeyForwardPorts,
	firewall.KindICMPBlock:   KeyICMPBlocks,
	firewall.KindRich:        KeyRichRules,
}

// entriesOf flattens a section into the entries the UI lists.
func entriesOf(s Section) []entry {
	var out []entry
	for _, kind := range kindOrder {
		switch kind {
		case firewall.KindMasquerade:
			if s.Flag(KeyMasquerade) {
				out = append(out, entry{kind: kind, value: "masquerade"})
			}
		case firewall.KindForward:
			if s.Flag(KeyForward) {
				out = append(out, entry{kind: kind, value: "forward"})
			}
		case firewall.KindRich:
			for _, raw := range s.RichRules {
				out = append(out, entry{kind: kind, value: raw})
			}
		default:
			for _, v := range s.Field(keyForKind[kind]) {
				out = append(out, entry{kind: kind, value: v})
			}
		}
	}
	return out
}

// mergeEntries unions the runtime and permanent entries of one object, keeping
// the runtime order and marking where each entry exists.
func mergeEntries(runtime, permanent []entry) ([]entry, map[entry]string) {
	scope := make(map[entry]string, len(runtime)+len(permanent))
	inPermanent := make(map[entry]bool, len(permanent))
	for _, e := range permanent {
		inPermanent[e] = true
	}

	merged := make([]entry, 0, len(runtime)+len(permanent))
	seen := make(map[entry]bool, len(runtime))
	for _, e := range runtime {
		if seen[e] {
			continue
		}
		seen[e] = true
		merged = append(merged, e)
		if inPermanent[e] {
			scope[e] = ScopeBoth
			continue
		}
		scope[e] = ScopeRuntime
	}
	for _, e := range permanent {
		if seen[e] {
			continue
		}
		seen[e] = true
		merged = append(merged, e)
		scope[e] = ScopePermanent
	}
	return merged, scope
}

// ruleFor turns one entry into a generic rule.
func ruleFor(zone string, e entry, index int, scope string) firewall.Rule {
	r := firewall.Rule{
		ID:     e.kind + ":" + e.value,
		Index:  index,
		Kind:   e.kind,
		Raw:    e.value,
		Action: firewall.ActionAllow,
		Note:   noteForScope(scope),
		Extra:  map[string]string{ExtraScope: scope, ExtraZone: zone},
	}

	switch e.kind {
	case firewall.KindService:
		r.Service, r.To = e.value, e.value
	case firewall.KindPort, firewall.KindSourcePort:
		r.Ports, r.Proto = splitPort(e.value)
		r.To = e.value
		if e.kind == firewall.KindSourcePort {
			r.From, r.To = e.value, ""
		}
	case firewall.KindSource:
		r.From = e.value
		// A source binds an address to the zone; it is not a verdict of its
		// own, so the action column stays empty rather than claiming one.
		r.Action = ""
	case firewall.KindInterface:
		r.To = e.value
		r.Action = ""
	case firewall.KindProtocol, firewall.KindMasquerade, firewall.KindForward:
		r.To = e.value
	case firewall.KindICMPBlock:
		r.To, r.Action = e.value, firewall.ActionDeny
	case firewall.KindForwardPort:
		r.Ports, r.Proto, r.To = describeForwardPort(e.value)
	case firewall.KindRich:
		applyRich(&r, ParseRichRule(e.value))
	}
	return r
}

// splitPort reads firewalld's "80/tcp" and "1000-2000/udp".
func splitPort(value string) (ports, proto string) {
	if before, after, ok := strings.Cut(value, "/"); ok {
		return before, after
	}
	return value, ""
}

// describeForwardPort reads
// "port=80:proto=tcp:toport=8080:toaddr=10.0.0.1" into the generic columns.
func describeForwardPort(value string) (ports, proto, to string) {
	var toPort, toAddr string
	for _, part := range strings.Split(value, ":") {
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch key {
		case "port":
			ports = val
		case "proto":
			proto = val
		case "toport":
			toPort = val
		case "toaddr":
			toAddr = val
		}
	}
	to = toAddr
	if toPort != "" {
		if to == "" {
			to = "localhost"
		}
		to += ":" + toPort
	}
	return ports, proto, to
}

// applyRich fills the generic columns from a decomposed rich rule.
func applyRich(r *firewall.Rule, rich RichRule) {
	r.From, r.To = rich.Source, rich.Destination
	r.Service = rich.Service
	r.Ports, r.Proto = rich.Port, rich.Protocol
	switch rich.Family {
	case "ipv4":
		r.Family = firewall.FamilyIPv4
	case "ipv6":
		r.Family = firewall.FamilyIPv6
	}
	switch rich.Verdict {
	case "accept":
		r.Action = firewall.ActionAllow
	case "reject":
		r.Action = firewall.ActionReject
	case "drop":
		r.Action = firewall.ActionDeny
	default:
		r.Action = ""
	}
	if r.To == "" {
		switch {
		case rich.Service != "":
			r.To = rich.Service
		case rich.Port != "":
			r.To = rich.Port + "/" + rich.Protocol
		}
	}
	if rich.Log {
		r.Comment = strings.TrimSpace("log " + rich.LogPrefix)
	}
}

// BuildModel folds a Snapshot into the model the UI renders: one group per
// zone, then one per policy object.
func BuildModel(s Snapshot) firewall.Model {
	model := firewall.Model{
		Backend:   Name,
		Enabled:   s.Running,
		Logging:   s.LogDenied,
		LoggingOn: s.LogDenied != "" && s.LogDenied != LogOff,
		Services:  s.Services,
	}
	switch {
	case s.Panic:
		model.Warning = PanicWarning
	case s.Lockdown:
		model.Warning = "lockdown is on: only allow-listed applications may change the firewall"
	}

	permanent := index(s.PermanentZones)
	active := activeIndex(s.Active)
	for _, section := range sortZones(s.Zones, s.DefaultZone, active) {
		model.Groups = append(model.Groups,
			zoneGroup(section, permanent[section.Name], s.DefaultZone, active))
	}
	// A permanent-only zone still deserves a group: it is what the machine
	// will have after the next reload.
	for _, section := range s.PermanentZones {
		if _, ok := index(s.Zones)[section.Name]; ok {
			continue
		}
		model.Groups = append(model.Groups,
			zoneGroup(Section{Name: section.Name, Fields: map[string][]string{}},
				section, s.DefaultZone, active))
	}

	permanentPolicies := index(s.PermanentPolicies)
	for _, section := range s.Policies {
		model.Groups = append(model.Groups,
			policyGroup(section, permanentPolicies[section.Name]))
	}
	return model
}

// index keys sections by name.
func index(sections []Section) map[string]Section {
	out := make(map[string]Section, len(sections))
	for _, s := range sections {
		out[s.Name] = s
	}
	return out
}

// activeIndex keys the active zones by name.
func activeIndex(zones []ActiveZone) map[string]ActiveZone {
	out := make(map[string]ActiveZone, len(zones))
	for _, z := range zones {
		out[z.Name] = z
	}
	return out
}

// sortZones puts the default zone first, then the other active ones, then the
// rest — which is the order someone reading a firewall cares about.
func sortZones(sections []Section, defaultZone string,
	active map[string]ActiveZone) []Section {
	out := append([]Section(nil), sections...)
	rank := func(s Section) int {
		switch {
		case s.Name == defaultZone:
			return 0
		case active[s.Name].Name != "":
			return 1
		default:
			return 2
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := rank(out[i]), rank(out[j]); a != b {
			return a < b
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// zoneGroup maps one zone, runtime and permanent, into a group.
func zoneGroup(runtime, permanent Section, defaultZone string,
	active map[string]ActiveZone) firewall.Group {
	merged, scope := mergeEntries(entriesOf(runtime), entriesOf(permanent))

	group := firewall.Group{
		Name:        runtime.Name,
		Title:       runtime.Name,
		PolicySlots: []firewall.PolicyDirection{firewall.PolicyTarget},
		Default:     firewall.Policies{Target: target(runtime, permanent)},
	}
	if runtime.Name == defaultZone {
		group.Title += " (default)"
	}
	group.Description = zoneDescription(runtime, permanent, active[runtime.Name])
	for i, e := range merged {
		group.Rules = append(group.Rules, ruleFor(runtime.Name, e, i+1, scope[e]))
	}
	return group
}

// target reads the zone target, preferring the runtime value.
func target(runtime, permanent Section) string {
	if t := runtime.First(KeyTarget); t != "" {
		return t
	}
	return permanent.First(KeyTarget)
}

// zoneDescription is the one-line summary in the header.
func zoneDescription(runtime, permanent Section, active ActiveZone) string {
	parts := []string{}
	if active.Name != "" {
		parts = append(parts, "active")
	}
	if ifaces := runtime.Field(KeyInterfaces); len(ifaces) > 0 {
		parts = append(parts, "interfaces: "+strings.Join(ifaces, ", "))
	}
	if sources := runtime.Field(KeySources); len(sources) > 0 {
		parts = append(parts, "sources: "+strings.Join(sources, ", "))
	}
	if len(runtime.Fields) == 0 && len(permanent.Fields) > 0 {
		parts = append(parts, "permanent only")
	}
	return strings.Join(parts, "  ·  ")
}

// policyGroup maps one policy object into a group. Policy objects filter
// between zones rather than for one, so they carry no policy slot: their
// target is set permanently only and is left to firewall-cmd.
func policyGroup(runtime, permanent Section) firewall.Group {
	merged, scope := mergeEntries(entriesOf(runtime), entriesOf(permanent))
	group := firewall.Group{
		Name:  PolicyPrefix + runtime.Name,
		Title: runtime.Name + " (policy)",
		Description: "target: " + runtime.First(KeyTarget) +
			"  ·  " + strings.Join(runtime.Field(KeyIngressZones), ",") +
			" → " + strings.Join(runtime.Field(KeyEgressZones), ","),
	}
	for i, e := range merged {
		group.Rules = append(group.Rules,
			ruleFor(PolicyPrefix+runtime.Name, e, i+1, scope[e]))
	}
	return group
}
