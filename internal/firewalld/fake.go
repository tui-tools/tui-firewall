package firewalld

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// Fake is an in-memory firewalld used by `--demo=firewalld` and by the tests.
//
// It holds the same Sections the parser produces from real firewall-cmd
// output, applies the same argv the real backend builds, and hands the result
// to the same BuildModel. What the demo shows is therefore the real mapping
// over fake output, rather than a screen drawn to look like one.
type Fake struct {
	mu       sync.Mutex
	snapshot Snapshot
	// Log records every command that was run, in order.
	Log []firewall.Command
	// FailWith, when set, makes the next Run fail with this error.
	FailWith error
}

// NewFake returns a Fake preloaded with a small but realistic server.
func NewFake() *Fake { return &Fake{snapshot: demoSnapshot()} }

// section builds one zone or policy block for the demo.
func section(name string, flags string, fields map[string][]string,
	rich ...string) Section {
	s := newSection(name, flags)
	for key, values := range fields {
		s.set(key, strings.Join(values, " "))
	}
	for _, raw := range rich {
		s.set(KeyRichRules, raw)
	}
	if _, ok := s.Fields[KeyRichRules]; !ok {
		s.set(KeyRichRules, "")
	}
	return s
}

// demoSnapshot is the sample firewall shown by `--demo=firewalld`. The
// permanent listing deliberately differs from the runtime one in both
// directions, because that difference is the thing this backend exists to
// make visible.
func demoSnapshot() Snapshot {
	publicRuntime := section("public", "default, active", map[string][]string{
		KeyTarget:      {"default"},
		KeyInterfaces:  {"eth0", "wg0"},
		KeySources:     {},
		KeyServices:    {"ssh", "http", "https", "cockpit"},
		KeyPorts:       {"8080/tcp", "51820/udp"},
		KeyProtocols:   {},
		KeyForward:     {"yes"},
		KeyMasquerade:  {"no"},
		KeySourcePorts: {},
		KeyICMPBlocks:  {},
	}, `rule family="ipv4" source address="10.0.0.0/8" service name="postgresql" accept`,
		`rule family="ipv4" source address="192.0.2.7" drop`)
	publicRuntime.set(KeyForwardPorts, "port=80:proto=tcp:toport=8080")

	publicPermanent := section("public", "default", map[string][]string{
		KeyTarget:      {"default"},
		KeyInterfaces:  {"eth0"},
		KeySources:     {},
		KeyServices:    {"ssh", "http", "https", "cockpit"},
		KeyPorts:       {"8080/tcp"},
		KeyProtocols:   {},
		KeyForward:     {"yes"},
		KeyMasquerade:  {"no"},
		KeySourcePorts: {},
		KeyICMPBlocks:  {},
	}, `rule family="ipv4" source address="10.0.0.0/8" service name="postgresql" accept`,
		`rule family="ipv6" source address="fd00::/8" service name="dns" accept`)
	publicPermanent.set(KeyForwardPorts, "port=80:proto=tcp:toport=8080")

	internal := section("internal", "active", map[string][]string{
		KeyTarget:     {"default"},
		KeyInterfaces: {"eth1"},
		KeySources:    {"10.20.0.0/16"},
		KeyServices:   {"ssh", "mdns", "samba-client", "nfs"},
		KeyPorts:      {},
		KeyForward:    {"yes"},
		KeyMasquerade: {"yes"},
		KeyICMPBlocks: {},
	})

	drop := section("drop", "", map[string][]string{
		KeyTarget:     {"DROP"},
		KeyInterfaces: {},
		KeySources:    {},
		KeyServices:   {},
		KeyPorts:      {},
		KeyForward:    {"no"},
		KeyMasquerade: {"no"},
	})

	trusted := section("trusted", "", map[string][]string{
		KeyTarget:     {"ACCEPT"},
		KeyInterfaces: {},
		KeySources:    {},
		KeyServices:   {},
		KeyPorts:      {},
		KeyForward:    {"yes"},
		KeyMasquerade: {"no"},
	})

	policy := section("libvirt-to-host", "active", map[string][]string{
		KeyPriority:     {"-15000"},
		KeyTarget:       {"CONTINUE"},
		KeyIngressZones: {"ANY"},
		KeyEgressZones:  {"HOST"},
		KeyServices:     {"dhcp", "dns"},
		KeyPorts:        {},
		KeyMasquerade:   {"no"},
	})

	// A Section holds maps, so the permanent listing is a deep copy: the two
	// configurations must be able to drift apart, which is the whole point.
	zones := []Section{publicRuntime, internal, drop, trusted}
	permanent := cloneSections([]Section{publicPermanent, internal, drop, trusted})
	return Snapshot{
		Running:     true,
		DefaultZone: "public",
		Active: []ActiveZone{
			{Name: "public", Default: true, Interfaces: []string{"eth0", "wg0"}},
			{Name: "internal", Interfaces: []string{"eth1"},
				Sources: []string{"10.20.0.0/16"}},
		},
		Zones:             zones,
		PermanentZones:    permanent,
		Policies:          []Section{policy},
		PermanentPolicies: cloneSections([]Section{policy}),
		Services: []string{
			"cockpit", "dhcpv6-client", "dns", "http", "https", "mdns", "nfs",
			"postgresql", "samba-client", "ssh", "wireguard",
		},
		LogDenied: LogOff,
	}
}

// Name identifies the backend.
func (f *Fake) Name() string { return Name }

// Describe names the backend for the status line.
func (f *Fake) Describe() string { return "firewalld demo (nothing is applied)" }

// Capabilities mirrors the real firewalld backend.
func (f *Fake) Capabilities() firewall.Capabilities { return capabilities }

// Preview renders the change without a privilege prefix: the demo never
// escalates.
func (f *Fake) Preview(change firewall.Change) string { return change.String() }

// Load maps the in-memory snapshot through the real mapping.
func (f *Fake) Load(_ context.Context) (firewall.Model, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return BuildModel(f.snapshot), nil
}

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

// runOne applies a single firewall-cmd invocation.
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
	if len(args) > 0 && args[0] == Bin {
		args = args[1:]
	}

	var (
		permanent bool
		target    = f.snapshot.DefaultZone
		isPolicy  bool
		ops       [][2]string
	)
	for _, arg := range args {
		flag, value, _ := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		switch flag {
		case "permanent":
			permanent = true
		case "zone":
			target, isPolicy = value, false
		case "policy":
			target, isPolicy = value, true
		default:
			ops = append(ops, [2]string{flag, value})
		}
	}
	if len(ops) == 0 {
		return "", fmt.Errorf("firewall-cmd: nothing to do")
	}

	for _, op := range ops {
		if err := f.apply(op[0], op[1], target, isPolicy, permanent); err != nil {
			return "", err
		}
	}
	return "success", nil
}

// sectionsFor picks the listing an operation applies to.
func (f *Fake) sectionsFor(isPolicy, permanent bool) *[]Section {
	switch {
	case isPolicy && permanent:
		return &f.snapshot.PermanentPolicies
	case isPolicy:
		return &f.snapshot.Policies
	case permanent:
		return &f.snapshot.PermanentZones
	default:
		return &f.snapshot.Zones
	}
}

// find returns the named section of a listing.
func find(sections *[]Section, name string) *Section {
	for i := range *sections {
		if (*sections)[i].Name == name {
			return &(*sections)[i]
		}
	}
	return nil
}

// addFlags maps an --add-* flag to the section key it appends to.
var addFlags = map[string]string{
	"add-service":      KeyServices,
	"add-port":         KeyPorts,
	"add-protocol":     KeyProtocols,
	"add-source-port":  KeySourcePorts,
	"add-forward-port": KeyForwardPorts,
	"add-icmp-block":   KeyICMPBlocks,
	"add-source":       KeySources,
	"add-interface":    KeyInterfaces,
	"add-rich-rule":    KeyRichRules,
}

// removeFlags maps a --remove-* flag to the section key it removes from.
var removeFlags = map[string]string{
	"remove-service":      KeyServices,
	"remove-port":         KeyPorts,
	"remove-protocol":     KeyProtocols,
	"remove-source-port":  KeySourcePorts,
	"remove-forward-port": KeyForwardPorts,
	"remove-icmp-block":   KeyICMPBlocks,
	"remove-source":       KeySources,
	"remove-interface":    KeyInterfaces,
	"remove-rich-rule":    KeyRichRules,
}

// apply mutates the in-memory state the way firewalld would.
func (f *Fake) apply(flag, value, target string, isPolicy, permanent bool) error {
	switch flag {
	case "set-log-denied":
		f.snapshot.LogDenied = value
		return nil
	case "panic-on":
		f.snapshot.Panic = true
		return nil
	case "panic-off":
		f.snapshot.Panic = false
		return nil
	case "set-default-zone":
		return f.setDefaultZone(value)
	case "reload":
		f.snapshot.Zones = cloneSections(f.snapshot.PermanentZones)
		f.snapshot.Policies = cloneSections(f.snapshot.PermanentPolicies)
		return nil
	case "runtime-to-permanent":
		f.snapshot.PermanentZones = cloneSections(f.snapshot.Zones)
		f.snapshot.PermanentPolicies = cloneSections(f.snapshot.Policies)
		return nil
	}

	sections := f.sectionsFor(isPolicy, permanent)
	s := find(sections, target)
	if s == nil {
		return fmt.Errorf("firewall-cmd: INVALID_ZONE: %s", target)
	}

	switch {
	case flag == "set-target":
		s.Fields[KeyTarget] = []string{value}
	case flag == "add-masquerade":
		s.Fields[KeyMasquerade] = []string{"yes"}
	case flag == "remove-masquerade":
		s.Fields[KeyMasquerade] = []string{"no"}
	case flag == "add-forward":
		s.Fields[KeyForward] = []string{"yes"}
	case flag == "remove-forward":
		s.Fields[KeyForward] = []string{"no"}
	case flag == "change-interface":
		f.moveInterface(sections, target, value)
	case addFlags[flag] != "":
		add(s, addFlags[flag], value)
	case removeFlags[flag] != "":
		if !remove(s, removeFlags[flag], value) {
			return fmt.Errorf("firewall-cmd: NOT_ENABLED: %s", value)
		}
	default:
		return fmt.Errorf("firewall-cmd: unsupported option --%s in demo mode", flag)
	}
	return nil
}

// setDefaultZone moves the "(default)" flag between zones.
func (f *Fake) setDefaultZone(zone string) error {
	if find(&f.snapshot.Zones, zone) == nil {
		return fmt.Errorf("firewall-cmd: INVALID_ZONE: %s", zone)
	}
	f.snapshot.DefaultZone = zone
	for _, sections := range []*[]Section{&f.snapshot.Zones, &f.snapshot.PermanentZones} {
		for i := range *sections {
			(*sections)[i].Default = (*sections)[i].Name == zone
		}
	}
	return nil
}

// moveInterface detaches an interface from every zone and attaches it to one.
func (f *Fake) moveInterface(sections *[]Section, zone, iface string) {
	for i := range *sections {
		remove(&(*sections)[i], KeyInterfaces, iface)
	}
	if s := find(sections, zone); s != nil {
		add(s, KeyInterfaces, iface)
	}
}

// add appends a value to a key, ignoring a duplicate as firewalld does.
func add(s *Section, key, value string) {
	for _, existing := range s.Fields[key] {
		if existing == value {
			return
		}
	}
	if key == KeyRichRules {
		s.RichRules = append(s.RichRules, value)
	}
	s.Fields[key] = append(s.Fields[key], value)
	if !contains(s.Order, key) {
		s.Order = append(s.Order, key)
	}
}

// remove drops a value from a key and reports whether it was there.
func remove(s *Section, key, value string) bool {
	found := false
	kept := make([]string, 0, len(s.Fields[key]))
	for _, existing := range s.Fields[key] {
		if existing == value {
			found = true
			continue
		}
		kept = append(kept, existing)
	}
	s.Fields[key] = kept
	if key == KeyRichRules {
		s.RichRules = append([]string(nil), kept...)
	}
	return found
}

// contains reports membership in a small slice.
func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// cloneSections deep-copies a listing, so a reload cannot alias the
// configuration it was copied from.
func cloneSections(sections []Section) []Section {
	out := make([]Section, 0, len(sections))
	for _, s := range sections {
		copied := Section{
			Name: s.Name, Default: s.Default, Active: s.Active,
			Fields:    make(map[string][]string, len(s.Fields)),
			Order:     append([]string(nil), s.Order...),
			RichRules: append([]string(nil), s.RichRules...),
		}
		for key, values := range s.Fields {
			copied.Fields[key] = append([]string(nil), values...)
		}
		out = append(out, copied)
	}
	return out
}

// BuildAddRule creates an entry in a zone.
func (f *Fake) BuildAddRule(group string, spec firewall.RuleSpec) (firewall.Change, error) {
	return BuildAddRule(group, spec)
}

// BuildDeleteRule removes an entry from a zone.
func (f *Fake) BuildDeleteRule(group string, rule firewall.Rule) (firewall.Change, error) {
	return BuildDeleteRule(group, rule)
}

// BuildSetEnabled reports that firewalld is a system service.
func (f *Fake) BuildSetEnabled(enabled bool) (firewall.Change, error) {
	return BuildSetEnabled(enabled)
}

// BuildReload re-applies the permanent configuration.
func (f *Fake) BuildReload() (firewall.Change, error) { return BuildReload() }

// BuildSetPolicy changes a zone target.
func (f *Fake) BuildSetPolicy(group string, slot firewall.PolicyDirection,
	policy firewall.Policy) (firewall.Change, error) {
	return BuildSetPolicy(group, slot, policy)
}

// BuildSetLogging changes the global log-denied value.
func (f *Fake) BuildSetLogging(level string) (firewall.Change, error) {
	return BuildSetLogging(level)
}

// Extras lists the firewalld-specific actions.
func (f *Fake) Extras(model firewall.Model, group string) []firewall.Extra {
	return Extras(model, group)
}

// BuildExtra builds one of those actions.
func (f *Fake) BuildExtra(group, id string, args []string) (firewall.Change, error) {
	return BuildExtra(group, id, args)
}
