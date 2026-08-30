package firewalld

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// hostSnapshot builds a Snapshot from the captured Fedora fixtures, which is
// as close to a real Load as a test can get without a firewalld.
func hostSnapshot(t *testing.T) Snapshot {
	t.Helper()
	return Snapshot{
		Running:           true,
		DefaultZone:       "FedoraWorkstation",
		Active:            ParseActiveZones(fixture(t, "get-active-zones.txt")),
		Zones:             ParseSections(fixture(t, "list-all-zones.txt")),
		PermanentZones:    ParseSections(fixture(t, "permanent-list-all-zones.txt")),
		Policies:          ParseSections(fixture(t, "policy-list-all.txt")),
		PermanentPolicies: ParseSections(fixture(t, "policy-list-all.txt")),
		Services:          []string{"http", "https", "ssh"},
		LogDenied:         LogOff,
	}
}

// group finds a group by name, failing the test when it is missing.
func group(t *testing.T, model firewall.Model, name string) firewall.Group {
	t.Helper()
	g, ok := model.Group(name)
	if !ok {
		t.Fatalf("no group %q", name)
	}
	return g
}

// rulesOfKind collects the raw values of one kind, in order.
func rulesOfKind(g firewall.Group, kind string) []string {
	var out []string
	for _, rule := range g.Rules {
		if rule.Kind == kind {
			out = append(out, rule.Raw)
		}
	}
	return out
}

func TestBuildModelOrdersTheDefaultZoneFirst(t *testing.T) {
	model := BuildModel(hostSnapshot(t))

	if model.Backend != Name || !model.Enabled {
		t.Errorf("model = %q enabled=%v", model.Backend, model.Enabled)
	}
	if model.Groups[0].Name != "FedoraWorkstation" {
		t.Errorf("first group = %q, want the default zone", model.Groups[0].Name)
	}
	if !strings.HasSuffix(model.Groups[0].Title, "(default)") {
		t.Errorf("title = %q, want it marked as the default", model.Groups[0].Title)
	}
	// Active zones come before inactive ones.
	var names []string
	for _, g := range model.Groups {
		names = append(names, g.Name)
	}
	want := []string{"FedoraWorkstation", "docker", "libvirt", "block", "trusted",
		PolicyPrefix + "allow-host-ipv6"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("groups = %q\n   want %q", names, want)
	}
}

func TestBuildModelMapsEveryEntryKind(t *testing.T) {
	model := BuildModel(Snapshot{
		Running:        true,
		DefaultZone:    "dmz",
		Zones:          ParseSections(fixture(t, "list-all-rich.txt")),
		PermanentZones: ParseSections(fixture(t, "list-all-rich.txt")),
	})
	dmz := group(t, model, "dmz")

	if got := dmz.Default.Target; got != "default" {
		t.Errorf("target = %q", got)
	}
	if len(dmz.PolicySlots) != 1 || dmz.PolicySlots[0] != firewall.PolicyTarget {
		t.Errorf("policy slots = %v, want the single target slot", dmz.PolicySlots)
	}

	for kind, want := range map[string][]string{
		firewall.KindInterface:   {"eth1"},
		firewall.KindSource:      {"10.20.0.0/16", "fd00:dead:beef::/48", "ipset:office"},
		firewall.KindService:     {"ssh", "http"},
		firewall.KindPort:        {"8080/tcp", "1000-2000/udp"},
		firewall.KindProtocol:    {"esp"},
		firewall.KindSourcePort:  {"5353/udp"},
		firewall.KindICMPBlock:   {"echo-request"},
		firewall.KindMasquerade:  {"masquerade"},
		firewall.KindForward:     {"forward"},
		firewall.KindForwardPort: {"port=80:proto=tcp:toport=8080", "port=443:proto=tcp:toport=8443:toaddr=10.20.0.9"},
	} {
		got := rulesOfKind(dmz, kind)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s entries = %q, want %q", kind, got, want)
		}
	}
	if got := len(rulesOfKind(dmz, firewall.KindRich)); got != 4 {
		t.Errorf("rich rules = %d, want 4", got)
	}

	// Entries in both configurations carry no marker.
	for _, rule := range dmz.Rules {
		if rule.Note != "" {
			t.Errorf("rule %q should have no note, got %q", rule.Raw, rule.Note)
		}
		if rule.Extra[ExtraScope] != ScopeBoth {
			t.Errorf("rule %q scope = %q", rule.Raw, rule.Extra[ExtraScope])
		}
	}
}

func TestBuildModelMarksTheRuntimePermanentDifference(t *testing.T) {
	runtime := ParseSections("public (default, active)\n" +
		"  target: default\n  interfaces: eth0 wg0\n  sources: \n" +
		"  services: ssh http\n  ports: 8080/tcp\n  forward: yes\n" +
		"  masquerade: no\n  forward-ports: \n  icmp-blocks: \n  rich rules: \n")
	permanent := ParseSections("public (default)\n" +
		"  target: default\n  interfaces: eth0\n  sources: \n" +
		"  services: ssh https\n  ports: 8080/tcp\n  forward: yes\n" +
		"  masquerade: no\n  forward-ports: \n  icmp-blocks: \n  rich rules: \n")

	model := BuildModel(Snapshot{
		Running: true, DefaultZone: "public",
		Zones: runtime, PermanentZones: permanent,
	})
	public := group(t, model, "public")

	notes := map[string]string{}
	for _, rule := range public.Rules {
		notes[rule.Raw] = rule.Note
	}
	for value, want := range map[string]string{
		"eth0":     "",
		"wg0":      "runtime only",
		"ssh":      "",
		"http":     "runtime only",
		"https":    "permanent only",
		"8080/tcp": "",
	} {
		if got, ok := notes[value]; !ok || got != want {
			t.Errorf("%q note = %q (present=%v), want %q", value, got, ok, want)
		}
	}
	// A permanent-only entry must come after the runtime ones, so the list
	// reads as "what is running, then what is only on disk".
	if public.Rules[len(public.Rules)-1].Raw != "https" {
		t.Errorf("last rule = %q, want the permanent-only one",
			public.Rules[len(public.Rules)-1].Raw)
	}
}

func TestBuildModelKeepsAPermanentOnlyZone(t *testing.T) {
	permanent := ParseSections("staging\n  target: default\n  services: ssh\n" +
		"  forward: yes\n  masquerade: no\n  rich rules: \n")
	model := BuildModel(Snapshot{
		Running: true, DefaultZone: "public", PermanentZones: permanent,
	})
	staging := group(t, model, "staging")
	if !strings.Contains(staging.Description, "permanent only") {
		t.Errorf("description = %q", staging.Description)
	}
	if len(staging.Rules) != 2 { // the ssh service and intra-zone forwarding
		t.Errorf("rules = %d, want 2", len(staging.Rules))
	}
}

func TestBuildModelReportsPanicMode(t *testing.T) {
	model := BuildModel(Snapshot{Running: true, Panic: true})
	if model.Warning != PanicWarning {
		t.Errorf("warning = %q", model.Warning)
	}
	// Lockdown is only reported when panic mode is not: panic is the louder
	// of the two and there is one banner.
	model = BuildModel(Snapshot{Running: true, Panic: true, Lockdown: true})
	if model.Warning != PanicWarning {
		t.Errorf("warning = %q, want the panic one", model.Warning)
	}
	model = BuildModel(Snapshot{Running: true, Lockdown: true})
	if !strings.Contains(model.Warning, "lockdown") {
		t.Errorf("warning = %q", model.Warning)
	}
}

func TestBuildModelReadsLogDenied(t *testing.T) {
	model := BuildModel(Snapshot{Running: true, LogDenied: LogAll})
	if model.Logging != LogAll || !model.LoggingOn {
		t.Errorf("logging = %q on=%v", model.Logging, model.LoggingOn)
	}
	model = BuildModel(Snapshot{Running: true, LogDenied: LogOff})
	if model.LoggingOn {
		t.Error("log-denied off must not read as logging on")
	}
}

func TestZoneName(t *testing.T) {
	if name, isPolicy := ZoneName("public"); name != "public" || isPolicy {
		t.Errorf("ZoneName(public) = %q %v", name, isPolicy)
	}
	if name, isPolicy := ZoneName(PolicyPrefix + "p1"); name != "p1" || !isPolicy {
		t.Errorf("ZoneName(policy) = %q %v", name, isPolicy)
	}
}
