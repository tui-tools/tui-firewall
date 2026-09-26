package firewalld

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// host is a firewalld made of captured firewall-cmd output: each read is
// answered from a table keyed by its arguments, and every read is recorded so
// a test can say how many processes a load would have started.
type host struct {
	mu      sync.Mutex
	answers map[string]string
	// missing lists the reads this firewalld does not know; they fail the
	// way an unknown option does.
	missing map[string]bool
	// stopped makes every read that needs the daemon fail the way it does
	// when firewalld is not running.
	stopped bool
	calls   []string
}

func (h *host) read(_ context.Context, args ...string) (string, error) {
	key := strings.Join(args, " ")
	h.mu.Lock()
	h.calls = append(h.calls, key)
	h.mu.Unlock()
	if h.stopped {
		return "Waiting on dbus connection...\nFirewallD is not running", errors.New("exit status 252")
	}
	if h.missing[key] {
		return "usage: see firewall-cmd man page", errors.New("exit status 2")
	}
	if out, ok := h.answers[key]; ok {
		return out, nil
	}
	// A per-policy read is answered from the full policy listing: on
	// firewall-cmd 2.3.2 `--policy=X --list-all` prints byte for byte the
	// block `--list-all-policies` prints for X (checked when the fixture was
	// captured).
	if name, ok := strings.CutPrefix(key, "--policy="); ok {
		return policyBlock(h.answers["--list-all-policies"], strings.TrimSuffix(name, " --list-all")), nil
	}
	if name, ok := strings.CutPrefix(key, "--permanent --policy="); ok {
		return policyBlock(h.answers["--permanent --list-all-policies"], strings.TrimSuffix(name, " --list-all")), nil
	}
	return "", fmt.Errorf("unexpected read %q", key)
}

// policyBlock cuts one policy's block out of a `--list-all-policies` listing.
func policyBlock(listing, name string) string {
	for _, block := range strings.Split(listing, "\n\n") {
		header, _, _ := strings.Cut(block, "\n")
		if strings.Fields(header)[0] == name {
			return block
		}
	}
	return ""
}

func (h *host) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.calls)
}

func (h *host) asked(key string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.calls {
		if c == key {
			return true
		}
	}
	return false
}

// newHost builds a firewalld from one release's fixtures.
func newHost(t *testing.T, zones, active, defaultZone string) *host {
	return &host{
		answers: map[string]string{
			"--state":                         "running",
			"--get-default-zone":              defaultZone,
			"--get-active-zones":              fixture(t, active),
			"--list-all-zones":                fixture(t, zones),
			"--permanent --list-all-zones":    fixture(t, "permanent-list-all-zones.txt"),
			"--get-services":                  "dhcp dns http https ssh",
			"--get-log-denied":                "off",
			"--query-panic":                   "no",
			"--query-lockdown":                "no",
			"--get-policies":                  "allow-host-ipv6 docker-forwarding libvirt-routed-in libvirt-routed-out libvirt-to-host",
			"--list-all-policies":             fixture(t, "list-all-policies.txt"),
			"--permanent --list-all-policies": fixture(t, "permanent-list-all-policies.txt"),
		},
		missing: map[string]bool{},
	}
}

// legacySnapshot is the Load of 0.6.1, read for read: one firewall-cmd after
// another, zones' default and active state from their own queries, and two
// reads per policy object. The new load has to produce the same model.
func legacySnapshot(ctx context.Context, read readFunc) Snapshot {
	text := func(args ...string) string {
		out, err := read(ctx, args...)
		if err != nil {
			return ""
		}
		return out
	}
	s := Snapshot{Running: true}
	s.DefaultZone = firstLine(text("--get-default-zone"))
	s.Active = ParseActiveZones(text("--get-active-zones"))
	s.Zones = ParseSections(text("--list-all-zones"))
	s.PermanentZones = ParseSections(text("--permanent", "--list-all-zones"))
	s.Services = ParseList(text("--get-services"))
	s.LogDenied = firstLine(text("--get-log-denied"))
	s.Panic = strings.TrimSpace(text("--query-panic")) == "yes"
	s.Lockdown = strings.TrimSpace(text("--query-lockdown")) == "yes"
	names := ParseList(text("--get-policies"))
	for _, name := range names {
		s.Policies = append(s.Policies, ParseSections(text("--policy="+name, "--list-all"))...)
		s.PermanentPolicies = append(s.PermanentPolicies,
			ParseSections(text("--permanent", "--policy="+name, "--list-all"))...)
	}
	return s
}

// releases are the two ends of the tested range, as captured.
var releases = []struct {
	name, zones, active, defaultZone string
}{
	{"firewalld 2.3.2", "list-all-zones.txt", "get-active-zones.txt", "FedoraWorkstation"},
	{"firewalld 2.4.4", "list-all-zones-firewalld244.txt", "get-active-zones-firewalld244.txt", "public"},
}

func TestLoadSnapshotIsOneWaveOfEightReads(t *testing.T) {
	for _, rel := range releases {
		t.Run(rel.name, func(t *testing.T) {
			h := newHost(t, rel.zones, rel.active, rel.defaultZone)
			snapshot, running := loadSnapshot(context.Background(), h.read)
			if !running {
				t.Fatal("running = false")
			}
			if got := h.count(); got != 8 {
				t.Errorf("reads = %d (%v), want 8", got, h.calls)
			}
			for _, fallback := range []string{"--state", "--get-default-zone", "--get-active-zones", "--get-policies"} {
				if h.asked(fallback) {
					t.Errorf("asked %s, which the listings already answer", fallback)
				}
			}
			if snapshot.DefaultZone != rel.defaultZone {
				t.Errorf("default zone = %q, want %q", snapshot.DefaultZone, rel.defaultZone)
			}
		})
	}
}

func TestLoadSnapshotBuildsTheSameModelAsTheLegacyReads(t *testing.T) {
	for _, rel := range releases {
		t.Run(rel.name, func(t *testing.T) {
			h := newHost(t, rel.zones, rel.active, rel.defaultZone)
			want := BuildModel(legacySnapshot(context.Background(), h.read))
			snapshot, _ := loadSnapshot(context.Background(), h.read)
			got := BuildModel(snapshot)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("model differs from the legacy reads\n got: %+v\nwant: %+v", got, want)
			}
			if len(got.Groups) == 0 {
				t.Fatal("no groups: the fixtures were not read")
			}
		})
	}
}

// flagsRe matches the "(default, active)" suffix of a zone header.
var flagsRe = regexp.MustCompile(`(?m)^(\S+) \([^)]*\)$`)

func TestLoadSnapshotAsksWhenTheZonesAreNotFlagged(t *testing.T) {
	h := newHost(t, "list-all-zones.txt", "get-active-zones.txt", "FedoraWorkstation")
	want := BuildModel(legacySnapshot(context.Background(), h.read))

	// A firewalld that prints bare zone names: the default and the active
	// zones must then come from their own queries.
	h.answers["--list-all-zones"] = flagsRe.ReplaceAllString(h.answers["--list-all-zones"], "$1")
	h.calls = nil
	snapshot, _ := loadSnapshot(context.Background(), h.read)
	if !h.asked("--get-default-zone") || !h.asked("--get-active-zones") {
		t.Fatalf("fallback reads not made: %v", h.calls)
	}
	if got := BuildModel(snapshot); !reflect.DeepEqual(got, want) {
		t.Errorf("model differs without the header flags\n got: %+v\nwant: %+v", got, want)
	}
}

func TestLoadSnapshotReadsPoliciesOneByOneWithoutListAllPolicies(t *testing.T) {
	h := newHost(t, "list-all-zones.txt", "get-active-zones.txt", "FedoraWorkstation")
	want := BuildModel(legacySnapshot(context.Background(), h.read))

	// The per-policy answers are cut from the listings, so the listings stay
	// in the table; only the options themselves are unknown.
	h.missing["--list-all-policies"] = true
	h.missing["--permanent --list-all-policies"] = true
	h.calls = nil
	snapshot, _ := loadSnapshot(context.Background(), h.read)
	if !h.asked("--get-policies") || !h.asked("--policy=allow-host-ipv6 --list-all") {
		t.Fatalf("per-policy reads not made: %v", h.calls)
	}
	if len(snapshot.Policies) != 5 || len(snapshot.PermanentPolicies) != 5 {
		t.Errorf("policies = %d/%d, want 5/5", len(snapshot.Policies), len(snapshot.PermanentPolicies))
	}
	if got := BuildModel(snapshot); !reflect.DeepEqual(got, want) {
		t.Errorf("model differs with the per-policy reads\n got: %+v\nwant: %+v", got, want)
	}
}

func TestLoadSnapshotWithoutPolicyObjects(t *testing.T) {
	// A firewalld older than 0.9: neither the listing nor the names exist.
	h := newHost(t, "list-all-zones.txt", "get-active-zones.txt", "FedoraWorkstation")
	h.missing["--list-all-policies"] = true
	h.missing["--permanent --list-all-policies"] = true
	h.missing["--get-policies"] = true
	snapshot, running := loadSnapshot(context.Background(), h.read)
	if !running || len(snapshot.Policies) != 0 || len(snapshot.Zones) == 0 {
		t.Errorf("running=%v policies=%d zones=%d", running, len(snapshot.Policies), len(snapshot.Zones))
	}
}

func TestLoadSnapshotStopsWhenTheDaemonIsDown(t *testing.T) {
	h := newHost(t, "list-all-zones.txt", "get-active-zones.txt", "FedoraWorkstation")
	h.stopped = true
	snapshot, running := loadSnapshot(context.Background(), h.read)
	if running {
		t.Fatal("running = true with --state failing")
	}
	if !reflect.DeepEqual(snapshot, Snapshot{}) {
		t.Errorf("snapshot = %+v, want empty", snapshot)
	}
	// Each read waits ~10 s for a stopped daemon, so nothing is asked after
	// the wave: not --state, and none of the fallbacks.
	for _, fallback := range []string{"--state", "--get-default-zone", "--get-policies"} {
		if h.asked(fallback) {
			t.Errorf("asked %s of a stopped daemon", fallback)
		}
	}
}

func TestZoneFlagsMatchGetActiveZones(t *testing.T) {
	for _, rel := range releases {
		t.Run(rel.name, func(t *testing.T) {
			defaultZone, active, ok := ZoneFlags(ParseSections(fixture(t, rel.zones)))
			if !ok || defaultZone != rel.defaultZone {
				t.Fatalf("ZoneFlags = %q, %v; want %q", defaultZone, ok, rel.defaultZone)
			}
			want := ParseActiveZones(fixture(t, rel.active))
			if len(active) != len(want) {
				t.Fatalf("active = %d zones, want %d", len(active), len(want))
			}
			for i := range want {
				if active[i].Name != want[i].Name || active[i].Default != want[i].Default {
					t.Errorf("active[%d] = %s/%v, want %s/%v", i,
						active[i].Name, active[i].Default, want[i].Name, want[i].Default)
				}
				if !sameSet(active[i].Interfaces, want[i].Interfaces) {
					t.Errorf("%s interfaces = %v, want %v", want[i].Name,
						active[i].Interfaces, want[i].Interfaces)
				}
			}
		})
	}
}

func TestZoneFlagsWithoutFlags(t *testing.T) {
	bare := flagsRe.ReplaceAllString(fixture(t, "list-all-zones.txt"), "$1")
	if zone, active, ok := ZoneFlags(ParseSections(bare)); ok || zone != "" || active != nil {
		t.Errorf("ZoneFlags on unflagged headers = %q, %v, %v", zone, active, ok)
	}
}

func TestPolicySectionsPairsAndBounds(t *testing.T) {
	runtime := ParseSections(fixture(t, "list-all-policies.txt"))
	permanent := ParseSections(fixture(t, "permanent-list-all-policies.txt"))
	kept, keptPermanent := PolicySections(runtime, permanent[1:])
	if len(kept) != 5 {
		t.Fatalf("kept = %d, want 5", len(kept))
	}
	if kept[0].Name != "allow-host-ipv6" || !kept[0].Active {
		t.Errorf("first = %+v", kept[0])
	}
	// The policy missing from the permanent listing simply has no pair.
	if len(keptPermanent) != 4 {
		t.Errorf("permanent pairs = %d, want 4", len(keptPermanent))
	}

	var many []Section
	for i := range maxPolicies + 8 {
		many = append(many, newSection(fmt.Sprintf("p%02d", i), ""))
	}
	many = append([]Section{newSection("-bad", "")}, many...)
	kept, _ = PolicySections(many, nil)
	if len(kept) != maxPolicies || kept[0].Name != "p00" {
		t.Errorf("kept %d starting at %q, want %d starting at p00", len(kept), kept[0].Name, maxPolicies)
	}
}

// sameSet compares two lists ignoring order: `--get-active-zones` prints a
// zone's interfaces in the daemon's order, the listing prints them sorted.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

func TestLoadSnapshotAsksStateWhenTheZoneListingFails(t *testing.T) {
	// The daemon is up but refused the zone listing: --state says so, and
	// the rest of the picture is still shown.
	h := newHost(t, "list-all-zones.txt", "get-active-zones.txt", "FedoraWorkstation")
	h.missing["--list-all-zones"] = true
	snapshot, running := loadSnapshot(context.Background(), h.read)
	if !running || !h.asked("--state") {
		t.Fatalf("running=%v asked --state=%v", running, h.asked("--state"))
	}
	if len(snapshot.Zones) != 0 || len(snapshot.PermanentZones) == 0 || len(snapshot.Services) == 0 {
		t.Errorf("zones=%d permanent=%d services=%d", len(snapshot.Zones),
			len(snapshot.PermanentZones), len(snapshot.Services))
	}

	// And a "not running" answer is still not running.
	h.answers["--state"] = "not running"
	if _, running := loadSnapshot(context.Background(), h.read); running {
		t.Error("running = true with --state saying not running")
	}
}
