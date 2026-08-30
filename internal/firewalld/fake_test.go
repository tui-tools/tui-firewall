package firewalld

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// apply runs a change against the fake and returns the model it produces.
func apply(t *testing.T, fake *Fake, change firewall.Change) firewall.Model {
	t.Helper()
	if _, err := fake.Run(context.Background(), change); err != nil {
		t.Fatalf("Run: %v", err)
	}
	model, err := fake.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return model
}

// noteOf finds a rule by its raw value and returns its note.
func noteOf(t *testing.T, model firewall.Model, groupName, raw string) (string, bool) {
	t.Helper()
	g, ok := model.Group(groupName)
	if !ok {
		t.Fatalf("no group %q", groupName)
	}
	for _, rule := range g.Rules {
		if rule.Raw == raw {
			return rule.Note, true
		}
	}
	return "", false
}

func TestFakeStartsFromTheDemoSnapshot(t *testing.T) {
	model, err := NewFake().Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if model.Backend != Name || !model.Enabled {
		t.Errorf("model = %+v", model)
	}
	if model.Groups[0].Name != "public" {
		t.Errorf("first group = %q, want the default zone", model.Groups[0].Name)
	}
	// The demo must show both directions of the runtime/permanent difference,
	// because that is the thing the firewalld backend exists to make visible.
	var runtimeOnly, permanentOnly int
	for _, g := range model.Groups {
		for _, rule := range g.Rules {
			switch rule.Note {
			case "runtime only":
				runtimeOnly++
			case "permanent only":
				permanentOnly++
			}
		}
	}
	if runtimeOnly == 0 || permanentOnly == 0 {
		t.Errorf("demo has %d runtime-only and %d permanent-only entries, want both",
			runtimeOnly, permanentOnly)
	}
}

func TestFakeAppliesAChangeToBothConfigurations(t *testing.T) {
	fake := NewFake()
	change, err := BuildAddRule("public", firewall.RuleSpec{
		Action: firewall.ActionAllow, Service: "wireguard",
	})
	if err != nil {
		t.Fatalf("BuildAddRule: %v", err)
	}

	model := apply(t, fake, change)
	note, found := noteOf(t, model, "public", "wireguard")
	if !found {
		t.Fatal("the service should have been added")
	}
	if note != "" {
		t.Errorf("note = %q, want none: it is in both configurations", note)
	}
	if len(fake.Log) != 2 {
		t.Errorf("ran %d commands, want the runtime and the permanent one", len(fake.Log))
	}
}

func TestFakeAppliesARuntimeOnlyChange(t *testing.T) {
	fake := NewFake()
	// Only the runtime line, as a delete of a runtime-only entry produces.
	model := apply(t, fake, firewall.One(firewall.Command{
		Argv: []string{Bin, "--zone=public", "--add-port=9090/tcp"},
	}))
	note, found := noteOf(t, model, "public", "9090/tcp")
	if !found || note != "runtime only" {
		t.Errorf("note = %q found=%v, want a runtime-only entry", note, found)
	}
}

func TestFakeReloadDiscardsRuntimeOnlyEntries(t *testing.T) {
	fake := NewFake()
	change, err := BuildReload()
	if err != nil {
		t.Fatalf("BuildReload: %v", err)
	}
	model := apply(t, fake, change)

	// 51820/udp was runtime-only in the demo, so a reload loses it.
	if _, found := noteOf(t, model, "public", "51820/udp"); found {
		t.Error("a reload must discard a runtime-only port")
	}
	// The permanent-only rich rule is now running.
	note, found := noteOf(t, model, "public",
		`rule family="ipv6" source address="fd00::/8" service name="dns" accept`)
	if !found || note != "" {
		t.Errorf("note = %q found=%v, want it in both after a reload", note, found)
	}
}

func TestFakeRuntimeToPermanentKeepsRuntimeEntries(t *testing.T) {
	fake := NewFake()
	change, err := BuildExtra("public", ExtraRuntimeToPermanent, nil)
	if err != nil {
		t.Fatalf("BuildExtra: %v", err)
	}
	model := apply(t, fake, change)

	note, found := noteOf(t, model, "public", "51820/udp")
	if !found || note != "" {
		t.Errorf("note = %q found=%v, want the runtime port made permanent",
			note, found)
	}
	if _, found := noteOf(t, model, "public",
		`rule family="ipv6" source address="fd00::/8" service name="dns" accept`); found {
		t.Error("a permanent-only entry is overwritten by the running configuration")
	}
}

func TestFakeSetDefaultZoneMovesTheMarker(t *testing.T) {
	fake := NewFake()
	change, err := BuildExtra("public", ExtraSetDefaultZone, []string{"internal"})
	if err != nil {
		t.Fatalf("BuildExtra: %v", err)
	}
	model := apply(t, fake, change)

	if model.Groups[0].Name != "internal" {
		t.Errorf("first group = %q, want the new default zone", model.Groups[0].Name)
	}
	if !strings.HasSuffix(model.Groups[0].Title, "(default)") {
		t.Errorf("title = %q", model.Groups[0].Title)
	}
	for _, g := range model.Groups[1:] {
		if strings.HasSuffix(g.Title, "(default)") {
			t.Errorf("%q is still marked as the default", g.Name)
		}
	}
}

func TestFakeRejectsWhatFirewalldWouldReject(t *testing.T) {
	fake := NewFake()
	_, err := fake.Run(context.Background(), firewall.One(firewall.Command{
		Argv: []string{Bin, "--zone=nowhere", "--add-service=ssh"},
	}))
	if err == nil || !strings.Contains(err.Error(), "INVALID_ZONE") {
		t.Errorf("err = %v, want an invalid-zone error", err)
	}

	_, err = fake.Run(context.Background(), firewall.One(firewall.Command{
		Argv: []string{Bin, "--zone=public", "--remove-service=nfs"},
	}))
	if err == nil || !strings.Contains(err.Error(), "NOT_ENABLED") {
		t.Errorf("err = %v, want a not-enabled error", err)
	}

	_, err = fake.Run(context.Background(), firewall.One(firewall.Command{
		Argv: []string{Bin, "--zone=public", "--add-lockdown-whitelist-user=root"},
	}))
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("err = %v, want an unsupported-option error", err)
	}
}

func TestFakeStopsAtTheFirstFailure(t *testing.T) {
	fake := NewFake()
	// The runtime line succeeds, the permanent one names a zone that is not
	// there: the change must report the failure rather than press on.
	_, err := fake.Run(context.Background(), firewall.Change{
		Commands: []firewall.Command{
			{Argv: []string{Bin, "--zone=public", "--add-port=9091/tcp"}},
			{Argv: []string{Bin, "--permanent", "--zone=nowhere", "--add-port=9091/tcp"}},
			{Argv: []string{Bin, "--zone=public", "--add-port=9092/tcp"}},
		},
	})
	if err == nil {
		t.Fatal("expected the change to fail")
	}
	if len(fake.Log) != 2 {
		t.Errorf("ran %d commands, want it to stop after the failing one", len(fake.Log))
	}
}

func TestFakeCapabilitiesMatchTheRealBackend(t *testing.T) {
	// The demo has to behave exactly like the real thing, so a screenshot of
	// it is a screenshot of the tool.
	fake := NewFake()
	if !reflect.DeepEqual(fake.Capabilities(), Capabilities()) {
		t.Error("the demo must report the real backend's capabilities")
	}
	if fake.Name() != Name {
		t.Errorf("Name = %q", fake.Name())
	}
}
