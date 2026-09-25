package backends

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/iptables"
	"github.com/tui-tools/tui-firewall/internal/nftables"
	"github.com/tui-tools/tui-kit/config"
)

// probeState is what a stubbed host reports about one backend.
type probeState struct {
	installed bool
	active    bool
	enabled   bool
}

// fixedProbe answers for a host the test is describing rather than running on.
func fixedProbe(state probeState) Probe {
	return Probe{
		Installed: func() bool { return state.installed },
		Active:    func() bool { return state.active },
		Enabled:   func() bool { return state.enabled },
	}
}

// stubProbes replaces the host detectors for the duration of a test. nft is
// reported absent unless a test says otherwise, which keeps the ufw and
// firewalld cases exactly as they were before nftables existed.
func stubProbes(t *testing.T, ufwState, firewalldState probeState) {
	t.Helper()
	stubAllProbes(t, ufwState, firewalldState, probeState{})
}

// stubAllProbes stubs the three detectors, and answers "the ruleset could not
// be read" unless a test replaces readManagement itself.
func stubAllProbes(t *testing.T, ufwState, firewalldState, nftState probeState) {
	t.Helper()
	originalProbes, originalRead := probes, readManagement
	originalLegacy, originalNative, originalLayout := readLegacy, readNativeTables, iptablesLayout
	t.Cleanup(func() {
		probes, readManagement = originalProbes, originalRead
		readLegacy, readNativeTables, iptablesLayout = originalLegacy, originalNative, originalLayout
	})
	probes = map[string]Probe{
		BackendUFW:       fixedProbe(ufwState),
		BackendFirewalld: fixedProbe(firewalldState),
		BackendIptables:  fixedProbe(probeState{}),
		BackendNftables:  fixedProbe(nftState),
	}
	readManagement = func([]string) (nftables.Management, bool) {
		return nftables.Management{}, false
	}
	readLegacy = func([]string) (int, bool) { return 0, false }
	readNativeTables = func([]string) []nftables.TableID { return nil }
	iptablesLayout = func() iptables.Layout { return iptables.Layout{} }
}

// stubIptables makes the iptables detector report a state and a
// persistence layout.
func stubIptables(t *testing.T, state probeState, layout iptables.Layout) {
	t.Helper()
	probes[BackendIptables] = fixedProbe(state)
	iptablesLayout = func() iptables.Layout { return layout }
}

// stubRuleset makes the detector see a ruleset managed by the named tool.
func stubRuleset(t *testing.T, management nftables.Management) {
	t.Helper()
	original := readManagement
	t.Cleanup(func() { readManagement = original })
	readManagement = func([]string) (nftables.Management, bool) {
		return management, true
	}
}

// autoConfig is the configuration every detection test starts from.
func autoConfig() config.Config {
	return config.Config{Values: map[string]string{KeyBackend: BackendAuto}}
}

func TestResolveAutoPrefersTheActiveBackend(t *testing.T) {
	// firewalld installed and running, ufw installed but stopped: the running
	// one wins even though ufw comes first in the preference order.
	stubProbes(t,
		probeState{installed: true},
		probeState{installed: true, active: true, enabled: true})

	selection, err := Resolve(autoConfig())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if selection.Name != BackendFirewalld {
		t.Errorf("Resolve = %q, want firewalld", selection.Name)
	}
}

func TestResolveAutoPrefersTheEnabledUnit(t *testing.T) {
	// Both installed, neither running: the one systemd would start at boot is
	// the one this machine is configured to use, even though ufw is first in
	// the preference order.
	stubProbes(t,
		probeState{installed: true},
		probeState{installed: true, enabled: true})

	selection, err := Resolve(autoConfig())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if selection.Name != BackendFirewalld {
		t.Errorf("Resolve = %q, want firewalld", selection.Name)
	}
}

func TestResolveAutoFallsBackToInstalled(t *testing.T) {
	// Nothing is running and nothing is enabled: the first installed backend
	// is used so the user can look at it.
	stubProbes(t, probeState{}, probeState{installed: true})

	selection, err := Resolve(autoConfig())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if selection.Name != BackendFirewalld {
		t.Errorf("Resolve = %q, want firewalld", selection.Name)
	}
}

func TestResolveAutoWithoutAnyFirewall(t *testing.T) {
	stubProbes(t, probeState{}, probeState{})

	_, err := Resolve(autoConfig())
	if err == nil {
		t.Fatal("expected an error when no firewall is installed")
	}
	for _, want := range []string{"install nftables", "install ufw", "firewalld",
		"--demo", "config.toml"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

func TestResolveUnknownBackend(t *testing.T) {
	if _, err := Resolve(config.Config{
		Values: map[string]string{KeyBackend: "pf"},
	}); err == nil {
		t.Error("expected an error for an unknown backend")
	}
}

func TestResolveHonoursAnExplicitChoice(t *testing.T) {
	// An explicit choice skips detection entirely: the user said which
	// firewall this machine runs, and the tool does not argue.
	stubProbes(t, probeState{installed: true, active: true}, probeState{})
	selection, err := Resolve(config.Config{
		Values: map[string]string{KeyBackend: BackendFirewalld},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if selection.Name != BackendFirewalld {
		t.Errorf("Resolve = %q, want firewalld", selection.Name)
	}
}

func TestSelectBuildsTheResolvedBackend(t *testing.T) {
	// Select reaches for the binary, which a test machine may not have; what
	// matters either way is that it reports the backend Resolve named, and
	// says so legibly when that binary is missing.
	stubProbes(t, probeState{installed: true, active: true}, probeState{})
	backend, err := Select(autoConfig())
	switch {
	case err != nil:
		if !strings.Contains(err.Error(), "ufw") {
			t.Errorf("error should name the backend it could not build: %v", err)
		}
	case backend.Name() != BackendUFW:
		t.Errorf("Name = %q, want ufw", backend.Name())
	}
}

func TestInspectReportsEveryBackend(t *testing.T) {
	// The detector must describe the backend it did not pick, so `--check`
	// can say "firewalld is here but stopped" instead of staying silent.
	stubProbes(t,
		probeState{installed: true, active: true, enabled: true},
		probeState{installed: true})

	states := Inspect(BackendUFW)
	if len(states) != len(preference) {
		t.Fatalf("Inspect returned %d states, want %d", len(states), len(preference))
	}
	byName := map[string]State{}
	for _, state := range states {
		byName[state.Name] = state
	}
	if got := byName[BackendUFW]; !got.Selected || !got.Active {
		t.Errorf("ufw state = %+v, want selected and active", got)
	}
	if got := byName[BackendFirewalld]; got.Selected || got.Active || !got.Installed {
		t.Errorf("firewalld state = %+v, want installed, inactive, not selected", got)
	}
}

func TestInspectSkipsProbingAnAbsentBackend(t *testing.T) {
	// A backend that is not installed must not have its service queried:
	// there is nothing to ask about, and the answer would be noise.
	asked := false
	original := probes
	t.Cleanup(func() { probes = original })
	probes = map[string]Probe{
		BackendUFW: {
			Installed: func() bool { return false },
			Active:    func() bool { asked = true; return false },
			Enabled:   func() bool { asked = true; return false },
		},
		BackendFirewalld: {
			Installed: func() bool { return true },
			Active:    func() bool { return true },
			Enabled:   func() bool { return true },
		},
		BackendIptables: fixedProbe(probeState{}),
		BackendNftables: fixedProbe(probeState{}),
	}

	Inspect(BackendFirewalld)
	if asked {
		t.Error("an absent backend must not be probed for its service state")
	}
}

func TestResolveAutoPicksNftablesWhenNothingElseManagesTheRuleset(t *testing.T) {
	// The machine that the nftables backend exists for: nft installed, no ufw
	// and no firewalld, and a ruleset nobody else claims.
	stubAllProbes(t, probeState{}, probeState{}, probeState{installed: true})

	selection, err := Resolve(autoConfig())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if selection.Name != BackendNftables {
		t.Fatalf("Resolve = %q, want nftables", selection.Name)
	}
	if !strings.Contains(selection.Detail, "nothing in the ruleset is managed") {
		t.Errorf("detail should say why nftables won, got %q", selection.Detail)
	}
}

func TestResolveAutoPrefersTheManagerNamedByTheRuleset(t *testing.T) {
	// Every binary is present and no service is running, which is the case
	// the ruleset has to break: firewalld's tables are loaded, so firewalld is
	// the firewall in charge and nftables must not claim it.
	stubAllProbes(t,
		probeState{installed: true},
		probeState{installed: true},
		probeState{installed: true})
	stubRuleset(t, nftables.Management{
		Manager: nftables.ManagerFirewalld,
		Tables:  []nftables.TableID{{Family: "inet", Name: "firewalld"}},
		Detail:  "the ruleset carries table inet firewalld",
	})

	selection, err := Resolve(autoConfig())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if selection.Name != BackendFirewalld {
		t.Fatalf("Resolve = %q, want firewalld", selection.Name)
	}
	if !strings.Contains(selection.Detail, "inet firewalld") {
		t.Errorf("detail should name the tables it saw, got %q", selection.Detail)
	}
}

func TestResolveAutoReadsAManagedRulesetWhenTheManagerIsGone(t *testing.T) {
	// ufw's chains are loaded but ufw itself is not installed — a machine
	// somebody uninstalled it from without flushing. nftables is the only
	// backend that can read that, and the detail has to say it will not write.
	stubAllProbes(t, probeState{}, probeState{}, probeState{installed: true})
	stubRuleset(t, nftables.Management{
		Manager: nftables.ManagerUFW,
		Tables:  []nftables.TableID{{Family: "ip", Name: "filter"}},
		Detail:  "the ruleset carries ufw's own chains in table ip filter",
	})

	selection, err := Resolve(autoConfig())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if selection.Name != BackendNftables {
		t.Fatalf("Resolve = %q, want nftables", selection.Name)
	}
	if !strings.Contains(selection.Detail, "does not write") {
		t.Errorf("detail should say the tables are read-only, got %q", selection.Detail)
	}
}

func TestResolveAutoPrefersAnEnabledManagerOverNftables(t *testing.T) {
	// Nothing is running and the ruleset says nothing, but systemd would
	// start firewalld at boot: that is what this machine is configured to
	// use, and nftables must not take it over.
	stubAllProbes(t,
		probeState{},
		probeState{installed: true, enabled: true},
		probeState{installed: true})

	selection, err := Resolve(autoConfig())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if selection.Name != BackendFirewalld {
		t.Errorf("Resolve = %q, want firewalld", selection.Name)
	}
}

func TestResolveAutoDoesNotReadTheRulesetWithoutNft(t *testing.T) {
	// Reading the ruleset means running nft. On a host without it there is
	// nothing to run, and the detector must not try.
	stubAllProbes(t, probeState{installed: true}, probeState{}, probeState{})
	read := false
	original := readManagement
	t.Cleanup(func() { readManagement = original })
	readManagement = func([]string) (nftables.Management, bool) {
		read = true
		return nftables.Management{}, false
	}

	if _, err := Resolve(autoConfig()); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if read {
		t.Error("the ruleset must not be read on a host with no nft")
	}
}

func TestResolveNftablesByConfiguration(t *testing.T) {
	stubAllProbes(t, probeState{}, probeState{}, probeState{})
	selection, err := Resolve(config.Config{
		Values: map[string]string{KeyBackend: BackendNftables},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if selection.Name != BackendNftables {
		t.Errorf("Resolve = %q, want nftables", selection.Name)
	}
}

// debianLayout is the persistence layer of an Ubuntu cloud image.
var debianLayout = iptables.Layout{
	Kind:    iptables.LayoutNetfilterPersistent,
	V4Path:  "/etc/iptables/rules.v4",
	V6Path:  "/etc/iptables/rules.v6",
	Enabled: true,
}

func TestResolveAutoPicksIptablesWhenItsLoaderRan(t *testing.T) {
	// The real case: an Ubuntu cloud image with iptables-persistent, ufw
	// installed but inactive, and nft on the machine too. The loader that
	// restored rules.v4 at boot is what makes iptables the firewall in charge.
	stubAllProbes(t, probeState{installed: true}, probeState{},
		probeState{installed: true})
	stubIptables(t, probeState{installed: true, active: true, enabled: true},
		debianLayout)

	selection, err := Resolve(autoConfig())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if selection.Name != BackendIptables {
		t.Fatalf("Resolve = %q, want iptables", selection.Name)
	}
	for _, want := range []string{"netfilter-persistent", "/etc/iptables/rules.v4"} {
		if !strings.Contains(selection.Detail, want) {
			t.Errorf("detail %q should mention %q", selection.Detail, want)
		}
	}
}

func TestResolveAutoIptablesSaysWhenNativeTablesExistToo(t *testing.T) {
	// A host with both: the iptables backend is chosen, and the sentence says
	// there is a native nft table it will not show.
	stubAllProbes(t, probeState{}, probeState{}, probeState{installed: true})
	stubIptables(t, probeState{installed: true, active: true, enabled: true},
		debianLayout)
	readNativeTables = func([]string) []nftables.TableID {
		return []nftables.TableID{{Family: "inet", Name: "filter"}}
	}

	selection, err := Resolve(autoConfig())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !strings.Contains(selection.Detail, "table inet filter") {
		t.Errorf("detail %q should name the native table", selection.Detail)
	}
}

func TestResolveAutoPicksIptablesFromTheRuleset(t *testing.T) {
	// No loader at all, but the nft ruleset shows iptables-nft tables with
	// rules of the operator's own: iptables is in charge, and the ruleset is
	// the witness.
	stubAllProbes(t, probeState{}, probeState{}, probeState{installed: true})
	stubIptables(t, probeState{installed: true}, iptables.Layout{})
	stubRuleset(t, nftables.Management{
		Manager: nftables.ManagerIptables,
		Detail:  "the ruleset's table ip filter is written by iptables-nft",
	})

	selection, err := Resolve(autoConfig())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if selection.Name != BackendIptables {
		t.Fatalf("Resolve = %q, want iptables", selection.Name)
	}
	if !strings.Contains(selection.Detail, "iptables-nft") {
		t.Errorf("detail %q should say why", selection.Detail)
	}
}

func TestResolveAutoPicksIptablesFromLegacyTables(t *testing.T) {
	// A legacy iptables keeps its rules where nft cannot see them; the
	// detector asks it directly.
	stubAllProbes(t, probeState{}, probeState{}, probeState{installed: true})
	stubIptables(t, probeState{installed: true}, iptables.Layout{})
	readLegacy = func([]string) (int, bool) { return 3, true }

	selection, err := Resolve(autoConfig())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if selection.Name != BackendIptables || !strings.Contains(selection.Detail, "legacy") {
		t.Errorf("Resolve = %+v, want iptables because of the legacy table", selection)
	}
}

func TestResolveAutoKeepsNftablesWhenIptablesIsOnlyInstalled(t *testing.T) {
	// iptables is on nearly every machine; installed alone, with no loader and
	// no rules of its own, it must not take a pure-nft host away from nftables.
	stubAllProbes(t, probeState{}, probeState{}, probeState{installed: true})
	stubIptables(t, probeState{installed: true}, iptables.Layout{})

	selection, err := Resolve(autoConfig())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if selection.Name != BackendNftables {
		t.Errorf("Resolve = %q, want nftables", selection.Name)
	}
}

func TestResolveAutoRunningUfwBeatsIptables(t *testing.T) {
	// ufw writes through iptables; when it is running, it is the firewall.
	stubAllProbes(t, probeState{installed: true, active: true}, probeState{},
		probeState{installed: true})
	stubIptables(t, probeState{installed: true, active: true, enabled: true},
		debianLayout)

	selection, err := Resolve(autoConfig())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if selection.Name != BackendUFW {
		t.Errorf("Resolve = %q, want ufw", selection.Name)
	}
}
