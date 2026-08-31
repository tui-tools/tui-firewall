package backends

import (
	"strings"
	"testing"

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
	t.Cleanup(func() { probes, readManagement = originalProbes, originalRead })
	probes = map[string]Probe{
		BackendUFW:       fixedProbe(ufwState),
		BackendFirewalld: fixedProbe(firewalldState),
		BackendNftables:  fixedProbe(nftState),
	}
	readManagement = func([]string) (nftables.Management, bool) {
		return nftables.Management{}, false
	}
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
		Values: map[string]string{KeyBackend: "iptables"},
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
