package backends

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-kit/config"
)

// probeState is what a stubbed host reports about one backend.
type probeState struct {
	installed bool
	active    bool
	enabled   bool
}

// stubProbes replaces the host detectors for the duration of a test.
func stubProbes(t *testing.T, ufwState, firewalldState probeState) {
	t.Helper()
	original := probes
	t.Cleanup(func() { probes = original })
	fixed := func(state probeState) Probe {
		return Probe{
			Installed: func() bool { return state.installed },
			Active:    func() bool { return state.active },
			Enabled:   func() bool { return state.enabled },
		}
	}
	probes = map[string]Probe{
		BackendUFW:       fixed(ufwState),
		BackendFirewalld: fixed(firewalldState),
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

	name, err := Resolve(autoConfig())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if name != BackendFirewalld {
		t.Errorf("Resolve = %q, want firewalld", name)
	}
}

func TestResolveAutoPrefersTheEnabledUnit(t *testing.T) {
	// Both installed, neither running: the one systemd would start at boot is
	// the one this machine is configured to use, even though ufw is first in
	// the preference order.
	stubProbes(t,
		probeState{installed: true},
		probeState{installed: true, enabled: true})

	name, err := Resolve(autoConfig())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if name != BackendFirewalld {
		t.Errorf("Resolve = %q, want firewalld", name)
	}
}

func TestResolveAutoFallsBackToInstalled(t *testing.T) {
	// Nothing is running and nothing is enabled: the first installed backend
	// is used so the user can look at it.
	stubProbes(t, probeState{}, probeState{installed: true})

	name, err := Resolve(autoConfig())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if name != BackendFirewalld {
		t.Errorf("Resolve = %q, want firewalld", name)
	}
}

func TestResolveAutoWithoutAnyFirewall(t *testing.T) {
	stubProbes(t, probeState{}, probeState{})

	_, err := Resolve(autoConfig())
	if err == nil {
		t.Fatal("expected an error when no firewall is installed")
	}
	for _, want := range []string{"install ufw", "firewalld", "--demo", "config.toml"} {
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
	name, err := Resolve(config.Config{
		Values: map[string]string{KeyBackend: BackendFirewalld},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if name != BackendFirewalld {
		t.Errorf("Resolve = %q, want firewalld", name)
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
	if len(states) != 2 {
		t.Fatalf("Inspect returned %d states, want 2", len(states))
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
	}

	Inspect(BackendFirewalld)
	if asked {
		t.Error("an absent backend must not be probed for its service state")
	}
}
