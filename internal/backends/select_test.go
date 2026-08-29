package backends

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-kit/config"
)

// stubProbes replaces the host detectors for the duration of a test.
func stubProbes(t *testing.T, ufwInstalled, ufwActive, fwdInstalled, fwdActive bool) {
	t.Helper()
	original := probes
	t.Cleanup(func() { probes = original })
	probes = map[string]Probe{
		BackendUFW: {
			Installed: func() bool { return ufwInstalled },
			Active:    func() bool { return ufwActive },
		},
		BackendFirewalld: {
			Installed: func() bool { return fwdInstalled },
			Active:    func() bool { return fwdActive },
		},
	}
}

func TestSelectAutoPrefersTheActiveBackend(t *testing.T) {
	// firewalld installed and running, ufw installed but stopped: the running
	// one wins even though ufw comes first in the preference order.
	stubProbes(t, true, false, true, true)

	backend, err := Select(config.Config{Values: map[string]string{KeyBackend: BackendAuto}})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if backend.Name() != BackendFirewalld {
		t.Errorf("Name = %q, want firewalld", backend.Name())
	}
}

func TestSelectAutoFallsBackToInstalled(t *testing.T) {
	// Nothing is running: the first installed backend is used so the user can
	// look at it and enable it.
	stubProbes(t, false, false, true, false)

	backend, err := Select(config.Config{Values: map[string]string{KeyBackend: BackendAuto}})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if backend.Name() != BackendFirewalld {
		t.Errorf("Name = %q, want firewalld", backend.Name())
	}
}

func TestSelectAutoWithoutAnyFirewall(t *testing.T) {
	stubProbes(t, false, false, false, false)

	_, err := Select(config.Config{Values: map[string]string{KeyBackend: BackendAuto}})
	if err == nil {
		t.Fatal("expected an error when no firewall is installed")
	}
	for _, want := range []string{"install ufw", "--demo", "config.toml"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

func TestSelectExplicitFirewalld(t *testing.T) {
	stubProbes(t, true, true, false, false)

	// An explicit choice is honoured even when the backend is not installed:
	// the stub reports its own clear error on first use.
	backend, err := Select(config.Config{Values: map[string]string{KeyBackend: BackendFirewalld}})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if backend.Name() != BackendFirewalld {
		t.Errorf("Name = %q, want firewalld", backend.Name())
	}
	if _, err := backend.BuildReload(); err == nil {
		t.Error("the firewalld stub should report that it is not implemented")
	}
}

func TestSelectUnknownBackend(t *testing.T) {
	if _, err := Select(config.Config{Values: map[string]string{KeyBackend: "iptables"}}); err == nil {
		t.Error("expected an error for an unknown backend")
	}
}
