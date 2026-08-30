// Package backends selects the firewall implementation to drive, from the
// configuration and from what the host actually has installed and running.
package backends

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/firewalld"
	"github.com/tui-tools/tui-firewall/internal/ufw"
	"github.com/tui-tools/tui-kit/config"
)

// KeyBackend is the configuration key naming the firewall to drive. It lives
// here rather than in the kit: which backends exist is tui-firewall's own
// business, not something every tool in the family shares.
const KeyBackend = "backend"

// The values KeyBackend accepts.
const (
	BackendAuto      = "auto"
	BackendUFW       = "ufw"
	BackendFirewalld = "firewalld"
)

// Names lists every accepted value, for config validation and the flag help.
func Names() []string { return []string{BackendAuto, BackendUFW, BackendFirewalld} }

// Probe reports what a candidate backend looks like on this host. It is a
// field so tests can substitute a fake detector.
type Probe struct {
	// Installed reports whether the backend's binary exists.
	Installed func() bool
	// Active reports whether its system service is running.
	Active func() bool
	// Enabled reports whether its system service is set to start at boot.
	// It breaks the tie when both firewalls are installed and neither is
	// running: the one the machine is configured to use is the one to show.
	Enabled func() bool
}

// State is what the detector found about one backend, for `--check` to report
// and for the "no firewall here" message to explain itself with.
type State struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Active    bool   `json:"active"`
	Enabled   bool   `json:"enabled"`
	// Selected marks the backend the tool is actually driving.
	Selected bool `json:"selected"`
}

// Inspect probes every known backend, without building any of them. `--check`
// uses it to report the backend it did not pick as present-but-inactive rather
// than leaving the reader to guess why it chose the other one.
func Inspect(selected string) []State {
	states := make([]State, 0, len(preference))
	for _, name := range preference {
		probe := probes[name]
		state := State{Name: name, Selected: name == selected}
		if state.Installed = probe.Installed(); state.Installed {
			state.Active = probe.Active()
			state.Enabled = probe.Enabled()
		}
		states = append(states, state)
	}
	return states
}

// probes maps a backend name to its detector. Package-level so tests can
// replace entries.
var probes = map[string]Probe{
	BackendUFW: {
		Installed: ufw.Available,
		Active:    func() bool { return unitIs("is-active", "ufw") },
		Enabled:   func() bool { return unitIs("is-enabled", "ufw") },
	},
	BackendFirewalld: {
		Installed: firewalld.Available,
		Active:    func() bool { return unitIs("is-active", "firewalld") },
		Enabled:   func() bool { return unitIs("is-enabled", "firewalld") },
	},
}

// preference is the order `auto` considers backends when none is active.
var preference = []string{BackendUFW, BackendFirewalld}

// unitIs asks systemd about a unit: `is-active` for running, `is-enabled` for
// starting at boot. A host without systemd simply reports false, which only
// affects tie-breaking. `is-enabled` prints several affirmative words
// ("enabled", "enabled-runtime", "static"), so anything that is not an
// explicit "disabled" or "masked" counts as enabled.
func unitIs(verb, unit string) bool {
	bin, err := exec.LookPath("systemctl")
	if err != nil {
		return false
	}
	out, err := exec.Command(bin, verb, unit).Output() //nolint:gosec // fixed verbs and unit names
	answer := strings.TrimSpace(string(out))
	if verb == "is-active" {
		return err == nil && answer == "active"
	}
	switch answer {
	case "", "disabled", "masked", "masked-runtime", "not-found", "bad":
		return false
	default:
		return true
	}
}

// Select builds the backend named by cfg.Backend, and reports which one it
// picked so the caller can probe its version and describe the others.
//
// With "auto" the order is: the installed backend whose service is running;
// failing that, the installed one systemd would start at boot; failing that,
// the first installed one. Two firewalls on one machine is a misconfiguration
// rather than a supported setup, so the tie-break exists to be predictable
// and explainable, not to be clever about it.
func Select(cfg config.Config) (firewall.Backend, error) {
	name, err := Resolve(cfg)
	if err != nil {
		return nil, err
	}
	return build(name, cfg)
}

// Resolve names the backend Select will build, without building it. It is
// separate because deciding *which* firewall this machine runs and reaching
// for its binary are two different questions, and only the first one can be
// answered — or tested — on a machine that has neither.
func Resolve(cfg config.Config) (string, error) {
	switch name := cfg.String(KeyBackend, BackendAuto); name {
	case BackendUFW, BackendFirewalld:
		return name, nil
	case BackendAuto:
		return resolveAuto()
	default:
		return "", fmt.Errorf("unknown backend %q", name)
	}
}

// resolveAuto implements the detection described on Select.
func resolveAuto() (string, error) {
	var installed, enabled []string
	for _, name := range preference {
		probe := probes[name]
		if !probe.Installed() {
			continue
		}
		installed = append(installed, name)
		if probe.Active() {
			return name, nil
		}
		if probe.Enabled() {
			enabled = append(enabled, name)
		}
	}
	if len(enabled) > 0 {
		// Nothing is running, but systemd would start this one at boot: it is
		// the firewall this machine is configured to use.
		return enabled[0], nil
	}
	if len(installed) > 0 {
		// Nothing is running or enabled: fall back to the first installed
		// backend so the user can at least inspect it.
		return installed[0], nil
	}
	return "", fmt.Errorf(
		"no supported firewall found; install ufw " +
			"(apt install ufw / pacman -S ufw) or firewalld " +
			"(dnf install firewalld), pick one with `backend = \"...\"` " +
			"in ~/.config/tui-firewall/config.toml, or run with --demo")
}

// build instantiates the named backend.
func build(name string, cfg config.Config) (firewall.Backend, error) {
	if name == BackendFirewalld {
		return firewalld.New(cfg.SudoPrefix())
	}
	return ufw.NewReal(cfg.SudoPrefix())
}
