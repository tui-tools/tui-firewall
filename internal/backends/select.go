// Package backends selects the firewall implementation to drive, from the
// configuration and from what the host actually has installed and running.
package backends

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/edimarlnx/tui-tools/internal/config"
	"github.com/edimarlnx/tui-tools/internal/firewall"
	"github.com/edimarlnx/tui-tools/internal/firewalld"
	"github.com/edimarlnx/tui-tools/internal/ufw"
)

// Probe reports what a candidate backend looks like on this host. It is a
// field so tests can substitute a fake detector.
type Probe struct {
	// Installed reports whether the backend's binary exists.
	Installed func() bool
	// Active reports whether its system service is running.
	Active func() bool
}

// probes maps a backend name to its detector. Package-level so tests can
// replace entries.
var probes = map[string]Probe{
	config.BackendUFW: {
		Installed: ufw.Available,
		Active:    func() bool { return serviceActive("ufw") },
	},
	config.BackendFirewalld: {
		Installed: firewalld.Available,
		Active:    func() bool { return serviceActive("firewalld") },
	},
}

// preference is the order `auto` considers backends when none is active.
var preference = []string{config.BackendUFW, config.BackendFirewalld}

// serviceActive asks systemd whether a unit is running. A host without
// systemd simply reports false, which only affects tie-breaking.
func serviceActive(unit string) bool {
	bin, err := exec.LookPath("systemctl")
	if err != nil {
		return false
	}
	out, err := exec.Command(bin, "is-active", unit).Output() //nolint:gosec // fixed unit names
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}

// Select builds the backend named by cfg.Backend. With "auto" it prefers an
// installed backend whose service is active, then the first installed one, and
// fails with an actionable message when the host has neither.
func Select(cfg config.Config) (firewall.Backend, error) {
	switch cfg.Backend {
	case config.BackendUFW:
		return ufw.NewReal(cfg.SudoPrefix())
	case config.BackendFirewalld:
		return firewalld.New(), nil
	case config.BackendAuto:
		return selectAuto(cfg)
	default:
		return nil, fmt.Errorf("unknown backend %q", cfg.Backend)
	}
}

// selectAuto implements the detection described on Select.
func selectAuto(cfg config.Config) (firewall.Backend, error) {
	var installed []string
	for _, name := range preference {
		probe := probes[name]
		if !probe.Installed() {
			continue
		}
		installed = append(installed, name)
		if probe.Active() {
			return build(name, cfg)
		}
	}
	if len(installed) > 0 {
		// Nothing is running: fall back to the first installed backend so the
		// user can inspect and enable it.
		return build(installed[0], cfg)
	}
	return nil, fmt.Errorf(
		"no supported firewall found; install ufw " +
			"(apt install ufw / pacman -S ufw), pick one with `backend = \"...\"` " +
			"in ~/.config/fwall/config.toml, or run with --demo")
}

// build instantiates the named backend.
func build(name string, cfg config.Config) (firewall.Backend, error) {
	if name == config.BackendFirewalld {
		return firewalld.New(), nil
	}
	return ufw.NewReal(cfg.SudoPrefix())
}
