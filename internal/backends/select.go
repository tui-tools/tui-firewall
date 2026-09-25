// Package backends selects the firewall implementation to drive, from the
// configuration and from what the host actually has installed and running.
package backends

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/firewalld"
	"github.com/tui-tools/tui-firewall/internal/iptables"
	"github.com/tui-tools/tui-firewall/internal/nftables"
	"github.com/tui-tools/tui-firewall/internal/ufw"
	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-kit/runner"
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
	BackendNftables  = "nftables"
	BackendIptables  = "iptables"
)

// Names lists every accepted value, for config validation and the flag help.
func Names() []string {
	return []string{BackendAuto, BackendUFW, BackendFirewalld, BackendIptables,
		BackendNftables}
}

// Selection is the backend that was chosen and the sentence explaining why.
// The reason is part of the answer rather than an afterthought: on a machine
// carrying more than one firewall, "why this one" is the question the user
// actually has, and --check and --report both print it.
type Selection struct {
	Name   string `json:"name"`
	Detail string `json:"detail"`
}

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
	BackendNftables: {
		Installed: nftables.Available,
		Active:    func() bool { return unitIs("is-active", "nftables") },
		Enabled:   func() bool { return unitIs("is-enabled", "nftables") },
	},
	// iptables is "running" when its persistence layer is: the unit that
	// restored the saved rules at boot (netfilter-persistent, or the iptables
	// unit of iptables-services). iptables itself is on nearly every machine —
	// ufw and docker both need it — so being installed says nothing, and only
	// a loader that restores its rules makes it the firewall in charge.
	BackendIptables: {
		Installed: iptables.Available,
		Active:    func() bool { return iptablesLayout().PersistenceActive() },
		Enabled:   func() bool { return iptablesLayout().Enabled },
	},
}

// iptablesLayout finds the iptables persistence layer. It is a variable so
// tests can answer for a machine they are not running on.
var iptablesLayout = iptables.DetectLayout

// readLegacy reports whether the legacy iptables tables carry rules of the
// operator's own. They live outside nf_tables, so the nft ruleset cannot show
// them; it is asked only when iptables says it is the legacy variant. It is a
// variable so tests can answer for a host they are not running on.
var readLegacy = func(sudoPrefix []string) (int, bool) {
	if iptables.Variant() != "legacy" {
		return 0, false
	}
	return iptables.LegacyFiltering(sudoPrefix)
}

// preference is the order `auto` considers backends. nftables comes last on
// purpose: it is the backend for a machine nothing else is managing, and a
// machine that runs ufw or firewalld also has nft installed, because that is
// what those two write through. iptables comes after the two managers because
// both of them drive it underneath.
var preference = []string{BackendUFW, BackendFirewalld, BackendIptables, BackendNftables}

// managers are the backends that own a ruleset rather than editing it in
// place. Their presence in the ruleset is what makes nftables the wrong
// answer on a machine that has one.
var managers = []string{BackendUFW, BackendFirewalld, BackendIptables}

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

// readManagement reads the loaded ruleset and reports who is writing to it.
// It is a variable so tests can answer for a host they are not running on.
//
// The question it answers cannot be answered any other way. Whether firewalld
// is installed says nothing about whether it is the firewall in charge; what
// is loaded in the kernel says exactly that, and it is still the right answer
// on a machine where the service was stopped but its rules are still there.
var readManagement = func(sudoPrefix []string) (nftables.Management, bool) {
	ruleset, ok := readRuleset(sudoPrefix)
	if !ok {
		return nftables.Management{}, false
	}
	return nftables.DetectManagement(ruleset), true
}

// readRuleset reads and parses the loaded nft ruleset, bounded so a wedged nft
// cannot hold the terminal before the UI is on screen.
func readRuleset(sudoPrefix []string) (nftables.Ruleset, bool) {
	if !nftables.Available() {
		return nftables.Ruleset{}, false
	}
	run, err := runner.New(runner.Options{
		Bin:         "nft",
		SearchPaths: []string{"/usr/sbin/nft", "/sbin/nft"},
		SudoPrefix:  sudoPrefix,
		// Selection happens before the UI is on screen; a machine whose nft
		// is wedged must not hold the terminal for the runner's full default.
		Timeout: 5 * time.Second,
	})
	if err != nil {
		return nftables.Ruleset{}, false
	}
	out, err := run.Read(context.Background(), "nft", "-j", "list", "ruleset")
	if err != nil {
		return nftables.Ruleset{}, false
	}
	ruleset, err := nftables.ParseRuleset([]byte(out))
	if err != nil {
		return nftables.Ruleset{}, false
	}
	return ruleset, true
}

// Select builds the backend named by cfg.Backend, and reports which one it
// picked so the caller can probe its version and describe the others.
func Select(cfg config.Config) (firewall.Backend, error) {
	selection, err := Resolve(cfg)
	if err != nil {
		return nil, err
	}
	return build(selection.Name, cfg)
}

// Resolve names the backend Select will build, without building it. It is
// separate because deciding *which* firewall this machine runs and reaching
// for its binary are two different questions, and only the first one can be
// answered — or tested — on a machine that has neither.
//
// With "auto" the order is: the manager whose service is running; failing
// that, whichever manager the loaded ruleset says is writing it; failing
// that, the manager systemd would start at boot; failing that, nftables on
// its own, which is the right answer precisely when nothing else claims the
// ruleset; and failing that, whichever manager is merely installed.
func Resolve(cfg config.Config) (Selection, error) {
	name := cfg.String(KeyBackend, BackendAuto)
	switch name {
	case BackendUFW, BackendFirewalld, BackendNftables, BackendIptables:
		return Selection{
			Name:   name,
			Detail: "chosen by configuration, not by detection",
		}, nil
	case BackendAuto:
		return resolveAuto(cfg.SudoPrefix())
	default:
		return Selection{}, fmt.Errorf("unknown backend %q", name)
	}
}

// resolveAuto implements the detection described on Resolve.
func resolveAuto(sudoPrefix []string) (Selection, error) {
	var installed, enabled []string
	for _, name := range managers {
		probe := probes[name]
		if !probe.Installed() {
			continue
		}
		installed = append(installed, name)
		if probe.Active() {
			return Selection{
				Name:   name,
				Detail: activeDetail(name, sudoPrefix),
			}, nil
		}
		if probe.Enabled() {
			enabled = append(enabled, name)
		}
	}

	// Nothing is running. The ruleset itself is the next-best witness, and
	// the only one that can tell a machine ufw merely has installed from one
	// ufw is actually filtering.
	nftInstalled := probes[BackendNftables].Installed()
	if nftInstalled {
		if management, ok := readManagement(sudoPrefix); ok && management.Managed() {
			if contains(installed, management.Manager) {
				detail := management.Detail
				if management.Manager == BackendIptables {
					detail += nativeTablesNote(sudoPrefix)
				}
				return Selection{Name: management.Manager, Detail: detail}, nil
			}
			// The tables are there and the tool that wrote them is not:
			// nftables can read them, and it will refuse to write to them.
			return Selection{
				Name: BackendNftables,
				Detail: management.Detail + ", but " + management.Manager +
					" is not installed here; nftables reads those tables " +
					"and does not write to them",
			}, nil
		}
	}

	// A legacy iptables keeps its tables outside nf_tables, where the ruleset
	// above cannot see them: ask it directly.
	if contains(installed, BackendIptables) {
		if rules, ok := readLegacy(sudoPrefix); ok {
			return Selection{
				Name: BackendIptables,
				Detail: fmt.Sprintf("the legacy iptables filter table carries %d "+
					"rule(s) of the operator's own, so iptables is the firewall "+
					"in charge of this machine", rules),
			}, nil
		}
	}

	if len(enabled) > 0 {
		detail := "nothing is running, and systemd would start " +
			enabled[0] + " at boot"
		if enabled[0] == BackendIptables {
			layout := iptablesLayout()
			detail = "nothing is running, and systemd would start " +
				layout.Unit() + " at boot, which restores " + layout.V4Path
		}
		return Selection{Name: enabled[0], Detail: detail}, nil
	}
	if nftInstalled {
		return Selection{
			Name: BackendNftables,
			Detail: "nft is installed and nothing in the ruleset is managed " +
				"by ufw or firewalld",
		}, nil
	}
	if len(installed) > 0 {
		return Selection{
			Name: installed[0],
			Detail: installed[0] + " is installed but neither running nor " +
				"enabled; showing it so it can be inspected",
		}, nil
	}
	return Selection{}, fmt.Errorf(
		"no supported firewall found; install nftables " +
			"(apt install nftables / dnf install nftables), ufw " +
			"(apt install ufw / pacman -S ufw), firewalld " +
			"(dnf install firewalld) or iptables-persistent " +
			"(apt install iptables-persistent), pick one with " +
			"`backend = \"...\"` in ~/.config/tui-firewall/config.toml, " +
			"or run with --demo")
}

// activeDetail is the sentence for a backend whose service is running. For
// iptables the service is the loader, and what it loads is what makes the
// sentence worth reading; when the nft ruleset also carries native tables the
// iptables backend cannot show, the sentence says so.
func activeDetail(name string, sudoPrefix []string) string {
	if name != BackendIptables {
		return "the " + name + " service is running on this machine"
	}
	layout := iptablesLayout()
	detail := layout.Unit() + " is enabled and restores " + layout.V4Path +
		" at boot, so iptables is the firewall in charge of this machine"
	if !layout.Enabled {
		detail = layout.Unit() + " restored " + layout.V4Path +
			" on this boot, so iptables is the firewall in charge of this machine"
	}
	return detail + nativeTablesNote(sudoPrefix)
}

// nativeTablesNote says when the nft ruleset also holds native tables beside
// the xtables ones: both filter packets, and the iptables backend shows only
// its own. It is empty when there are none, or nft is not there to ask.
func nativeTablesNote(sudoPrefix []string) string {
	native := readNativeTables(sudoPrefix)
	if len(native) == 0 {
		return ""
	}
	names := make([]string, 0, len(native))
	for _, id := range native {
		names = append(names, "table "+id.String())
	}
	return "; the nft ruleset also has " + strings.Join(names, ", ") +
		", which this backend does not show (--backend nftables reads it)"
}

// readNativeTables lists the native nft tables of the loaded ruleset. It is a
// variable so tests can answer for a host they are not running on.
var readNativeTables = func(sudoPrefix []string) []nftables.TableID {
	ruleset, ok := readRuleset(sudoPrefix)
	if !ok {
		return nil
	}
	return nftables.NativeTables(ruleset)
}

// contains reports whether a slice holds a value.
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// build instantiates the named backend.
func build(name string, cfg config.Config) (firewall.Backend, error) {
	switch name {
	case BackendFirewalld:
		return firewalld.New(cfg.SudoPrefix())
	case BackendNftables:
		return nftables.NewReal(cfg.SudoPrefix())
	case BackendIptables:
		return iptables.NewReal(cfg.SudoPrefix())
	default:
		return ufw.NewReal(cfg.SudoPrefix())
	}
}
