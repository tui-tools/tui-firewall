package iptables

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/tui-tools/tui-kit/runner"
)

// sbinPaths returns the sbin locations a non-root PATH commonly omits, for one
// binary.
func sbinPaths(bin string) []string {
	return []string{"/usr/sbin/" + bin, "/sbin/" + bin, "/usr/local/sbin/" + bin}
}

// Available reports whether iptables and iptables-save are installed.
func Available() bool {
	return runner.Available("iptables", sbinPaths("iptables")...) &&
		runner.Available("iptables-save", sbinPaths("iptables-save")...)
}

// fileExists reports whether a path exists. It is a variable so tests can
// answer for a machine they are not running on.
var fileExists = func(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// unitEnabled asks systemd whether a unit starts at boot. It is a variable so
// tests can answer for a machine they are not running on. Anything that is not
// an explicit refusal counts, the same reading the backend selector uses:
// Ubuntu answers "alias" for iptables.service, which netfilter-persistent
// provides.
var unitEnabled = func(unit string) bool {
	bin, err := exec.LookPath("systemctl")
	if err != nil {
		return false
	}
	out, _ := exec.Command(bin, "is-enabled", unit).Output() //nolint:gosec // fixed verb, unit names are package constants
	switch strings.TrimSpace(string(out)) {
	case "", "disabled", "masked", "masked-runtime", "not-found", "bad":
		return false
	default:
		return true
	}
}

// unitActive asks systemd whether a unit is running (for a oneshot loader
// like netfilter-persistent: whether it ran and stayed "active (exited)").
var unitActive = func(unit string) bool {
	bin, err := exec.LookPath("systemctl")
	if err != nil {
		return false
	}
	out, err := exec.Command(bin, "is-active", unit).Output() //nolint:gosec // fixed verb, unit names are package constants
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

// DetectLayout finds the persistence layer installed on this machine, if any:
// netfilter-persistent first (Debian, Ubuntu), then iptables-services (Fedora,
// RHEL). The Kind is empty when neither is installed.
func DetectLayout() Layout {
	if runner.Available("netfilter-persistent", sbinPaths("netfilter-persistent")...) {
		layout := netfilterPersistentLayout
		layout.Enabled = unitEnabled("netfilter-persistent")
		return layout
	}
	if fileExists("/usr/libexec/iptables/iptables.init") {
		layout := iptablesServicesLayout
		layout.Enabled = unitEnabled("iptables")
		return layout
	}
	return Layout{}
}

// Unit is the systemd unit that restores a layout's files at boot.
func (l Layout) Unit() string {
	switch l.Kind {
	case LayoutNetfilterPersistent:
		return "netfilter-persistent"
	case LayoutIptablesServices:
		return "iptables"
	default:
		return ""
	}
}

// PersistenceActive reports whether the layout's loader ran on this boot.
func (l Layout) PersistenceActive() bool {
	if unit := l.Unit(); unit != "" {
		return unitActive(unit)
	}
	return false
}

// Variant reads which kernel interface the iptables on the PATH drives,
// "nf_tables" or "legacy", from `iptables --version`, which needs no
// privilege. It is empty when iptables is missing or says neither.
func Variant() string {
	r, err := runner.New(runner.Options{
		Bin:             "iptables",
		SearchPaths:     sbinPaths("iptables"),
		Timeout:         5 * time.Second,
		PrivilegedReads: new(bool),
	})
	if err != nil {
		return ""
	}
	out, err := r.Read(context.Background(), "iptables", "--version")
	if err != nil {
		return ""
	}
	switch {
	case strings.Contains(out, "nf_tables"):
		return "nf_tables"
	case strings.Contains(out, "legacy"):
		return "legacy"
	default:
		// iptables before 1.8 had only the legacy interface and did not say.
		return "legacy"
	}
}

// LegacyFiltering reads the legacy xtables filter table and reports whether it
// carries rules of the operator's own — the case the nft ruleset cannot show,
// because legacy tables live outside nf_tables. It is only asked on a machine
// whose iptables is the legacy variant.
func LegacyFiltering(sudoPrefix []string) (int, bool) {
	r, err := runner.New(runner.Options{
		Bin:         "iptables-save",
		SearchPaths: sbinPaths("iptables-save"),
		SudoPrefix:  sudoPrefix,
		Timeout:     5 * time.Second,
	})
	if err != nil {
		return 0, false
	}
	out, err := r.Read(context.Background(), "iptables-save", "-t", TableFilter)
	if err != nil {
		return 0, false
	}
	dump, err := ParseSave(V4, out)
	if err != nil {
		return 0, false
	}
	rules, drops := OwnFilterRules(dump)
	return rules, rules > 0 || drops
}
