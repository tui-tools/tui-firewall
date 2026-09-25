package iptables

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// The persistence layers this backend knows. Each restores the saved rules at
// boot; what differs is where the files live and what writes them.
const (
	// LayoutNetfilterPersistent is Debian and Ubuntu's iptables-persistent:
	// netfilter-persistent restores /etc/iptables/rules.v4 and rules.v6 at
	// boot, and `netfilter-persistent save` writes them.
	LayoutNetfilterPersistent = "netfilter-persistent"
	// LayoutIptablesServices is Fedora and RHEL's iptables-services: the
	// iptables and ip6tables units restore /etc/sysconfig/iptables and
	// ip6tables, and `service iptables save` writes them.
	LayoutIptablesServices = "iptables-services"
)

// Layout is one persistence layer: its name, the files it restores, and
// whether systemd starts it at boot.
type Layout struct {
	Kind   string `json:"kind"`
	V4Path string `json:"v4Path"`
	V6Path string `json:"v6Path"`
	// Enabled reports whether the unit that restores the files is enabled.
	Enabled bool `json:"enabled"`
}

// Layouts are the two layers, with their conventional paths.
var (
	netfilterPersistentLayout = Layout{
		Kind:   LayoutNetfilterPersistent,
		V4Path: "/etc/iptables/rules.v4",
		V6Path: "/etc/iptables/rules.v6",
	}
	iptablesServicesLayout = Layout{
		Kind:   LayoutIptablesServices,
		V4Path: "/etc/sysconfig/iptables",
		V6Path: "/etc/sysconfig/ip6tables",
	}
)

// Persistence is what the persistence layer would restore at boot, compared
// with what is running.
type Persistence struct {
	// Layout is the layer found on this machine; its Kind is empty when there
	// is none, which means the running rules are gone at the next reboot.
	Layout Layout `json:"layout"`
	// SavedV4 and SavedV6 are the saved files, decoded; nil when the file does
	// not exist.
	SavedV4 *Dump `json:"-"`
	SavedV6 *Dump `json:"-"`
	// ReadErr says why a saved file could not be read or parsed, which makes
	// the drift below unknown rather than zero.
	ReadErr string `json:"readError,omitempty"`
	// Drift compares the running filter rules with the saved ones.
	Drift Drift `json:"drift"`
}

// Found reports whether this machine restores iptables rules at boot at all.
func (p Persistence) Found() bool { return p.Layout.Kind != "" }

// Drift is the difference between the running filter rules and the saved
// ones, for one or both families.
type Drift struct {
	// Known is false when there is no saved file to compare with, or it
	// could not be read.
	Known bool `json:"known"`
	// InSync reports that the running filter rules are exactly the saved ones,
	// ignoring the chains other daemons rebuild when they start.
	InSync bool `json:"inSync"`
	// RuntimeOnly and SavedOnly list the dump lines present on one side and
	// not the other; Reordered names chains whose rules are the same but in a
	// different order, which for a firewall is a different ruleset.
	RuntimeOnly []string `json:"runtimeOnly,omitempty"`
	SavedOnly   []string `json:"savedOnly,omitempty"`
	Reordered   []string `json:"reordered,omitempty"`
}

// Summary is the one-line form of the drift the header and the status line
// show.
func (d Drift) Summary() string {
	switch {
	case !d.Known:
		return "unknown"
	case d.InSync:
		return "in sync"
	}
	var parts []string
	if n := len(d.RuntimeOnly); n > 0 {
		parts = append(parts, plural(n, "line")+" not saved")
	}
	if n := len(d.SavedOnly); n > 0 {
		parts = append(parts, plural(n, "saved line")+" not running")
	}
	if n := len(d.Reordered); n > 0 {
		parts = append(parts, "order differs in "+strings.Join(d.Reordered, ", "))
	}
	return strings.Join(parts, ", ")
}

// ComputeDrift compares the filter table of the running dumps with the saved
// ones. Only the filter table is compared, because it is the only one this
// backend writes; and the chains of other daemons are left out, because
// docker and tailscaled rebuild them at start and their differences are not
// the operator's doing.
func ComputeDrift(state State) Drift {
	p := state.Persistence
	if !p.Found() || p.ReadErr != "" || p.SavedV4 == nil {
		return Drift{}
	}
	drift := Drift{Known: true}
	pairs := []struct {
		family  Family
		running Dump
		saved   *Dump
	}{{V4, state.V4, p.SavedV4}}
	if state.HasV6 {
		pairs = append(pairs, struct {
			family  Family
			running Dump
			saved   *Dump
		}{V6, state.V6, p.SavedV6})
	}
	for _, pair := range pairs {
		saved := Dump{Family: pair.family}
		if pair.saved != nil {
			saved = *pair.saved
		}
		compareFilter(&drift, pair.family, pair.running, saved)
	}
	drift.InSync = len(drift.RuntimeOnly) == 0 && len(drift.SavedOnly) == 0 &&
		len(drift.Reordered) == 0
	return drift
}

// compareFilter adds one family's differences to the drift.
func compareFilter(drift *Drift, family Family, running, saved Dump) {
	run := filterLines(running)
	sav := filterLines(saved)
	prefix := family.Binary() + ": "
	onlyRun, onlySav := multisetDiff(run.all, sav.all)
	for _, l := range onlyRun {
		drift.RuntimeOnly = append(drift.RuntimeOnly, prefix+l)
	}
	for _, l := range onlySav {
		drift.SavedOnly = append(drift.SavedOnly, prefix+l)
	}
	if len(onlyRun) > 0 || len(onlySav) > 0 {
		return
	}
	// Same lines: the order inside each chain still decides what matches.
	for _, name := range sortedKeys(run.byChain) {
		if strings.Join(run.byChain[name], "\n") != strings.Join(sav.byChain[name], "\n") {
			drift.Reordered = append(drift.Reordered, prefix+name)
		}
	}
}

// lineSet is the comparable form of a filter table: every line, and the rule
// lines grouped by chain in order.
type lineSet struct {
	all     []string
	byChain map[string][]string
}

// filterLines renders the filter table as comparable lines: the built-in
// policies, the user chains, and every rule, leaving out what belongs to
// another daemon.
func filterLines(d Dump) lineSet {
	set := lineSet{byChain: map[string][]string{}}
	table, ok := d.Table(TableFilter)
	if !ok {
		// An absent filter table is the kernel's default: three empty chains
		// with policy ACCEPT, which is what a saved file would say.
		table = Table{Name: TableFilter, Chains: []Chain{
			{Name: ChainInput, Policy: TargetAccept},
			{Name: ChainForward, Policy: TargetAccept},
			{Name: ChainOutput, Policy: TargetAccept},
		}}
	}
	for _, chain := range table.Chains {
		if DaemonOf(chain.Name) != "" {
			continue
		}
		policy := chain.Policy
		if policy == "" {
			policy = "-"
		}
		set.all = append(set.all, ":"+chain.Name+" "+policy)
		for _, rule := range chain.Rules {
			if daemonRule(rule) {
				continue
			}
			set.all = append(set.all, rule.Line())
			set.byChain[chain.Name] = append(set.byChain[chain.Name], rule.Line())
		}
	}
	return set
}

// multisetDiff returns the lines only in a and only in b, counting
// duplicates.
func multisetDiff(a, b []string) (onlyA, onlyB []string) {
	count := map[string]int{}
	for _, l := range b {
		count[l]++
	}
	for _, l := range a {
		if count[l] > 0 {
			count[l]--
			continue
		}
		onlyA = append(onlyA, l)
	}
	count = map[string]int{}
	for _, l := range a {
		count[l]++
	}
	for _, l := range b {
		if count[l] > 0 {
			count[l]--
			continue
		}
		onlyB = append(onlyB, l)
	}
	return onlyA, onlyB
}

// sortedKeys returns a map's keys in order, for stable output.
func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Comparable renders a dump the way the persist preview diffs it: the tables
// and their lines without the generated-by comments and counters, which
// differ on every save and say nothing about the rules.
func Comparable(d Dump) string {
	var b strings.Builder
	for _, table := range d.Tables {
		b.WriteString("*" + table.Name + "\n")
		for _, chain := range table.Chains {
			policy := chain.Policy
			if policy == "" {
				policy = "-"
			}
			b.WriteString(":" + chain.Name + " " + policy + "\n")
		}
		for _, chain := range table.Chains {
			for _, rule := range chain.Rules {
				b.WriteString(rule.Line() + "\n")
			}
		}
		b.WriteString("COMMIT\n")
	}
	return b.String()
}

// Render renders a dump as a loadable iptables-restore file, without
// counters. The fake uses it for what iptables-save would print.
func Render(d Dump, header string) string {
	var b strings.Builder
	if header != "" {
		b.WriteString("# " + header + "\n")
	}
	b.WriteString(Comparable(d))
	return b.String()
}

// BuildPersist is the change that writes the running rules to the files the
// persistence layer restores at boot.
func BuildPersist(state State) (firewall.Change, error) {
	p := state.Persistence
	switch p.Layout.Kind {
	case LayoutNetfilterPersistent:
		note := fmt.Sprintf("netfilter-persistent runs its plugins, which write "+
			"iptables-save into %s and ip6tables-save into %s; it restores both "+
			"at boot", p.Layout.V4Path, p.Layout.V6Path)
		if !p.Layout.Enabled {
			note += "; the netfilter-persistent unit is not enabled, so nothing " +
				"restores them yet: systemctl enable netfilter-persistent"
		}
		note += daemonNote(state)
		return firewall.Change{
			Description: "Persist the running rules (netfilter-persistent)",
			Note:        note,
			Commands: []firewall.Command{{
				Argv:        []string{"netfilter-persistent", "save"},
				Description: "Save the running iptables and ip6tables rules",
			}},
		}, nil
	case LayoutIptablesServices:
		note := fmt.Sprintf("the iptables-services scripts write iptables-save "+
			"into %s and ip6tables-save into %s; the iptables and ip6tables units "+
			"restore them at boot", p.Layout.V4Path, p.Layout.V6Path)
		if !p.Layout.Enabled {
			note += "; the iptables unit is not enabled, so nothing restores them " +
				"yet: systemctl enable iptables ip6tables"
		}
		note += daemonNote(state)
		commands := []firewall.Command{{
			Argv:        []string{"service", "iptables", "save"},
			Description: "Save the running iptables rules",
		}}
		if state.HasV6 {
			commands = append(commands, firewall.Command{
				Argv:        []string{"service", "ip6tables", "save"},
				Description: "Save the running ip6tables rules",
			})
		}
		return firewall.Change{
			Description: "Persist the running rules (iptables-services)",
			Note:        note,
			Commands:    commands,
		}, nil
	default:
		return firewall.Change{}, errorf("nothing on this machine restores " +
			"iptables rules at boot, so there is nowhere to persist them: install " +
			"iptables-persistent (apt) or iptables-services (dnf)")
	}
}

// daemonNote warns when the save carries chains another daemon rebuilds at
// start, which is harmless but worth knowing: the file then holds a copy the
// daemon will replace.
func daemonNote(state State) string {
	seen := map[string]bool{}
	var daemons []string
	for _, family := range []Family{V4, V6} {
		for _, table := range state.Dump(family).Tables {
			for _, chain := range table.Chains {
				if d := DaemonOf(chain.Name); d != "" && !seen[d] {
					seen[d] = true
					daemons = append(daemons, d)
				}
			}
		}
	}
	if len(daemons) == 0 {
		return ""
	}
	sort.Strings(daemons)
	verb := "rebuilds"
	if len(daemons) > 1 {
		verb = "rebuild"
	}
	return "; the save also copies the chains " + strings.Join(daemons, " and ") +
		" " + verb + " when started, which is how these tools always save"
}
