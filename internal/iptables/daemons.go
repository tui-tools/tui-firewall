package iptables

import "github.com/tui-tools/tui-firewall/internal/firewall"

// DaemonOf names the daemon that owns a chain, or "" for a chain nobody else
// claims. A rule in one of these chains is not the operator's to edit here,
// and a difference between the running rules and the saved file that is only
// about them is not drift the operator caused: docker and tailscaled rebuild
// them at start whatever the file says.
func DaemonOf(chain string) string { return firewall.ChainDaemon(chain) }

// daemonRule reports whether a rule belongs to another daemon: it lives in a
// daemon's chain, or it is the hook a daemon put in a built-in chain to reach
// one ("-A INPUT -j ts-input", "-A FORWARD -j DOCKER-USER").
func daemonRule(rule Rule) bool {
	return DaemonOf(rule.Chain) != "" || DaemonOf(rule.Match.Target) != ""
}

// OwnFilterRules counts the rules of the built-in filter chains that belong
// to the operator rather than to another daemon, and reports whether INPUT
// drops by default. Together they say whether these tables are this machine's
// firewall or only docker's plumbing.
func OwnFilterRules(d Dump) (rules int, inputDrops bool) {
	table, ok := d.Table(TableFilter)
	if !ok {
		return 0, false
	}
	for _, chain := range table.Chains {
		if !isFilterBuiltin(chain.Name) {
			continue
		}
		if chain.Name == ChainInput && chain.Policy == TargetDrop {
			inputDrops = true
		}
		for _, rule := range chain.Rules {
			if !daemonRule(rule) {
				rules++
			}
		}
	}
	return rules, inputDrops
}
