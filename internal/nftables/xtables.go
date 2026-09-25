package nftables

import (
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// ManagerIptables names the xtables tools — iptables-nft, and whatever
// restores their saved rules at boot — as the writer of a table.
const ManagerIptables = "iptables"

// xtablesTableNames are the tables iptables knows by name, and xtablesChains
// the built-in chains it creates in them. iptables-nft writes exactly these
// into the ip and ip6 families; nft's own conventions spell a chain in lower
// case ("input"), which is what makes the upper-case set a signature.
var (
	xtablesTableNames = map[string]bool{
		"filter": true, "nat": true, "mangle": true, "raw": true, "security": true,
	}
	xtablesChains = map[string]bool{
		"INPUT": true, "FORWARD": true, "OUTPUT": true,
		"PREROUTING": true, "POSTROUTING": true,
	}
	xtablesFamilies = map[string]bool{
		"ip": true, "ip6": true, "arp": true, "bridge": true,
	}
)

// IsXtables reports whether a table is one the xtables tools own: an iptables
// table name in an iptables family, whose rules carry xtables expressions or
// whose base chains carry iptables' upper-case names.
//
// Such a table must not get a native nft rule. iptables-nft reads its tables
// back to print them, and a rule it did not write can make `iptables-save`
// refuse the whole table ("table ip filter is incompatible, use 'nft' tool")
// — which is also what netfilter-persistent runs to save — and whatever
// restores the saved rules at boot replaces the table without it anyway.
func IsXtables(t Table) bool {
	if !xtablesFamilies[t.Family] || !xtablesTableNames[t.Name] {
		return false
	}
	for _, c := range t.Chains {
		if c.Base() && xtablesChains[c.Name] {
			return true
		}
		for _, r := range c.Rules {
			if len(r.Match.Xtables) > 0 {
				return true
			}
		}
	}
	return false
}

// XtablesTables lists the tables of a ruleset the xtables tools own.
func XtablesTables(rs Ruleset) []TableID {
	var ids []TableID
	for _, t := range rs.Tables {
		if IsXtables(t) {
			ids = append(ids, t.TableID)
		}
	}
	return ids
}

// NativeTables lists the tables that are nft's own: neither written by the
// xtables tools nor the tool's own table. On a machine where iptables is in
// charge, these are the rules the iptables backend cannot show.
func NativeTables(rs Ruleset) []TableID {
	var ids []TableID
	for _, t := range rs.Tables {
		if !IsXtables(t) {
			ids = append(ids, t.TableID)
		}
	}
	return ids
}

// xtablesFiltering counts the rules of the xtables filter tables that belong
// to the operator — the ones in a hooked chain that are not another daemon's
// hook — and reports whether an input chain drops by default. Docker alone
// fills table ip filter on a machine whose firewall is somewhere else; these
// two facts are what separate that from a machine whose firewall is iptables.
func xtablesFiltering(rs Ruleset) (rules int, inputDrops bool, tables []TableID) {
	for _, t := range rs.Tables {
		if t.Name != "filter" || !IsXtables(t) {
			continue
		}
		counted := false
		for _, c := range t.Chains {
			if !c.Base() {
				continue
			}
			if c.Hook == "input" && c.Policy == PolicyDrop {
				inputDrops = true
				counted = true
			}
			for _, r := range c.Rules {
				if daemonHook(r) {
					continue
				}
				rules++
				counted = true
			}
		}
		if counted {
			tables = append(tables, t.TableID)
		}
	}
	return rules, inputDrops, tables
}

// daemonHook reports whether a rule is another daemon's jump into its own
// chain ("jump DOCKER-USER", "jump ts-input").
func daemonHook(r Rule) bool {
	target, ok := strings.CutPrefix(r.Match.Verdict, "jump ")
	if !ok {
		target, ok = strings.CutPrefix(r.Match.Verdict, "goto ")
	}
	return ok && firewall.ChainDaemon(target) != ""
}

// detectXtablesManagement reports iptables as the firewall in charge when the
// xtables filter tables carry rules of the operator's own.
func detectXtablesManagement(rs Ruleset) Management {
	rules, drops, filters := xtablesFiltering(rs)
	if rules == 0 && !drops {
		return Management{}
	}
	detail := "the ruleset's " + describeTables(filters) + " " +
		map[bool]string{true: "is", false: "are"}[len(filters) == 1] +
		" written by iptables-nft"
	if rules > 0 {
		detail += " and carr" + map[bool]string{true: "ies", false: "y"}[len(filters) == 1] +
			" " + plural(rules, "rule") + " of the operator's own"
	} else {
		detail += " and drop" + map[bool]string{true: "s", false: ""}[len(filters) == 1] +
			" incoming traffic by default"
	}
	detail += ", so iptables is the firewall in charge of this machine"
	return Management{
		Manager: ManagerIptables,
		Tables:  XtablesTables(rs),
		Detail:  detail,
	}
}

// xtablesRefusal is the reason a chain of an xtables table is not written to.
func xtablesRefusal(table TableID) error {
	return errorf("table %s is written by iptables-nft (upper-case chains, "+
		"xtables matches): a native nft rule there can make iptables-save refuse "+
		"the table, breaking netfilter-persistent save, and is lost when the saved "+
		"iptables rules are restored at boot; manage it with the iptables backend "+
		"(tui-firewall --backend iptables)", table)
}
