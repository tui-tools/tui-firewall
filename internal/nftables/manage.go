package nftables

import "strings"

// OwnTable is the table the router profile provisions and the only table this
// backend creates. Everything outside it is read freely and written to only
// under the conditions checkMutable spells out.
var OwnTable = TableID{Family: "inet", Name: "tui"}

// The names of the tools whose ruleset this backend recognises but does not
// drive.
const (
	ManagerFirewalld = "firewalld"
	ManagerUFW       = "ufw"
)

// Management is what the ruleset says about who else is writing to it.
type Management struct {
	// Manager is "firewalld", "ufw" or empty when nothing recognisable owns
	// the ruleset.
	Manager string `json:"manager,omitempty"`
	// Tables lists the tables that belong to that manager.
	Tables []TableID `json:"tables,omitempty"`
	// Detail is the sentence the selection and --check print.
	Detail string `json:"detail,omitempty"`
}

// Managed reports whether another tool owns this ruleset.
func (m Management) Managed() bool { return m.Manager != "" }

// Owns reports whether the given table belongs to the manager.
func (m Management) Owns(id TableID) bool {
	for _, t := range m.Tables {
		if t == id {
			return true
		}
	}
	return false
}

// DetectManagement reports whether ufw or firewalld is the thing writing this
// ruleset.
//
// It reads the ruleset rather than the machine on purpose. Whether firewalld
// is installed says nothing about whether it is the firewall in charge here;
// whether its tables are loaded says exactly that, and it is the same fact on
// a machine where the service is stopped but the rules are still in place.
//
// firewalld names its table after itself. ufw does not use nft directly — it
// drives iptables, which on any current distribution is iptables-nft — so
// what it leaves in the ruleset is the legacy filter table carrying the chain
// names ufw generates.
func DetectManagement(rs Ruleset) Management {
	var firewalldTables, ufwTables []TableID
	for _, t := range rs.Tables {
		switch {
		case t.Name == ManagerFirewalld:
			firewalldTables = append(firewalldTables, t.TableID)
		case hasUFWChains(t):
			ufwTables = append(ufwTables, t.TableID)
		}
	}

	switch {
	case len(firewalldTables) > 0:
		return Management{
			Manager: ManagerFirewalld,
			Tables:  firewalldTables,
			Detail: "the ruleset carries " + describeTables(firewalldTables) +
				", so firewalld is the firewall in charge of this machine",
		}
	case len(ufwTables) > 0:
		return Management{
			Manager: ManagerUFW,
			Tables:  ufwTables,
			Detail: "the ruleset carries ufw's own chains in " +
				describeTables(ufwTables) +
				", so ufw is the firewall in charge of this machine",
		}
	default:
		return Management{}
	}
}

// hasUFWChains reports whether a table carries the chains ufw generates.
func hasUFWChains(t Table) bool {
	for _, c := range t.Chains {
		if strings.HasPrefix(c.Name, "ufw-") || strings.HasPrefix(c.Name, "ufw6-") {
			return true
		}
	}
	return false
}

// describeTables renders a table list as prose.
func describeTables(ids []TableID) string {
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		names = append(names, "table "+id.String())
	}
	switch len(names) {
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	default:
		return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
}
