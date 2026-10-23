package ufw

import (
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// ExtraHalf is the Rule.Extra key ufw sets on each half of a rule that exists
// once for IPv4 and once for IPv6. `ufw allow 8080/tcp` creates two entries,
// and `ufw status numbered` lists and deletes them separately, so the two look
// identical apart from the "(v6)" tag; the value ("v4" or "v6") says which
// half a row is, so the delete dialog can name it.
const ExtraHalf = "half"

// The ExtraHalf values.
const (
	HalfIPv4 = "v4"
	HalfIPv6 = "v6"
)

// markHalves sets ExtraHalf on every rule whose twin in the other family is
// also listed. Twins are matched on everything ufw prints except the "(v6)"
// tag. The rules are copied, Extra maps included, so a caller's slice is
// never changed.
func markHalves(rules []firewall.Rule) []firewall.Rule {
	out := make([]firewall.Rule, len(rules))
	v6 := map[string]bool{}
	for _, r := range rules {
		if r.Family == firewall.FamilyIPv6 {
			v6[halfKey(r)] = true
		}
	}
	v4 := map[string]bool{}
	for _, r := range rules {
		if r.Family != firewall.FamilyIPv6 && v6[halfKey(r)] {
			v4[halfKey(r)] = true
		}
	}
	for i, r := range rules {
		out[i] = r
		half := ""
		switch {
		case r.Family == firewall.FamilyIPv6 && v4[halfKey(r)]:
			half = HalfIPv6
		case r.Family != firewall.FamilyIPv6 && v4[halfKey(r)]:
			half = HalfIPv4
		}
		if half == "" {
			continue
		}
		extra := make(map[string]string, len(r.Extra)+1)
		for k, v := range r.Extra {
			extra[k] = v
		}
		extra[ExtraHalf] = half
		out[i].Extra = extra
	}
	return out
}

// halfKey identifies a rule regardless of its address family.
func halfKey(r firewall.Rule) string {
	return strings.Join([]string{
		string(r.Action), string(r.Direction), r.To, r.From, r.Comment,
	}, "\x00")
}
