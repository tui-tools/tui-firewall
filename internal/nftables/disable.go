package nftables

import (
	"fmt"
	"strconv"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// BuildDisableRule takes a rule out of the live ruleset and returns, beside
// the command that does it, the spec entry that remembers it.
//
// nftables has no per-rule off switch: a rule is in the ruleset or it is not.
// So disabling is a delete plus a memory — the statement the rule was, and the
// position it sat at — and the memory is what the Save file carries in the
// comment block ParseSpec reads back. The delete alone would be a delete; it
// is the pair that makes it reversible.
//
// The statement is rebuilt from the rule's own modelled match by the same
// machinery a move uses, and the refusals are the ones an edit makes: a rule
// this package does not hold in full is refused here rather than deleted with
// a half-written note of how to put it back.
func (r Ruleset) BuildDisableRule(chain Chain, target Rule) (firewall.Change,
	DisabledRule, error) {
	if err := r.checkMutable(chain); err != nil {
		return firewall.Change{}, DisabledRule{}, err
	}
	if target.Handle <= 0 {
		return firewall.Change{}, DisabledRule{}, errorf(
			"this rule has no handle, so there is no safe way to name it to nft; " +
				"re-read the ruleset with R")
	}
	if err := checkRebuildable(target, "disable it"); err != nil {
		return firewall.Change{}, DisabledRule{}, err
	}
	if err := checkLogRoundTrip(target); err != nil {
		return firewall.Change{}, DisabledRule{}, err
	}

	// The position comes from where the handle sits right now, not from the
	// row's display index: the two agree unless the ruleset changed
	// underneath, and then the handle is the one that is true.
	position := -1
	for i, rule := range chain.Rules {
		if rule.Handle == target.Handle {
			position = i
			break
		}
	}
	if position < 0 {
		return firewall.Change{}, DisabledRule{}, errorf(
			"rule handle %d is no longer in chain %s; press R to re-read the "+
				"ruleset", target.Handle, chain.Name)
	}

	// The rule keeps its expression exactly as it stands, its own log prefix
	// included: disabling changes whether the rule is there, nothing about
	// what it does when it is.
	expr, err := rebuildRuleExpr(chain, target, target.Match.Log,
		target.Match.LogPrefix)
	if err != nil {
		return firewall.Change{}, DisabledRule{}, err
	}

	stored := target
	stored.Table = chain.Table
	stored.Chain = chain.Name
	// The display index is the live chain's numbering, which the disabled row
	// is no longer part of; the row shows a dash instead of claiming a
	// position it does not hold.
	stored.Index = 0
	entry := sanitizeDisabled(DisabledRule{
		Index:  position,
		Expr:   expr,
		Family: target.Match.Family(),
		Rule:   stored,
	})
	if err := checkDisabled(entry); err != nil {
		return firewall.Change{}, DisabledRule{}, err
	}

	argv := []string{"nft", "delete", "rule"}
	argv = append(argv, chain.Table.Args()...)
	argv = append(argv, chain.Name, "handle", strconv.Itoa(target.Handle))

	return firewall.Change{
		Description: fmt.Sprintf("Disable rule handle %d of %s",
			target.Handle, chain.Name),
		Destructive: true,
		Note: "nftables has no disabled state, so the rule leaves the ruleset " +
			"and this tool remembers it at position " + strconv.Itoa(position+1) +
			" of " + chain.Name + "; press W afterwards to write that memory to " +
			"the saved file, or it is lost when tui-firewall exits",
		Commands: []firewall.Command{{
			Argv: argv,
			Description: fmt.Sprintf("Delete rule handle %d from %s, keeping "+
				"its spec", target.Handle, chain.Name),
			Destructive: true,
		}},
	}, entry, nil
}

// BuildEnableRule puts a disabled rule back where it was.
//
// The statement is the one captured when the rule was disabled, replayed
// verbatim: an insert before whatever now sits at the recorded position, or an
// append when the chain has since become shorter than that. The rule comes
// back with a fresh handle and a zeroed counter, which is what re-adding a
// rule to nftables means and what the preview says.
func (r Ruleset) BuildEnableRule(chain Chain, entry DisabledRule) (firewall.Change, error) {
	if err := r.checkMutable(chain); err != nil {
		return firewall.Change{}, err
	}
	if err := checkDisabled(entry); err != nil {
		return firewall.Change{}, err
	}

	argv := []string{"nft"}
	var where string
	if entry.Index >= len(chain.Rules) {
		// The chain is shorter than it was: there is no position N to insert
		// before, so the rule goes back at the end rather than nowhere.
		argv = append(argv, "add", "rule")
		argv = append(argv, chain.Table.Args()...)
		argv = append(argv, chain.Name)
		where = "at the end of " + chain.Name +
			", which is now shorter than when the rule was disabled"
	} else {
		argv = append(argv, "insert", "rule")
		argv = append(argv, chain.Table.Args()...)
		argv = append(argv, chain.Name, "index", strconv.Itoa(entry.Index))
		where = fmt.Sprintf("at position %d of %s", entry.Index+1, chain.Name)
	}
	argv = append(argv, entry.Expr...)

	return firewall.Change{
		Description: "Enable the disabled rule " + where,
		Destructive: true,
		Note: "the rule is added back from the spec this tool saved when it " +
			"was disabled; it gets a fresh handle and a counter starting at zero",
		Commands: []firewall.Command{{
			Argv:        argv,
			Description: "Add the rule back " + where,
			Destructive: true,
		}},
	}, nil
}
