package nftables

import (
	"fmt"
	"strconv"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// BuildMoveRule moves a rule one position up or down its chain.
//
// nftables has no move command, so a move is two statements: a copy of the
// rule written at the new position, and a delete of the old handle. The two
// only make sense together — run apart, a failure in between leaves the rule
// duplicated or gone — which is why the Change carries a note saying it must
// apply as one `nft -f` transaction, and why the callers route it through the
// staging engine (or wrap it with staging.AtomicCommand) rather than running
// the commands one at a time.
//
// The copy is rebuilt from the rule's own modelled match, exactly like the log
// toggle: a rule the model does not hold in full is refused rather than
// re-rendered with half its matches missing.
func (r Ruleset) BuildMoveRule(chain Chain, target Rule, delta int) (firewall.Change, error) {
	if err := r.checkMutable(chain); err != nil {
		return firewall.Change{}, err
	}
	if delta != 1 && delta != -1 {
		return firewall.Change{}, errorf("a rule moves one position at a time")
	}
	if target.Handle <= 0 {
		return firewall.Change{}, errorf(
			"this rule has no handle, so there is no safe way to name it to nft; " +
				"re-read the ruleset with R")
	}
	if err := checkRebuildable(target, "move it"); err != nil {
		return firewall.Change{}, err
	}
	if err := checkLogRoundTrip(target); err != nil {
		return firewall.Change{}, err
	}

	// The position comes from where the handle sits in the chain right now,
	// not from the row's display index: the two agree unless the ruleset
	// changed underneath, and then the handle is the one that is true.
	position := -1
	for i, rule := range chain.Rules {
		if rule.Handle == target.Handle {
			position = i
			break
		}
	}
	if position < 0 {
		return firewall.Change{}, errorf(
			"rule handle %d is no longer in chain %s; press R to re-read the "+
				"ruleset", target.Handle, chain.Name)
	}

	// The rule keeps its expression exactly as it stands, its own log prefix
	// included: a move changes where the rule sits, nothing about what it does.
	expr, err := rebuildRuleExpr(chain, target, target.Match.Log,
		target.Match.LogPrefix)
	if err != nil {
		return firewall.Change{}, err
	}
	// nft counts rule indexes from zero. `insert … index N` writes the copy
	// before the rule now at N; `add … index N` writes it after. Moving up
	// inserts before the previous rule, moving down appends after the next
	// one, and in both cases the original is still in place when the copy
	// lands, so the indexes name the pre-move chain.
	var verb string
	var index int
	var where string
	if delta < 0 {
		if position == 0 {
			return firewall.Change{}, errorf(
				"rule handle %d is already first in %s", target.Handle, chain.Name)
		}
		verb, index, where = "insert", position-1, "up"
	} else {
		if position == len(chain.Rules)-1 {
			return firewall.Change{}, errorf(
				"rule handle %d is already last in %s", target.Handle, chain.Name)
		}
		verb, index, where = "add", position+1, "down"
	}

	place := []string{"nft", verb, "rule"}
	place = append(place, chain.Table.Args()...)
	place = append(place, chain.Name, "index", strconv.Itoa(index))
	place = append(place, expr...)

	del := []string{"nft", "delete", "rule"}
	del = append(del, chain.Table.Args()...)
	del = append(del, chain.Name, "handle", strconv.Itoa(target.Handle))

	description := fmt.Sprintf("Move rule handle %d %s in %s",
		target.Handle, where, chain.Name)
	return firewall.Change{
		Description: description,
		Destructive: true,
		Note: "the copy and the delete apply as one atomic nft transaction, " +
			"so the rule is never duplicated or missing in between; the new " +
			"copy gets a fresh handle and a reset counter",
		Commands: []firewall.Command{
			{
				Argv: place,
				Description: fmt.Sprintf("Write the rule at its new position "+
					"in %s", chain.Name),
				Destructive: true,
			},
			{
				Argv: del,
				Description: fmt.Sprintf("Delete the old copy, handle %d",
					target.Handle),
				Destructive: true,
			},
		},
	}, nil
}
