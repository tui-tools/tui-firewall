package nftables

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// BuildEditRule replaces a rule in place with the rule the spec describes.
//
// nftables rules are immutable, so an edit is the same machinery the log
// toggle uses: `nft replace rule … handle H …`, which keeps the handle and the
// position while swapping the whole expression. The rule being replaced must
// be one this package holds in full — the same refusal BuildToggleLog makes —
// because an edit form was pre-filled from the modelled match, and a rule the
// model shows only half of would silently lose the other half on submit.
func (r Ruleset) BuildEditRule(chain Chain, target Rule,
	spec firewall.RuleSpec) (firewall.Change, error) {
	if err := r.checkMutable(chain); err != nil {
		return firewall.Change{}, err
	}
	if target.Handle <= 0 {
		return firewall.Change{}, errorf(
			"this rule has no handle, so there is no safe way to name it to nft; " +
				"re-read the ruleset with R")
	}
	if err := checkRebuildable(target, "edit it"); err != nil {
		return firewall.Change{}, err
	}
	if err := checkLogRoundTrip(target); err != nil {
		return firewall.Change{}, err
	}
	if spec.Position > 0 {
		return firewall.Change{}, errorf(
			"an edited rule keeps its position; move it with K and J instead " +
				"of setting an insert position")
	}
	// The edited rule logs with the stable tui: prefix, the one the live log
	// view greps for, so an edit that keeps logging on keeps feeding it.
	prefix := ""
	if spec.Log {
		verdict, err := verdictFor(spec.Action)
		if err != nil {
			return firewall.Change{}, err
		}
		prefix = logPrefix(chain.Name, verdict)
	}
	expr, err := r.ruleExpression(chain, spec, prefix)
	if err != nil {
		return firewall.Change{}, err
	}

	argv := []string{"nft", "replace", "rule"}
	argv = append(argv, chain.Table.Args()...)
	argv = append(argv, chain.Name, "handle", strconv.Itoa(target.Handle))
	argv = append(argv, expr...)

	return firewall.One(firewall.Command{
		Argv: argv,
		Description: fmt.Sprintf("Edit rule handle %d of %s in place",
			target.Handle, chain.Name),
		// Replacing a rule resets its counter, and an edit can open or close
		// traffic: both reasons for the danger colour.
		Destructive: true,
	}), nil
}

// SpecForRule reads a modelled rule back into the RuleSpec the add-rule form
// is built from, so the edit form opens pre-filled with the rule as it stands.
// A rule the form could not have expressed — a source-port match, say — is
// refused here, before the form opens, rather than silently dropped on submit.
func (r Ruleset) SpecForRule(chain Chain, target Rule) (firewall.RuleSpec, error) {
	m := target.Match
	if err := checkRebuildable(target, "edit it"); err != nil {
		return firewall.RuleSpec{}, err
	}
	if err := checkLogRoundTrip(target); err != nil {
		return firewall.RuleSpec{}, err
	}
	if m.SPort != "" {
		return firewall.RuleSpec{}, errorf(
			"rule handle %d matches a source port, which the form cannot "+
				"express; edit it with nft directly", target.Handle)
	}
	if m.Verdict == "" {
		return firewall.RuleSpec{}, errorf(
			"rule handle %d has no verdict of its own (it only logs and falls "+
				"through), so the form cannot express it; toggle its log with l "+
				"or edit it with nft directly", target.Handle)
	}
	if m.RejectWith != "" {
		return firewall.RuleSpec{}, errorf(
			"rule handle %d rejects with %q, an answer the form cannot "+
				"express; edit it with nft directly", target.Handle, m.RejectWith)
	}

	spec := firewall.RuleSpec{
		Action:   actionOf(m.Verdict),
		Proto:    m.Proto,
		Ports:    formPorts(m.DPort),
		To:       m.Daddr,
		InIface:  m.IIF,
		OutIface: m.OIF,
		ICMPType: m.ICMPType,
		Comment:  target.Comment,
		Family:   firewall.Family(m.Family()),
		Log:      m.Log,
	}
	// An alias source goes in the form's alias field, a literal in From: the
	// same split the form's own validation enforces on the way back.
	if strings.HasPrefix(m.Saddr, "@") {
		spec.Service = m.Saddr
	} else {
		spec.From = m.Saddr
	}
	// An ICMP match came out of the parser as a protocol plus a port-less
	// selector; the form spells icmp with an empty port, so nothing to map.
	if m.CTState != "" {
		spec.CTStates = strings.Split(m.CTState, ",")
	}
	return spec, nil
}

// formPorts renders a modelled port match the way the form's port field spells
// it: a braced set the reader rendered as "{ 80, 443 }" becomes "80,443", and
// anything else passes through.
func formPorts(port string) string {
	inner, ok := strings.CutPrefix(strings.TrimSpace(port), "{")
	if !ok {
		return port
	}
	inner = strings.TrimSuffix(strings.TrimSpace(inner), "}")
	items := strings.Split(inner, ",")
	for i := range items {
		items[i] = strings.TrimSpace(items[i])
	}
	return strings.Join(items, ",")
}
