package nftables

import (
	"sort"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// The identifiers of the actions the nftables backend offers beyond the
// common keys. They are passed back to BuildExtra and never shown.
const (
	ExtraCreateTable        = "create-table"
	ExtraCreateFilterChains = "create-filter-chains"
	ExtraCreateNATChains    = "create-nat-chains"
	ExtraCreateAlias        = "create-alias"
	ExtraAddElement         = "add-element"
	ExtraRemoveElement      = "remove-element"
	ExtraMasquerade         = "add-masquerade"
	ExtraPortForward        = "add-port-forward"
	ExtraDeleteChain        = "delete-chain"
	ExtraDeleteTable        = "delete-table"
)

// Writable reports whether this backend would accept a rule in the group, and
// says why not when it would not. It is the mutation guard asked directly, so
// --check can report it and the UI can grey a view out without building a
// command nobody asked for.
func (r Ruleset) Writable(group string) error {
	switch group {
	case GroupNAT, GroupAliases:
		// Neither view takes a plain rule; what they take is an action, and
		// every one of those writes into the table this tool owns. Until
		// that table exists there is nowhere for them to write.
		if _, ok := r.Table(OwnTable); !ok {
			return errorf(
				"table %s does not exist yet, and every alias and address "+
					"translation this tool creates lives in it; the actions "+
					"menu offers to create it", OwnTable)
		}
		return nil
	}
	chain, err := r.ChainForGroup(group)
	if err != nil {
		return err
	}
	return r.checkMutable(chain)
}

// AddRule builds the add-rule command for whichever group is on screen.
func (r Ruleset) AddRule(group string, spec firewall.RuleSpec) (firewall.Change, error) {
	switch group {
	case GroupNAT:
		return firewall.Change{}, errorf(
			"a NAT rule is not a filter rule: use the actions menu, which " +
				"asks for the interface and the host to translate to")
	case GroupAliases:
		return firewall.Change{}, errorf(
			"an alias is created from the actions menu, which asks what " +
				"kind of values it holds")
	}
	chain, err := r.ChainForGroup(group)
	if err != nil {
		return firewall.Change{}, err
	}
	return r.BuildAddRule(chain, spec)
}

// DeleteRule builds the delete command for the selected row, which is a rule
// in a chain view, a rule in the NAT view, and an alias in the alias view.
func (r Ruleset) DeleteRule(group string, rule firewall.Rule) (firewall.Change, error) {
	if err := checkNotDisabled(rule.ID, "deleting"); err != nil {
		return firewall.Change{}, err
	}
	switch group {
	case GroupAliases:
		table, err := parseTableID(rule.Note)
		if err != nil {
			return firewall.Change{}, err
		}
		return r.BuildDeleteSet(table, rule.ID)
	case GroupNAT:
		// The NAT view mixes the chains of every table, so the row carries
		// the name of the group its rule really belongs to.
		group = rule.Note
	}
	chain, err := r.ChainForGroup(group)
	if err != nil {
		return firewall.Change{}, err
	}
	return r.BuildDeleteRule(chain, rule)
}

// ToggleLog builds the log-toggle command for the selected row. The row the UI
// hands back carries a handle, which is looked up in the chain it names so the
// full modelled rule — not just the row's few columns — is what the replacement
// is rebuilt from.
func (r Ruleset) ToggleLog(group string, rule firewall.Rule) (firewall.Change, error) {
	switch group {
	case GroupAliases:
		return firewall.Change{}, errorf(
			"an alias does not log; logging is a rule statement, toggled on a " +
				"rule in one of the chain views")
	case GroupNAT:
		return firewall.Change{}, errorf(
			"logging is toggled on filter rules; a NAT rule's job is the " +
				"translation, not the verdict")
	}
	if err := checkNotDisabled(rule.ID, "toggling a log"); err != nil {
		return firewall.Change{}, err
	}
	chain, err := r.ChainForGroup(group)
	if err != nil {
		return firewall.Change{}, err
	}
	handle, err := strconv.Atoi(rule.ID)
	if err != nil || handle <= 0 {
		return firewall.Change{}, errorf(
			"this rule has no handle (%q), so there is no safe way to name it to "+
				"nft; re-read the ruleset with R", rule.ID)
	}
	target, ok := findRuleByHandle(chain, handle)
	if !ok {
		return firewall.Change{}, errorf(
			"rule handle %d is no longer in chain %s; press R to re-read the "+
				"ruleset", handle, chain.Name)
	}
	return r.BuildToggleLog(chain, target)
}

// chainRule resolves a group and a UI row down to the chain and the modelled
// rule the row stands for: the shared front half of every action that rebuilds
// a rule by its handle. what names the action for the refusal messages.
func (r Ruleset) chainRule(group string, row firewall.Rule,
	what string) (Chain, Rule, error) {
	if err := checkNotDisabled(row.ID, what); err != nil {
		return Chain{}, Rule{}, err
	}
	switch group {
	case GroupAliases:
		return Chain{}, Rule{}, errorf(
			"an alias is not a rule; %s applies to a rule in one of the chain "+
				"views", what)
	case GroupNAT:
		return Chain{}, Rule{}, errorf(
			"%s applies to filter rules; a NAT rule is deleted and re-created "+
				"from the actions menu", what)
	}
	chain, err := r.ChainForGroup(group)
	if err != nil {
		return Chain{}, Rule{}, err
	}
	handle, err := strconv.Atoi(row.ID)
	if err != nil || handle <= 0 {
		return Chain{}, Rule{}, errorf(
			"this rule has no handle (%q), so there is no safe way to name it to "+
				"nft; re-read the ruleset with R", row.ID)
	}
	target, ok := findRuleByHandle(chain, handle)
	if !ok {
		return Chain{}, Rule{}, errorf(
			"rule handle %d is no longer in chain %s; press R to re-read the "+
				"ruleset", handle, chain.Name)
	}
	return chain, target, nil
}

// EditRule builds the in-place replacement for the selected row from the spec
// the edit form collected.
func (r Ruleset) EditRule(group string, row firewall.Rule,
	spec firewall.RuleSpec) (firewall.Change, error) {
	chain, target, err := r.chainRule(group, row, "editing")
	if err != nil {
		return firewall.Change{}, err
	}
	return r.BuildEditRule(chain, target, spec)
}

// SpecFor reads the selected row back into the RuleSpec the edit form opens
// pre-filled with.
func (r Ruleset) SpecFor(group string, row firewall.Rule) (firewall.RuleSpec, error) {
	chain, target, err := r.chainRule(group, row, "editing")
	if err != nil {
		return firewall.RuleSpec{}, err
	}
	return r.SpecForRule(chain, target)
}

// MoveRule builds the atomic up-or-down move for the selected row.
func (r Ruleset) MoveRule(group string, row firewall.Rule,
	delta int) (firewall.Change, error) {
	chain, target, err := r.chainRule(group, row, "moving")
	if err != nil {
		return firewall.Change{}, err
	}
	return r.BuildMoveRule(chain, target, delta)
}

// DisableRule builds the delete for the selected row, plus the spec entry that
// remembers it. The caller records the entry once the command has actually
// run: a rule that is still in the ruleset is not disabled, whatever the spec
// says.
func (r Ruleset) DisableRule(group string, row firewall.Rule) (Toggle, error) {
	chain, target, err := r.chainRule(group, row, "disabling")
	if err != nil {
		return Toggle{}, err
	}
	change, entry, err := r.BuildDisableRule(chain, target)
	if err != nil {
		return Toggle{}, err
	}
	return Toggle{Change: change, Entry: entry}, nil
}

// EnableRule builds the re-add for a rule the spec holds. The row the UI hands
// back names the entry; the chain comes from the group on screen.
func (r Ruleset) EnableRule(group string, spec Spec, row firewall.Rule) (Toggle, error) {
	switch group {
	case GroupAliases, GroupNAT:
		return Toggle{}, errorf(
			"enabling applies to filter rules; there is nothing disabled in " +
				"this view")
	}
	chain, err := r.ChainForGroup(group)
	if err != nil {
		return Toggle{}, err
	}
	entry, ok := spec.Find(chain.Table, chain.Name, row.ID)
	if !ok {
		return Toggle{}, errorf(
			"this tool has no disabled rule %q in chain %s; press R to "+
				"re-read the ruleset", row.ID, chain.Name)
	}
	change, err := r.BuildEnableRule(chain, entry)
	if err != nil {
		return Toggle{}, err
	}
	return Toggle{Change: change, Entry: entry, Enabling: true}, nil
}

// checkNotDisabled refuses an action on a rule the firewall is not enforcing.
// Every other action names its rule to nft by handle, and a disabled rule has
// none: it is not in the ruleset. Saying so is better than the "this rule has
// no handle" the handle parse would produce, which reads like a bug.
func checkNotDisabled(id, what string) error {
	if !DisabledID(id) {
		return nil
	}
	return errorf(
		"this rule is disabled, so it is not in the ruleset and %s does not "+
			"apply to it; press D to enable it first", what)
}

// findRuleByHandle returns the rule a chain holds under a handle.
func findRuleByHandle(chain Chain, handle int) (Rule, bool) {
	for _, rule := range chain.Rules {
		if rule.Handle == handle {
			return rule, true
		}
	}
	return Rule{}, false
}

// SetPolicy builds the policy change for the chain a group shows.
func (r Ruleset) SetPolicy(group string, policy firewall.Policy) (firewall.Change, error) {
	chain, err := r.ChainForGroup(group)
	if err != nil {
		return firewall.Change{}, err
	}
	return r.BuildSetPolicy(chain, policy)
}

// parseTableID reads a table back out of its rendered form.
func parseTableID(text string) (TableID, error) {
	family, name, found := strings.Cut(text, " ")
	if !found || family == "" || name == "" {
		return TableID{}, errorf("%q does not name a table", text)
	}
	return TableID{Family: family, Name: name}, nil
}

// ownChain returns a chain of the table this tool owns.
func (r Ruleset) ownChain(name string) (Chain, bool) {
	return r.Chain(OwnTable, name)
}

// Extras lists the nftables actions, built from what the ruleset already has
// so the menu never offers to create something that is there or to translate
// an address in a chain that does not exist.
func (r Ruleset) Extras() []firewall.Extra {
	_, hasTable := r.Table(OwnTable)
	if !hasTable {
		return []firewall.Extra{{
			ID:    ExtraCreateTable,
			Label: "Create " + OwnTable.String() + ", the table this tool owns",
			Warning: "Everything this tool creates — rules, aliases, port " +
				"forwards — lives in that table, and nothing outside it is " +
				"written to. Creating it changes no traffic on its own.",
		}}
	}

	extras := []firewall.Extra{}
	if _, ok := r.ownChain("input"); !ok {
		extras = append(extras, firewall.Extra{
			ID:    ExtraCreateFilterChains,
			Label: "Create the input, forward and output chains",
			Warning: "All three are created with policy accept, so nothing " +
				"is blocked until you add rules and change the policy with p.",
		})
	}
	if _, ok := r.ownChain("postrouting"); !ok {
		extras = append(extras, firewall.Extra{
			ID:    ExtraCreateNATChains,
			Label: "Create the prerouting and postrouting NAT chains",
			Warning: "Both are created empty with policy accept: no address " +
				"is translated until a masquerade or a port forward is added.",
		})
	}

	extras = append(extras, r.aliasExtras()...)
	if chain, ok := r.ownChain("postrouting"); ok && chain.Type == "nat" {
		extras = append(extras, firewall.Extra{
			ID:    ExtraMasquerade,
			Label: "Masquerade an interface (optionally one source network)",
			Steps: []firewall.ExtraStep{
				{
					Prompt:      "Outgoing interface",
					Placeholder: "wan0, eth0, ppp0",
				},
				{
					Prompt:      "Source network (optional)",
					Placeholder: "empty for all, or 10.0.0.0/24",
				},
			},
			Danger: true,
			Warning: "Every packet routed out of that interface leaves with " +
				"the router's own address, and the hosts behind it stop " +
				"being reachable from outside except through a port forward. " +
				"A source network scopes it to one subnet.",
		})
	}
	if chain, ok := r.ownChain("prerouting"); ok && chain.Type == "nat" {
		extras = append(extras, firewall.Extra{
			ID:    ExtraPortForward,
			Label: "Forward a port to a host behind the router",
			Steps: []firewall.ExtraStep{
				{Prompt: "Incoming interface", Placeholder: "wan0, eth0"},
				{Prompt: "Protocol", Options: []string{"tcp", "udp"}, Current: "tcp"},
				{Prompt: "Port on this machine", Placeholder: "8080"},
				{Prompt: "Host to forward to", Placeholder: "10.10.0.5"},
				{Prompt: "Port on that host", Placeholder: "80"},
			},
			Danger: true,
			Warning: "The service on that host becomes reachable from " +
				"whatever the incoming interface is connected to. The " +
				"forward chain still has to allow the traffic as well.",
		})
	}
	extras = append(extras, r.structureExtras()...)
	return extras
}

// structureExtras are the actions that remove the structure this tool created:
// a chain of its own table, and the table itself. They act only on OwnTable —
// the guard in the builders refuses anything else — and they are the reason a
// router set up by mistake can be taken apart from the same menu that built it.
func (r Ruleset) structureExtras() []firewall.Extra {
	table, ok := r.Table(OwnTable)
	if !ok {
		return nil
	}
	var extras []firewall.Extra
	if names := chainNames(table); len(names) > 0 {
		extras = append(extras, firewall.Extra{
			ID:    ExtraDeleteChain,
			Label: "Delete a chain of " + OwnTable.String(),
			Steps: []firewall.ExtraStep{
				{Prompt: "Chain to delete", Options: names},
				{
					Prompt:  "Delete its rules too, if it has any",
					Options: []string{"no", "yes"},
					Current: "no",
				},
			},
			Danger: true,
			Warning: "A base chain that is deleted stops filtering its hook " +
				"entirely: with the input chain gone, its policy goes with it.",
		})
	}
	extras = append(extras, firewall.Extra{
		ID:     ExtraDeleteTable,
		Label:  "Delete the whole " + OwnTable.String() + " table",
		Danger: true,
		Warning: "Every chain, alias, rule and port forward this tool ever " +
			"created is in that table, and all of it goes at once. Nothing " +
			"outside " + OwnTable.String() + " is touched.",
	})
	return extras
}

// chainNames lists the chains of a table in a stable order, for the picker
// that offers one to delete.
func chainNames(table Table) []string {
	names := make([]string, 0, len(table.Chains))
	for _, chain := range table.Chains {
		names = append(names, chain.Name)
	}
	sort.Strings(names)
	return names
}

// aliasExtras are the alias actions, offered against the table this tool
// owns. The ones that act on an existing alias appear only when there is one.
func (r Ruleset) aliasExtras() []firewall.Extra {
	extras := []firewall.Extra{{
		ID:    ExtraCreateAlias,
		Label: "Create an alias (a named set)",
		Steps: []firewall.ExtraStep{
			{Prompt: "Alias name", Placeholder: "lan_hosts, admin_ports"},
			{Prompt: "What it holds", Options: setTypes, Current: setTypes[0]},
			{
				Prompt:  "Allow ranges and prefixes",
				Options: []string{"yes", "no"},
				Current: "yes",
			},
			{Prompt: "Comment", Placeholder: "why this alias exists"},
		},
	}}

	table, ok := r.Table(OwnTable)
	if !ok || len(table.Sets) == 0 {
		return extras
	}
	names := sortedSetNames(table.Sets)
	return append(extras,
		firewall.Extra{
			ID:    ExtraAddElement,
			Label: "Add a member to an alias",
			Steps: []firewall.ExtraStep{
				{Prompt: "Alias", Options: names},
				{Prompt: "Member", Placeholder: "10.0.0.5, 10.0.0.0/24, 9090-9095"},
			},
			Warning: "Every rule that uses the alias starts matching the new " +
				"member the moment this runs.",
		},
		firewall.Extra{
			ID:    ExtraRemoveElement,
			Label: "Remove a member from an alias",
			Steps: []firewall.ExtraStep{
				{Prompt: "Alias", Options: names},
				{Prompt: "Member", Placeholder: "the value to remove"},
			},
			Danger: true,
			Warning: "Every rule that uses the alias stops matching that " +
				"member the moment this runs.",
		})
}

// BuildExtra turns a collected action into the commands it runs.
func (r Ruleset) BuildExtra(id string, args []string) (firewall.Change, error) {
	switch id {
	case ExtraCreateTable:
		return BuildCreateTable(), nil
	case ExtraCreateFilterChains:
		return r.buildFilterChains()
	case ExtraCreateNATChains:
		return r.buildNATChains()
	case ExtraCreateAlias:
		return r.buildCreateAlias(args)
	case ExtraAddElement:
		if len(args) < 2 {
			return firewall.Change{}, tooFewAnswers(args, 2)
		}
		return r.BuildAddElement(OwnTable, args[0], args[1])
	case ExtraRemoveElement:
		if len(args) < 2 {
			return firewall.Change{}, tooFewAnswers(args, 2)
		}
		return r.BuildRemoveElement(OwnTable, args[0], args[1])
	case ExtraMasquerade:
		if len(args) < 1 {
			return firewall.Change{}, tooFewAnswers(args, 1)
		}
		chain, ok := r.ownChain("postrouting")
		if !ok {
			return firewall.Change{}, errorf(
				"table %s has no postrouting chain to masquerade in", OwnTable)
		}
		source := ""
		if len(args) > 1 {
			source = args[1]
		}
		return r.BuildMasquerade(chain, args[0], source)
	case ExtraDeleteChain:
		if len(args) < 1 {
			return firewall.Change{}, tooFewAnswers(args, 1)
		}
		chain, ok := r.ownChain(args[0])
		if !ok {
			return firewall.Change{}, errorf("table %s has no chain %s",
				OwnTable, args[0])
		}
		force := len(args) > 1 && args[1] == "yes"
		return r.BuildDeleteChain(chain, force)
	case ExtraDeleteTable:
		return r.BuildDeleteTable(OwnTable)
	case ExtraPortForward:
		if len(args) < 5 {
			return firewall.Change{}, tooFewAnswers(args, 5)
		}
		chain, ok := r.ownChain("prerouting")
		if !ok {
			return firewall.Change{}, errorf(
				"table %s has no prerouting chain to forward a port in", OwnTable)
		}
		return r.BuildPortForward(chain, args[0], args[1], args[2], args[3], args[4])
	default:
		return firewall.Change{}, errorf("no action %q", id)
	}
}

// tooFewAnswers is the refusal for an action whose steps did not all come
// back. Each caller checks the length at the point it indexes, rather than
// through a helper: the check and the indexing belong in one place, and a
// guard a static analyser cannot follow is a guard a reader has to trust.
func tooFewAnswers(args []string, want int) error {
	return errorf("this action needs %d answers and got %d", want, len(args))
}

// buildCreateAlias reads the four answers the alias form collects.
func (r Ruleset) buildCreateAlias(args []string) (firewall.Change, error) {
	if len(args) < 3 {
		return firewall.Change{}, tooFewAnswers(args, 3)
	}
	comment := ""
	if len(args) > 3 {
		comment = args[3]
	}
	return r.BuildCreateSet(OwnTable, args[0], args[1], args[2] == "yes", comment)
}

// buildFilterChains creates the three filter chains of the tool's own table,
// all with policy accept.
//
// Accept is not a default chosen for tidiness. A chain created with policy
// drop starts dropping the moment it exists, including the connection the
// user is running this tool over, and no confirm dialog makes that a
// reasonable thing for a "create the chains" action to do.
func (r Ruleset) buildFilterChains() (firewall.Change, error) {
	if _, ok := r.Table(OwnTable); !ok {
		return firewall.Change{}, errorf("create table %s first", OwnTable)
	}
	var commands []firewall.Command
	for _, hook := range []string{"input", "forward", "output"} {
		if _, exists := r.ownChain(hook); exists {
			continue
		}
		commands = append(commands, chainCommand(hook, "filter", hook, 0, PolicyAccept))
	}
	if len(commands) == 0 {
		return firewall.Change{}, errorf("table %s already has all three chains", OwnTable)
	}
	return firewall.Change{
		Description: "Create the filter chains of " + OwnTable.String(),
		Commands:    commands,
		Note: "each chain is created with policy accept, so nothing is " +
			"blocked until a policy is changed",
	}, nil
}

// buildNATChains creates the two NAT chains, at the priorities the kernel
// expects for translation on the way in and on the way out.
func (r Ruleset) buildNATChains() (firewall.Change, error) {
	if _, ok := r.Table(OwnTable); !ok {
		return firewall.Change{}, errorf("create table %s first", OwnTable)
	}
	var commands []firewall.Command
	// -100 is dstnat and 100 is srcnat: the numbers are written out rather
	// than the names because the named form is not accepted by every nft that
	// this backend's minimum version allows.
	for _, chain := range []struct {
		name     string
		hook     string
		priority int
	}{
		{"prerouting", "prerouting", -100},
		{"postrouting", "postrouting", 100},
	} {
		if _, exists := r.ownChain(chain.name); exists {
			continue
		}
		commands = append(commands,
			chainCommand(chain.name, "nat", chain.hook, chain.priority, PolicyAccept))
	}
	if len(commands) == 0 {
		return firewall.Change{}, errorf("table %s already has both NAT chains", OwnTable)
	}
	return firewall.Change{
		Description: "Create the NAT chains of " + OwnTable.String(),
		Commands:    commands,
		Note:        "both are created empty, so no address is translated yet",
	}, nil
}

// chainCommand builds one `nft add chain` invocation.
func chainCommand(name, kind, hook string, priority int, policy string) firewall.Command {
	argv := []string{"nft", "add", "chain"}
	argv = append(argv, OwnTable.Args()...)
	argv = append(argv, name, "{", "type", kind, "hook", hook,
		"priority", strconv.Itoa(priority), ";", "policy", policy, ";", "}")
	return firewall.Command{
		Argv:        argv,
		Description: "Create chain " + name,
	}
}
