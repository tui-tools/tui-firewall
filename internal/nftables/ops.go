package nftables

import (
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
)

// Writable reports whether this backend would accept a rule in the group, and
// says why not when it would not. It is the mutation guard asked directly, so
// --check can report it and the UI can grey a view out without building a
// command nobody asked for.
func (r Ruleset) Writable(group string) error {
	switch group {
	case GroupNAT, GroupAliases:
		// Neither view takes a plain rule; what they take is an action, and
		// the actions guard themselves against the table they write to.
		return r.checkOwnTable(OwnTable)
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
			Label: "Masquerade everything leaving an interface",
			Steps: []firewall.ExtraStep{{
				Prompt:      "Outgoing interface",
				Placeholder: "wan0, eth0, ppp0",
			}},
			Danger: true,
			Warning: "Every packet routed out of that interface leaves with " +
				"the router's own address, and the hosts behind it stop " +
				"being reachable from outside except through a port forward.",
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
	return extras
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
		if err := needArgs(args, 2); err != nil {
			return firewall.Change{}, err
		}
		return r.BuildAddElement(OwnTable, args[0], args[1])
	case ExtraRemoveElement:
		if err := needArgs(args, 2); err != nil {
			return firewall.Change{}, err
		}
		return r.BuildRemoveElement(OwnTable, args[0], args[1])
	case ExtraMasquerade:
		if err := needArgs(args, 1); err != nil {
			return firewall.Change{}, err
		}
		chain, ok := r.ownChain("postrouting")
		if !ok {
			return firewall.Change{}, errorf(
				"table %s has no postrouting chain to masquerade in", OwnTable)
		}
		return r.BuildMasquerade(chain, args[0])
	case ExtraPortForward:
		if err := needArgs(args, 5); err != nil {
			return firewall.Change{}, err
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

// needArgs checks that an action collected every answer it asked for.
func needArgs(args []string, want int) error {
	if len(args) < want {
		return errorf("this action needs %d answers and got %d", want, len(args))
	}
	return nil
}

// buildCreateAlias reads the four answers the alias form collects.
func (r Ruleset) buildCreateAlias(args []string) (firewall.Change, error) {
	if err := needArgs(args, 3); err != nil {
		return firewall.Change{}, err
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
