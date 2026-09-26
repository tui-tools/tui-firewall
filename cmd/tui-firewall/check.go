package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/tui-tools/tui-firewall/internal/backends"
	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/iptables"
	"github.com/tui-tools/tui-firewall/internal/nftables"
	"github.com/tui-tools/tui-firewall/internal/nftables/staging"
	"github.com/tui-tools/tui-kit/compat"
)

// checkTimeout bounds the read. Loading the rule set shells out to the
// backend, and a machine whose firewall service is wedged must not hang a
// non-interactive check forever.
const checkTimeout = 30 * time.Second

// checkReport is what --check prints: the model the backend parsed, plus the
// counts a test can assert on without walking the whole structure.
//
// It is a report of the read path only. --check never builds and never runs a
// mutation: the whole point is that it is safe to run anywhere, including in
// CI against a production-shaped machine.
type checkReport struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Backend string `json:"backend"`
	// Describe is the backend's own one-line summary, which is where a stub
	// backend says it is a stub.
	Describe string `json:"describe"`
	Enabled  bool   `json:"enabled"`
	Logging  string `json:"logging,omitempty"`
	// Groups and Rules are the totals across the model.
	Groups int `json:"groups"`
	Rules  int `json:"rules"`
	// Compat is what the backend version probe found, for the backend that
	// was selected and only that one: probing the other would run a binary
	// nobody asked this tool to touch. It is reported rather than asserted —
	// an untested version is a fact about the machine, not a failure of the
	// read path.
	Compat compat.Result `json:"compat"`
	// Selection is the sentence the detector gave for the backend it chose.
	// On a machine carrying more than one firewall it is the only part of
	// this report that answers "why this one".
	Selection string `json:"selection,omitempty"`
	// Backends is what the detector saw for every backend this tool knows,
	// installed or not, so a reader can tell "firewalld was chosen" from
	// "ufw is not here" without running the detection again.
	Backends []backends.State `json:"backends"`
	// Nftables carries the facts that are about the nftables ruleset rather
	// than about the generic model: who is writing it, and what this backend
	// is therefore allowed to change. It is absent for the other backends.
	Nftables *nftablesFacts `json:"nftables,omitempty"`
	// Iptables carries the facts that are about iptables rather than about the
	// generic model: which variant printed the rules, where a new rule would
	// land in each writable chain, and whether the running rules match what
	// the persistence layer restores at boot. It is absent for the others.
	Iptables *iptablesFacts `json:"iptables,omitempty"`
	// Model is the parsed state in full.
	Model firewall.Model `json:"model"`
}

// nftablesFacts is the nftables block of --check.
type nftablesFacts struct {
	// NftVersion is what nft reported about itself in the ruleset JSON, which
	// is the version that produced the output being parsed rather than
	// whatever `nft --version` on the PATH would say.
	NftVersion string `json:"nftVersion,omitempty"`
	// SchemaVersion is the JSON schema version of that output.
	SchemaVersion int `json:"schemaVersion"`
	// Tables, Chains, BaseChains, Sets and Rules count what was read.
	Tables     int `json:"tables"`
	Chains     int `json:"chains"`
	BaseChains int `json:"baseChains"`
	Sets       int `json:"sets"`
	NATRules   int `json:"natRules"`
	// OwnTable is the table this backend writes to, and Managed reports
	// whether it exists.
	OwnTable        string `json:"ownTable"`
	OwnTablePresent bool   `json:"ownTablePresent"`
	// Manager is the tool the ruleset says is writing it, and ReadOnly is the
	// sentence explaining what that means for this backend. Both are empty on
	// a ruleset nobody else claims.
	Manager  string `json:"manager,omitempty"`
	ReadOnly string `json:"readOnly,omitempty"`
	// Writable lists the groups this backend would accept a rule in, which is
	// the mutation guard reported rather than described.
	Writable []string `json:"writable"`
	// Staging reports the connectivity-safe apply: whether this backend offers
	// it, and — in an interactive session — whether a batch is active.
	Staging stagingFacts `json:"staging"`
	// Logging reports the per-rule log feature: how many rules log, how many of
	// those this backend owns, and whether the live log source can be read.
	Logging logFacts `json:"logging"`
}

// logFacts is the per-rule-logging block of --check: whether any owned rule
// logs, and whether the live view's source (the journald kernel log) is there
// to read.
type logFacts struct {
	// LoggedRules is how many rules in a chain this backend may write to log;
	// LoggedRulesTotal counts every logging rule, owned or not.
	LoggedRules      int `json:"loggedRules"`
	LoggedRulesTotal int `json:"loggedRulesTotal"`
	// LiveSource names the live view's source, LiveReadable reports whether it
	// can be read, and LiveDetail says why.
	LiveSource   string `json:"liveSource"`
	LiveReadable bool   `json:"liveReadable"`
	LiveDetail   string `json:"liveDetail"`
	// Prefix is the marker every log prefix this tool writes begins with, which
	// is what the live view greps.
	Prefix string `json:"prefix"`
}

// stagingFacts is the staging block of --check: staging is a mode of the
// interactive session, so a non-interactive check reports the capability and a
// zero batch, which is the honest answer for a path that never stages.
type stagingFacts struct {
	// Supported reports whether this backend can stage and roll back at all.
	Supported bool `json:"supported"`
	// Active reports whether a staging batch is open, and Pending how many
	// changes it holds. Both are zero outside the interactive UI.
	Active  bool `json:"active"`
	Pending int  `json:"pending"`
	// TimeoutSeconds is the keep-confirmation window a batch would apply under.
	TimeoutSeconds int `json:"timeoutSeconds"`
}

// rulesetSource is the part of the nftables backends --check reads its extra
// facts from. Both the real backend and the fake satisfy it, so --demo
// produces the same block as a real read.
type rulesetSource interface {
	Ruleset() nftables.Ruleset
}

// collectNftablesFacts fills the nftables block, or returns nil for a backend
// that is not nftables at all.
func collectNftablesFacts(backend firewall.Backend, model firewall.Model) *nftablesFacts {
	source, ok := backend.(rulesetSource)
	if !ok {
		return nil
	}
	ruleset := source.Ruleset()
	facts := &nftablesFacts{
		NftVersion:    ruleset.Version,
		SchemaVersion: ruleset.SchemaVersion,
		Tables:        len(ruleset.Tables),
		OwnTable:      nftables.OwnTable.String(),
	}
	_, facts.OwnTablePresent = ruleset.Table(nftables.OwnTable)
	for _, table := range ruleset.Tables {
		facts.Sets += len(table.Sets)
		facts.Chains += len(table.Chains)
	}
	facts.BaseChains = len(ruleset.BaseChains())
	if group, ok := model.Group(nftables.GroupNAT); ok {
		facts.NATRules = len(group.Rules)
	}
	if management := nftables.DetectManagement(ruleset); management.Managed() {
		facts.Manager = management.Manager
		facts.ReadOnly = management.Detail
	}
	// A group this backend would refuse is worth knowing before a change is
	// attempted, so the writable ones are listed rather than counted.
	facts.Writable = []string{}
	for _, group := range model.Groups {
		if err := ruleset.Writable(group.Name); err != nil {
			continue
		}
		facts.Writable = append(facts.Writable, group.Name)
	}
	// Staging is a property of the interactive session, which --check never
	// starts; what it can report is whether this backend supports it and under
	// what timeout a batch would apply.
	_, supported := backend.(snapshotter)
	facts.Staging = stagingFacts{
		Supported:      supported,
		TimeoutSeconds: int(staging.DefaultTimeout.Seconds()),
	}
	// Per-rule logging: how many owned rules log, and whether the live source is
	// readable. The source probe reads the machine (is journald here) rather
	// than the ruleset, so a demo backend reports the demo source instead.
	owned, total := ruleset.LoggedRules()
	liveReadable, liveSource, liveDetail := nftables.LogSourceProbe()
	if backend.Name() == "demo" {
		liveReadable, liveSource, liveDetail = true, "demo synthetic stream",
			"the demo live view plays a synthetic feed; nothing on this machine is read"
	}
	facts.Logging = logFacts{
		LoggedRules:      owned,
		LoggedRulesTotal: total,
		LiveSource:       liveSource,
		LiveReadable:     liveReadable,
		LiveDetail:       liveDetail,
		Prefix:           nftables.LogPrefixMarker,
	}
	return facts
}

// iptablesFacts is the iptables block of --check.
type iptablesFacts struct {
	// Version and Variant are what iptables-save said about itself: the
	// xtables version, and "nf_tables" or "legacy".
	Version string `json:"version,omitempty"`
	Variant string `json:"variant,omitempty"`
	// HasV6 reports whether ip6tables-save could be read.
	HasV6 bool `json:"hasV6"`
	// Tables and Rules count what was read, per family.
	TablesV4 int `json:"tablesV4"`
	TablesV6 int `json:"tablesV6"`
	RulesV4  int `json:"rulesV4"`
	RulesV6  int `json:"rulesV6"`
	// Warnings are the tool's own "# Warning:" lines, such as legacy tables
	// loaded beside nf_tables ones.
	Warnings []string `json:"warnings,omitempty"`
	// Writable lists the chains this backend would accept a rule in, and
	// Placement where a new rule would land in each, with the reason.
	Writable  []string          `json:"writable"`
	Placement map[string]string `json:"placement"`
	// OpenInput lists, per family, the ports INPUT accepts ahead of its
	// catch-all, and ShadowedInput the accepts that sit after it and never
	// match — the bug an appended rule causes on a cloud image.
	OpenInput     map[string][]string `json:"openInput"`
	ShadowedInput map[string][]string `json:"shadowedInput,omitempty"`
	// InputEnd says, per family, what decides a packet no INPUT rule
	// accepted: the catch-all rule, or the chain policy. With policy ACCEPT
	// and no catch-all, every port not refused above is open, which the
	// openInput list alone would not say.
	InputEnd map[string]string `json:"inputEnd"`
	// InputRules counts the rules of INPUT per family, for a smoke test to
	// compare with `iptables -S INPUT`.
	InputRules map[string]int `json:"inputRules"`
	// Persistence is the layer that restores the rules at boot and the drift
	// between it and the running rules.
	Persistence iptablesPersistence `json:"persistence"`
	// Staging reports the connectivity-safe apply.
	Staging stagingFacts `json:"staging"`
}

// iptablesPersistence is the persistence part of the iptables block.
type iptablesPersistence struct {
	// Kind is "netfilter-persistent", "iptables-services" or empty when
	// nothing restores the rules at boot.
	Kind    string `json:"kind"`
	V4Path  string `json:"v4Path,omitempty"`
	V6Path  string `json:"v6Path,omitempty"`
	Enabled bool   `json:"enabled"`
	// Drift is the one-line summary ("in sync", "2 lines not saved"), and
	// InSync the verdict a script can test.
	Drift       string   `json:"drift"`
	DriftKnown  bool     `json:"driftKnown"`
	InSync      bool     `json:"inSync"`
	RuntimeOnly []string `json:"runtimeOnly,omitempty"`
	SavedOnly   []string `json:"savedOnly,omitempty"`
	Reordered   []string `json:"reordered,omitempty"`
	ReadError   string   `json:"readError,omitempty"`
}

// iptablesSource is the part of the iptables backends --check reads its extra
// facts from. The real backend and the fake both satisfy it.
type iptablesSource interface {
	State() iptables.State
}

// collectIptablesFacts fills the iptables block, or returns nil for a backend
// that is not iptables.
func collectIptablesFacts(backend firewall.Backend, model firewall.Model) *iptablesFacts {
	source, ok := backend.(iptablesSource)
	if !ok {
		return nil
	}
	state := source.State()
	facts := &iptablesFacts{
		Version:    state.V4.Version,
		Variant:    state.V4.Variant,
		HasV6:      state.HasV6,
		TablesV4:   len(state.V4.Tables),
		TablesV6:   len(state.V6.Tables),
		RulesV4:    countDumpRules(state.V4),
		RulesV6:    countDumpRules(state.V6),
		Warnings:   append(append([]string(nil), state.V4.Warnings...), state.V6.Warnings...),
		Writable:   []string{},
		Placement:  map[string]string{},
		OpenInput:  map[string][]string{},
		InputEnd:   map[string]string{},
		InputRules: map[string]int{},
	}
	for _, family := range iptables.Families() {
		if family == iptables.V6 && !state.HasV6 {
			continue
		}
		chain, ok := state.Dump(family).Chain(iptables.TableFilter, iptables.ChainInput)
		if !ok {
			continue
		}
		facts.InputRules[string(family)] = len(chain.Rules)
		if at, rule := chain.CatchAll(); at > 0 {
			facts.InputEnd[string(family)] = fmt.Sprintf("rule %d: %s", at,
				rule.Match.TargetDetail())
		} else {
			facts.InputEnd[string(family)] = "policy " + chain.Policy
		}
		open, shadowed := chain.OpenPorts()
		facts.OpenInput[string(family)] = append([]string{}, open...)
		if len(shadowed) > 0 {
			if facts.ShadowedInput == nil {
				facts.ShadowedInput = map[string][]string{}
			}
			facts.ShadowedInput[string(family)] = shadowed
		}
	}
	for _, group := range model.Groups {
		if err := state.Writable(group.Name); err != nil {
			continue
		}
		facts.Writable = append(facts.Writable, group.Name)
		family, table, name, err := iptables.ParseGroup(group.Name)
		if err != nil {
			continue
		}
		chain, ok := state.Dump(family).Chain(table, name)
		if !ok {
			chain = iptables.Chain{Name: name, Policy: iptables.TargetAccept}
		}
		if placement, err := iptables.Place(chain, 0); err == nil {
			facts.Placement[group.Name] = placement.Why
		}
	}
	p := state.Persistence
	facts.Persistence = iptablesPersistence{
		Kind:        p.Layout.Kind,
		V4Path:      p.Layout.V4Path,
		V6Path:      p.Layout.V6Path,
		Enabled:     p.Layout.Enabled,
		Drift:       p.Drift.Summary(),
		DriftKnown:  p.Drift.Known,
		InSync:      p.Drift.InSync,
		RuntimeOnly: p.Drift.RuntimeOnly,
		SavedOnly:   p.Drift.SavedOnly,
		Reordered:   p.Drift.Reordered,
		ReadError:   p.ReadErr,
	}
	_, supported := backend.(snapshotter)
	facts.Staging = stagingFacts{
		Supported:      supported,
		TimeoutSeconds: int(staging.DefaultTimeout.Seconds()),
	}
	return facts
}

// countDumpRules counts every rule of a dump.
func countDumpRules(d iptables.Dump) int {
	n := 0
	for _, t := range d.Tables {
		for _, c := range t.Chains {
			n += len(c.Rules)
		}
	}
	return n
}

// checkFacts is what --check reports beside the model: the probed backend
// version, what the detector saw of every backend, and why this one was
// chosen. They are gathered while the backend loads; see run.
type checkFacts struct {
	compat    compat.Result
	backends  []backends.State
	selection string
}

// runCheck exercises the backend's real read path and prints the parsed model
// as JSON. It returns an error when the backend cannot be read, which main
// turns into a non-zero exit — so a caller can treat the exit code alone as
// the verdict.
//
// A backend that cannot be read fails here, and that is the correct result:
// the exit code alone says whether this machine's firewall is legible to the
// tool.
func runCheck(backend firewall.Backend, facts <-chan checkFacts, out io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()

	model, err := backend.Load(ctx)
	if err != nil {
		return fmt.Errorf("%s backend read failed: %w", backend.Name(), err)
	}
	survey := <-facts
	backendCompat, states, selection := survey.compat, survey.backends, survey.selection

	report := checkReport{
		Tool:      toolName,
		Version:   version,
		Backend:   backend.Name(),
		Describe:  backend.Describe(),
		Enabled:   model.Enabled,
		Logging:   model.Logging,
		Groups:    len(model.Groups),
		Compat:    backendCompat,
		Selection: selection,
		Backends:  states,
		Nftables:  collectNftablesFacts(backend, model),
		Iptables:  collectIptablesFacts(backend, model),
		Model:     model,
	}
	for _, group := range model.Groups {
		report.Rules += len(group.Rules)
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
