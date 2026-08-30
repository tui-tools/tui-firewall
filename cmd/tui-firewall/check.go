package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/tui-tools/tui-firewall/internal/backends"
	"github.com/tui-tools/tui-firewall/internal/firewall"
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
	return facts
}

// runCheck exercises the backend's real read path and prints the parsed model
// as JSON. It returns an error when the backend cannot be read, which main
// turns into a non-zero exit — so a caller can treat the exit code alone as
// the verdict.
//
// A backend that cannot be read fails here, and that is the correct result:
// the exit code alone says whether this machine's firewall is legible to the
// tool.
func runCheck(backend firewall.Backend, backendCompat compat.Result,
	states []backends.State, selection string, out io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()

	model, err := backend.Load(ctx)
	if err != nil {
		return fmt.Errorf("%s backend read failed: %w", backend.Name(), err)
	}

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
		Model:     model,
	}
	for _, group := range model.Groups {
		report.Rules += len(group.Rules)
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
