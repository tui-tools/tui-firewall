package nftables

import (
	"context"
	"strings"
	"sync"

	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-kit/runner"
)

// ErrNotAvailable reports that the nftables backend cannot be used on this
// machine (nft missing, or no non-interactive privilege escalation).
var ErrNotAvailable = runner.ErrNotAvailable

// searchPaths are the sbin locations a non-root PATH commonly omits.
var searchPaths = []string{"/usr/sbin/nft", "/sbin/nft", "/usr/local/sbin/nft"}

// installHint is appended to the "not found" error.
const installHint = "install it (apt install nftables / dnf install nftables / " +
	"pacman -S nftables), or use --demo to explore the UI"

// Real drives the nft binary on the host. It satisfies firewall.Backend.
//
// This is the only place in tui-firewall that starts an nft process. Reading
// goes through one command, `nft -j list ruleset`; every change is a single
// nft invocation built in command.go, previewed, and run through the same
// runner that printed the preview.
type Real struct {
	run *runner.Runner
	// sudoPrefix is the escalation prefix the runner was built with, kept so the
	// live log view can wrap journalctl the same way nft is wrapped. The live
	// stream reads journald rather than nft, so it does not go through the nft
	// runner, but it needs the same privilege to read the kernel log.
	sudoPrefix []string

	// mu guards ruleset, which is the state the command builders decide
	// against: which chains exist, which of them have a policy, how many
	// rules use each alias. It is replaced wholesale by Load. It also guards
	// the lazily-built install runner below.
	mu      sync.Mutex
	ruleset Ruleset
	// spec is the tool's own record of the rules it has disabled, seeded from
	// the saved file on the first Load and authoritative from then on: a rule
	// disabled in this session is in it before anything is written to disk.
	// specDirty says the two have drifted, which is what the header reports
	// and what makes the Save offer after a disable more than a courtesy.
	spec       Spec
	specLoaded bool
	specDirty  bool
	// specErr is what went wrong reading the saved file, kept so the model can
	// carry it as a warning and BuildSave can refuse to overwrite a file whose
	// disabled rules were not understood.
	specErr error
	// install runs install(1) for the Save action; built on first use.
	install    *runner.Runner
	installErr error
}

// Available reports whether nft is installed on this host.
func Available() bool { return runner.Available("nft", searchPaths...) }

// NewReal locates nft and, when not running as root, validates the configured
// privilege prefix. sudoPrefix comes from the configuration ("sudo -n"); pass
// nil to run nft directly.
func NewReal(sudoPrefix []string) (*Real, error) {
	r, err := runner.New(runner.Options{
		Bin:         "nft",
		SearchPaths: searchPaths,
		SudoPrefix:  sudoPrefix,
		InstallHint: installHint,
	})
	if err != nil {
		return nil, err
	}
	return &Real{run: r, sudoPrefix: sudoPrefix}, nil
}

// Name identifies the backend.
func (r *Real) Name() string { return "nftables" }

// Describe names the backend for the status line.
func (r *Real) Describe() string { return r.run.Describe() }

// Capabilities reports what this backend supports.
func (r *Real) Capabilities() firewall.Capabilities { return capabilities }

// Preview renders the exact command lines Run will execute.
func (r *Real) Preview(change firewall.Change) string {
	return firewall.PreviewChange(r.run, change)
}

// Load reads the whole ruleset in one command. Listing the ruleset needs
// root, like every other nft read, so it goes through the runner's privileged
// read path.
//
// There is no `-a` on the command line and there does not need to be: nft's
// `-a` adds handles to its *human* output, and the JSON form carries them
// unconditionally. Which matters, because a handle is the only identifier a
// delete can safely name.
func (r *Real) Load(ctx context.Context) (firewall.Model, error) {
	out, err := r.run.Read(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return firewall.Model{}, err
	}
	ruleset, err := ParseRuleset([]byte(out))
	if err != nil {
		return firewall.Model{}, err
	}
	r.mu.Lock()
	r.ruleset = ruleset
	// The spec is read once, from the file the Save action writes. Re-reading
	// it on every Load would throw away a rule disabled in this session and
	// not saved yet, which is the one thing the record exists to prevent.
	if !r.specLoaded {
		r.specLoaded = true
		path, _ := SavePath()
		r.spec, r.specErr = LoadSpec(path)
	}
	spec, specErr := r.spec, r.specErr
	r.mu.Unlock()

	model := ModelWithSpec(ruleset, spec)
	if specErr != nil {
		model.Warning = strings.TrimSpace(specErr.Error() + "  ·  " + model.Warning)
	}
	return model, nil
}

// Spec is the tool's own record of the rules it has disabled.
func (r *Real) Spec() Spec {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.spec
}

// SpecError is what went wrong reading the saved file's spec, if anything. A
// save is refused while it is set: overwriting a file whose disabled rules
// this build could not read would delete them.
func (r *Real) SpecError() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.specErr
}

// SpecDirty reports that a rule was disabled or enabled since the last save,
// so the record on screen is not yet the record on disk.
func (r *Real) SpecDirty() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.specDirty
}

// SpecSaved records that the spec now matches the file on disk.
func (r *Real) SpecSaved() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.specDirty = false
}

// BuildToggleDisabled builds the change that disables the selected live rule,
// or enables the selected disabled one.
func (r *Real) BuildToggleDisabled(group string,
	rule firewall.Rule) (Toggle, error) {
	ruleset, spec := r.Ruleset(), r.Spec()
	if DisabledID(rule.ID) {
		return ruleset.EnableRule(group, spec, rule)
	}
	return ruleset.DisableRule(group, rule)
}

// CommitToggleDisabled records a toggle once its command has actually run. It
// is deliberately a second call rather than a side effect of the build: a
// change that was previewed and then cancelled must leave the record exactly
// as it was, and one that ran must be recorded from the very Toggle the
// preview was built from rather than from a ruleset that has moved on since.
func (r *Real) CommitToggleDisabled(toggle Toggle) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.spec.Apply(toggle)
	r.specDirty = true
}

// Ruleset returns the last ruleset that was read. --check uses it for the
// facts that are about nftables rather than about the generic model.
func (r *Real) Ruleset() Ruleset {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ruleset
}

// Run executes a previewed change. Almost every command is an nft invocation;
// the one exception is the Save action's `install`, which the dispatching
// runner below routes to its own binary.
func (r *Real) Run(ctx context.Context, change firewall.Change) (string, error) {
	return firewall.RunChange(ctx, dispatchRunner{r}, change)
}

// dispatchRunner routes each command of a change to the runner that owns its
// binary. The nft runner resolves argv[0] to the nft path, so a command whose
// argv[0] is another binary must not go through it; today that is only the
// Save action's install(1).
type dispatchRunner struct{ r *Real }

// Preview renders the command the way the nft runner would; the privilege
// prefix is the same for both binaries, so the text is too.
func (d dispatchRunner) Preview(cmd firewall.Command) string {
	return d.r.run.Preview(cmd)
}

// Run routes one command to its binary's runner.
func (d dispatchRunner) Run(ctx context.Context, cmd firewall.Command) (string, error) {
	if len(cmd.Argv) > 0 && cmd.Argv[0] == "install" {
		ir, err := d.r.installRunner()
		if err != nil {
			return "", err
		}
		return ir.Run(ctx, cmd)
	}
	return d.r.run.Run(ctx, cmd)
}

// installRunner lazily builds the runner for install(1), which the Save action
// uses to write the serialized table with the right owner and mode in one
// step. It is built on first use rather than at startup so a machine without
// it — none in practice; install ships with coreutils — still gets every other
// feature.
func (r *Real) installRunner() (*runner.Runner, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.install != nil || r.installErr != nil {
		return r.install, r.installErr
	}
	r.install, r.installErr = runner.New(runner.Options{
		Bin:         "install",
		SearchPaths: []string{"/usr/bin/install", "/bin/install"},
		SudoPrefix:  r.sudoPrefix,
		InstallHint: "install(1) ships with coreutils",
	})
	return r.install, r.installErr
}

// SnapshotOwnTable serialises the table this tool owns as nft's own text,
// which is what the Save action writes to disk. Like the staging snapshot it
// is the human listing, not the JSON: the text is a valid nft script, so the
// saved file loads straight back with `nft -f`.
func (r *Real) SnapshotOwnTable(ctx context.Context) (string, error) {
	argv := append([]string{"nft", "list", "table"}, OwnTable.Args()...)
	return r.run.Read(ctx, argv...)
}

// RuleSpecFor reads the selected row back into the spec the edit form opens
// pre-filled with.
func (r *Real) RuleSpecFor(group string, rule firewall.Rule) (firewall.RuleSpec, error) {
	return r.Ruleset().SpecFor(group, rule)
}

// BuildEditRule replaces the selected row in place with the edited spec.
func (r *Real) BuildEditRule(group string, rule firewall.Rule,
	spec firewall.RuleSpec) (firewall.Change, error) {
	return r.Ruleset().EditRule(group, rule, spec)
}

// BuildMoveRule moves the selected row one position up or down its chain.
func (r *Real) BuildMoveRule(group string, rule firewall.Rule,
	delta int) (firewall.Change, error) {
	return r.Ruleset().MoveRule(group, rule, delta)
}

// SnapshotRuleset reads the whole ruleset as nft's own text, which is what the
// connectivity-safe rollback replays. It is `nft list ruleset` (not the JSON
// form): the human text is a valid nft script, so `nft -f` can load it straight
// back, which the JSON cannot. Like every nft read it needs privilege.
func (r *Real) SnapshotRuleset(ctx context.Context) (string, error) {
	return r.run.Read(ctx, "nft", "list", "ruleset")
}

// BuildAddRule creates a rule in the chain the group names.
func (r *Real) BuildAddRule(group string, spec firewall.RuleSpec) (firewall.Change, error) {
	return r.Ruleset().AddRule(group, spec)
}

// BuildDeleteRule removes the selected row.
func (r *Real) BuildDeleteRule(group string, rule firewall.Rule) (firewall.Change, error) {
	return r.Ruleset().DeleteRule(group, rule)
}

// BuildToggleLog turns per-rule logging on or off for the selected row.
func (r *Real) BuildToggleLog(group string, rule firewall.Rule) (firewall.Change, error) {
	return r.Ruleset().ToggleLog(group, rule)
}

// BuildSetEnabled always refuses: nftables has no on/off switch.
func (r *Real) BuildSetEnabled(bool) (firewall.Change, error) {
	return firewall.Change{}, errorf("%s", capabilities.EnableHint)
}

// BuildReload always refuses. `nft -f` re-reads a file this tool did not
// write and cannot show, which is exactly the invisible change the whole
// preview contract exists to prevent.
func (r *Real) BuildReload() (firewall.Change, error) {
	return firewall.Change{}, errorf(
		"there is nothing to reload: an nft command takes effect the moment " +
			"it runs, and re-applying /etc/nftables.conf would replace the " +
			"ruleset on screen with a file this tool has not shown you")
}

// BuildSetPolicy changes the policy of the chain a group shows.
func (r *Real) BuildSetPolicy(group string, _ firewall.PolicyDirection,
	policy firewall.Policy) (firewall.Change, error) {
	return r.Ruleset().SetPolicy(group, policy)
}

// BuildSetLogging always refuses: nftables logs per rule, not by level.
func (r *Real) BuildSetLogging(string) (firewall.Change, error) {
	return firewall.Change{}, errorf(
		"nftables has no logging level: logging is a statement on a rule, " +
			"which the add-rule form offers as \"Log matches\"")
}

// Extras lists the nftables-specific actions.
func (r *Real) Extras(_ firewall.Model, _ string) []firewall.Extra {
	return r.Ruleset().Extras()
}

// BuildExtra turns a collected action into its commands.
func (r *Real) BuildExtra(_, id string, args []string) (firewall.Change, error) {
	return r.Ruleset().BuildExtra(id, args)
}
