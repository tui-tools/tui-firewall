package iptables

import (
	"context"
	"strings"
	"sync"

	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/nftables"
	"github.com/tui-tools/tui-firewall/internal/nftables/staging"
	"github.com/tui-tools/tui-kit/runner"
)

// ErrNotAvailable reports that the iptables backend cannot be used on this
// machine (iptables missing, or no non-interactive privilege escalation).
var ErrNotAvailable = runner.ErrNotAvailable

// installHint is appended to the "not found" error.
const installHint = "install it (apt install iptables / dnf install iptables-nft), " +
	"or use --demo=iptables to explore the UI"

// Real drives iptables and ip6tables on the host. It satisfies
// firewall.Backend.
//
// Unlike the nft backend, which reaches everything through one binary, this
// one needs several: iptables and ip6tables to change rules, their -save
// siblings to read them, their -restore siblings for the staged apply, and
// the persistence layer's own command to write the saved files. Each gets its
// own runner, built on first use, and every command is routed to the runner of
// the binary its argv names — so the preview and the exec still go through the
// same value.
type Real struct {
	sudoPrefix []string

	mu      sync.Mutex
	runners map[string]*runner.Runner
	errs    map[string]error
	// state is the last Load, which the command builders decide against.
	state State
}

// NewReal locates iptables and iptables-save and validates the privilege
// prefix. The other binaries are resolved when a command first needs them, so
// a machine without ip6tables or without a persistence layer still gets every
// other feature.
func NewReal(sudoPrefix []string) (*Real, error) {
	r := &Real{
		sudoPrefix: sudoPrefix,
		runners:    map[string]*runner.Runner{},
		errs:       map[string]error{},
	}
	for _, bin := range []string{"iptables", "iptables-save"} {
		if _, err := r.runnerFor(bin); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// runnerFor returns the runner for one binary, building it on first use.
func (r *Real) runnerFor(bin string) (*runner.Runner, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if run, ok := r.runners[bin]; ok {
		return run, nil
	}
	if err, ok := r.errs[bin]; ok {
		return nil, err
	}
	search := sbinPaths(bin)
	switch {
	case bin == "cat":
		search = []string{"/usr/bin/cat", "/bin/cat"}
	case strings.HasPrefix(bin, "/"):
		// An absolute path, like the iptables-services init scripts, is its
		// own location: there is nothing to search for.
		search = nil
	}
	run, err := runner.New(runner.Options{
		Bin:         bin,
		SearchPaths: search,
		SudoPrefix:  r.sudoPrefix,
		InstallHint: installHint,
	})
	if err != nil {
		r.errs[bin] = err
		return nil, err
	}
	r.runners[bin] = run
	return run, nil
}

// Name identifies the backend.
func (r *Real) Name() string { return "iptables" }

// Describe names the backend for the status line: the binary, the kernel
// interface it drives once that is known, and how it is reached.
func (r *Real) Describe() string {
	run, err := r.runnerFor("iptables")
	if err != nil {
		return "iptables"
	}
	describe := run.Describe()
	r.mu.Lock()
	variant := r.state.V4.Variant
	r.mu.Unlock()
	if variant != "" {
		describe = strings.Replace(describe, "iptables", "iptables ("+variant+")", 1)
	}
	return describe
}

// Capabilities reports what this backend supports.
func (r *Real) Capabilities() firewall.Capabilities { return capabilities }

// Preview renders the exact command lines Run will execute.
func (r *Real) Preview(change firewall.Change) string {
	return firewall.PreviewChange(dispatchRunner{r}, change)
}

// Run executes a previewed change, each command through its binary's runner.
func (r *Real) Run(ctx context.Context, change firewall.Change) (string, error) {
	return firewall.RunChange(ctx, dispatchRunner{r}, change)
}

// dispatchRunner routes each command to the runner that owns its binary.
type dispatchRunner struct{ r *Real }

// Preview renders the command the way its runner would. The privilege prefix
// is the same for every binary, so a runner that cannot be built still
// previews correctly through the iptables one.
func (d dispatchRunner) Preview(cmd firewall.Command) string {
	if len(cmd.Argv) > 0 {
		if run, err := d.r.runnerFor(cmd.Argv[0]); err == nil {
			return run.Preview(cmd)
		}
	}
	run, err := d.r.runnerFor("iptables")
	if err != nil {
		return cmd.String()
	}
	return run.Preview(cmd)
}

// Run routes one command to its binary's runner.
func (d dispatchRunner) Run(ctx context.Context, cmd firewall.Command) (string, error) {
	if len(cmd.Argv) == 0 {
		return "", errorf("an empty command cannot run")
	}
	run, err := d.r.runnerFor(cmd.Argv[0])
	if err != nil {
		return "", err
	}
	return run.Run(ctx, cmd)
}

// read runs one privileged read through the binary's runner.
func (r *Real) read(ctx context.Context, argv ...string) (string, error) {
	run, err := r.runnerFor(argv[0])
	if err != nil {
		return "", err
	}
	return run.Read(ctx, argv...)
}

// Load reads both families with counters, and the saved files the persistence
// layer restores at boot.
func (r *Real) Load(ctx context.Context) (firewall.Model, error) {
	state, err := r.readState(ctx, true)
	if err != nil {
		return firewall.Model{}, err
	}
	r.mu.Lock()
	r.state = state
	r.mu.Unlock()
	return Model(state), nil
}

// readState reads the running dumps and the saved files. withCounters asks
// iptables-save for -c, which the rule list wants and a persist diff does not.
func (r *Real) readState(ctx context.Context, withCounters bool) (State, error) {
	args := func(bin string) []string {
		if withCounters {
			return []string{bin, "-c"}
		}
		return []string{bin}
	}
	var state State
	out, err := r.read(ctx, args(V4.SaveBinary())...)
	if err != nil {
		return State{}, err
	}
	if state.V4, err = ParseSave(V4, out); err != nil {
		return State{}, err
	}
	// ip6tables is optional: a machine without it still has an IPv4 firewall
	// to show.
	if out, err := r.read(ctx, args(V6.SaveBinary())...); err == nil {
		if dump, perr := ParseSave(V6, out); perr == nil {
			state.V6, state.HasV6 = dump, true
		}
	}
	state.Persistence = r.readPersistence(ctx, state.HasV6)
	state.Persistence.Drift = ComputeDrift(state)
	return state, nil
}

// readPersistence finds the persistence layer and reads its saved files. The
// files are root-only on Debian (mode 640), so they are read through the same
// privilege as everything else.
func (r *Real) readPersistence(ctx context.Context, hasV6 bool) Persistence {
	p := Persistence{Layout: DetectLayout()}
	if !p.Found() {
		return p
	}
	read := func(path string, family Family) (*Dump, string) {
		if !fileExists(path) {
			return nil, ""
		}
		out, err := r.read(ctx, "cat", path)
		if err != nil {
			return nil, "could not read " + path + ": " + err.Error()
		}
		dump, err := ParseSave(family, out)
		if err != nil {
			return nil, path + " could not be parsed, so drift is unknown: " + err.Error()
		}
		return &dump, ""
	}
	var errs []string
	var msg string
	if p.SavedV4, msg = read(p.Layout.V4Path, V4); msg != "" {
		errs = append(errs, msg)
	}
	if hasV6 {
		if p.SavedV6, msg = read(p.Layout.V6Path, V6); msg != "" {
			errs = append(errs, msg)
		}
	}
	p.ReadErr = strings.Join(errs, "; ")
	return p
}

// State returns the last state that was read. --check uses it for the facts
// that are about iptables rather than the generic model.
func (r *Real) State() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

// SnapshotRuleset captures the filter table of both families as restore files,
// which is what the staged apply's rollback replays.
func (r *Real) SnapshotRuleset(ctx context.Context) (string, error) {
	v4, err := r.read(ctx, V4.SaveBinary(), "-t", TableFilter)
	if err != nil {
		return "", err
	}
	v6 := ""
	if r.State().HasV6 {
		if v6, err = r.read(ctx, V6.SaveBinary(), "-t", TableFilter); err != nil {
			return "", err
		}
	}
	return JoinSnapshot(v4, v6), nil
}

// StagingDialect is how the staged apply runs on this backend.
func (r *Real) StagingDialect() staging.Dialect {
	return Dialect{HasV6: r.State().HasV6}
}

// PreparePersist builds the persist change and the diff it would make to the
// saved files, from a fresh read: the file is compared with what is running
// now, not with what was on screen.
func (r *Real) PreparePersist(ctx context.Context) (firewall.Change, string, error) {
	state, err := r.readState(ctx, false)
	if err != nil {
		return firewall.Change{}, "", err
	}
	change, err := BuildPersist(state)
	if err != nil {
		return firewall.Change{}, "", err
	}
	return change, PersistDiff(state), nil
}

// PersistState is the persistence part of the last Load, for the header.
func (r *Real) PersistState() Persistence { return r.State().Persistence }

// PersistDiff renders what persisting would change in the saved files: a
// unified diff per family between the file as it stands and the running rules,
// counters and generated-by comments left out on both sides.
func PersistDiff(state State) string {
	p := state.Persistence
	var parts []string
	pairs := []struct {
		family Family
		saved  *Dump
		path   string
	}{{V4, p.SavedV4, p.Layout.V4Path}}
	if state.HasV6 {
		pairs = append(pairs, struct {
			family Family
			saved  *Dump
			path   string
		}{V6, p.SavedV6, p.Layout.V6Path})
	}
	for _, pair := range pairs {
		old := ""
		if pair.saved != nil {
			old = Comparable(*pair.saved)
		}
		diff := nftables.UnifiedDiff(old, Comparable(state.Dump(pair.family)),
			pair.path, "running "+pair.family.Binary()+" rules")
		if diff != "" {
			parts = append(parts, strings.TrimRight(diff, "\n"))
		}
	}
	return strings.Join(parts, "\n")
}

// BuildAddRule creates a rule in the chain the group names.
func (r *Real) BuildAddRule(group string, spec firewall.RuleSpec) (firewall.Change, error) {
	return r.State().BuildAddRule(group, spec)
}

// BuildDeleteRule removes the selected rule.
func (r *Real) BuildDeleteRule(group string, rule firewall.Rule) (firewall.Change, error) {
	return r.State().BuildDeleteRule(group, rule)
}

// BuildSetEnabled always refuses: iptables has no on/off switch.
func (r *Real) BuildSetEnabled(bool) (firewall.Change, error) {
	return firewall.Change{}, errorf("%s", capabilities.EnableHint)
}

// BuildReload always refuses. Re-applying the saved file would replace the
// rules on screen with a file this tool has not shown; the persist diff (W) is
// the way to compare the two.
func (r *Real) BuildReload() (firewall.Change, error) {
	return firewall.Change{}, errorf("there is nothing to reload: an iptables " +
		"command takes effect the moment it runs, and restoring the saved file " +
		"would replace the rules on screen with one this tool has not shown you; " +
		"W shows the difference between the two")
}

// BuildSetPolicy changes the policy of the chain a group shows.
func (r *Real) BuildSetPolicy(group string, _ firewall.PolicyDirection,
	policy firewall.Policy) (firewall.Change, error) {
	return r.State().BuildSetPolicy(group, policy)
}

// BuildSetLogging always refuses: iptables logs with rules, not a level.
func (r *Real) BuildSetLogging(string) (firewall.Change, error) {
	return firewall.Change{}, errorf("iptables has no logging level: logging is " +
		"a LOG rule in a chain")
}

// Extras reports that iptables has no actions beyond the common set.
func (r *Real) Extras(_ firewall.Model, _ string) []firewall.Extra { return nil }

// BuildExtra always fails: iptables offers no extra actions.
func (r *Real) BuildExtra(_, id string, _ []string) (firewall.Change, error) {
	return firewall.Change{}, errorf("no extra action %q", id)
}
