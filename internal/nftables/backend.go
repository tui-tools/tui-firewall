package nftables

import (
	"context"
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

	// mu guards ruleset, which is the state the command builders decide
	// against: which chains exist, which of them have a policy, how many
	// rules use each alias. It is replaced wholesale by Load.
	mu      sync.Mutex
	ruleset Ruleset
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
	return &Real{run: r}, nil
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
	r.mu.Unlock()
	return Model(ruleset), nil
}

// Ruleset returns the last ruleset that was read. --check uses it for the
// facts that are about nftables rather than about the generic model.
func (r *Real) Ruleset() Ruleset {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ruleset
}

// Run executes a previewed change.
func (r *Real) Run(ctx context.Context, change firewall.Change) (string, error) {
	return firewall.RunChange(ctx, r.run, change)
}

// BuildAddRule creates a rule in the chain the group names.
func (r *Real) BuildAddRule(group string, spec firewall.RuleSpec) (firewall.Change, error) {
	return r.Ruleset().AddRule(group, spec)
}

// BuildDeleteRule removes the selected row.
func (r *Real) BuildDeleteRule(group string, rule firewall.Rule) (firewall.Change, error) {
	return r.Ruleset().DeleteRule(group, rule)
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
