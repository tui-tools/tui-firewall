package ufw

import (
	"context"

	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-kit/runner"
)

// ErrNotAvailable reports that the ufw backend cannot be used on this machine
// (ufw missing, or no non-interactive privilege escalation).
var ErrNotAvailable = runner.ErrNotAvailable

// searchPaths are the sbin locations a non-root PATH commonly omits.
var searchPaths = []string{"/usr/sbin/ufw", "/sbin/ufw", "/usr/local/sbin/ufw"}

// installHint is appended to the "not found" error.
const installHint = "install it (apt install ufw / pacman -S ufw), " +
	"or use --demo to explore the UI"

// Real drives the ufw binary on the host. It satisfies firewall.Backend.
//
// Everything about actually reaching the machine — resolving the binary,
// applying the privilege prefix, bounding each call, turning a failure into
// one readable line — belongs to the kit runner. What is left here is the
// translation between ufw's output and the backend-agnostic model.
type Real struct {
	run *runner.Runner
}

// Available reports whether ufw is installed on this host.
func Available() bool { return runner.Available("ufw", searchPaths...) }

// NewReal locates ufw and, when not running as root, validates the configured
// privilege prefix. sudoPrefix comes from the configuration ("sudo -n"); pass
// nil to run ufw directly. Errors wrap ErrNotAvailable and carry a message
// meant to be shown verbatim.
func NewReal(sudoPrefix []string) (*Real, error) {
	r, err := runner.New(runner.Options{
		Bin:         "ufw",
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
func (r *Real) Name() string { return "ufw" }

// Describe names the backend for the status line.
func (r *Real) Describe() string { return r.run.Describe() }

// Capabilities reports what this backend supports.
func (r *Real) Capabilities() firewall.Capabilities { return capabilities }

// Preview renders the exact command line Run will execute.
func (r *Real) Preview(cmd firewall.Command) string { return r.run.Preview(cmd) }

// Load reads status (verbose + numbered) and the app profile list. Every ufw
// read needs root, so these go through the runner's privileged read path.
func (r *Real) Load(ctx context.Context) (firewall.Model, error) {
	verboseOut, err := r.run.Read(ctx, "ufw", "status", "verbose")
	if err != nil {
		return firewall.Model{}, err
	}
	numberedOut, err := r.run.Read(ctx, "ufw", "status", "numbered")
	if err != nil {
		return firewall.Model{}, err
	}
	model := MergeModels(ParseStatus(verboseOut), ParseStatus(numberedOut))
	// A missing app profile list is not fatal: the rule form simply offers no
	// profile picker.
	if appsOut, appErr := r.run.Read(ctx, "ufw", "app", "list"); appErr == nil {
		model.Services = ParseAppList(appsOut)
	}
	return model, nil
}

// Run executes a previewed command.
func (r *Real) Run(ctx context.Context, cmd firewall.Command) (string, error) {
	return r.run.Run(ctx, cmd)
}

// BuildAddRule creates a rule.
func (r *Real) BuildAddRule(group string, spec firewall.RuleSpec) (firewall.Command, error) {
	return BuildAddRule(group, spec)
}

// BuildDeleteRule removes a rule.
func (r *Real) BuildDeleteRule(group string, rule firewall.Rule) (firewall.Command, error) {
	return BuildDeleteRule(group, rule)
}

// BuildSetEnabled turns the firewall on or off.
func (r *Real) BuildSetEnabled(enabled bool) (firewall.Command, error) {
	return BuildSetEnabled(enabled)
}

// BuildReload re-applies the rule set.
func (r *Real) BuildReload() (firewall.Command, error) { return BuildReload() }

// BuildSetPolicy changes one default policy.
func (r *Real) BuildSetPolicy(group string, slot firewall.PolicyDirection,
	policy firewall.Policy) (firewall.Command, error) {
	return BuildSetPolicy(group, slot, policy)
}

// BuildSetLogging changes the logging level.
func (r *Real) BuildSetLogging(level string) (firewall.Command, error) {
	return BuildSetLogging(level)
}
