package ufw

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/edimarlnx/tui-tools/internal/firewall"
)

// ErrNotAvailable reports that the ufw backend cannot be used on this machine
// (ufw missing, or no non-interactive privilege escalation).
var ErrNotAvailable = errors.New("ufw backend not available")

// defaultTimeout bounds every ufw invocation so a stuck command cannot freeze
// the UI.
const defaultTimeout = 15 * time.Second

// Real drives the ufw binary on the host. It satisfies firewall.Backend.
type Real struct {
	// Bin is the resolved ufw executable.
	Bin string
	// Privilege is the escalation prefix ("sudo", "-n"); empty when running
	// as root or when escalation is disabled.
	Privilege []string
	// Timeout bounds each invocation; defaults to defaultTimeout.
	Timeout time.Duration
}

// Available reports whether ufw is installed on this host.
func Available() bool {
	_, err := lookUfw()
	return err == nil
}

// NewReal locates ufw and, when not running as root, validates the configured
// privilege prefix. sudoPrefix comes from the config file ("sudo -n"); pass
// nil to run ufw directly. Errors wrap ErrNotAvailable and carry a message
// meant to be shown verbatim.
func NewReal(sudoPrefix []string) (*Real, error) {
	bin, err := lookUfw()
	if err != nil {
		return nil, err
	}
	r := &Real{Bin: bin, Timeout: defaultTimeout}
	if os.Geteuid() == 0 || len(sudoPrefix) == 0 {
		return r, nil
	}
	resolved, err := exec.LookPath(sudoPrefix[0])
	if err != nil {
		return nil, fmt.Errorf(
			"%w: not running as root and %q was not found; re-run with sudo, "+
				"or use --demo to explore the UI", ErrNotAvailable, sudoPrefix[0])
	}
	r.Privilege = append([]string{resolved}, sudoPrefix[1:]...)
	return r, nil
}

// lookUfw finds the ufw binary, including the sbin paths that are commonly
// missing from a non-root PATH.
func lookUfw() (string, error) {
	if bin, err := exec.LookPath("ufw"); err == nil {
		return bin, nil
	}
	for _, candidate := range []string{"/usr/sbin/ufw", "/sbin/ufw", "/usr/local/sbin/ufw"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf(
		"%w: the ufw command was not found; install it "+
			"(apt install ufw / pacman -S ufw), or use --demo to explore the UI",
		ErrNotAvailable)
}

// Name identifies the backend.
func (r *Real) Name() string { return "ufw" }

// Describe names the backend for the status line.
func (r *Real) Describe() string {
	if len(r.Privilege) == 0 {
		return "ufw (root)"
	}
	return "ufw via " + strings.Join(r.Privilege, " ")
}

// Capabilities reports what this backend supports.
func (r *Real) Capabilities() firewall.Capabilities { return capabilities }

// argv builds the full command line, replacing the "ufw" placeholder in
// Argv[0] with the resolved binary and prefixing the privilege wrapper.
func (r *Real) argv(cmd firewall.Command) (bin string, args []string) {
	rest := cmd.Argv
	if len(rest) > 0 && rest[0] == "ufw" {
		rest = rest[1:]
	}
	if len(r.Privilege) == 0 {
		return r.Bin, rest
	}
	return r.Privilege[0], append(append([]string{}, r.Privilege[1:]...),
		append([]string{r.Bin}, rest...)...)
}

// Preview renders the exact command line Run will execute.
func (r *Real) Preview(cmd firewall.Command) string {
	if len(r.Privilege) == 0 {
		return cmd.String()
	}
	return strings.Join(r.Privilege, " ") + " " + cmd.String()
}

// exec runs one ufw invocation and returns its combined output.
func (r *Real) exec(ctx context.Context, cmd firewall.Command) (string, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	bin, args := r.argv(cmd)
	c := exec.CommandContext(ctx, bin, args...) //nolint:gosec // argv is built by this package
	// LANG=C keeps ufw's output in the English form the parsers expect.
	c.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")
	out, err := c.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, r.wrapErr(cmd, text, err)
	}
	return text, nil
}

// wrapErr turns an exec failure into a message worth showing in a status line.
func (r *Real) wrapErr(cmd firewall.Command, output string, err error) error {
	preview := r.Preview(cmd)
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("`%s` timed out", preview)
	}
	if len(r.Privilege) > 0 && strings.Contains(output, "password is required") {
		return fmt.Errorf("sudo needs a password: run `sudo -v` in another " +
			"terminal, then retry")
	}
	if output != "" {
		return fmt.Errorf("`%s` failed: %s", preview, firstLine(output))
	}
	return fmt.Errorf("`%s` failed: %w", preview, err)
}

// firstLine keeps status-line errors to a single line.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Load reads status (verbose + numbered) and the app profile list.
func (r *Real) Load(ctx context.Context) (firewall.Model, error) {
	verboseOut, err := r.exec(ctx, firewall.Command{Argv: []string{"ufw", "status", "verbose"}})
	if err != nil {
		return firewall.Model{}, err
	}
	numberedOut, err := r.exec(ctx, firewall.Command{Argv: []string{"ufw", "status", "numbered"}})
	if err != nil {
		return firewall.Model{}, err
	}
	model := MergeModels(ParseStatus(verboseOut), ParseStatus(numberedOut))
	// A missing app profile list is not fatal: the rule form simply offers no
	// profile picker.
	appsCmd := firewall.Command{Argv: []string{"ufw", "app", "list"}}
	if appsOut, appErr := r.exec(ctx, appsCmd); appErr == nil {
		model.Services = ParseAppList(appsOut)
	}
	return model, nil
}

// Run executes a previewed command.
func (r *Real) Run(ctx context.Context, cmd firewall.Command) (string, error) {
	return r.exec(ctx, cmd)
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
