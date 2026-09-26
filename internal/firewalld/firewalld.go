// Package firewalld implements firewall.Backend on top of firewalld, driven
// through `firewall-cmd`. It parses firewall-cmd's text output into the
// generic model and builds the exact argv used to change it; as with every
// backend in this tool, nothing here mutates the system implicitly.
//
// # Why firewall-cmd and not D-Bus
//
// firewalld's real interface is D-Bus, and a Go client could speak it. This
// backend deliberately does not. The promise tui-firewall makes is that the
// command line it shows you is the command line that runs — a promise a D-Bus
// method call cannot keep, because there is no command line to show. Driving
// `firewall-cmd` costs a process per read and buys a preview the user can
// copy, paste and run themselves, which is the whole point of the tool.
//
// A process per read is not free: every firewall-cmd is a Python interpreter
// that imports the firewalld client before its D-Bus calls, several hundred
// milliseconds on a small VM. So Load asks for whole listings rather than
// piecemeal answers, and starts its reads together; see loadSnapshot.
//
// # The mapping
//
// firewalld is zone-based, and a zone holds several species of entry at once,
// so it maps onto the generic model like this:
//
//   - Model.Groups: one firewall.Group per zone, from `--list-all-zones`,
//     ordered default zone first, then the other active zones, then the
//     rest. Which zone is the default and which are active comes from the
//     "(default, active)" flags of that same listing (`--get-default-zone`
//     and `--get-active-zones` only on a firewalld that does not print
//     them). Policy objects (`--list-all-policies`) follow as further
//     groups, named with PolicyPrefix.
//   - Group.Default.Target: the zone target, exposed through the single
//     policy slot firewall.PolicyTarget. firewalld has no global
//     incoming/outgoing/routed policies, so those slots stay empty.
//   - Group.Rules: every entry of the zone — interfaces, bound sources,
//     services, ports, protocols, source ports, forward ports, masquerading,
//     intra-zone forwarding, ICMP blocks and rich rules — each carrying its
//     Kind, which is what tells the delete command which flag to use. A rich
//     rule keeps its own text in Rule.Raw, because that is the string
//     `--remove-rich-rule` takes back.
//   - Rule.Note: firewalld keeps a running configuration and a permanent one.
//     Both are read (`--list-all-zones` and the same with `--permanent`) and
//     an entry present in only one is marked "runtime only" or
//     "permanent only".
//   - Model.Services: `--get-services`.
//   - Model.Enabled: `--state`. Model.Logging: `--get-log-denied`.
//   - Model.Warning: panic mode, from `--query-panic`.
//   - Mutations: the runtime command and the same command with `--permanent`,
//     both shown in the confirm dialog. No reload, so no connection is
//     dropped. The one exception is a zone target, which firewalld can only
//     set permanently; that change says so and reloads.
package firewalld

import (
	"context"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-kit/runner"
)

// searchPaths are the sbin locations a non-root PATH commonly omits.
var searchPaths = []string{"/usr/sbin/firewall-cmd", "/sbin/firewall-cmd"}

// installHint is appended to the "not found" error.
const installHint = "install it (dnf install firewalld / apt install firewalld), " +
	"or use --demo to explore the UI"

// maxPolicies bounds the per-policy reads. A machine with more policy objects
// than this has a generated configuration, and listing them all would cost
// more startup time than the listing is worth.
const maxPolicies = 32

// Available reports whether firewall-cmd is installed on this host. The
// backend detector uses it so `backend = "auto"` can explain what it found.
func Available() bool { return runner.Available(Bin, searchPaths...) }

// Real drives firewall-cmd on the host. It satisfies firewall.Backend.
type Real struct {
	run *runner.Runner
}

// New locates firewall-cmd and, when not running as root, validates the
// configured privilege prefix. sudoPrefix comes from the configuration
// ("sudo -n"); pass nil to run firewall-cmd directly.
func New(sudoPrefix []string) (*Real, error) {
	r, err := runner.New(runner.Options{
		Bin:         Bin,
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
func (r *Real) Name() string { return Name }

// Describe names the backend for the status line.
func (r *Real) Describe() string { return r.run.Describe() }

// Capabilities reports what this backend supports.
func (r *Real) Capabilities() firewall.Capabilities { return capabilities }

// Preview renders the exact command lines Run will execute.
func (r *Real) Preview(change firewall.Change) string {
	return firewall.PreviewChange(r.run, change)
}

// Run executes a previewed change.
func (r *Real) Run(ctx context.Context, change firewall.Change) (string, error) {
	return firewall.RunChange(ctx, r.run, change)
}

// Load reads the whole firewalld state: the daemon's own status, the runtime
// and permanent zone listings, the policy objects and the global settings.
//
// Only `--state` is fatal. Everything else degrades: a firewalld too old for
// policy objects, or one that refuses a read, loses that part of the picture
// rather than the whole screen. The reads themselves, and why they run
// together rather than one after another, are described on loadSnapshot.
func (r *Real) Load(ctx context.Context) (firewall.Model, error) {
	snapshot, running := loadSnapshot(ctx, r.read)
	if !running {
		// firewall-cmd cannot read anything while the daemon is down, so
		// there is no partial picture to show — only the reason.
		return firewall.Model{
			Backend: Name,
			Warning: "firewalld is not running; start it with " +
				"`systemctl start firewalld` and press R",
		}, nil
	}
	return BuildModel(snapshot), nil
}

// read runs one firewall-cmd read. It is the only place the real backend
// reaches the runner for a read, so loadSnapshot can be driven by a table of
// captured outputs in the tests.
func (r *Real) read(ctx context.Context, args ...string) (string, error) {
	return r.run.Read(ctx, append([]string{Bin}, args...)...)
}

// firstLine trims a one-value answer.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// BuildAddRule creates an entry in a zone.
func (r *Real) BuildAddRule(group string, spec firewall.RuleSpec) (firewall.Change, error) {
	return BuildAddRule(group, spec)
}

// BuildDeleteRule removes an entry from a zone.
func (r *Real) BuildDeleteRule(group string, rule firewall.Rule) (firewall.Change, error) {
	return BuildDeleteRule(group, rule)
}

// BuildSetEnabled reports that firewalld is a system service.
func (r *Real) BuildSetEnabled(enabled bool) (firewall.Change, error) {
	return BuildSetEnabled(enabled)
}

// BuildReload re-applies the permanent configuration.
func (r *Real) BuildReload() (firewall.Change, error) { return BuildReload() }

// BuildSetPolicy changes a zone target.
func (r *Real) BuildSetPolicy(group string, slot firewall.PolicyDirection,
	policy firewall.Policy) (firewall.Change, error) {
	return BuildSetPolicy(group, slot, policy)
}

// BuildSetLogging changes the global log-denied value.
func (r *Real) BuildSetLogging(level string) (firewall.Change, error) {
	return BuildSetLogging(level)
}

// Extras lists the firewalld-specific actions.
func (r *Real) Extras(model firewall.Model, group string) []firewall.Extra {
	return Extras(model, group)
}

// BuildExtra builds one of those actions.
func (r *Real) BuildExtra(group, id string, args []string) (firewall.Change, error) {
	return BuildExtra(group, id, args)
}
