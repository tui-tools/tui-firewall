// Package firewalld is the placeholder for the firewalld (firewall-cmd)
// implementation of firewall.Backend. It compiles and satisfies the interface
// today, but every operation reports ErrNotImplemented; tui-firewall only selects it
// when the user asks for it explicitly, so the error is visible instead of
// silent.
//
// # Planned mapping
//
// firewalld is zone-based, so it maps onto the generic model as follows:
//
//   - Model.Groups: one firewall.Group per zone, from `firewall-cmd
//     --get-zones`; the active zones (`--get-active-zones`) are listed first
//     and their interfaces go in Group.Description.
//   - Group.Default: the zone target (`--zone=Z --get-target`: default,
//     ACCEPT, REJECT, DROP) goes in Policies.Target, exposed through the
//     single policy slot firewall.PolicyTarget. firewalld has no global
//     incoming/outgoing/routed policies, so those slots stay empty.
//   - Group.Rules: the union of the zone's services (`--list-services`),
//     ports (`--list-ports`), forward ports and rich rules
//     (`--list-rich-rules`). A service becomes a Rule with Service set; a port
//     becomes a Rule with Ports/Proto; a rich rule is parsed as far as it
//     decomposes and always keeps its original text in Rule.Raw, which is also
//     its Rule.ID (that is what `--remove-rich-rule=` takes back).
//   - Model.Services: `firewall-cmd --get-services`.
//   - Model.Enabled: whether the firewalld service is running
//     (`firewall-cmd --state`). Logging maps to `--get-log-denied`.
//   - Mutations: `--permanent` plus `--reload`, so a change survives a reboot;
//     the confirm dialog will show both commands.
package firewalld

import (
	"context"
	"errors"
	"os/exec"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// ErrNotImplemented reports that the firewalld backend is not written yet.
var ErrNotImplemented = errors.New(
	"the firewalld backend is not implemented yet; " +
		"set backend = \"ufw\" in the config file, or use --demo")

// Available reports whether firewall-cmd is installed on this host. The
// detector uses it so `backend = "auto"` can explain what it found.
func Available() bool {
	_, err := exec.LookPath("firewall-cmd")
	return err == nil
}

// Backend is the not-yet-implemented firewalld backend. It exists so the rest
// of tui-firewall can be written against the interface only.
type Backend struct{}

// New returns the stub backend.
func New() *Backend { return &Backend{} }

// Name identifies the backend.
func (b *Backend) Name() string { return "firewalld" }

// Describe names the backend for the status line.
func (b *Backend) Describe() string { return "firewalld (not implemented)" }

// Capabilities reports the options the future implementation will support.
func (b *Backend) Capabilities() firewall.Capabilities {
	return firewall.Capabilities{
		Actions: []firewall.Action{
			firewall.ActionAllow, firewall.ActionDeny, firewall.ActionReject,
		},
		Directions: []firewall.Direction{firewall.DirIn},
		Policies: []firewall.Policy{
			firewall.PolicyAllow, firewall.PolicyDeny, firewall.PolicyReject,
		},
		LogLevels:        []string{"off", "all", "unicast", "broadcast", "multicast"},
		SupportsInsert:   false,
		SupportsComments: false,
		SupportsRouted:   false,
		SupportsLogging:  true,
		ServiceLabel:     "Service",
		GroupLabel:       "Zone",
	}
}

// Preview renders the command line, matching the Backend contract.
func (b *Backend) Preview(cmd firewall.Command) string { return cmd.String() }

// Load reports ErrNotImplemented.
func (b *Backend) Load(_ context.Context) (firewall.Model, error) {
	return firewall.Model{}, ErrNotImplemented
}

// Run reports ErrNotImplemented.
func (b *Backend) Run(_ context.Context, _ firewall.Command) (string, error) {
	return "", ErrNotImplemented
}

// BuildAddRule reports ErrNotImplemented.
func (b *Backend) BuildAddRule(_ string, _ firewall.RuleSpec) (firewall.Command, error) {
	return firewall.Command{}, ErrNotImplemented
}

// BuildDeleteRule reports ErrNotImplemented.
func (b *Backend) BuildDeleteRule(_ string, _ firewall.Rule) (firewall.Command, error) {
	return firewall.Command{}, ErrNotImplemented
}

// BuildSetEnabled reports ErrNotImplemented.
func (b *Backend) BuildSetEnabled(_ bool) (firewall.Command, error) {
	return firewall.Command{}, ErrNotImplemented
}

// BuildReload reports ErrNotImplemented.
func (b *Backend) BuildReload() (firewall.Command, error) {
	return firewall.Command{}, ErrNotImplemented
}

// BuildSetPolicy reports ErrNotImplemented.
func (b *Backend) BuildSetPolicy(_ string, _ firewall.PolicyDirection,
	_ firewall.Policy) (firewall.Command, error) {
	return firewall.Command{}, ErrNotImplemented
}

// BuildSetLogging reports ErrNotImplemented.
func (b *Backend) BuildSetLogging(_ string) (firewall.Command, error) {
	return firewall.Command{}, ErrNotImplemented
}
