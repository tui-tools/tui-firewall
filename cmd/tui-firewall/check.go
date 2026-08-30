package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/tui-tools/tui-firewall/internal/backends"
	"github.com/tui-tools/tui-firewall/internal/firewall"
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
	// Backends is what the detector saw for every backend this tool knows,
	// installed or not, so a reader can tell "firewalld was chosen" from
	// "ufw is not here" without running the detection again.
	Backends []backends.State `json:"backends"`
	// Model is the parsed state in full.
	Model firewall.Model `json:"model"`
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
	states []backends.State, out io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()

	model, err := backend.Load(ctx)
	if err != nil {
		return fmt.Errorf("%s backend read failed: %w", backend.Name(), err)
	}

	report := checkReport{
		Tool:     toolName,
		Version:  version,
		Backend:  backend.Name(),
		Describe: backend.Describe(),
		Enabled:  model.Enabled,
		Logging:  model.Logging,
		Groups:   len(model.Groups),
		Compat:   backendCompat,
		Backends: states,
		Model:    model,
	}
	for _, group := range model.Groups {
		report.Rules += len(group.Rules)
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
