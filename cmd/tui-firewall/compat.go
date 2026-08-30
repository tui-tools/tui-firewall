package main

import (
	"context"

	tuifirewall "github.com/tui-tools/tui-firewall"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/manifest"
)

// probeCompat reads the version of the backend the tool is about to drive.
//
// The facts it is judged against — the minimum version, the versions the lab
// has actually run against, the caveats that apply to a range — come from the
// repository's own tool.json, embedded in the binary, so there is no second
// copy of them in the code.
//
// It never fails: a backend the manifest does not describe, a manifest that
// cannot be parsed and a missing binary all produce the zero Result, which the
// header renders as nothing at all.
func probeCompat(ctx context.Context, backendName string, demo bool) compat.Result {
	// --demo drives an in-memory firewall; probing the real ufw on the host
	// would report a version that has nothing to do with what is on screen.
	if demo {
		return compat.Result{}
	}
	m, err := manifest.Load(tuifirewall.ManifestJSON)
	if err != nil {
		return compat.Result{}
	}
	backend, ok := m.Backend(backendName)
	if !ok {
		return compat.Result{}
	}
	return compat.Probe(ctx, backend)
}
