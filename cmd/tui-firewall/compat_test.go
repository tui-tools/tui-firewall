package main

import (
	"context"
	"strings"
	"testing"

	tuifirewall "github.com/tui-tools/tui-firewall"
	"github.com/tui-tools/tui-firewall/internal/backends"
	"github.com/tui-tools/tui-firewall/internal/ufw"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/manifest"
	"github.com/tui-tools/tui-kit/theme"
)

// The embedded manifest is the source the header reads, so it has to parse and
// describe the backend the tool actually drives.
func TestEmbeddedManifestDeclaresUfw(t *testing.T) {
	m, err := manifest.Load(tuifirewall.ManifestJSON)
	if err != nil {
		t.Fatalf("the embedded tool.json does not parse: %v", err)
	}
	if m.Name != toolName {
		t.Errorf("manifest name = %q, want %q", m.Name, toolName)
	}
	backend, ok := m.Backend("ufw")
	if !ok {
		t.Fatal("no ufw backend in the manifest")
	}
	if len(backend.VersionCommand) == 0 || backend.Minimum == "" {
		t.Errorf("ufw backend is incomplete: %+v", backend)
	}
}

// --demo must never probe the host: the version on screen would describe a
// machine the demo is not driving.
func TestProbeCompatSkipsDemo(t *testing.T) {
	got := probeCompat(context.Background(), "ufw", true)
	if got.Backend != "" || got.Version != "" {
		t.Errorf("demo probe = %+v, want the zero result", got)
	}
}

// A backend the manifest does not describe is not an error, it is simply
// nothing to show.
func TestProbeCompatUnknownBackend(t *testing.T) {
	got := probeCompat(context.Background(), "iptables", false)
	if got.Backend != "" {
		t.Errorf("unknown backend = %+v, want the zero result", got)
	}
}

// Every backend the tool can select has a block in the manifest, or the
// header would quietly stop saying which version it is driving.
func TestEveryBackendIsDescribedByTheManifest(t *testing.T) {
	m, err := manifest.Load(tuifirewall.ManifestJSON)
	if err != nil {
		t.Fatalf("loading the manifest: %v", err)
	}
	for _, name := range backends.Names() {
		if name == backends.BackendAuto {
			continue
		}
		backend, ok := m.Backend(name)
		if !ok {
			t.Errorf("the manifest describes no backend %q", name)
			continue
		}
		if backend.Minimum == "" {
			t.Errorf("backend %q declares no minimum version", name)
		}
	}
}

// The whole point of the feature: the version reaches the header.
func TestHeaderShowsTheBackendVersion(t *testing.T) {
	a, _ := newTestApp(t, 100, 30)
	if got := a.View(); !strings.Contains(got, "ufw 0.36.2") {
		t.Errorf("the header should carry the probed version, got:\n%s", got)
	}

	a.backendCompat = testCompat(t, "ufw 0.37.0")
	if got := a.View(); !strings.Contains(got, "ufw 0.37.0 (untested)") {
		t.Errorf("an untested version should say so, got:\n%s", got)
	}

	a.backendCompat = testCompat(t, "ufw 0.35")
	if got := a.View(); !strings.Contains(got, "below minimum 0.36") {
		t.Errorf("a version below the minimum should say so, got:\n%s", got)
	}
}

// A tool that could not read the version still renders a header.
func TestHeaderWithoutAProbe(t *testing.T) {
	a, _ := newTestApp(t, 100, 30)
	a.backendCompat = compat.Result{}
	_ = theme.TokyoNight()
	if got := a.View(); strings.Contains(got, "backend:") {
		t.Errorf("no probe means no backend fact, got:\n%s", got)
	}
}

// Rule comments are a ufw 0.35 feature. The form must drop the field on an
// older machine rather than build a command ufw refuses.
func TestRuleCommentsAreGatedOnTheUfwVersion(t *testing.T) {
	a, _ := newTestApp(t, 100, 30)
	if !a.caps.SupportsComments {
		t.Error("0.36.2 supports rule comments")
	}

	old := newApp(ufw.NewFake(), theme.FromPalette(theme.TokyoNight()),
		testCompat(t, "ufw 0.34"))
	if old.caps.SupportsComments {
		t.Error("0.34 has no rule comments, so the form must not offer them")
	}
}
