package main

import (
	"os"
	"testing"

	"github.com/edimarlnx/tui-tools/internal/config"
)

func TestParseFlags(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer func() { _ = devNull.Close() }()

	opts, err := parseFlags([]string{"--demo", "--backend", "ufw"}, devNull)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if !opts.demo || opts.backend != "ufw" {
		t.Errorf("opts = %+v", opts)
	}
	if opts.sudoSet {
		t.Error("sudoSet should be false when -sudo is absent")
	}
}

func TestApplyOverrides(t *testing.T) {
	cfg := config.Default()
	applyOverrides(&cfg, options{backend: "firewalld", themePath: "/t/colors.toml"})
	if cfg.Backend != config.BackendFirewalld || cfg.Theme != "/t/colors.toml" {
		t.Errorf("cfg = %+v", cfg)
	}
	// An untouched -sudo must not clear the configured prefix.
	if cfg.Sudo != "sudo -n" {
		t.Errorf("Sudo = %q, want the config value", cfg.Sudo)
	}

	// An explicit empty -sudo disables escalation.
	cfg = config.Default()
	applyOverrides(&cfg, options{sudoSet: true, sudo: ""})
	if cfg.Sudo != "" {
		t.Errorf("Sudo = %q, want empty", cfg.Sudo)
	}
	if got := cfg.SudoPrefix(); got != nil {
		t.Errorf("SudoPrefix = %q, want nil", got)
	}
}

func TestPickBackendDemo(t *testing.T) {
	backend, err := pickBackend(config.Default(), options{demo: true})
	if err != nil {
		t.Fatalf("pickBackend: %v", err)
	}
	if backend.Name() != "demo" {
		t.Errorf("Name = %q, want demo", backend.Name())
	}
}
