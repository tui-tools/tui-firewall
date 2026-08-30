// Command tui-firewall is a terminal UI for the system firewall. It shows the
// current rules and previews the exact command line of every change before
// running it. ufw and firewalld are both driven, behind one generic interface,
// and the UI never builds a command line for either.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-firewall/internal/backends"
	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/firewalld"
	"github.com/tui-tools/tui-firewall/internal/ufw"
	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-kit/theme"
)

// toolName is the binary name, which is also the configuration directory:
// /etc/tui-firewall/config.toml and ~/.config/tui-firewall/config.toml.
const toolName = "tui-firewall"

// version is stamped by the release build (-ldflags "-X main.version=…").
var version = "dev"

// defaults declares the configuration keys tui-firewall understands. Only
// these are read from the environment (TUI_FIREWALL_BACKEND, …).
func defaults() map[string]string {
	return map[string]string{
		backends.KeyBackend: backends.BackendAuto,
		config.KeySudo:      "sudo -n",
		config.KeyTheme:     "",
	}
}

// demoFlag is the value of --demo: which backend the in-memory sample
// firewall imitates.
//
// It is a flag.Value rather than a bool so that both spellings work: plain
// `--demo` gives the default backend, and `--demo=firewalld` gives the other
// one. IsBoolFlag is what lets the bare form parse; without it the flag
// package would swallow the next argument as its value.
type demoFlag struct {
	on      bool
	backend string
}

// String renders the flag's current value for the usage text.
func (d *demoFlag) String() string {
	if d == nil || !d.on {
		return ""
	}
	return d.backend
}

// Set accepts the bare form ("true", from `--demo`) and a backend name.
func (d *demoFlag) Set(value string) error {
	d.on = true
	switch value {
	case "", "true":
		d.backend = backends.BackendUFW
		return nil
	case backends.BackendUFW, backends.BackendFirewalld:
		d.backend = value
		return nil
	default:
		return fmt.Errorf("unknown demo backend %q: use %s or %s",
			value, backends.BackendUFW, backends.BackendFirewalld)
	}
}

// IsBoolFlag lets `--demo` stand on its own.
func (d *demoFlag) IsBoolFlag() bool { return true }

// options holds the parsed command line.
type options struct {
	demo        demoFlag
	check       bool
	backend     string
	themePath   string
	sudo        string
	showVersion bool
	// sudoSet records whether -sudo was passed, so `--sudo ""` can disable
	// escalation instead of reading as "not given".
	sudoSet bool
}

// parseFlags defines and reads the command line.
func parseFlags(args []string, out *os.File) (options, error) {
	var opts options
	fs := flag.NewFlagSet("tui-firewall", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Var(&opts.demo, "demo",
		"run against sample data, without touching the system firewall; "+
			"--demo=firewalld shows the firewalld model instead of the ufw one")
	fs.BoolVar(&opts.check, "check", false,
		"read the firewall and print the parsed model as JSON, then exit "+
			"(no UI, no changes); exit 1 if the backend cannot be read")
	fs.StringVar(&opts.backend, "backend", "",
		"firewall backend: auto, ufw or firewalld (overrides the config file)")
	fs.StringVar(&opts.themePath, "theme", "",
		"path to an Omarchy-style colors.toml (overrides the config file)")
	fs.StringVar(&opts.sudo, "sudo", "",
		"privilege escalation prefix, e.g. \"sudo -n\" or \"\" to disable")
	fs.BoolVar(&opts.showVersion, "version", false, "print the version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(out, "tui-firewall — a terminal UI for the system firewall\n\n"+
			"Usage:\n  tui-firewall [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		_, _ = fmt.Fprintf(out, "\nConfiguration is read from %s, then %s, "+
			"then TUI_FIREWALL_* in the environment.\n",
			config.SystemPathFor(toolName), config.UserPathFor(toolName))
	}
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "sudo" {
			opts.sudoSet = true
		}
	})
	return opts, nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tui-firewall:", err)
		os.Exit(1)
	}
}

// run wires the configuration, the backend and the Bubble Tea program.
func run(args []string) error {
	opts, err := parseFlags(args, os.Stdout)
	if err != nil {
		// flag already printed the reason and the usage.
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if opts.showVersion {
		fmt.Println("tui-firewall", version)
		return nil
	}

	cfg, err := config.Load(config.Options{Tool: toolName, Defaults: defaults()})
	if err != nil {
		return err
	}
	applyOverrides(&cfg, opts)
	if err := cfg.OneOf(backends.KeyBackend, backends.Names()...); err != nil {
		return err
	}

	backend, err := pickBackend(cfg, opts)
	if err != nil {
		return err
	}

	// --check is the non-interactive path: it reads the backend and prints,
	// and never starts a terminal program. It is checked after the backend is
	// built so that a machine with no usable firewall fails here with the same
	// message the UI would have shown.
	// The backend version is probed once, here, and used by both paths: the
	// header shows it, --check reports it, and the smoke test records it.
	backendCompat := probeCompat(context.Background(), backend.Name(), opts.demo.on)

	if opts.check {
		return runCheck(backend, backendCompat, backends.Inspect(backend.Name()),
			os.Stdout)
	}

	// The configured theme is handed to the kit through the same variable the
	// user could set by hand, so precedence stays in one place.
	if path := cfg.Theme(); path != "" {
		if err := os.Setenv("TUI_THEME", path); err != nil {
			return err
		}
	}

	program := tea.NewProgram(newApp(backend, theme.New(), backendCompat),
		tea.WithAltScreen())
	_, err = program.Run()
	return err
}

// applyOverrides folds the command line into the configuration, which is the
// last and highest-precedence layer.
func applyOverrides(cfg *config.Config, opts options) {
	if opts.backend != "" {
		cfg.Set(backends.KeyBackend, opts.backend)
	}
	if opts.themePath != "" {
		cfg.Set(config.KeyTheme, opts.themePath)
	}
	// An explicitly empty -sudo disables escalation, so the flag is applied
	// whenever it was passed, empty value included.
	if opts.sudoSet {
		cfg.Set(config.KeySudo, opts.sudo)
	}
}

// pickBackend returns the demo backend or the configured real one. Each
// backend brings its own fake, so `--demo=firewalld` exercises the firewalld
// mapping and command builders rather than a firewalld-flavoured ufw.
func pickBackend(cfg config.Config, opts options) (firewall.Backend, error) {
	if opts.demo.on {
		if opts.demo.backend == backends.BackendFirewalld {
			return firewalld.NewFake(), nil
		}
		return ufw.NewFake(), nil
	}
	return backends.Select(cfg)
}
