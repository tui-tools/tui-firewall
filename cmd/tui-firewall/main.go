// Command fwall is a terminal UI for the system firewall. It shows the
// current rules and previews the exact command line of every change before
// running it. ufw is the backend implemented today; the code is written
// against a generic interface so firewalld can follow.
package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/edimarlnx/tui-tools/internal/backends"
	"github.com/edimarlnx/tui-tools/internal/config"
	"github.com/edimarlnx/tui-tools/internal/firewall"
	"github.com/edimarlnx/tui-tools/internal/ufw"
	"github.com/edimarlnx/tui-tools/pkg/theme"
)

// version is stamped by the release build (-ldflags "-X main.version=…").
var version = "dev"

// options holds the parsed command line.
type options struct {
	demo        bool
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
	fs := flag.NewFlagSet("fwall", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.BoolVar(&opts.demo, "demo", false,
		"run against sample data, without touching the system firewall")
	fs.StringVar(&opts.backend, "backend", "",
		"firewall backend: auto, ufw or firewalld (overrides the config file)")
	fs.StringVar(&opts.themePath, "theme", "",
		"path to an Omarchy-style colors.toml (overrides the config file)")
	fs.StringVar(&opts.sudo, "sudo", "",
		"privilege escalation prefix, e.g. \"sudo -n\" or \"\" to disable")
	fs.BoolVar(&opts.showVersion, "version", false, "print the version and exit")
	fs.Usage = func() {
		fmt.Fprintf(out, "fwall — a terminal UI for the system firewall\n\n"+
			"Usage:\n  fwall [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(out, "\nConfiguration is read from %s then %s.\n",
			config.SystemPath, config.UserPath)
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
		fmt.Fprintln(os.Stderr, "fwall:", err)
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
		fmt.Println("fwall", version)
		return nil
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	applyOverrides(&cfg, opts)
	if err := cfg.Validate(); err != nil {
		return err
	}

	backend, err := pickBackend(cfg, opts)
	if err != nil {
		return err
	}

	// The config theme is exposed to pkg/theme through the same variable the
	// user could set by hand, so precedence stays in one place.
	if cfg.Theme != "" {
		if err := os.Setenv("TUI_THEME", cfg.Theme); err != nil {
			return err
		}
	}

	program := tea.NewProgram(newApp(backend, theme.New()), tea.WithAltScreen())
	_, err = program.Run()
	return err
}

// applyOverrides folds the command line into the configuration.
func applyOverrides(cfg *config.Config, opts options) {
	if opts.backend != "" {
		cfg.Backend = opts.backend
	}
	if opts.themePath != "" {
		cfg.Theme = opts.themePath
	}
	// An explicitly empty -sudo disables escalation, so the flag is applied
	// whenever it was passed, empty value included.
	if opts.sudoSet {
		cfg.Sudo = opts.sudo
	}
}

// pickBackend returns the demo backend or the configured real one.
func pickBackend(cfg config.Config, opts options) (firewall.Backend, error) {
	if opts.demo {
		return ufw.NewFake(), nil
	}
	return backends.Select(cfg)
}
