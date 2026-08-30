package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/backends"
	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-kit/report"
	"github.com/tui-tools/tui-kit/theme"
)

// runReport prints the block a bug report needs and exits. Everything generic
// — the kit version, the distribution, the kernel, the terminal, where the
// binary came from — is collected by the kit, so the whole family answers
// --report in the same shape. What this function adds is the part only
// tui-firewall knows: which backend was selected, what the compat probe read
// off it, and what the detector saw of the backend it did not pick.
//
// It never reads the firewall. --check is the flag that does that, and it needs
// privileges; a report has to work for a user who cannot get them, because the
// missing privilege may be the bug. For the same reason a machine with no
// firewall at all still gets a report, with the selection error as one of its
// lines: "there is nothing here to drive" is a bug report, not a refusal.
func runReport(cfg config.Config, opts options, out io.Writer) error {
	palette, _ := theme.ResolvePalette()

	var backendName, selectError string
	if backend, err := pickBackend(cfg, opts); err != nil {
		selectError = err.Error()
	} else {
		backendName = backend.Name()
	}

	// The same probe --check and the header use. There is one version probe in
	// this tool and this is it.
	backendCompat := probeCompat(context.Background(), backendName, opts.demo.on)

	info := report.Info{
		Tool:           toolName,
		Version:        version,
		Backend:        backendName,
		BackendVersion: backendCompat.Version,
		BackendDetail:  backendCompat.Detail,
		Demo:           opts.demo.on,
		Sudo:           cfg.String(config.KeySudo, ""),
		Theme:          palette.Name,
	}
	if opts.demo.on {
		// The fake imitates one of the real backends, and which one decides
		// which command builders and which parser the session exercised. It is
		// taken from the flag rather than from the fake's own name, because a
		// fake is free to call itself "demo".
		info.Backend = "demo"
		info.Extra = append(info.Extra, report.Field{
			Key: "demo backend", Value: opts.demo.backend,
		})
	}
	info.Extra = append(info.Extra, report.Field{
		Key: "backends", Value: describeBackends(backends.Inspect(backendName)),
	})
	if selectError != "" {
		info.Extra = append(info.Extra, report.Field{
			Key: "backend error", Value: selectError,
		})
	}

	_, err := io.WriteString(out, report.Render(info))
	return err
}

// describeBackends renders the detector's view of every backend the tool knows
// as one line. A report that says only "firewalld" leaves the reader guessing
// whether ufw was absent or merely stopped, and that difference is most of the
// backend selection bugs.
func describeBackends(states []backends.State) string {
	parts := make([]string, 0, len(states))
	for _, s := range states {
		switch {
		case !s.Installed:
			parts = append(parts, s.Name+" absent")
		case s.Active:
			parts = append(parts, s.Name+" active")
		default:
			parts = append(parts, s.Name+" installed")
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// reportUsage is the flag's one-line help, kept here next to what it prints.
var reportUsage = fmt.Sprintf(
	"print the versions and machine facts a bug report needs, then exit "+
		"(no UI, no privileges, nothing about you: paste it into a %s issue)",
	toolName)
