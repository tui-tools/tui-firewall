package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tui-tools/tui-firewall/internal/backends"
	"github.com/tui-tools/tui-firewall/internal/nftables"
	"github.com/tui-tools/tui-firewall/internal/nftables/staging"
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
	// Why this backend was chosen is the first thing a firewall bug report
	// needs, and on a machine carrying more than one firewall it is the fact
	// nobody can reconstruct afterwards.
	selection := selectionDetail(cfg, opts)

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
	if selection != "" {
		info.Extra = append(info.Extra, report.Field{
			Key: "selected because", Value: selection,
		})
	}
	// The nftables backend answers a question the others do not have: whether
	// the ruleset on this machine is somebody else's. It is read from the
	// ruleset, so it is only added when the ruleset could be read at all.
	if backendName == backends.BackendNftables && !opts.demo.on {
		if line := describeNftables(cfg); line != "" {
			info.Extra = append(info.Extra, report.Field{
				Key: "nft ruleset", Value: line,
			})
		}
	}
	if selectError != "" {
		info.Extra = append(info.Extra, report.Field{
			Key: "backend error", Value: selectError,
		})
	}

	_, err := io.WriteString(out, report.Render(info))
	return err
}

// describeNftables reports what the loaded ruleset says about itself: the nft
// that printed it, whether the table this tool owns is there, and whether
// something else is managing the rest. It never fails: a ruleset that cannot
// be read is simply a line the report does not carry, because the missing
// privilege is already reported elsewhere.
func describeNftables(cfg config.Config) string {
	backend, err := nftables.NewReal(cfg.SudoPrefix())
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := backend.Load(ctx); err != nil {
		return ""
	}
	ruleset := backend.Ruleset()
	parts := []string{
		fmt.Sprintf("nft %s, schema %d, %d tables, %d base chains",
			ruleset.Version, ruleset.SchemaVersion,
			len(ruleset.Tables), len(ruleset.BaseChains())),
	}
	if _, ok := ruleset.Table(nftables.OwnTable); ok {
		parts = append(parts, "table "+nftables.OwnTable.String()+" present")
	} else {
		parts = append(parts, "table "+nftables.OwnTable.String()+" absent")
	}
	if management := nftables.DetectManagement(ruleset); management.Managed() {
		parts = append(parts, "read-only: "+management.Detail)
	}
	// Staging is always available on this backend; a report says so, with the
	// keep-confirmation window a batch would apply under, because "does this
	// build have the atomic apply" is a question a bug report has to answer.
	parts = append(parts, fmt.Sprintf("staging available (%.0fs keep window)",
		staging.DefaultTimeout.Seconds()))
	return strings.Join(parts, "; ")
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
