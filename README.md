<img src="assets/logo.png" alt="tui-firewall" width="240">

A terminal UI for the Linux firewall. It shows the rules you actually have, and
**previews the exact command line of every change before running it**.

`ufw` has no TUI: you get the CLI, or Gufw if you have a desktop. `tui-firewall`
fills the gap on a server or a tiling desktop, in the
[Omarchy](https://omarchy.org) visual style.

![Rules table](docs/screenshots/tui-firewall-main.png)

> **Status: early, under validation.** An independent tool that follows the
> Omarchy visual style; it is **not** part of the Omarchy project and not
> endorsed by its maintainers. Expect rough edges.

## Install

Grab a static binary from the [releases](https://github.com/tui-tools/tui-firewall/releases),
or build it yourself:

```sh
git clone https://github.com/tui-tools/tui-firewall
cd tui-firewall
make build
sudo install -m0755 bin/tui-firewall /usr/local/bin/tui-firewall
```

One static binary, no daemon, no state of its own. Nothing keeps running after
you quit.

## Try it without root

```sh
tui-firewall --demo
```

`--demo` runs against an in-memory sample firewall. Every key works, every
command is built and previewed for real, and nothing touches your system.

## Every change is previewed

![Delete confirmation](docs/screenshots/tui-firewall-delete.png)

`y` runs the command shown, `n` does not. There is no other path to a change:
the UI hands the same value to the preview and to the runner, so what you read
is what executes.

## Usage

```sh
tui-firewall                      # drive the real firewall
tui-firewall --demo               # sample data, no privileges needed
tui-firewall --backend ufw        # skip autodetection
tui-firewall --theme ~/mytheme/colors.toml
tui-firewall --sudo ""            # run the firewall command directly (as root)
tui-firewall --version
```

`tui-firewall` needs root to change anything. When it is not running as root it
uses `sudo -n`, which never prompts: run `sudo -v` in another terminal first, or
start `tui-firewall` with sudo. If neither `ufw` nor `sudo` is available, it
says so and points at `--demo`.

## Keys

| Key | Action |
| --- | --- |
| `↑`/`k`, `↓`/`j` | Move the selection |
| `g` / `G` | First / last rule |
| `pgup` / `pgdn` | Scroll a page |
| `/` | Filter rules (matches any column; `esc` clears) |
| `a` | Add a rule |
| `d` | Delete the selected rule |
| `e` | Enable or disable the firewall |
| `r` | Reload the firewall |
| `p` | Change a default policy |
| `L` | Change the logging level |
| `[` / `]` | Previous / next group (multi-group backends only) |
| `R` | Re-read the firewall |
| `?` | Help |
| `q` | Quit |

In the **add rule** form: `tab` / `shift+tab` move between fields, `←`/`→`
cycle a choice, `enter` opens a picker on a choice field and submits from a
text field, `esc` cancels.

![Add rule form](docs/screenshots/tui-firewall-add.png)

![Default policies](docs/screenshots/tui-firewall-policies.png)

![Help](docs/screenshots/tui-firewall-help.png)

## What v0.1 can do

- Read `ufw status verbose`, `ufw status numbered` and `ufw app list`.
- Show status, default policies (incoming/outgoing/routed) and logging level.
- List rules with action, direction, source, destination, ports, protocol,
  app profile, address family and comment; IPv6 and `route` rules included.
- Filter rules across every column.
- Add a rule: action (allow/deny/reject/limit), direction, port or port list or
  range, protocol, app profile, source and destination CIDR, comment, and
  insertion at a given position.
- Delete a rule by number, enable/disable, reload, change a default policy,
  change the logging level.
- Follow the active Omarchy theme, and respect `NO_COLOR`.

## What v0.1 cannot do

- **No firewalld yet.** The backend interface is in place and
  `internal/firewalld` is a documented stub; selecting it reports that clearly.
- **No rule editing.** Change a rule by deleting it and adding the new one.
- **No interface qualifiers** (`ufw allow in on eth0 …`): they are parsed and
  displayed, but the form cannot create them.
- **No `ufw` application profile management** (only using existing profiles).
- **No live log tail**, no packet counters, no nft view.
- Rules are ordered by ufw's own numbering; there is no reordering key.

## Configuration

`/etc/tui-firewall/config.toml`, then `~/.config/tui-firewall/config.toml` (the
user file overrides the machine-wide one), then `TUI_FIREWALL_*` in the
environment. Flags override everything. See
[`examples/config.toml`](examples/config.toml).

```toml
# Which firewall to drive: "auto", "ufw" or "firewalld".
backend = "auto"

# Privilege escalation prefix; "" runs the command directly.
sudo = "sudo -n"

# Path to an Omarchy-style colors.toml; empty follows the active theme.
theme = ""
```

With `backend = "auto"`, tui-firewall prefers an installed backend whose system
service is running, falls back to the first installed one, and otherwise exits
with a message naming what to install.

## Theme

The default palette is **Tokyo Night**. On Omarchy, the tool reads the active
desktop theme from `~/.config/omarchy/current/theme/colors.toml` and follows it.
`TUI_THEME` or `--theme` override; `NO_COLOR` drops color and keeps layout. The
rules live in [tui-kit](https://github.com/tui-tools/tui-kit#theme-rules).

## Architecture

The UI never builds a `ufw` command line. It talks to
`internal/firewall.Backend`, which returns a backend-neutral model:

```
Model{Enabled, Logging, Groups []Group}
Group{Name, Default policies, PolicySlots, Rules []Rule}
Rule{Action, Direction, Proto, Ports, From, To, Service, Comment, Family, Raw, Extra}
```

ufw exposes a single group (`rules`) carrying the global in/out/routed
policies; the group selector stays hidden when there is only one. firewalld
will expose one group per zone, with the zone target as its policy — the
mapping is documented at the top of `internal/firewalld/firewalld.go`.

Mutations are `runner.Command` values produced by the backend. The UI shows
them and, on confirmation, hands them back to the
[kit runner](https://github.com/tui-tools/tui-kit#the-contract-preview-confirm-run),
which resolves the binary and the privilege prefix. That is the whole trust
boundary, and it is why the preview is guaranteed to match what executes.

## Development

```sh
make check        # gofmt, go vet and the tests: what CI runs
make test
make build
make demo
make screenshots  # re-render the frames above from --demo
```

Dependencies are deliberately small: Bubble Tea, Bubbles and
[tui-kit](https://github.com/tui-tools/tui-kit), which carries the palette, the
widgets, the config loader and the command runner shared by the whole family.

## Prior art

[The-Robin-Hood/ufWall](https://github.com/The-Robin-Hood/ufWall) is an earlier
Go + Bubble Tea TUI for ufw (MIT, early-stage, inactive since March 2026);
`tui-firewall` is an independent implementation with its own parsers and a
backend-agnostic core aimed at covering firewalld as well.

## Safety notes

- Enabling the firewall over SSH can lock you out. `tui-firewall` warns before
  confirming, but **add a rule for your SSH port first**.
- `ufw enable` and `ufw delete` are run with `--force`, because ufw's own
  interactive prompt cannot be answered from inside a TUI. The confirm dialog
  replaces it.
- `tui-firewall` re-reads the firewall after every change, so what you see is
  what the system reports, not what the tool assumed.

## License

MIT — see [LICENSE](LICENSE). Part of the
[tui-tools](https://github.com/tui-tools) family.
