# fwall

A terminal UI for the Linux firewall. It shows the rules you actually have, and
**previews the exact command line of every change before running it**.

`ufw` has no TUI: you get the CLI, or Gufw if you have a desktop. `fwall` fills
the gap on a server or a tiling desktop, in the Omarchy visual style.

```
 fwall  ufw via sudo -n
 status: enabled   incoming: deny   outgoing: allow   routed: disabled   logging: low

 #   ACTION DIR TO                         FROM                     IP  COMMENT
 1   LIMIT  IN  22/tcp                     Anywhere                 v4  ssh rate limit
 2   ALLOW  IN  80,443/tcp (Nginx Full)    Anywhere                 v4
 3   ALLOW  IN  5432/tcp                   10.0.0.0/8               v4  postgres from lan
 4   DENY   IN  3306/tcp                   Anywhere                 v4
 5   ALLOW  FWD Anywhere                   192.168.1.0/24           v4  lan forwarding

 a add  d delete  e enable/disable  r reload  p policies  L logging  / filter  ? help  q quit
 9 rules  ·  ? for help
```

> Screenshots: _to add_ — `docs/screenshot-main.png`, `docs/screenshot-add.png`.

## Try it without root

```sh
fwall --demo
```

`--demo` runs against an in-memory sample firewall. Every key works, every
command is built and previewed for real, and nothing touches your system.

## Usage

```sh
fwall                      # drive the real firewall
fwall --demo               # sample data, no privileges needed
fwall --backend ufw        # skip autodetection
fwall --theme ~/mytheme/colors.toml
fwall --sudo ""            # run the firewall command directly (as root)
fwall --version
```

`fwall` needs root to change anything. When it is not running as root it uses
`sudo -n`, which never prompts: run `sudo -v` in another terminal first, or
start `fwall` with `sudo`. If neither `ufw` nor `sudo` is available, it says so
and points at `--demo`.

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

Every mutation opens a confirm dialog showing the literal command:

```
╭──────────────────────────────────────────╮
│  Delete rule 1                           │
│                                          │
│  Rule: LIMIT IN 22/tcp from Anywhere     │
│                                          │
│  Command to run:                         │
│  $ sudo -n ufw --force delete 1          │
│                                          │
│  y confirm    n cancel                   │
╰──────────────────────────────────────────╯
```

`y` runs it, `n` does not. There is no other path to a change.

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

`/etc/fwall/config.toml`, then `~/.config/fwall/config.toml` (the user file
overrides the machine-wide one). Flags override both. See
[`examples/config.toml`](../../examples/config.toml).

```toml
# Which firewall to drive: "auto", "ufw" or "firewalld".
backend = "auto"

# Privilege escalation prefix; "" runs the command directly.
sudo = "sudo -n"

# Path to an Omarchy-style colors.toml; empty follows the active theme.
theme = ""
```

With `backend = "auto"`, fwall prefers an installed backend whose system
service is running, falls back to the first installed one, and otherwise exits
with a message naming what to install.

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

Mutations are `Command{Argv, Description}` values produced by the backend. The
UI shows them and, on confirmation, hands them back to the backend to run. That
is the whole trust boundary, and it is why the preview is guaranteed to match
what executes.

## Prior art

[The-Robin-Hood/ufWall](https://github.com/The-Robin-Hood/ufWall) is an earlier
Go + Bubble Tea TUI for ufw (MIT, early-stage, inactive since March 2026);
`fwall` is an independent implementation with its own parsers and a
backend-agnostic core aimed at covering firewalld as well.

## Safety notes

- Enabling the firewall over SSH can lock you out. `fwall` warns before
  confirming, but **add a rule for your SSH port first**.
- `ufw enable` and `ufw delete` are run with `--force`, because ufw's own
  interactive prompt cannot be answered from inside a TUI. The confirm dialog
  replaces it.
- `fwall` re-reads the firewall after every change, so what you see is what the
  system reports, not what the tool assumed.
