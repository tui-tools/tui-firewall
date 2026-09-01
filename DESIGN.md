# Design notes

## Per-rule enable/disable, and the saved-file format

nftables has no disabled state. A rule is in the ruleset or it is not, so
"disable" can only mean deleting the rule while remembering enough to put it
back exactly where it was. That memory is a file format, and this is what it
is.

### The file is still one file, and still an nft script

The Save action (`W`) writes `nft list table inet tui` — nft's own text, which
is a valid nft script — to `/etc/omarchy/router/tui-firewall.nft` on an
Omarchy router or `/etc/nftables.d/tui-firewall.nft` elsewhere. The router
profile loads that file with `nft -f` on boot, and nothing about that may
change: a machine that loses this tool still has to boot the rules it had.

So the disabled rules ride in the same file, in comment lines. `nft -f`
ignores a line starting with `#`; this tool parses those lines and nobody else
has to know they exist.

```
# tui-firewall:spec v2
table inet tui {
	chain input {
		type filter hook input priority 0; policy drop;
		iifname "wan0" tcp dport 22 counter drop comment "no ssh from the wan"
	}
}
# tui-firewall:disabled {"index":2,"expr":["iifname","\"wan0\"","udp","dport","53","counter","drop"],"family":"v4","rule":{…}}
```

- `# tui-firewall:spec v2` is the version marker, and it is written **only
  when something is actually disabled**. A ruleset with nothing disabled
  produces the byte-identical v1 file earlier versions wrote, so a user who
  never presses `D` never sees the format change and never sees a diff for it.
- `# tui-firewall:disabled <json>` is one disabled rule, one line.
- A file with no marker is version 1 and loads as "nothing disabled". A marker
  naming a version this build does not read is an error, not a guess, and the
  save is refused while it stands: overwriting a file whose disabled rules
  could not be read would delete them.

A sidecar file was the other option and was rejected. Two files drift, the
boot path would have to learn about the second one, and the operator who
copies `tui-firewall.nft` to another machine would silently leave half the
configuration behind.

### What one disabled entry holds

Two renderings of the same rule, for two different jobs:

- `expr` — the nft statement, one argv word per element, captured from the
  live match at the moment the rule was disabled. This is what the re-add
  replays. It is a snapshot rather than something recomputed later, so a
  ruleset that has been re-read in between cannot change what comes back.
- `rule` — the modelled rule (`Match` and all), because a disabled rule still
  has to be a row in the table and the kernel no longer holds it. Plus
  `family`, which `Match` derives from the expressions it decoded rather than
  from a field nft printed, so it does not survive a JSON round trip on its
  own.
- `index` — the 0-based position in its chain the rule goes back to.

`counter` is dropped on the way in: a disabled rule is not counting anything,
and a stale number is a number the row invites the reader to believe.

### Disable and enable

- **Disable** is `nft delete rule … handle H`, plus the entry recorded in the
  spec once that command has actually run. The statement is rebuilt from the
  rule's own modelled match by the same machinery a move uses
  (`rebuildRuleExpr`), so a rule this package does not hold in full — an
  unmodelled match, a NAT translation, a verdict other than accept/drop/reject,
  a log statement carrying a level or an nflog group — is refused before
  anything is deleted. That is the same refusal set `E` makes.
- **Enable** replays `expr` with `nft insert rule … index N`, or `nft add rule`
  when the chain has since become shorter than the recorded position. The rule
  comes back with a fresh handle and a counter at zero, and the preview says
  so.

Both are previewed and confirmed like every other change, and both go through
`internal/nftables` — the only place in this tool that starts a process.

### Why disable does not join a staged batch

Staging collects changes and applies them later as one `nft -f` transaction.
The record of what is disabled is written the moment its command succeeds. If
the ruleset change were staged and the record were not, the file would claim a
rule is disabled while the kernel still enforces it — the exact lie the
preview contract exists to prevent — and a batch cannot carry the record
either, because the record is a file write and an `nft -f` transaction is not.

So `D` applies on its own, as one nft command, and is refused while staging is
collecting or while an applied batch is waiting to be kept. It then **offers
the save**, once the reload has put the new list on screen, because until that
save happens the disabled rule lives only in this process. The header says the
same thing: `rules: 1 disabled, unsaved (W)`.

### Reading a file this tool did not write

Everything that comes off disk is guarded before it becomes an nft statement
or a table cell. A statement word is either a bare operand from a fixed
alphabet or one closed double-quoted string; a table, family or chain name is
a short name with no nft syntax in it; every string the row draws goes through
the same one-line pass nft's own output goes through. A line that does not
parse is an error rather than a skip, because dropping the ones that did not
parse would lose exactly the rules the file exists to preserve.

`FuzzParseSpec` asserts those invariants on arbitrary input, and
`FuzzSaveFileRoundTrip` asserts that anything this package writes, it reads
back.

### What is still open

The spec is not reconciled against a ruleset that changed behind this tool's
back. If something else adds rules to `inet tui` while a rule is disabled, the
recorded position is a position in a chain that has moved; enabling then puts
the rule back at that index, which may not be the neighbour it had. The
position past the end of a shorter chain is handled (it appends); the rest is
a reconciliation pass this tool does not do yet.
