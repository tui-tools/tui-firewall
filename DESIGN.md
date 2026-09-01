# Design notes

## Per-rule enable/disable (not implemented)

The manage feature set (Save, edit in place, move) deliberately leaves
per-rule disable out. nftables has no disabled state: a rule either is in the
ruleset or it is not, so "disable" means deleting the rule while remembering
enough to put it back exactly where it was.

Doing that honestly needs a second persistence format — call it v2 of the
saved file — that stores the tool's own view of the ruleset rather than nft's
listing: a list of rule *specs* (the same `RuleSpec` the add and edit forms
produce), each with an enabled flag and its position. Disabling would then be
"delete the rule, keep its spec"; enabling, "insert the spec at its recorded
position"; and Save would write both the active ruleset (as the `.nft` file it
writes today, still loadable by plain `nft -f` on boot) and the spec sidecar
that carries the disabled entries.

That sidecar is a real format with compatibility duties, and it only pays for
itself once the tool also reconciles it against a ruleset that changed behind
its back. Until that reconciliation exists, a fake disable would silently drop
rules on the floor, so the feature waits for persistence v2 instead of
shipping as a trap.
