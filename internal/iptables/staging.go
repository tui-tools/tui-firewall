package iptables

import (
	"fmt"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/nftables/staging"
)

// snapshotMarker separates the two families inside one snapshot string. The
// staging session holds a single snapshot; iptables keeps two, so they travel
// together and Restore splits them again. It is a comment line, which
// iptables-restore ignores, so each half is still a valid restore file.
const snapshotMarker = "# tui-firewall: ip6tables snapshot follows"

// JoinSnapshot packs the two filter-table snapshots into the one string the
// staging session keeps.
func JoinSnapshot(v4, v6 string) string {
	return strings.TrimRight(v4, "\n") + "\n" + snapshotMarker + "\n" +
		strings.TrimRight(v6, "\n") + "\n"
}

// SplitSnapshot unpacks a snapshot made by JoinSnapshot.
func SplitSnapshot(snapshot string) (v4, v6 string) {
	v4, v6, _ = strings.Cut(snapshot, snapshotMarker+"\n")
	return v4, v6
}

// Dialect is the iptables staging dialect: a batch applies through
// `iptables-restore --noflush`, one transaction per family, and a rollback
// replays the filter-table snapshot with a plain iptables-restore, which
// replaces the table it names in one step.
type Dialect struct {
	// HasV6 reports whether ip6tables is there to restore into.
	HasV6 bool
}

// check that Dialect satisfies the staging contract.
var _ staging.Dialect = Dialect{}

// Atomicity describes an iptables-restore batch.
func (Dialect) Atomicity() string {
	return "through iptables-restore --noflush: all of them or none, " +
		"once for IPv4 and once for IPv6"
}

// Apply renders the staged changes as one iptables-restore --noflush per
// family that has any.
func (d Dialect) Apply(pending []firewall.Change) (firewall.Change, error) {
	scripts, err := batchScripts(pending)
	if err != nil {
		return firewall.Change{}, err
	}
	change := firewall.Change{
		Description: fmt.Sprintf("Apply %s", plural(countCommands(pending), "staged change")),
		Destructive: true,
	}
	for _, family := range Families() {
		script, ok := scripts[family]
		if !ok {
			continue
		}
		change.Commands = append(change.Commands, firewall.Command{
			Argv:        []string{family.RestoreBinary(), "--noflush"},
			Description: "Apply the staged " + family.Binary() + " changes atomically",
			Destructive: true,
			Stdin:       script,
		})
	}
	return change, nil
}

// Preview renders the scripts the batch sends, one per family.
func (d Dialect) Preview(pending []firewall.Change) string {
	scripts, err := batchScripts(pending)
	if err != nil {
		return err.Error()
	}
	var parts []string
	for _, family := range Families() {
		if script, ok := scripts[family]; ok {
			parts = append(parts, "# "+family.RestoreBinary()+" --noflush\n"+
				strings.TrimRight(script, "\n"))
		}
	}
	return strings.Join(parts, "\n")
}

// Restore renders the rollback: each family's filter table replaced by its
// snapshot. A plain iptables-restore flushes only the tables its input names,
// and the snapshot names only filter, so docker's nat table is left alone.
func (d Dialect) Restore(snapshot string) firewall.Change {
	v4, v6 := SplitSnapshot(snapshot)
	change := firewall.Change{
		Description: "Restore the filter rules captured before the staged apply",
		Destructive: true,
	}
	for _, part := range []struct {
		family Family
		text   string
	}{{V4, v4}, {V6, v6}} {
		if strings.TrimSpace(part.text) == "" || (part.family == V6 && !d.HasV6) {
			continue
		}
		change.Commands = append(change.Commands, firewall.Command{
			Argv:        []string{part.family.RestoreBinary()},
			Description: "Restore the " + part.family.Binary() + " filter snapshot",
			Destructive: true,
			Stdin:       strings.TrimRight(part.text, "\n") + "\n",
		})
	}
	return change
}

// batchScripts renders every staged command as a restore-file line in its
// family's script. Only iptables and ip6tables commands can join a batch: the
// batch is one transaction of rule changes, and anything else is refused
// rather than run outside it.
func batchScripts(pending []firewall.Change) (map[Family]string, error) {
	lines := map[Family][]string{}
	for _, change := range pending {
		for _, cmd := range change.Commands {
			if len(cmd.Argv) < 2 {
				return nil, errorf("an empty command cannot join a staged batch")
			}
			var family Family
			switch cmd.Argv[0] {
			case V4.Binary():
				family = V4
			case V6.Binary():
				family = V6
			default:
				return nil, errorf("%s cannot join an iptables-restore batch; apply "+
					"it on its own with staging off", cmd.Argv[0])
			}
			lines[family] = append(lines[family], JoinArgs(cmd.Argv[1:]))
		}
	}
	scripts := map[Family]string{}
	for family, ls := range lines {
		scripts[family] = "*" + TableFilter + "\n" + strings.Join(ls, "\n") + "\nCOMMIT\n"
	}
	return scripts, nil
}

// countCommands counts the commands of a list of changes.
func countCommands(changes []firewall.Change) int {
	n := 0
	for _, c := range changes {
		n += len(c.Commands)
	}
	return n
}
