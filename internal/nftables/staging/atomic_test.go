package staging

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

func TestAtomicCommandWrapsAMultiCommandChange(t *testing.T) {
	change := firewall.Change{
		Description: "Move rule handle 14 up in input",
		Destructive: true,
		Commands: []firewall.Command{
			{Argv: []string{"nft", "insert", "rule", "inet", "tui", "input",
				"index", "3", "tcp", "dport", "22", "counter", "drop"}},
			{Argv: []string{"nft", "delete", "rule", "inet", "tui", "input",
				"handle", "14"}},
		},
	}
	cmd := AtomicCommand(change)
	if strings.Join(cmd.Argv, " ") != "nft -f -" {
		t.Errorf("argv = %v, want nft -f -", cmd.Argv)
	}
	want := "insert rule inet tui input index 3 tcp dport 22 counter drop\n" +
		"delete rule inet tui input handle 14\n"
	if cmd.Stdin != want {
		t.Errorf("stdin =\n%q\nwant\n%q", cmd.Stdin, want)
	}
	if cmd.Description != change.Description {
		t.Errorf("description = %q", cmd.Description)
	}
	if !cmd.Destructive {
		t.Error("the wrapper keeps the change's danger flag")
	}
}
