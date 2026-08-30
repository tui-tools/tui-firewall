package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tui-tools/tui-kit/runner"
)

func TestOneWrapsACommand(t *testing.T) {
	change := One(Command{
		Argv: []string{"ufw", "disable"}, Description: "Disable", Destructive: true,
	})
	if len(change.Commands) != 1 {
		t.Fatalf("Commands = %d, want 1", len(change.Commands))
	}
	if change.Description != "Disable" || !change.Destructive {
		t.Errorf("change = %+v, want the command's description and danger flag", change)
	}
	if change.String() != "ufw disable" {
		t.Errorf("String = %q", change.String())
	}
	if change.Empty() {
		t.Error("a change with a command is not empty")
	}
	if !(Change{}).Empty() {
		t.Error("a change with no command is empty")
	}
}

func TestChangeStringIsOneLinePerCommand(t *testing.T) {
	change := Change{Commands: []Command{
		{Argv: []string{"firewall-cmd", "--zone=public", "--add-service=ssh"}},
		{Argv: []string{"firewall-cmd", "--permanent", "--zone=public", "--add-service=ssh"}},
	}}
	want := "firewall-cmd --zone=public --add-service=ssh\n" +
		"firewall-cmd --permanent --zone=public --add-service=ssh"
	if got := change.String(); got != want {
		t.Errorf("String\n got: %q\nwant: %q", got, want)
	}
}

func TestPreviewChangeShowsEveryLineWithItsPrefix(t *testing.T) {
	// The preview is the only promise the tool makes, so every command of a
	// change must appear in it, escalation prefix included.
	fake := &runner.Fake{Prefix: "sudo -n"}
	change := Change{Commands: []Command{
		{Argv: []string{"firewall-cmd", "--panic-on"}},
		{Argv: []string{"firewall-cmd", "--reload"}},
	}}
	want := "sudo -n firewall-cmd --panic-on\nsudo -n firewall-cmd --reload"
	if got := PreviewChange(fake, change); got != want {
		t.Errorf("PreviewChange\n got: %q\nwant: %q", got, want)
	}
}

func TestRunChangeRunsInOrder(t *testing.T) {
	fake := &runner.Fake{Default: "ok"}
	change := Change{Commands: []Command{
		{Argv: []string{"a", "1"}},
		{Argv: []string{"b", "2"}},
	}}
	out, err := RunChange(context.Background(), fake, change)
	if err != nil {
		t.Fatalf("RunChange: %v", err)
	}
	if len(fake.Ran) != 2 || fake.Ran[0].Argv[0] != "a" || fake.Ran[1].Argv[0] != "b" {
		t.Errorf("ran %v", fake.Previews())
	}
	if out != "ok\nok" {
		t.Errorf("output = %q", out)
	}
}

func TestRunChangeStopsAtTheFirstFailure(t *testing.T) {
	// A half-applied change is reported as such: pressing on would leave the
	// machine in a state neither the user nor the tool asked for.
	boom := errors.New("boom")
	fake := &runner.Fake{Err: boom}
	change := Change{Commands: []Command{{Argv: []string{"a"}}, {Argv: []string{"b"}}}}

	_, err := RunChange(context.Background(), fake, change)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the runner's error", err)
	}
	if len(fake.Ran) != 1 {
		t.Errorf("ran %d commands, want it to stop after the first", len(fake.Ran))
	}
}

func TestGroupLabelFallsBackToName(t *testing.T) {
	if got := (Group{Name: "public"}).Label(); got != "public" {
		t.Errorf("Label = %q", got)
	}
	if got := (Group{Name: "public", Title: "public (default)"}).Label(); got !=
		"public (default)" {
		t.Errorf("Label = %q", got)
	}
}

func TestModelGroup(t *testing.T) {
	model := Model{Groups: []Group{{Name: "public"}, {Name: "internal"}}}
	if g, ok := model.Group("internal"); !ok || g.Name != "internal" {
		t.Errorf("Group(internal) = %+v %v", g, ok)
	}
	if _, ok := model.Group("dmz"); ok {
		t.Error("an unknown group must not be found")
	}
}

func TestActionAndDirectionArgs(t *testing.T) {
	if got := ActionAllow.Arg(); got != "allow" {
		t.Errorf("Arg = %q", got)
	}
	if got := DirForward.Arg(); got != "fwd" {
		t.Errorf("Arg = %q", got)
	}
	if got := DirAny.Arg(); got != "" {
		t.Errorf("Arg = %q, want empty", got)
	}
}

func TestKindsAreDistinct(t *testing.T) {
	// The kinds are the delete contract: two of them naming the same string
	// would silently remove the wrong entry.
	kinds := []string{
		KindService, KindPort, KindProtocol, KindSourcePort, KindForwardPort,
		KindRich, KindSource, KindInterface, KindMasquerade, KindForward,
		KindICMPBlock,
	}
	seen := map[string]bool{}
	for _, kind := range kinds {
		if kind == "" || strings.ContainsAny(kind, " \t") {
			t.Errorf("kind %q is not a usable identifier", kind)
		}
		if seen[kind] {
			t.Errorf("kind %q is declared twice", kind)
		}
		seen[kind] = true
	}
}
