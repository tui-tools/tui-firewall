package nftables

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

func TestSavePathEnvOverride(t *testing.T) {
	t.Setenv(SavePathEnv, "/tmp/somewhere/save.nft")
	path, note := SavePath()
	if path != "/tmp/somewhere/save.nft" {
		t.Errorf("path = %q, want the override", path)
	}
	if !strings.Contains(note, SavePathEnv) {
		t.Errorf("the note should say where the path came from: %q", note)
	}
}

func TestSavePathByMachineKind(t *testing.T) {
	t.Setenv(SavePathEnv, "")
	path, note := SavePath()
	if info, err := os.Stat("/etc/omarchy"); err == nil && info.IsDir() {
		if path != savePathRouter || !strings.Contains(note, "Omarchy") {
			t.Errorf("on an Omarchy machine: path %q, note %q", path, note)
		}
		return
	}
	if path != savePathPlain {
		t.Errorf("path = %q, want %q", path, savePathPlain)
	}
	if !strings.Contains(note, "nftables") {
		t.Errorf("the note should say how the file loads on boot: %q", note)
	}
}

func TestBuildSave(t *testing.T) {
	listing := "table inet tui {\n\tchain input {\n\t}\n}\n"
	change, _, err := BuildSave(listing, Spec{}, savePathPlain, "loaded on boot")
	if err != nil {
		t.Fatalf("BuildSave: %v", err)
	}
	got := argvString(t, change)
	want := "install -m 644 /dev/stdin " + savePathPlain
	if got != want {
		t.Errorf("argv = %q, want %q", got, want)
	}
	if change.Commands[0].Stdin != listing {
		t.Errorf("the stdin must be the capture byte for byte:\n%q", change.Commands[0].Stdin)
	}
	if change.Note != "loaded on boot" {
		t.Errorf("the boot note must reach the dialog: %q", change.Note)
	}
	if change.Destructive {
		t.Error("saving the running table to disk closes no traffic")
	}
}

func TestBuildSaveRefusals(t *testing.T) {
	good := "table inet tui {\n}\n"
	cases := []struct {
		name    string
		listing string
		path    string
	}{
		{"empty capture", "", savePathPlain},
		{"whitespace capture", "  \n", savePathPlain},
		{"not the owned table", "table inet firewalld {\n}\n", savePathPlain},
		{"relative path", good, "etc/save.nft"},
		{"path with a space", good, "/etc/save file.nft"},
		{"path with a newline", good, "/etc/save\n.nft"},
		{"path with a semicolon", good, "/etc/save;rm.nft"},
		{"path with a quote", good, `/etc/"save".nft`},
	}
	for _, tc := range cases {
		if _, _, err := BuildSave(tc.listing, Spec{}, tc.path, ""); err == nil {
			t.Errorf("%s: should have been refused", tc.name)
		}
	}
}

func TestUnifiedDiff(t *testing.T) {
	if diff := UnifiedDiff("a\nb\n", "a\nb\n", "old", "new"); diff != "" {
		t.Errorf("equal texts diff to nothing, got %q", diff)
	}
	diff := UnifiedDiff("a\nb\nc\n", "a\nB\nc\nd\n", "old", "new")
	for _, want := range []string{"--- old", "+++ new", "-b", "+B", "+d", " a"} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff missing %q:\n%s", want, diff)
		}
	}
	// A brand-new file is all additions.
	fresh := UnifiedDiff("", "table inet tui {\n}\n", "old", "new")
	if !strings.Contains(fresh, "+table inet tui {") {
		t.Errorf("a first save shows the whole file as additions:\n%s", fresh)
	}
}

// TestFakeSaveRoundTrip proves the --demo parity: the fake serialises its own
// table, the builder wraps it, and the fake's Run records the install instead
// of touching the machine.
func TestFakeSaveRoundTrip(t *testing.T) {
	fake := NewFake()
	listing, err := fake.SnapshotOwnTable(context.Background())
	if err != nil {
		t.Fatalf("SnapshotOwnTable: %v", err)
	}
	for _, want := range []string{"table inet tui {", "chain input {", "set lan_hosts {"} {
		if !strings.Contains(listing, want) {
			t.Errorf("the demo capture should carry %q:\n%s", want, listing)
		}
	}
	change, _, err := BuildSave(listing, Spec{}, "/tmp/tui-firewall-test.nft", "note")
	if err != nil {
		t.Fatalf("BuildSave: %v", err)
	}
	if _, err := fake.Run(context.Background(), change); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fake.SavedPath != "/tmp/tui-firewall-test.nft" {
		t.Errorf("SavedPath = %q", fake.SavedPath)
	}
	if fake.Saved != change.Commands[0].Stdin {
		t.Error("the demo must record exactly the bytes the install would write")
	}
	if _, err := os.Stat("/tmp/tui-firewall-test.nft"); err == nil {
		t.Error("the demo must not create the file")
	}
}

// TestSaveNeverJoinsAnNftBatch documents why the Save change is one install
// command: a change that mixed nft statements with a file write could not be
// one atomic transaction, and the builder never produces such a mix.
func TestSaveNeverJoinsAnNftBatch(t *testing.T) {
	change, _, err := BuildSave("table inet tui {\n}\n", Spec{}, savePathPlain, "")
	if err != nil {
		t.Fatalf("BuildSave: %v", err)
	}
	if len(change.Commands) != 1 || change.Commands[0].Argv[0] != "install" {
		t.Errorf("the save is exactly one install command, got %v", change.Commands)
	}
	var _ = firewall.Change{} // keep the import honest if assertions change
}
