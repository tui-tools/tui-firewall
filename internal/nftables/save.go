package nftables

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// SavePathEnv overrides where the Save action writes the serialized table.
// It exists for the tests and the lab, which must not touch /etc.
const SavePathEnv = "TUI_FIREWALL_SAVE_PATH"

// The two places the saved table lands, by kind of machine. On an Omarchy
// router the profile's own boot script includes the file; on any other host it
// goes where nftables include snippets conventionally live, and loading it on
// boot is one include line the note below spells out.
const (
	savePathRouter = "/etc/omarchy/router/tui-firewall.nft"
	savePathPlain  = "/etc/nftables.d/tui-firewall.nft"
)

// SavePath decides where the Save action writes, and what happens to the file
// on boot. The environment wins, then the Omarchy router layout when the
// machine has one, then the plain nftables.d convention.
func SavePath() (path, bootNote string) {
	if p := os.Getenv(SavePathEnv); p != "" {
		return p, "the path comes from " + SavePathEnv +
			"; arrange for your boot to load it with nft -f"
	}
	if info, err := os.Stat("/etc/omarchy"); err == nil && info.IsDir() {
		return savePathRouter, "the Omarchy router profile includes this file " +
			"when it renders the firewall on boot"
	}
	return savePathPlain, "load it on boot by including it from " +
		"/etc/nftables.conf (include \"/etc/nftables.d/*.nft\") and enabling " +
		"the nftables service"
}

// BuildSave turns a captured `nft list table` listing and the tool's own spec
// into the install command that writes them to disk, and returns the file
// content beside it so the caller can diff what is there against what is
// about to replace it.
//
// The content travels on standard input rather than in an argv word: a whole
// ruleset does not belong on a command line, and `install -m 644 /dev/stdin
// <path>` writes it root-owned with the mode in one step, no temp file left
// behind on failure.
//
// The listing is nft's own text, which is a valid nft script — the same
// property the staged rollback relies on — so the file `nft -f` loads on boot
// is byte-for-byte what nft printed here. The spec rides underneath it in
// comment lines nft ignores, which is what keeps the file loadable by a plain
// `nft -f` while still carrying the rules this tool has disabled.
func BuildSave(listing string, spec Spec, path,
	bootNote string) (firewall.Change, string, error) {
	if err := checkSavePath(path); err != nil {
		return firewall.Change{}, "", err
	}
	trimmed := strings.TrimSpace(listing)
	if trimmed == "" {
		return firewall.Change{}, "", errorf(
			"there is nothing to save: table %s does not exist yet; the "+
				"actions menu offers to create it", OwnTable)
	}
	if !strings.Contains(trimmed, "table "+OwnTable.String()) {
		return firewall.Change{}, "", errorf(
			"the capture does not look like table %s, so it is not written "+
				"anywhere; re-read the ruleset with R and try again", OwnTable)
	}
	content, err := RenderSaveFile(trimmed, spec)
	if err != nil {
		return firewall.Change{}, "", err
	}

	note := bootNote
	if !spec.Empty() {
		note += "; the " + plural(spec.Len(), "disabled rule") +
			" ride in comment lines nft ignores and this tool reads back"
	}
	return firewall.Change{
		Description: "Save table " + OwnTable.String() + " to " + path,
		Note:        note,
		Commands: []firewall.Command{{
			Argv:        []string{"install", "-m", "644", "/dev/stdin", path},
			Description: "Install the serialized table as " + path,
			Stdin:       content + "\n",
		}},
	}, content + "\n", nil
}

// LoadSpec reads the disabled rules back out of the file the Save action
// writes. A path that does not exist yet is a machine that has never saved,
// which is an empty spec and not an error; anything else the reader cannot
// make sense of is reported, because a spec that silently came back empty
// would look exactly like a ruleset with nothing disabled.
func LoadSpec(path string) (Spec, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the vetted save location (a package constant or the TUI_FIREWALL_SAVE_PATH override), read to recover the tool's own spec
	if err != nil {
		if os.IsNotExist(err) {
			return Spec{}, nil
		}
		return Spec{}, errorf("could not read the saved file %s: %v", path, err)
	}
	return ParseSpec(string(data))
}

// checkSavePath refuses a destination that could not have come from this
// tool's own constants or a sane override: relative, empty, or carrying a
// character that has no business in a system path.
func checkSavePath(path string) error {
	if !filepath.IsAbs(path) {
		return errorf("the save path must be absolute, not %q", path)
	}
	if strings.ContainsAny(path, " \t\n\r\"';") {
		return errorf("%q contains a character a save path cannot carry", path)
	}
	return nil
}
