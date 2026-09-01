package nftables

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// The saved-file format, version 2.
//
// nftables has no disabled state: a rule is in the ruleset or it is not. So
// "disabled" is a fact this tool owns, and it has to live somewhere the tool
// can read back after a reboot. That somewhere is the file the Save action
// already writes — `nft list table inet tui`, nft's own text — with the
// disabled rules carried in comments underneath it.
//
// Comments are the whole trick. `nft -f` ignores a line starting with '#', so
// the file the router profile loads on boot stays exactly as loadable as it
// was: the live part is still nft's own listing, byte for byte, and the
// disabled rules are invisible to nft and legible to this tool. Nothing has to
// learn a second file, and a machine that loses this tool still boots the
// rules it had.
//
// A file with no marker line is version 1 — everything written before this
// feature existed — and reads back as a ruleset with nothing disabled. The
// marker and the disabled lines are written only when something is actually
// disabled, so a user who never presses D keeps getting a byte-identical v1
// file and no diff churn.
const (
	// specMarkerPrefix opens the version line: "# tui-firewall:spec v2".
	specMarkerPrefix = "# tui-firewall:spec "
	// SpecVersion is the format this package writes and reads.
	SpecVersion = "v2"
	// disabledPrefix opens one disabled rule's line, followed by its JSON.
	disabledPrefix = "# tui-firewall:disabled "
)

// DisabledRule is one rule the tool has taken out of the live ruleset and
// remembers, so it can be put back exactly where it was.
//
// It carries two renderings of the same rule on purpose. Expr is the nft
// statement the re-add replays, captured at the moment the rule was disabled
// from the live match the kernel reported — a snapshot, not something
// recomputed later from a model that may have been re-read since. Rule is the
// modelled rule, which is what the table draws the greyed-out row from: a
// disabled rule has to be visible, and the kernel no longer holds it.
type DisabledRule struct {
	// Index is the 0-based position in its chain the rule is put back at.
	Index int `json:"index"`
	// Expr is the nft statement, one argv word per element, with no leading
	// "nft add rule …": just the match and the statements.
	Expr []string `json:"expr"`
	// Family is the address family the rule's own matches pinned it to ("v4",
	// "v6", or empty for both). Match records it from the expressions it
	// decoded rather than from a field nft printed, so it does not survive a
	// JSON round trip on its own.
	Family string `json:"family,omitempty"`
	// Rule is the modelled rule, for the row the table shows.
	Rule Rule `json:"rule"`
}

// ID is how the UI names a disabled row back to this package. Live rows are
// named by their handle, which is a bare number; the "off:" prefix is what
// keeps the two apart, and the handle the rule had is unique inside its table,
// so it stays unique among the rules disabled out of one chain.
func (d DisabledRule) ID() string { return disabledIDPrefix + strconv.Itoa(d.Rule.Handle) }

// disabledIDPrefix marks a row that stands for a disabled rule.
const disabledIDPrefix = "off:"

// DisabledID reports whether a UI row names a disabled rule rather than a live
// one, which is what the D key branches on.
func DisabledID(id string) bool { return strings.HasPrefix(id, disabledIDPrefix) }

// Toggle is a disable or an enable: the change to preview and run, and the
// record it makes once it has. The two travel together because the record has
// to be the one the preview was built from — a change that ran and a record
// derived again afterwards, off a ruleset that has moved on, would not
// necessarily agree.
type Toggle struct {
	// Change is what the confirm dialog shows and the runner runs.
	Change firewall.Change
	// Entry is the rule being disabled, or the one being enabled.
	Entry DisabledRule
	// Enabling says which direction this is: true puts Entry back in the
	// ruleset and out of the spec, false the other way around.
	Enabling bool
}

// Apply records a toggle that has run, in the spec.
func (s *Spec) Apply(t Toggle) {
	if t.Enabling {
		s.Remove(t.Entry.Rule.Table, t.Entry.Rule.Chain, t.Entry.ID())
		return
	}
	s.Add(t.Entry)
}

// Spec is the tool's own view of the rules it manages beyond what the kernel
// holds: today, the ones it has disabled.
type Spec struct {
	Disabled []DisabledRule `json:"disabled,omitempty"`
}

// Empty reports a spec with nothing in it, which is what a v1 file parses to.
func (s Spec) Empty() bool { return len(s.Disabled) == 0 }

// Len is how many rules are disabled.
func (s Spec) Len() int { return len(s.Disabled) }

// InChain returns the rules disabled out of one chain, ordered by the position
// each goes back to.
func (s Spec) InChain(table TableID, chain string) []DisabledRule {
	var out []DisabledRule
	for _, d := range s.Disabled {
		if d.Rule.Table == table && d.Rule.Chain == chain {
			out = append(out, d)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

// Find returns the disabled rule a UI row names.
func (s Spec) Find(table TableID, chain, id string) (DisabledRule, bool) {
	for _, d := range s.Disabled {
		if d.Rule.Table == table && d.Rule.Chain == chain && d.ID() == id {
			return d, true
		}
	}
	return DisabledRule{}, false
}

// Add records a disabled rule, replacing an entry that already names it.
func (s *Spec) Add(entry DisabledRule) {
	s.Remove(entry.Rule.Table, entry.Rule.Chain, entry.ID())
	s.Disabled = append(s.Disabled, entry)
}

// Remove drops the entry a UI row names and reports whether it was there.
func (s *Spec) Remove(table TableID, chain, id string) bool {
	for i, d := range s.Disabled {
		if d.Rule.Table == table && d.Rule.Chain == chain && d.ID() == id {
			s.Disabled = append(s.Disabled[:i], s.Disabled[i+1:]...)
			return true
		}
	}
	return false
}

// ParseSpec reads the disabled rules back out of a saved file.
//
// Everything that is not one of this tool's own comment lines is ignored: the
// live part of the file is nft's business, and re-parsing it here would be a
// second nft parser nobody asked for. A file with no marker line is version 1
// and parses to an empty spec, which is exactly what it means.
//
// A line this package cannot read is an error rather than a skip. The whole
// point of the file is that a disabled rule is not lost; dropping the ones
// that did not parse would lose them silently, which is the failure mode the
// feature exists to avoid.
func ParseSpec(content string) (Spec, error) {
	var spec Spec
	seenMarker := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, specMarkerPrefix):
			version := strings.TrimSpace(strings.TrimPrefix(trimmed, specMarkerPrefix))
			if version != SpecVersion {
				return Spec{}, errorf(
					"the saved file is format %s and this build reads %s; "+
						"upgrade tui-firewall rather than letting it rewrite a "+
						"file it does not understand", version, SpecVersion)
			}
			seenMarker = true
		case strings.HasPrefix(trimmed, disabledPrefix):
			if !seenMarker {
				return Spec{}, errorf(
					"the saved file carries a disabled rule before its %s%s "+
						"marker, so it was not written by this tool",
					specMarkerPrefix, SpecVersion)
			}
			entry, err := parseDisabled(strings.TrimPrefix(trimmed, disabledPrefix))
			if err != nil {
				return Spec{}, err
			}
			spec.Disabled = append(spec.Disabled, entry)
		}
	}
	return spec, nil
}

// parseDisabled decodes and validates one disabled entry.
func parseDisabled(payload string) (DisabledRule, error) {
	var entry DisabledRule
	decoder := json.NewDecoder(strings.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entry); err != nil {
		return DisabledRule{}, errorf(
			"a disabled rule in the saved file is not readable: %v", err)
	}
	if err := checkDisabled(entry); err != nil {
		return DisabledRule{}, err
	}
	return sanitizeDisabled(entry), nil
}

// checkDisabled is the guard on everything that came off disk. The file is
// root-owned and this tool wrote it, but what it holds becomes an nft
// statement and a table row, and neither may be assembled from bytes nobody
// checked: a word carrying a semicolon or a newline is the nftables equivalent
// of a shell injection, and a control character in a rendered field breaks the
// table's own layout rather than just its cell.
func checkDisabled(entry DisabledRule) error {
	if entry.Index < 0 {
		return errorf("a disabled rule records position %d, which is not a "+
			"position a chain has", entry.Index)
	}
	if err := checkSpecName(entry.Rule.Table.Family); err != nil {
		return errorf("a disabled rule names family %v", err)
	}
	if err := checkSpecName(entry.Rule.Table.Name); err != nil {
		return errorf("a disabled rule names table %v", err)
	}
	if err := checkSpecName(entry.Rule.Chain); err != nil {
		return errorf("a disabled rule names chain %v", err)
	}
	if len(entry.Expr) == 0 {
		return errorf("a disabled rule in the saved file carries no statement " +
			"to put back, so enabling it would add a match-everything rule")
	}
	for _, word := range entry.Expr {
		if err := checkSpecWord(word); err != nil {
			return err
		}
	}
	switch entry.Family {
	case "", "v4", "v6":
	default:
		return errorf("a disabled rule records address family %q, which is "+
			"not one nft has", entry.Family)
	}
	return nil
}

// specNameRunes are the characters an nft table or chain name may carry here.
// nft itself is looser; this is the subset that cannot end a statement early
// or start a second one.
func specNameRunes(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case r == '_' || r == '-' || r == '.':
		return true
	default:
		return false
	}
}

// checkSpecName refuses a table, family or chain name that is empty, too long
// for anything nft accepts, or carrying a character nft would read as syntax.
func checkSpecName(name string) error {
	if name == "" {
		return errorf("nothing, so it cannot be put back")
	}
	if len(name) > 64 {
		return errorf("%q, which is longer than any name nft accepts", name)
	}
	for _, r := range name {
		if !specNameRunes(r) {
			return errorf("%q, which carries a character nft would read as "+
				"syntax", name)
		}
	}
	return nil
}

// checkSpecWord refuses an nft statement word the builders could not have
// produced. A word is either a bare operand — the alphabet an address, a port
// range, a set brace or a keyword needs — or one double-quoted string, which
// is how a comment and an interface name ride in a single argv word.
func checkSpecWord(word string) error {
	if word == "" {
		return errorf("a disabled rule carries an empty statement word")
	}
	if len(word) > 256 {
		return errorf("a disabled rule carries a statement word longer than " +
			"anything this tool writes")
	}
	if strings.HasPrefix(word, "\"") {
		if len(word) < 2 || !strings.HasSuffix(word, "\"") {
			return errorf("%q is not a closed quoted word", word)
		}
		inner := word[1 : len(word)-1]
		if strings.ContainsAny(inner, "\"\\") {
			return errorf("%q quotes a value nft would not round-trip", word)
		}
		return checkSpecPrintable(inner)
	}
	for _, r := range word {
		if !specWordRune(r) {
			return errorf("%q contains a character nft would read as syntax", word)
		}
	}
	return nil
}

// specWordRune is the alphabet of a bare nft operand as this package writes
// them: names and keywords, addresses and prefixes, port ranges, set braces
// and the comma that separates set members.
func specWordRune(r rune) bool {
	if specNameRunes(r) {
		return true
	}
	switch r {
	case ':', '/', '@', ',', '{', '}', '*':
		return true
	default:
		return false
	}
}

// checkSpecPrintable refuses a control character in a value that ends up
// inside a quoted nft word or in a table cell.
func checkSpecPrintable(value string) error {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errorf("%q carries a control character", value)
		}
	}
	return nil
}

// sanitizeDisabled makes the display half of an entry safe to draw. Every
// string the table shows goes through the same one-line pass the ruleset
// reader puts nft's own output through, so a file edited by hand cannot break
// the layout of the screen it is drawn on.
func sanitizeDisabled(entry DisabledRule) DisabledRule {
	r := entry.Rule
	r.Comment = oneLine(r.Comment)
	r.Raw = oneLine(r.Raw)
	m := r.Match
	for _, field := range []*string{
		&m.Verdict, &m.IIF, &m.OIF, &m.Proto, &m.CTState, &m.ICMPType,
		&m.Saddr, &m.Daddr, &m.SPort, &m.DPort, &m.LogPrefix, &m.LogLevel,
		&m.LogGroup, &m.RejectWith,
	} {
		*field = oneLine(*field)
	}
	for i := range m.Unmodeled {
		m.Unmodeled[i] = oneLine(m.Unmodeled[i])
	}
	for i := range m.Sets {
		m.Sets[i] = oneLine(m.Sets[i])
	}
	// A disabled rule is not in the kernel, so it has no counter and no
	// address translation to show; a stale one would be a number the row
	// invites the reader to believe.
	m.Counter = nil
	r.Match = m
	entry.Rule = r
	return entry
}

// RenderSaveFile builds what the Save action writes: nft's own listing of the
// table, with the disabled rules appended as comment lines nft ignores and
// this package reads back.
//
// With nothing disabled it returns the listing unchanged, so a user who never
// disables a rule keeps getting the exact v1 file earlier versions wrote.
func RenderSaveFile(listing string, spec Spec) (string, error) {
	body := strings.TrimSpace(listing)
	if spec.Empty() {
		return body, nil
	}
	var b strings.Builder
	b.WriteString(specMarkerPrefix + SpecVersion + "\n")
	b.WriteString(body + "\n")
	for _, entry := range spec.Disabled {
		if err := checkDisabled(entry); err != nil {
			return "", err
		}
		payload, err := json.Marshal(entry)
		if err != nil {
			return "", errorf("a disabled rule could not be written: %v", err)
		}
		// json.Marshal escapes every control character, so the payload is one
		// line by construction; the guard is here because a comment line that
		// broke in two would be read back as a rule that is not there.
		if strings.ContainsAny(string(payload), "\n\r") {
			return "", errorf("a disabled rule would not fit on one line")
		}
		b.WriteString(disabledPrefix + string(payload) + "\n")
	}
	return strings.TrimRight(b.String(), "\n"), nil
}
