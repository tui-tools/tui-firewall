package nftables

import (
	"encoding/json"
	"sort"
	"strconv"
)

// schemaVersion is the `nft -j` JSON schema this reader was written against.
// nft has emitted 1 since 0.9.0 and bumps it only on an incompatible change,
// so a different number is a reason to stop rather than to guess.
const schemaVersion = 1

// document is the envelope `nft -j list ruleset` prints: one array whose
// entries are single-key objects naming what they carry.
type document struct {
	Nftables []map[string]json.RawMessage `json:"nftables"`
}

// metainfo is nft's own header object.
type metainfo struct {
	Version       string `json:"version"`
	ReleaseName   string `json:"release_name"`
	SchemaVersion int    `json:"json_schema_version"`
}

// tableJSON, chainJSON, setJSON and ruleJSON are the wire shapes. They are
// kept separate from the domain types in model.go on purpose: the domain
// model is what the UI reads and what the tests assert on, and it must not
// change shape every time nft adds a field.
type tableJSON struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
}

type chainJSON struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	// Prio is a number on every nft that emits schema 1, but `nft -j` without
	// -y has printed the named form in the past, so both are accepted.
	Prio   json.RawMessage `json:"prio"`
	Policy string          `json:"policy"`
}

type setJSON struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
	// Type is a plain string for a single-type set and an array for a
	// concatenated one ("ipv4_addr . inet_service").
	Type    json.RawMessage `json:"type"`
	Flags   []string        `json:"flags"`
	Comment string          `json:"comment"`
	Elem    []any           `json:"elem"`
}

type ruleJSON struct {
	Family  string `json:"family"`
	Table   string `json:"table"`
	Chain   string `json:"chain"`
	Handle  int    `json:"handle"`
	Comment string `json:"comment"`
	Expr    []any  `json:"expr"`
}

// ParseRuleset decodes the output of `nft -j list ruleset`.
//
// It is deliberately tolerant about everything except the schema version: an
// entry it does not recognise is skipped, a chain whose table was never
// announced gets its table created, and an expression it cannot decompose is
// kept as text. A ruleset this tool half-understands still has to be readable,
// because read-only always has to work — the mutation guard in command.go is
// what makes sure the half it did not understand is never written to.
func ParseRuleset(data []byte) (Ruleset, error) {
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return Ruleset{}, errorf("could not read the ruleset JSON: %w", err)
	}

	var out Ruleset
	// index maps a table to its position in out.Tables, so chains, sets and
	// rules can find their table whatever order nft listed them in.
	index := map[TableID]int{}
	ensure := func(id TableID) *Table {
		if at, ok := index[id]; ok {
			return &out.Tables[at]
		}
		index[id] = len(out.Tables)
		out.Tables = append(out.Tables, Table{TableID: id})
		return &out.Tables[len(out.Tables)-1]
	}

	// Rules are held back to a second pass: a rule can only be appended to
	// its chain once that chain exists, and nft is not required to list them
	// in that order.
	var pending []ruleJSON

	for _, entry := range doc.Nftables {
		for kind, raw := range entry {
			switch kind {
			case "metainfo":
				var meta metainfo
				if err := json.Unmarshal(raw, &meta); err != nil {
					continue
				}
				out.Version = meta.Version
				out.SchemaVersion = meta.SchemaVersion
			case "table":
				var t tableJSON
				if err := json.Unmarshal(raw, &t); err != nil || t.Name == "" {
					continue
				}
				ensure(TableID{Family: t.Family, Name: t.Name}).Handle = t.Handle
			case "chain":
				var c chainJSON
				if err := json.Unmarshal(raw, &c); err != nil || c.Name == "" {
					continue
				}
				id := TableID{Family: c.Family, Name: c.Table}
				table := ensure(id)
				priority, name := parsePriority(c.Prio)
				table.Chains = append(table.Chains, Chain{
					Table: id, Name: c.Name, Handle: c.Handle,
					Type: c.Type, Hook: c.Hook,
					Priority: priority, PriorityName: name, Policy: c.Policy,
				})
			case "set", "map":
				var s setJSON
				if err := json.Unmarshal(raw, &s); err != nil || s.Name == "" {
					continue
				}
				id := TableID{Family: s.Family, Name: s.Table}
				table := ensure(id)
				table.Sets = append(table.Sets, Set{
					Table: id, Name: s.Name, Handle: s.Handle,
					Type: parseSetType(s.Type), Flags: s.Flags,
					Comment: s.Comment, Elements: renderElements(s.Elem),
				})
			case "rule":
				var r ruleJSON
				if err := json.Unmarshal(raw, &r); err != nil || r.Chain == "" {
					continue
				}
				pending = append(pending, r)
			}
		}
	}

	if out.SchemaVersion != 0 && out.SchemaVersion != schemaVersion {
		return Ruleset{}, errorf(
			"this nft reports JSON schema version %d and the tool reads "+
				"version %d; refusing to guess at a ruleset it may be "+
				"misreading", out.SchemaVersion, schemaVersion)
	}

	for _, r := range pending {
		id := TableID{Family: r.Family, Name: r.Table}
		table := ensure(id)
		chain := findChain(table, r.Chain)
		if chain == nil {
			// A rule whose chain was never announced: keep it rather than
			// drop it, in a chain with no hook and so no policy, which the
			// mutation guard already refuses to write to.
			table.Chains = append(table.Chains, Chain{Table: id, Name: r.Chain})
			chain = &table.Chains[len(table.Chains)-1]
		}
		match, raw := decodeExprs(r.Expr)
		chain.Rules = append(chain.Rules, Rule{
			Table: id, Chain: r.Chain, Handle: r.Handle,
			Index: len(chain.Rules) + 1, Comment: r.Comment,
			Match: match, Raw: raw,
		})
	}

	out.countReferences()
	return out, nil
}

// findChain returns the named chain of a table, or nil.
func findChain(t *Table, name string) *Chain {
	for i := range t.Chains {
		if t.Chains[i].Name == name {
			return &t.Chains[i]
		}
	}
	return nil
}

// parsePriority reads a chain priority, which nft prints as a number and, on
// some releases, as the name it has in the manual.
func parsePriority(raw json.RawMessage) (value int, name string) {
	if len(raw) == 0 {
		return 0, ""
	}
	var number float64
	if err := json.Unmarshal(raw, &number); err == nil {
		return int(number), ""
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		if n, err := strconv.Atoi(text); err == nil {
			return n, ""
		}
		return 0, text
	}
	return 0, ""
}

// parseSetType renders a set's element type: a plain string, or the parts of
// a concatenated type joined the way nft spells them.
func parseSetType(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text
	}
	var parts []string
	if err := json.Unmarshal(raw, &parts); err == nil {
		return joinNonEmpty(parts, " . ")
	}
	return ""
}

// renderElements renders every member of a set the way nft prints it.
func renderElements(elems []any) []string {
	out := make([]string, 0, len(elems))
	for _, e := range elems {
		if rendered := renderElement(e); rendered != "" {
			out = append(out, rendered)
		}
	}
	return out
}

// renderElement renders one set member. nft spells a member as a bare value,
// as a prefix object, as a range, as a concatenation, or wrapped in an "elem"
// object when it carries a comment or a timeout.
func renderElement(e any) string {
	switch v := e.(type) {
	case string:
		return v
	case float64:
		return jsonNumber(v)
	case bool:
		return strconv.FormatBool(v)
	case map[string]any:
		return renderElementObject(v)
	default:
		return ""
	}
}

// renderElementObject renders the object forms of a set member.
func renderElementObject(v map[string]any) string {
	if prefix, ok := v["prefix"].(map[string]any); ok {
		addr := renderElement(prefix["addr"])
		length := renderElement(prefix["len"])
		if addr != "" && length != "" {
			return addr + "/" + length
		}
	}
	if r, ok := v["range"].([]any); ok && len(r) == 2 {
		return renderElement(r[0]) + "-" + renderElement(r[1])
	}
	if concat, ok := v["concat"].([]any); ok {
		parts := make([]string, 0, len(concat))
		for _, part := range concat {
			parts = append(parts, renderElement(part))
		}
		return joinNonEmpty(parts, " . ")
	}
	if elem, ok := v["elem"].(map[string]any); ok {
		rendered := renderElement(elem["val"])
		if comment, ok := elem["comment"].(string); ok && comment != "" {
			rendered += " # " + comment
		}
		return rendered
	}
	return compactJSON(v)
}

// joinNonEmpty joins the parts that are not blank.
func joinNonEmpty(parts []string, sep string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	if len(kept) == 0 {
		return ""
	}
	out := kept[0]
	for _, p := range kept[1:] {
		out += sep + p
	}
	return out
}

// singleKey returns the one key of a statement object. Every nft statement is
// a single-key object; the sort is there so a malformed one with several keys
// still decodes the same way twice, which a fuzz target needs.
func singleKey(obj map[string]any) (string, any, bool) {
	switch len(obj) {
	case 0:
		return "", nil, false
	case 1:
		for k, v := range obj {
			return k, v, true
		}
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys[0], obj[keys[0]], true
}
