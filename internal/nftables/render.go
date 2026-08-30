package nftables

import (
	"strconv"
	"strings"
)

// decodeExprs walks a rule's expression list once, filling the columns the
// rule list shows and building the textual rendering of the whole rule.
//
// Two things come out of the same walk on purpose. A rule the columns cannot
// hold is still shown in full in the Raw line, and a rule the columns do hold
// is still shown verbatim in the detail view, so the two renderings can never
// disagree about what the rule says.
func decodeExprs(exprs []any) (Match, string) {
	var m Match
	parts := make([]string, 0, len(exprs))
	for _, expr := range exprs {
		obj, ok := expr.(map[string]any)
		if !ok {
			parts = append(parts, oneLine(compactJSON(expr)))
			continue
		}
		key, value, ok := singleKey(obj)
		if !ok {
			continue
		}
		if text := oneLine(decodeStatement(&m, key, value)); text != "" {
			parts = append(parts, text)
		}
	}
	return m, strings.Join(parts, " ")
}

// decodeStatement folds one statement into the Match and returns its textual
// rendering. A statement it has no column for still gets rendered, and lands
// in Match.Unmodeled as well so the UI can show it beside the columns.
func decodeStatement(m *Match, key string, value any) string {
	switch key {
	case "match":
		return decodeMatch(m, value)
	case "counter":
		return decodeCounter(m, value)
	case "accept", "drop", "continue", "return":
		m.Verdict = key
		return key
	case "reject":
		m.Verdict = "reject"
		return renderReject(value)
	case "jump", "goto":
		target := targetOf(value)
		m.Verdict = key + " " + target
		return m.Verdict
	case "log":
		m.Log = true
		return renderLog(value)
	case "masquerade":
		m.NAT = &NAT{Kind: "masquerade"}
		m.Verdict = "masquerade"
		return renderMasquerade(value)
	case "dnat", "snat", "redirect":
		return decodeNAT(m, key, value)
	default:
		// An expression with no column of its own: keep it as text, beside
		// the columns rather than instead of them.
		rendered := renderUnknown(key, value)
		m.Unmodeled = append(m.Unmodeled, rendered)
		return rendered
	}
}

// decodeMatch folds a match expression into the columns it belongs to.
func decodeMatch(m *Match, value any) string {
	obj, ok := value.(map[string]any)
	if !ok {
		return compactJSON(value)
	}
	op, _ := obj["op"].(string)
	if op == "" {
		op = "=="
	}
	left := renderOperand(obj["left"])
	right := renderOperand(obj["right"])
	if left == "" && right == "" {
		// A match with neither operand is not a match this package can render
		// as nft syntax; showing nft's own JSON for it is honest and showing
		// a bare operator is not.
		rendered := compactJSON(obj)
		m.Unmodeled = append(m.Unmodeled, rendered)
		return rendered
	}
	m.collectSets(right)

	// A ct state match is what makes a rule stateful, and it reads back as a
	// column of its own rather than as raw text: `ct state established,related`,
	// the way nft spells the compact form.
	if isCTStateMatch(obj["left"]) {
		// The states go through the same one-line sanitising the raw rendering
		// does, so the modelled value and the raw line cannot disagree about
		// what the match says.
		if states := oneLine(ctStateValues(obj["right"])); states != "" &&
			setOnce(&m.CTState, states) {
			return "ct state " + states
		}
	}

	column := matchColumn(obj["left"])
	// Only a plain equality lands in a column: a "!=" or a ">" in the source
	// column would read as the opposite of what the rule does.
	if column != "" && op == "==" {
		if m.assign(column, right, obj["left"]) {
			return strings.TrimSpace(left + " " + right)
		}
	}

	rendered := strings.TrimSpace(left + " " + op + " " + right)
	m.Unmodeled = append(m.Unmodeled, rendered)
	return rendered
}

// isCTStateMatch reports whether a match's left operand is `ct state`.
func isCTStateMatch(left any) bool {
	obj, ok := left.(map[string]any)
	if !ok {
		return false
	}
	ct, ok := obj["ct"].(map[string]any)
	if !ok {
		return false
	}
	key, _ := ct["key"].(string)
	return key == "state"
}

// ctStateValues renders the states of a ct state match as nft's compact form,
// "established,related", whether nft printed one state, a JSON array or a set.
func ctStateValues(right any) string {
	switch value := right.(type) {
	case string:
		return value
	case []any:
		return joinStates(value)
	case map[string]any:
		if set, ok := value["set"].([]any); ok {
			return joinStates(set)
		}
	}
	return ""
}

// joinStates renders a list of state operands, comma-joined and with any
// control characters already gone (each goes through renderOperand).
func joinStates(items []any) string {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		if s := renderOperand(item); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ",")
}

// matchColumn names the Match field a match expression's left operand feeds,
// or "" when this package has no column for it.
func matchColumn(left any) string {
	obj, ok := left.(map[string]any)
	if !ok {
		return ""
	}
	if meta, ok := obj["meta"].(map[string]any); ok {
		switch key, _ := meta["key"].(string); key {
		case "iif", "iifname":
			return "iif"
		case "oif", "oifname":
			return "oif"
		case "l4proto", "protocol":
			return "proto"
		}
		return ""
	}
	if payload, ok := obj["payload"].(map[string]any); ok {
		protocol, _ := payload["protocol"].(string)
		switch field, _ := payload["field"].(string); field {
		case "saddr":
			return "saddr"
		case "daddr":
			return "daddr"
		case "sport":
			return "sport"
		case "dport":
			return "dport"
		case "protocol", "nexthdr":
			// `ip protocol` and `ip6 nexthdr` both name the layer 4 protocol.
			if protocol == "ip" || protocol == "ip6" {
				return "proto"
			}
		}
	}
	return ""
}

// assign writes a match into its column, and reports whether it fitted. A
// second match on a column already filled does not overwrite it: the first
// one is what the rule leads with, and the rest belongs in the raw line.
func (m *Match) assign(column, value string, left any) bool {
	switch column {
	case "iif":
		return setOnce(&m.IIF, value)
	case "oif":
		return setOnce(&m.OIF, value)
	case "proto":
		return setOnce(&m.Proto, value)
	case "saddr":
		m.noteFamily(left)
		return setOnce(&m.Saddr, value)
	case "daddr":
		m.noteFamily(left)
		return setOnce(&m.Daddr, value)
	case "sport":
		m.noteProto(left)
		return setOnce(&m.SPort, value)
	case "dport":
		m.noteProto(left)
		return setOnce(&m.DPort, value)
	}
	return false
}

// noteProto records the protocol a port match was qualified with: nft spells
// a port match as `tcp dport 22`, so the protocol is part of the payload
// header rather than a match of its own.
func (m *Match) noteProto(left any) {
	obj, ok := left.(map[string]any)
	if !ok {
		return
	}
	payload, ok := obj["payload"].(map[string]any)
	if !ok {
		return
	}
	if protocol, _ := payload["protocol"].(string); protocol != "" {
		setOnce(&m.Proto, protocol)
	}
}

// noteFamily is the address-family half of the same story: `ip saddr` and
// `ip6 saddr` are different payload headers, and which one a rule used is
// what the family column shows.
func (m *Match) noteFamily(left any) {
	obj, ok := left.(map[string]any)
	if !ok {
		return
	}
	payload, ok := obj["payload"].(map[string]any)
	if !ok {
		return
	}
	if protocol, _ := payload["protocol"].(string); protocol == "ip6" {
		m.family6 = true
	} else if protocol == "ip" {
		m.family4 = true
	}
}

// setOnce fills a column only when it is still empty.
func setOnce(field *string, value string) bool {
	if *field != "" || value == "" {
		return false
	}
	*field = value
	return true
}

// collectSets records every named set a rendered operand refers to.
//
// It reads the sanitised rendering rather than the raw one on purpose: the
// reference count and the rule the user is shown have to be counting the same
// name, and a name that only exists before the control characters are stripped
// is a reference to something nobody can see.
func (m *Match) collectSets(rendered string) {
	for _, word := range strings.FieldsFunc(oneLine(rendered), func(r rune) bool {
		return r == ' ' || r == ',' || r == '{' || r == '}' || r == '.'
	}) {
		if name, ok := strings.CutPrefix(word, "@"); ok && name != "" {
			m.Sets = append(m.Sets, name)
		}
	}
}

// decodeCounter reads a counter statement.
func decodeCounter(m *Match, value any) string {
	obj, ok := value.(map[string]any)
	if !ok {
		// `counter` with no numbers: a counter all the same.
		m.Counter = &Counter{}
		return "counter"
	}
	packets, _ := obj["packets"].(float64)
	bytes, _ := obj["bytes"].(float64)
	m.Counter = &Counter{Packets: uint64(max(packets, 0)), Bytes: uint64(max(bytes, 0))}
	return "counter packets " + strconv.FormatUint(m.Counter.Packets, 10) +
		" bytes " + strconv.FormatUint(m.Counter.Bytes, 10)
}

// decodeNAT reads a dnat, snat or redirect statement.
func decodeNAT(m *Match, kind string, value any) string {
	nat := &NAT{Kind: kind}
	obj, _ := value.(map[string]any)
	if obj != nil {
		nat.Addr = renderOperand(obj["addr"])
		nat.Port = renderOperand(obj["port"])
	}
	m.NAT = nat
	m.Verdict = kind
	return strings.TrimSpace(nat.String())
}

// renderMasquerade renders a masquerade statement, which may carry a port or
// a flag list.
func renderMasquerade(value any) string {
	obj, ok := value.(map[string]any)
	if !ok || len(obj) == 0 {
		return "masquerade"
	}
	if port := renderOperand(obj["port"]); port != "" {
		return "masquerade to :" + port
	}
	return "masquerade " + compactJSON(obj)
}

// renderReject renders a reject statement with the ICMP type it answers with.
func renderReject(value any) string {
	obj, ok := value.(map[string]any)
	if !ok || len(obj) == 0 {
		return "reject"
	}
	out := "reject"
	if kind, _ := obj["type"].(string); kind != "" {
		out += " with " + kind
	}
	if expr := renderOperand(obj["expr"]); expr != "" {
		out += " " + expr
	}
	return out
}

// renderLog renders a log statement with its prefix and level.
func renderLog(value any) string {
	obj, ok := value.(map[string]any)
	if !ok || len(obj) == 0 {
		return "log"
	}
	out := "log"
	if prefix, _ := obj["prefix"].(string); prefix != "" {
		out += " prefix " + strconv.Quote(prefix)
	}
	if level, _ := obj["level"].(string); level != "" {
		out += " level " + level
	}
	return out
}

// renderUnknown renders a statement this package has no column for, keeping
// nft's own word for it in front so the line still reads as nft syntax.
func renderUnknown(key string, value any) string {
	rendered := renderOperand(value)
	if rendered == "" || rendered == "null" {
		return key
	}
	return key + " " + rendered
}

// renderOperand renders one side of a match, or any nested value, as the text
// nft would have printed.
func renderOperand(v any) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return value
	case float64:
		return jsonNumber(value)
	case bool:
		return strconv.FormatBool(value)
	case []any:
		parts := make([]string, 0, len(value))
		for _, item := range value {
			parts = append(parts, renderOperand(item))
		}
		return "{ " + joinNonEmpty(parts, ", ") + " }"
	case map[string]any:
		return renderOperandObject(value)
	default:
		return compactJSON(v)
	}
}

// renderOperandObject renders the object operands nft uses.
func renderOperandObject(obj map[string]any) string {
	key, value, ok := singleKey(obj)
	if !ok {
		return ""
	}
	if len(obj) > 1 && !knownOperands[key] {
		// An object carrying several fields is the payload of a statement
		// this package does not model — a limit's rate and unit, a queue's
		// numbers. Rendering one field of it would drop the rest silently,
		// so nft's own JSON is shown instead.
		return compactJSON(obj)
	}
	switch key {
	case "meta":
		return renderMeta(fieldOf(value, "key"))
	case "ct":
		return "ct " + fieldOf(value, "key")
	case "payload":
		return renderPayload(value)
	case "prefix", "range", "concat", "elem":
		return renderElementObject(obj)
	case "set":
		items, ok := value.([]any)
		if !ok {
			return compactJSON(obj)
		}
		parts := make([]string, 0, len(items))
		for _, item := range items {
			parts = append(parts, renderOperand(item))
		}
		return "{ " + joinNonEmpty(parts, ", ") + " }"
	case "fib":
		return "fib " + compactJSON(value)
	default:
		return key + " " + renderOperand(value)
	}
}

// knownOperands are the object operands with a rendering of their own, which
// keep it even when nft attached another field to them.
var knownOperands = map[string]bool{
	"meta": true, "ct": true, "payload": true, "prefix": true,
	"range": true, "concat": true, "elem": true, "set": true, "fib": true,
}

// bareMetaKeys are the meta keys nft prints without the "meta" word in front,
// because they have a keyword of their own in the grammar.
var bareMetaKeys = map[string]bool{
	"iif": true, "iifname": true, "iiftype": true,
	"oif": true, "oifname": true, "oiftype": true,
	"l4proto": true, "nfproto": true, "protocol": true,
}

// renderMeta renders a meta operand the way nft spells it.
func renderMeta(key string) string {
	switch {
	case key == "":
		return "meta"
	case bareMetaKeys[key]:
		return key
	default:
		return "meta " + key
	}
}

// renderPayload renders a payload operand: "tcp dport", "ip saddr", or the
// raw base/offset/length form nft falls back to.
func renderPayload(value any) string {
	obj, ok := value.(map[string]any)
	if !ok {
		return "payload"
	}
	protocol, _ := obj["protocol"].(string)
	field, _ := obj["field"].(string)
	if protocol != "" && field != "" {
		return protocol + " " + field
	}
	base, _ := obj["base"].(string)
	if base != "" {
		return "@" + base + "," + renderOperand(obj["offset"]) +
			"," + renderOperand(obj["len"])
	}
	return "payload " + compactJSON(obj)
}

// fieldOf reads one string field out of a decoded object.
func fieldOf(v any, name string) string {
	obj, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	text, _ := obj[name].(string)
	return text
}

// targetOf reads the chain a jump or goto names.
func targetOf(v any) string {
	if target := fieldOf(v, "target"); target != "" {
		return target
	}
	return renderOperand(v)
}
