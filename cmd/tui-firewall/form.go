package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-kit/ui"
)

// noneOption is the "leave empty" entry of every optional choice field.
const noneOption = "(none)"

// ctStateOptions are the connection-state presets the form offers. They are
// the combinations a stateful firewall is actually built from; the field is a
// single pick because a rule almost never wants an arbitrary subset, and the
// one it usually wants — established,related — leads the list.
var ctStateOptions = []string{
	noneOption,
	"established,related",
	"established,related,new",
	"new",
	"invalid",
	"established",
	"related",
}

// fieldKind tells a cycled choice from a free-text field.
type fieldKind int

const (
	fieldChoice fieldKind = iota
	fieldText
)

// formField is one row of the add-rule form.
type formField struct {
	// key identifies the field when building the RuleSpec.
	key   string
	label string
	kind  fieldKind
	// options and choice hold the state of a choice field.
	options []string
	choice  int
	// input holds the state of a text field.
	input textinput.Model
	// help is a one-line hint shown under the form.
	help string
}

// value returns the current value of the field.
func (f formField) value() string {
	if f.kind == fieldChoice {
		if f.choice < 0 || f.choice >= len(f.options) {
			return ""
		}
		return f.options[f.choice]
	}
	return strings.TrimSpace(f.input.Value())
}

// ruleForm is the "add rule" form. It is built from the backend capabilities,
// so it never offers an option the backend cannot express.
type ruleForm struct {
	fields []formField
	active int
	caps   firewall.Capabilities
	// title heads the dialog: "Add rule", or the edit flow's own heading.
	title string
}

// newRuleForm builds the form for a backend and its service list. Which
// fields exist is the backend's decision: an address family and a per-rule log
// flag only appear where the backend can express them, which on firewalld is
// the difference between a plain `--add-service` and a rich rule.
func newRuleForm(caps firewall.Capabilities, services []string) ruleForm {
	text := func(placeholder string) textinput.Model {
		ti := textinput.New()
		ti.Placeholder = placeholder
		ti.CharLimit = 128
		ti.Prompt = ""
		return ti
	}

	actions := make([]string, 0, len(caps.Actions))
	for _, a := range caps.Actions {
		actions = append(actions, string(a))
	}
	directions := []string{noneOption}
	for _, d := range caps.Directions {
		directions = append(directions, string(d))
	}
	protos := []string{noneOption, "tcp", "udp"}
	if caps.SupportsICMP {
		protos = append(protos, "icmp", "icmpv6")
	}
	serviceOptions := append([]string{noneOption}, services...)

	fields := []formField{
		{key: "action", label: "Action", kind: fieldChoice, options: actions},
	}
	// A backend that qualifies a rule by direction gets the field; one whose
	// rules take their direction from where they live — an nftables chain is
	// hooked at exactly one point — would only be offering "(none)".
	if len(caps.Directions) > 0 {
		fields = append(fields, formField{key: "direction", label: "Direction",
			kind: fieldChoice, options: directions,
			help: "Leave empty to let the backend decide."})
	}
	fields = append(fields, []formField{
		{key: "service", label: caps.ServiceLabel, kind: fieldChoice,
			options: serviceOptions, help: "Replaces port and protocol."},
		{key: "ports", label: "Port(s)", kind: fieldText,
			input: text("22, 80,443 or 2000:2100")},
		{key: "proto", label: "Protocol", kind: fieldChoice, options: protos},
		{key: "from", label: "From", kind: fieldText,
			input: text("any, 10.0.0.0/8, fd00::/8")},
		{key: "to", label: "To", kind: fieldText, input: text("any, 192.168.1.10")},
	}...)
	if caps.SupportsICMP {
		fields = append(fields, formField{key: "icmptype", label: "ICMP type",
			kind: fieldText, input: text("echo-request, echo-reply (icmp only)"),
			help: "Only used when the protocol is icmp or icmpv6."})
	}
	// Interface matches are what make a router rule a router rule: "SSH from
	// the LAN side only" is an iifname match. They exist only where the backend
	// can express them.
	if caps.SupportsInterfaces {
		fields = append(fields,
			formField{key: "iif", label: "In iface", kind: fieldText,
				input: text("lan0, wan0 — the interface it arrives on")},
			formField{key: "oif", label: "Out iface", kind: fieldText,
				input: text("wan0 — the interface it leaves on")})
	}
	// The connection-state match is what makes a rule stateful. The presets are
	// the combinations a router actually uses; "established,related" is the one
	// every stateful firewall opens with.
	if caps.SupportsConntrack {
		fields = append(fields, formField{key: "ctstate", label: "Conn. state",
			kind: fieldChoice, options: ctStateOptions,
			help: "established,related is the stateful default."})
	}
	if caps.SupportsFamily {
		fields = append(fields, formField{key: "family", label: "Family",
			kind: fieldChoice, options: []string{noneOption, "v4", "v6"},
			help: "Leave empty to take the family from the addresses."})
	}
	if caps.SupportsLog {
		fields = append(fields, formField{key: "log", label: "Log matches",
			kind: fieldChoice, options: []string{"no", "yes"},
			help: "Logs packets this rule matches, rate-limited."})
	}
	if caps.SupportsComments {
		fields = append(fields, formField{key: "comment", label: "Comment",
			kind: fieldText, input: text("why this rule exists")})
	}
	if caps.SupportsRouted {
		fields = append(fields, formField{key: "routed", label: "Routed",
			kind: fieldChoice, options: []string{"no", "yes"},
			help: "A forwarding rule (ufw route)."})
	}
	if caps.SupportsInsert {
		fields = append(fields, formField{key: "position", label: "Insert at",
			kind: fieldText, input: text("empty appends to the end")})
	}

	f := ruleForm{fields: fields, caps: caps, title: "Add rule"}
	f.focusActive()
	return f
}

// prefill writes a spec back into the form, which is how the edit flow opens
// the form showing the rule as it stands. Field keys the form does not carry
// (a backend without interfaces, say) are silently skipped: the spec came from
// the same backend the form was built for, so nothing can actually be lost.
func (f *ruleForm) prefill(spec firewall.RuleSpec) {
	f.setChoice("action", string(spec.Action))
	f.setChoice("service", spec.Service)
	f.setText("ports", spec.Ports)
	f.setChoice("proto", spec.Proto)
	f.setText("from", spec.From)
	f.setText("to", spec.To)
	f.setText("icmptype", spec.ICMPType)
	f.setText("iif", spec.InIface)
	f.setText("oif", spec.OutIface)
	f.setChoice("ctstate", strings.Join(spec.CTStates, ","))
	f.setChoice("family", string(spec.Family))
	if spec.Log {
		f.setChoice("log", "yes")
	} else {
		f.setChoice("log", "no")
	}
	f.setText("comment", spec.Comment)
	f.active = 0
	f.focusActive()
}

// setText fills a text field by key.
func (f *ruleForm) setText(key, value string) {
	for i := range f.fields {
		if f.fields[i].key == key && f.fields[i].kind == fieldText {
			f.fields[i].input.SetValue(value)
			return
		}
	}
}

// setChoice selects an option by key. An empty value selects the "(none)"
// entry where the field has one. A value the option list does not carry — a
// rule whose conntrack combination is not among the presets, say — is added to
// the list and selected, so pre-filling never silently changes the rule.
func (f *ruleForm) setChoice(key, value string) {
	for i := range f.fields {
		field := &f.fields[i]
		if field.key != key || field.kind != fieldChoice {
			continue
		}
		want := value
		if want == "" {
			want = noneOption
		}
		for j, option := range field.options {
			if option == want {
				field.choice = j
				return
			}
		}
		if value == "" {
			return
		}
		field.options = append(field.options, value)
		field.choice = len(field.options) - 1
		return
	}
}

// focusActive moves the text cursor to the active field.
func (f *ruleForm) focusActive() {
	for i := range f.fields {
		if f.fields[i].kind != fieldText {
			continue
		}
		if i == f.active {
			f.fields[i].input.Focus()
			continue
		}
		f.fields[i].input.Blur()
	}
}

// next moves to the following field.
func (f *ruleForm) next() {
	f.active = (f.active + 1) % len(f.fields)
	f.focusActive()
}

// prev moves to the previous field.
func (f *ruleForm) prev() {
	f.active = (f.active - 1 + len(f.fields)) % len(f.fields)
	f.focusActive()
}

// activeIsChoice reports whether the active field is a cycled choice.
func (f ruleForm) activeIsChoice() bool {
	return f.fields[f.active].kind == fieldChoice
}

// activeLabel, activeOptions and activeValue expose the active field to the
// picker dialog.
func (f ruleForm) activeLabel() string     { return f.fields[f.active].label }
func (f ruleForm) activeOptions() []string { return f.fields[f.active].options }
func (f ruleForm) activeValue() string     { return f.fields[f.active].value() }

// setActiveValue applies a value chosen in the picker.
func (f *ruleForm) setActiveValue(value string) {
	field := &f.fields[f.active]
	for i, o := range field.options {
		if o == value {
			field.choice = i
			return
		}
	}
}

// cycle moves a choice field one step.
func (f *ruleForm) cycle(delta int) {
	field := &f.fields[f.active]
	if len(field.options) == 0 {
		return
	}
	field.choice = (field.choice + delta + len(field.options)) % len(field.options)
}

// updateActive forwards a message to the active text field.
func (f *ruleForm) updateActive(msg tea.Msg) tea.Cmd {
	if f.fields[f.active].kind != fieldText {
		return nil
	}
	var cmd tea.Cmd
	f.fields[f.active].input, cmd = f.fields[f.active].input.Update(msg)
	return cmd
}

// get returns the value of a field by key.
func (f ruleForm) get(key string) string {
	for _, field := range f.fields {
		if field.key == key {
			v := field.value()
			if v == noneOption {
				return ""
			}
			return v
		}
	}
	return ""
}

// spec turns the form into a RuleSpec, validating what the backend cannot.
func (f ruleForm) spec() (firewall.RuleSpec, error) {
	spec := firewall.RuleSpec{
		Action:    firewall.Action(f.get("action")),
		Direction: firewall.Direction(f.get("direction")),
		Service:   f.get("service"),
		Ports:     f.get("ports"),
		Proto:     f.get("proto"),
		From:      f.get("from"),
		To:        f.get("to"),
		InIface:   f.get("iif"),
		OutIface:  f.get("oif"),
		ICMPType:  f.get("icmptype"),
		Comment:   f.get("comment"),
		Family:    firewall.Family(f.get("family")),
		Log:       f.get("log") == "yes",
		Routed:    f.get("routed") == "yes",
	}
	if states := f.get("ctstate"); states != "" {
		spec.CTStates = strings.Split(states, ",")
	}
	if position := f.get("position"); position != "" {
		n, err := strconv.Atoi(position)
		if err != nil || n <= 0 {
			return spec, fmt.Errorf("insert position must be a positive number")
		}
		spec.Position = n
	}
	return spec, nil
}

// view renders the form as a dialog.
func (f ruleForm) view(t theme.Theme, width, height int) string {
	labelWidth := 0
	for _, field := range f.fields {
		if w := len(field.label); w > labelWidth {
			labelWidth = w
		}
	}

	inner := min(max(width-8, 30), 72)
	valueWidth := max(inner-labelWidth-6, 10)

	lines := []string{t.Title.Render(f.title), ""}
	for i, field := range f.fields {
		label := t.Muted.Render(ui.Pad(field.label, labelWidth))
		var value string
		switch {
		case field.kind == fieldChoice:
			value = renderChoice(t, field, i == f.active, valueWidth)
		case i == f.active:
			field.input.Width = valueWidth - 2
			value = field.input.View()
		default:
			value = renderIdleText(t, field, valueWidth)
		}
		marker := "  "
		if i == f.active {
			marker = t.Accent.Render("> ")
		}
		lines = append(lines, marker+label+"  "+value)
	}

	if help := f.fields[f.active].help; help != "" {
		lines = append(lines, "", t.Muted.Render(help))
	}
	lines = append(lines, "",
		t.Key.Render("tab")+t.KeyDesc.Render(" next    ")+
			t.Key.Render("←/→")+t.KeyDesc.Render(" change    ")+
			t.Key.Render("enter")+t.KeyDesc.Render(" pick/submit    ")+
			t.Key.Render("esc")+t.KeyDesc.Render(" cancel"))

	box := t.Dialog.Width(inner).Render(strings.Join(lines, "\n"))
	return placeCenter(box, width, height)
}

// renderChoice draws a choice field with its cycling arrows.
func renderChoice(t theme.Theme, field formField, active bool, width int) string {
	value := ui.Truncate(field.value(), width-4)
	if active {
		return t.Accent.Render("‹ ") + t.Base.Render(value) + t.Accent.Render(" ›")
	}
	return t.Base.Render("  " + value)
}

// renderIdleText draws a text field that does not have focus.
func renderIdleText(t theme.Theme, field formField, width int) string {
	value := field.value()
	if value == "" {
		return t.Muted.Render(ui.Truncate(field.input.Placeholder, width))
	}
	return t.Base.Render(ui.Truncate(value, width))
}

// setFieldForTest sets a field's value by key, whatever its kind, and leaves
// the cursor on it. It exists so a test can fill the form without simulating
// every keystroke; nothing in the running program uses it.
func (f *ruleForm) setFieldForTest(key, value string) {
	for i := range f.fields {
		if f.fields[i].key != key {
			continue
		}
		f.active = i
		f.focusActive()
		if f.fields[i].kind == fieldText {
			f.fields[i].input.SetValue(value)
			return
		}
		for j, option := range f.fields[i].options {
			if option == value {
				f.fields[i].choice = j
				return
			}
		}
	}
}
