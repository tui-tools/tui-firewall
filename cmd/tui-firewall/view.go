package main

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-kit/ui"
)

// Layout constants: the rows the table cannot use.
const (
	headerLines = 2
	footerLines = 2
	// minTableHeight keeps at least one visible row on a very short terminal.
	minTableHeight = 1
)

// tableHeight is the number of rule rows that fit on screen.
func (a *app) tableHeight() int {
	// header + table header + footer + status line.
	return max(a.height-headerLines-footerLines-2, minTableHeight)
}

// View renders the whole screen.
func (a *app) View() string {
	body := a.tableView()
	switch a.mode {
	case modeConfirm:
		return a.confirm.View(a.theme, a.width, a.height)
	case modeFilter:
		return a.input.View(a.theme, a.width, a.height)
	case modePicker:
		return a.picker.View(a.theme, a.width, a.height)
	case modeForm:
		return a.form.view(a.theme, a.width, a.height)
	case modeHelp:
		return placeCenter(ui.HelpScreen(a.theme, "tui-firewall — keys", helpKeys(), a.width),
			a.width, a.height)
	}
	return body
}

// placeCenter centers a rendered box in the terminal.
func placeCenter(box string, width, height int) string {
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

// tableView renders the main screen: header, rule table, help bar, status.
func (a *app) tableView() string {
	header := a.headerView()

	var body string
	switch {
	case a.loading && len(a.visible) == 0:
		body = ui.EmptyState(a.theme, "reading the firewall…", a.width, a.tableHeight()+1)
	case len(a.visible) == 0 && a.filter != "":
		body = ui.EmptyState(a.theme, "no rule matches "+strconv.Quote(a.filter),
			a.width, a.tableHeight()+1)
	case len(a.visible) == 0 && a.loadFailed:
		body = ui.EmptyState(a.theme, "could not read the firewall — see the message below",
			a.width, a.tableHeight()+1)
	case len(a.visible) == 0:
		body = ui.EmptyState(a.theme, "no rules yet — press a to add one",
			a.width, a.tableHeight()+1)
	default:
		body = a.rulesTable()
	}

	help := ui.HelpBar(a.theme, shortHelpKeys(), a.width)
	status := ui.StatusLine(a.theme, a.statusKind, a.status, a.defaultStatus(), a.width)
	return strings.Join([]string{header, body, help, status}, "\n")
}

// headerView renders the status facts at the top of the screen.
func (a *app) headerView() string {
	t := a.theme
	enabled := "disabled"
	style := t.Danger
	if a.model.Enabled {
		enabled, style = "enabled", t.OK
	}

	facts := []ui.Fact{{Label: "status", Value: enabled, Style: &style}}
	if group, ok := a.model.Group(a.group); ok {
		facts = append(facts, policyFacts(group)...)
	}
	logging := a.model.Logging
	if logging == "" {
		logging = "unknown"
	}
	facts = append(facts, ui.Fact{Label: "logging", Value: logging})

	// The group selector only makes sense when the backend has more than one
	// group; ufw always has exactly one.
	subtitle := a.backend.Describe()
	if len(a.model.Groups) > 1 {
		group, _ := a.model.Group(a.group)
		subtitle += "  ·  " + a.caps.GroupLabel + ": " + group.Label() +
			" (" + strconv.Itoa(len(a.model.Groups)) + " total, [ ] to switch)"
	}
	if a.filter != "" {
		subtitle += "  ·  filter: " + a.filter
	}

	return ui.Header{Title: "tui-firewall", Subtitle: subtitle, Facts: facts}.
		Render(t, a.width)
}

// policyFacts renders the default policies a group exposes.
func policyFacts(g firewall.Group) []ui.Fact {
	var facts []ui.Fact
	for _, slot := range g.PolicySlots {
		value := string(currentPolicy(g, slot))
		if slot == firewall.PolicyRouted && g.Default.RoutedDisabled {
			value = "disabled"
		}
		if value == "" {
			value = "unknown"
		}
		facts = append(facts, ui.Fact{Label: string(slot), Value: value})
	}
	return facts
}

// defaultStatus is the hint shown when there is no message to report.
func (a *app) defaultStatus() string {
	count := strconv.Itoa(len(a.visible))
	if a.filter != "" {
		total := 0
		if group, ok := a.model.Group(a.group); ok {
			total = len(group.Rules)
		}
		return count + " of " + strconv.Itoa(total) + " rules  ·  ? for help"
	}
	return count + " rules  ·  ? for help"
}

// rulesTable renders the rule list, dropping columns on narrow terminals.
func (a *app) rulesTable() string {
	columns := []ui.Column{
		{Title: "#", Width: 3},
		{Title: "ACTION", Width: 6},
		{Title: "DIR", Width: 3},
		{Title: "TO", Width: 18, Flex: true},
		{Title: "FROM", Width: 16, Flex: true},
	}
	// Progressive disclosure: extra columns only when they fit.
	showFamily := a.width >= 70
	showComment := a.width >= 90
	if showFamily {
		columns = append(columns, ui.Column{Title: "IP", Width: 3})
	}
	if showComment {
		columns = append(columns, ui.Column{Title: "COMMENT", Width: 20, Flex: true})
	}

	rows := make([][]string, 0, len(a.visible))
	styles := make([]*lipgloss.Style, 0, len(a.visible))
	for _, rule := range a.visible {
		row := []string{
			ruleNumber(rule),
			string(rule.Action),
			string(rule.Direction),
			rule.To,
			rule.From,
		}
		if showFamily {
			row = append(row, familyLabel(rule.Family))
		}
		if showComment {
			row = append(row, rule.Comment)
		}
		rows = append(rows, row)
		styles = append(styles, a.actionStyle(rule.Action))
	}

	return ui.Table{
		Columns:  columns,
		Rows:     rows,
		Styles:   styles,
		Selected: a.cursor,
		Offset:   a.offset,
		Height:   a.tableHeight(),
	}.Render(a.theme, a.width)
}

// ruleNumber renders the rule position, or a dash when the backend has none.
func ruleNumber(r firewall.Rule) string {
	if r.Index <= 0 {
		return "-"
	}
	return strconv.Itoa(r.Index)
}

// familyLabel renders the address family column.
func familyLabel(f firewall.Family) string {
	switch f {
	case firewall.FamilyIPv6:
		return "v6"
	case firewall.FamilyIPv4:
		return "v4"
	default:
		return ""
	}
}

// actionStyle colors a row by its verdict, so a deny stands out from an allow.
func (a *app) actionStyle(action firewall.Action) *lipgloss.Style {
	var style lipgloss.Style
	switch action {
	case firewall.ActionAllow:
		style = a.theme.Row.Foreground(a.theme.OK.GetForeground())
	case firewall.ActionDeny, firewall.ActionReject:
		style = a.theme.Row.Foreground(a.theme.Danger.GetForeground())
	case firewall.ActionLimit:
		style = a.theme.Row.Foreground(a.theme.Warn.GetForeground())
	default:
		style = a.theme.Row
	}
	return &style
}

// describeRule renders a rule as one line, for confirm dialogs.
func describeRule(r firewall.Rule) string {
	parts := []string{string(r.Action)}
	if r.Direction != firewall.DirAny {
		parts = append(parts, string(r.Direction))
	}
	parts = append(parts, r.To, "from", r.From)
	if r.Comment != "" {
		parts = append(parts, "#", r.Comment)
	}
	return strings.Join(parts, " ")
}

// shortHelpKeys is the single-line hint bar.
func shortHelpKeys() []ui.KeyHint {
	return []ui.KeyHint{
		{Key: "a", Desc: "add"},
		{Key: "d", Desc: "delete"},
		{Key: "e", Desc: "enable/disable"},
		{Key: "r", Desc: "reload"},
		{Key: "p", Desc: "policies"},
		{Key: "L", Desc: "logging"},
		{Key: "/", Desc: "filter"},
		{Key: "?", Desc: "help"},
		{Key: "q", Desc: "quit"},
	}
}

// helpKeys is the full key list shown on the help screen.
func helpKeys() []ui.KeyHint {
	return []ui.KeyHint{
		{Key: "↑/k, ↓/j", Desc: "move the selection"},
		{Key: "g / G", Desc: "first / last rule"},
		{Key: "pgup/pgdn", Desc: "scroll a page"},
		{Key: "/", Desc: "filter the rules (esc clears)"},
		{Key: "a", Desc: "add a rule"},
		{Key: "d", Desc: "delete the selected rule"},
		{Key: "e", Desc: "enable or disable the firewall"},
		{Key: "r", Desc: "reload the firewall"},
		{Key: "p", Desc: "change a default policy"},
		{Key: "L", Desc: "change the logging level"},
		{Key: "[ / ]", Desc: "previous / next group (multi-group backends)"},
		{Key: "R", Desc: "reload the view from the firewall"},
		{Key: "?", Desc: "this help"},
		{Key: "q", Desc: "quit"},
		{Key: "", Desc: ""},
		{Key: "note", Desc: "every change is previewed and confirmed first"},
	}
}
