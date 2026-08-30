package main

import (
	"fmt"
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
	case modeFilter, modePrompt:
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
		body = ui.EmptyState(a.theme, a.emptyMessage(), a.width, a.tableHeight()+1)
	default:
		body = a.groupTable()
	}

	help := ui.HelpBar(a.theme, a.shortHelpKeys(), a.width)
	// A backend-supplied warning — firewalld's panic mode — outranks whatever
	// the last action had to say: it describes the machine, not the action.
	kind, message := a.statusKind, a.status
	if a.model.Warning != "" && kind != ui.StatusError {
		// While every packet is being dropped, that is the most important
		// thing on the screen; only an error the user just caused outranks it.
		kind, message = ui.StatusWarn, a.model.Warning
	}
	status := ui.StatusLine(a.theme, kind, message, a.defaultStatus(), a.width)
	return strings.Join([]string{header, body, help, status}, "\n")
}

// emptyMessage says what an empty view means and which key fills it, which
// differs by view: a rule is added with a, and an alias or a port forward
// comes from the actions menu.
func (a *app) emptyMessage() string {
	switch a.currentView() {
	case firewall.ViewNAT:
		return "nothing is translated here — press x for masquerading and port forwards"
	case firewall.ViewAliases:
		return "no aliases yet — press x to create one"
	default:
		return "no rules yet — press a to add one"
	}
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
	// A backend with no logging concept gets no logging fact: "logging:
	// unknown" reads as a machine whose state could not be read, and on
	// nftables it only means the question does not apply.
	if a.caps.SupportsLogging {
		logging := a.model.Logging
		if logging == "" {
			logging = "unknown"
		}
		facts = append(facts, ui.Fact{Label: a.loggingFactLabel(), Value: logging})
	}
	// The backend version, when it was probed: quiet on a tested version,
	// coloured on one nobody has run against.
	if a.backendCompat.Backend != "" {
		facts = append(facts, ui.CompatFact(t, a.backendCompat))
	}
	// Staging is a mode the operator has to be able to see they are in: a change
	// that was staged rather than applied, and a batch that is waiting to be
	// kept, are both facts about the machine's near future.
	if fact, ok := a.stagingFact(); ok {
		facts = append(facts, fact)
	}

	// The group selector only makes sense when the backend has more than one
	// group; ufw always has exactly one.
	subtitle := a.backend.Describe()
	if len(a.model.Groups) > 1 {
		group, _ := a.model.Group(a.group)
		subtitle += "  ·  " + a.caps.GroupLabel + ": " + group.Label() +
			"  ·  " + strconv.Itoa(len(a.model.Groups)) + " " +
			strings.ToLower(a.caps.GroupLabel) + "s, [ ] or v switches"
	}
	if a.filter != "" {
		subtitle += "  ·  filter: " + a.filter
	}

	return ui.Header{Title: "tui-firewall", Subtitle: subtitle, Facts: facts}.
		Render(t, a.width)
}

// stagingFact renders the header fact for staging: whether it is on, how many
// changes are pending, and whether an applied batch is waiting to be kept.
func (a *app) stagingFact() (ui.Fact, bool) {
	if a.staging == nil {
		return ui.Fact{}, false
	}
	switch {
	case a.awaitingKeep:
		style := a.theme.Warn
		return ui.Fact{Label: "staging", Value: "awaiting keep (k)", Style: &style}, true
	case a.stagingOn:
		style := a.theme.Warn
		return ui.Fact{Label: "staging",
			Value: fmt.Sprintf("on, %d pending", a.staging.Len()), Style: &style}, true
	case a.staging.Len() > 0:
		return ui.Fact{Label: "staging",
			Value: fmt.Sprintf("%d pending", a.staging.Len())}, true
	}
	return ui.Fact{}, false
}

// loggingFactLabel names the logging fact the way the backend does, in the
// short form the header has room for.
func (a *app) loggingFactLabel() string {
	if a.caps.LoggingLabel == "" {
		return "logging"
	}
	return strings.ToLower(a.caps.LoggingLabel)
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
	if a.filter != "" {
		total := 0
		if group, ok := a.model.Group(a.group); ok {
			total = len(group.Rules)
		}
		return strconv.Itoa(len(a.visible)) + " of " +
			viewCountLabel(a.currentView(), total) + "  ·  ? for help"
	}
	return viewCountLabel(a.currentView(), len(a.visible)) + "  ·  ? for help"
}

// groupTable renders whichever table the current group asks for. A backend
// whose groups all hold the same species of entry never leaves the first
// branch; the nftables backend shows filter rules, address translation and
// named sets, and no one set of columns is honest about all three.
func (a *app) groupTable() string {
	switch a.currentView() {
	case firewall.ViewNAT:
		return a.natTable()
	case firewall.ViewAliases:
		return a.aliasTable()
	default:
		return a.rulesTable()
	}
}

// currentView names the layout the group on screen wants.
func (a *app) currentView() string {
	group, ok := a.model.Group(a.group)
	if !ok {
		return firewall.ViewRules
	}
	return group.View
}

// rulesTable renders the rule list, dropping columns on narrow terminals.
func (a *app) rulesTable() string {
	if a.flowColumns() {
		return a.flowRuleTable()
	}
	// A backend whose group holds one species of rule (ufw) leaves Kind empty
	// and gets no kind column; one that mixes them (firewalld) gets one. Same
	// for the note a backend attaches to a rule.
	showKind := anyRule(a.visible, func(r firewall.Rule) bool { return r.Kind != "" })
	showNote := anyRule(a.visible, func(r firewall.Rule) bool { return r.Note != "" })

	columns := []ui.Column{
		{Title: "#", Width: 3},
		{Title: "ACTION", Width: 6},
	}
	if showKind {
		// Wide enough for "forward-port", the longest kind there is.
		columns = append(columns, ui.Column{Title: "KIND", Width: 12})
	} else {
		columns = append(columns, ui.Column{Title: "DIR", Width: 3})
	}
	columns = append(columns,
		ui.Column{Title: "TO", Width: 18, Flex: true},
		ui.Column{Title: "FROM", Width: 16, Flex: true})

	// Progressive disclosure: extra columns only when they fit.
	showFamily := a.width >= 70
	showComment := a.width >= 90 && !showNote
	if showFamily {
		columns = append(columns, ui.Column{Title: "IP", Width: 3})
	}
	if showNote {
		columns = append(columns, ui.Column{Title: "WHERE", Width: 14})
	}
	if showComment {
		columns = append(columns, ui.Column{Title: "COMMENT", Width: 20, Flex: true})
	}

	rows := make([][]string, 0, len(a.visible))
	styles := make([]*lipgloss.Style, 0, len(a.visible))
	for _, rule := range a.visible {
		second := string(rule.Direction)
		if showKind {
			second = rule.Kind
		}
		row := []string{
			ruleNumber(rule),
			string(rule.Action),
			second,
			rule.To,
			rule.From,
		}
		if showFamily {
			row = append(row, familyLabel(rule.Family))
		}
		if showNote {
			row = append(row, rule.Note)
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

// anyRule reports whether any rule satisfies a predicate. It is what decides
// whether an optional column is worth its width.
func anyRule(rules []firewall.Rule, match func(firewall.Rule) bool) bool {
	for _, rule := range rules {
		if match(rule) {
			return true
		}
	}
	return false
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

// shortHelpKeys is the single-line hint bar. It is built from what the
// backend can do, so a key that would only answer "not supported here" is not
// advertised in the first place.
func (a *app) shortHelpKeys() []ui.KeyHint {
	hints := []ui.KeyHint{
		{Key: "a", Desc: "add"},
		{Key: "d", Desc: "delete"},
	}
	if a.caps.SupportsEnable {
		hints = append(hints, ui.KeyHint{Key: "e", Desc: "enable/disable"})
	}
	if len(a.model.Groups) > 1 {
		hints = append(hints, ui.KeyHint{Key: "v", Desc: "view"})
	}
	if a.caps.SupportsReload {
		hints = append(hints, ui.KeyHint{Key: "r", Desc: "reload"})
	}
	hints = append(hints, ui.KeyHint{Key: "p", Desc: "policies"})
	if a.caps.SupportsLogging {
		hints = append(hints,
			ui.KeyHint{Key: "L", Desc: strings.ToLower(a.loggingLabel())})
	}
	if len(a.backend.Extras(a.model, a.group)) > 0 {
		hints = append(hints, ui.KeyHint{Key: "x", Desc: "actions"})
	}
	if a.awaitingKeep {
		hints = append(hints, ui.KeyHint{Key: "k", Desc: "keep"})
	} else if a.staging != nil {
		desc := "stage"
		if a.stagingOn {
			desc = "staging on"
		}
		hints = append(hints, ui.KeyHint{Key: "s", Desc: desc})
		if a.staging.Len() > 0 {
			hints = append(hints, ui.KeyHint{Key: "S", Desc: "apply"})
		}
	}
	return append(hints,
		ui.KeyHint{Key: "/", Desc: "filter"},
		ui.KeyHint{Key: "?", Desc: "help"},
		ui.KeyHint{Key: "q", Desc: "quit"})
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
		{Key: "e", Desc: "enable or disable the firewall (ufw)"},
		{Key: "r", Desc: "reload the firewall"},
		{Key: "p", Desc: "change a default policy or a zone target"},
		{Key: "L", Desc: "change the logging level or log-denied value"},
		{Key: "x", Desc: "actions this backend offers beyond these keys"},
		{Key: "[ / ]", Desc: "previous / next group (multi-group backends)"},
		{Key: "v", Desc: "pick a group: a firewalld zone, an nftables chain, NAT, aliases"},
		{Key: "R", Desc: "reload the view from the firewall"},
		{Key: "s", Desc: "toggle staging: collect changes instead of applying them (nftables)"},
		{Key: "S", Desc: "review and apply the staged changes as one atomic transaction"},
		{Key: "k", Desc: "keep an applied batch before its rollback timer fires"},
		{Key: "?", Desc: "this help"},
		{Key: "q", Desc: "quit"},
		{Key: "", Desc: ""},
		{Key: "note", Desc: "every change is previewed and confirmed first"},
	}
}
