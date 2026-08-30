package main

import (
	"strconv"

	"github.com/charmbracelet/lipgloss"
	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-kit/ui"
)

// natTable renders the address translation view: what is rewritten, on the
// way through which interface, and to where.
//
// It is a view of its own rather than the rule table with a column added,
// because the question it answers is different. A filter rule is read as
// "what is allowed"; a NAT rule is read as "what does this become", and the
// target is the column the eye goes to first.
func (a *app) natTable() string {
	columns := []ui.Column{
		{Title: "#", Width: 3},
		{Title: "KIND", Width: 10},
		{Title: "IN", Width: 6},
		{Title: "OUT", Width: 6},
	}
	showProto := a.width >= 70
	showCounter := a.width >= 90
	showComment := a.width >= 100
	if showProto {
		columns = append(columns,
			ui.Column{Title: "PROTO", Width: 5},
			ui.Column{Title: "PORT", Width: 7})
	}
	columns = append(columns, ui.Column{Title: "TRANSLATED TO", Width: 24, Flex: true})
	if showCounter {
		columns = append(columns, ui.Column{Title: "COUNTER", Width: 12})
	}
	if showComment {
		columns = append(columns, ui.Column{Title: "COMMENT", Width: 18, Flex: true})
	}

	rows := make([][]string, 0, len(a.visible))
	for _, rule := range a.visible {
		row := []string{
			ruleNumber(rule),
			orDash(rule.Kind),
			orDash(rule.Extra[firewall.ExtraInIface]),
			orDash(rule.Extra[firewall.ExtraOutIface]),
		}
		if showProto {
			row = append(row, orDash(rule.Proto), orDash(rule.Ports))
		}
		row = append(row, orDash(rule.Extra[firewall.ExtraTarget]))
		if showCounter {
			row = append(row, rule.Extra[firewall.ExtraCounter])
		}
		if showComment {
			row = append(row, rule.Comment)
		}
		rows = append(rows, row)
	}
	return a.renderTable(columns, rows, nil)
}

// aliasTable renders the named sets, with the number of rules that use each.
//
// The reference count earns its column: an alias nothing refers to is dead
// weight the user can delete, and one that four rules refer to is four rules
// they are about to change by editing it. Neither fact is visible anywhere
// else in the tool.
func (a *app) aliasTable() string {
	columns := []ui.Column{
		{Title: "#", Width: 3},
		{Title: "NAME", Width: 16, Flex: true},
		// Wide enough for the longest type with its flags spelled out:
		// "ipv4_addr (interval,timeout)" is what firewalld's own sets look
		// like, and an alias whose type is truncated says very little.
		{Title: "HOLDS", Width: 20, Flex: true},
	}
	showTable := a.width >= 80
	showComment := a.width >= 100
	columns = append(columns,
		ui.Column{Title: "MEMBERS", Width: 7},
		ui.Column{Title: "USED BY", Width: 7})
	if showTable {
		columns = append(columns, ui.Column{Title: "TABLE", Width: 14})
	}
	columns = append(columns, ui.Column{Title: "CONTENTS", Width: 24, Flex: true})
	if showComment {
		columns = append(columns, ui.Column{Title: "COMMENT", Width: 18, Flex: true})
	}

	rows := make([][]string, 0, len(a.visible))
	styles := make([]*lipgloss.Style, 0, len(a.visible))
	for _, rule := range a.visible {
		references := rule.Extra[firewall.ExtraReferences]
		row := []string{
			ruleNumber(rule),
			rule.Service,
			describeHolds(rule),
			rule.Extra[firewall.ExtraElements],
			describeReferences(references),
		}
		if showTable {
			row = append(row, rule.Note)
		}
		row = append(row, rule.To)
		if showComment {
			row = append(row, rule.Comment)
		}
		rows = append(rows, row)
		// An alias no rule refers to is dimmed: it is not wrong, it is just
		// not doing anything.
		if references == "0" {
			style := a.theme.Row.Foreground(a.theme.Muted.GetForeground())
			styles = append(styles, &style)
			continue
		}
		styles = append(styles, nil)
	}
	return a.renderTable(columns, rows, styles)
}

// describeHolds renders an alias's element type with its flags.
func describeHolds(rule firewall.Rule) string {
	holds := rule.Kind
	if flags := rule.Extra[firewall.ExtraFlags]; flags != "" {
		holds += " (" + flags + ")"
	}
	return holds
}

// describeReferences renders the reference count, spelling out the zero.
func describeReferences(count string) string {
	if count == "0" {
		return "unused"
	}
	return count
}

// orDash renders an empty cell as a dash, so a column of blanks does not read
// as a column of missing data.
func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

// renderTable is the shared tail of every view: the same scroll position, the
// same height, the same selection.
func (a *app) renderTable(columns []ui.Column, rows [][]string,
	styles []*lipgloss.Style) string {
	return ui.Table{
		Columns:  columns,
		Rows:     rows,
		Styles:   styles,
		Selected: a.cursor,
		Offset:   a.offset,
		Height:   a.tableHeight(),
	}.Render(a.theme, a.width)
}

// flowColumns reports whether the rule table should show the interface, port
// and counter columns: the OPNsense-style reading of a rule, which needs a
// backend that fills them. ufw and firewalld put the port inside the TO cell
// and know nothing about per-rule counters, so on those backends the extra
// columns would be three columns of dashes.
func (a *app) flowColumns() bool {
	return anyRule(a.visible, func(r firewall.Rule) bool {
		return r.Extra[firewall.ExtraInIface] != "" ||
			r.Extra[firewall.ExtraOutIface] != "" ||
			r.Extra[firewall.ExtraCounter] != ""
	})
}

// flowRuleTable renders a rule the way a router's rule list reads: the
// verdict, the interfaces the packet passes between, what it matches, and
// whether the rule has ever fired.
func (a *app) flowRuleTable() string {
	columns := []ui.Column{
		{Title: "#", Width: 3},
		{Title: "ACTION", Width: 7},
		{Title: "IN", Width: 6},
		{Title: "OUT", Width: 6},
	}
	showProto := a.width >= 70
	showFamily := a.width >= 78 &&
		anyRule(a.visible, func(r firewall.Rule) bool { return r.Family != "" })
	showCounter := a.width >= 96
	showComment := a.width >= 110
	if showProto {
		columns = append(columns, ui.Column{Title: "PROTO", Width: 5})
	}
	if showFamily {
		columns = append(columns, ui.Column{Title: "IP", Width: 2})
	}
	columns = append(columns,
		ui.Column{Title: "SOURCE", Width: 16, Flex: true},
		ui.Column{Title: "DESTINATION", Width: 16, Flex: true},
		ui.Column{Title: "PORT", Width: 9})
	if showCounter {
		columns = append(columns, ui.Column{Title: "COUNTER", Width: 12})
	}
	if showComment {
		columns = append(columns, ui.Column{Title: "COMMENT", Width: 18, Flex: true})
	}

	rows := make([][]string, 0, len(a.visible))
	styles := make([]*lipgloss.Style, 0, len(a.visible))
	for _, rule := range a.visible {
		row := []string{
			ruleNumber(rule),
			orDash(string(rule.Action)),
			orDash(rule.Extra[firewall.ExtraInIface]),
			orDash(rule.Extra[firewall.ExtraOutIface]),
		}
		if showProto {
			row = append(row, orDash(rule.Proto))
		}
		if showFamily {
			row = append(row, familyLabel(rule.Family))
		}
		row = append(row, rule.From, rule.To, orDash(rule.Ports))
		if showCounter {
			row = append(row, rule.Extra[firewall.ExtraCounter])
		}
		if showComment {
			row = append(row, ruleNote(rule))
		}
		rows = append(rows, row)
		styles = append(styles, a.actionStyle(rule.Action))
	}
	return a.renderTable(columns, rows, styles)
}

// ruleNote is the comment column of the flow table: the rule's own comment,
// falling back to whatever the columns had no room for, so a rule with no
// comment still says something about itself.
func ruleNote(rule firewall.Rule) string {
	if rule.Comment != "" {
		return rule.Comment
	}
	return rule.Extra[firewall.ExtraDetail]
}

// viewCountLabel renders the count the status line shows, with the noun the
// view on screen actually holds: "9 rules" is wrong on the alias view.
func viewCountLabel(view string, count int) string {
	noun := "rules"
	switch view {
	case firewall.ViewAliases:
		noun = "aliases"
	case firewall.ViewNAT:
		noun = "NAT rules"
	}
	return strconv.Itoa(count) + " " + noun
}
