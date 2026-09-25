package main

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/iptables"
	"github.com/tui-tools/tui-firewall/internal/nftables"
	"github.com/tui-tools/tui-kit/ui"
)

// openUsage is the --help text of --open. It is the hand-off entry point for
// another tool (tui-tailscale, say) that has just found a port closed: it
// never applies anything by itself, it opens the add form already filled in.
const openUsage = "open the add-rule form prefilled to allow each `port/proto` " +
	"(e.g. 19443/tcp,41641/udp; repeatable), one form and one confirm per port, " +
	"still previewed; nothing is applied without the confirm"

// commentUsage is the --help text of --comment.
const commentUsage = "comment for the rules --open prefills " +
	"(ignored where the backend has no rule comments, e.g. firewalld)"

// maxOpenComment is the longest --comment accepted: the form's text fields
// hold at most this many characters, and a longer value would be cut silently.
const maxOpenComment = 128

// openPort is one port/protocol pair asked for with --open.
type openPort struct {
	port  int
	proto string
}

// String renders the pair the way it was typed: 19443/tcp.
func (p openPort) String() string { return strconv.Itoa(p.port) + "/" + p.proto }

// openFlag collects --open. It is a flag.Value so the flag can be repeated as
// well as given a comma-separated list; both spellings end in the same list.
type openFlag struct {
	ports []openPort
}

// String renders the collected list for the usage text.
func (o *openFlag) String() string {
	if o == nil {
		return ""
	}
	parts := make([]string, 0, len(o.ports))
	for _, p := range o.ports {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ",")
}

// Set parses one --open value and appends its pairs, refusing a pair that
// was already given so the user is not asked twice for the same rule.
func (o *openFlag) Set(value string) error {
	ports, err := parseOpenPorts(value)
	if err != nil {
		return err
	}
	for _, p := range ports {
		for _, seen := range o.ports {
			if seen == p {
				return fmt.Errorf("%s is given twice", p)
			}
		}
		o.ports = append(o.ports, p)
	}
	return nil
}

// parseOpenPorts reads "19443/tcp,41641/udp": a comma-separated list of a
// single port (1-65535) and a protocol (tcp or udp). Ranges and lists of
// ports are left to the form itself; the hand-off names exact ports.
func parseOpenPorts(value string) ([]openPort, error) {
	var ports []openPort
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, fmt.Errorf("empty entry in %q: use port/proto, "+
				"e.g. 19443/tcp,41641/udp", value)
		}
		portText, proto, ok := strings.Cut(item, "/")
		if !ok {
			return nil, fmt.Errorf("%q has no protocol: use port/proto, "+
				"e.g. %s/tcp", item, portText)
		}
		proto = strings.ToLower(strings.TrimSpace(proto))
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("%q: the protocol must be tcp or udp", item)
		}
		port, err := strconv.Atoi(strings.TrimSpace(portText))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("%q: the port must be a single number "+
				"from 1 to 65535", item)
		}
		p := openPort{port: port, proto: proto}
		for _, seen := range ports {
			if seen == p {
				return nil, fmt.Errorf("%s is given twice", p)
			}
		}
		ports = append(ports, p)
	}
	return ports, nil
}

// validateOpenComment refuses a --comment the form could not hold as typed:
// a control character (a newline would split the rule) or one longer than a
// form field.
func validateOpenComment(comment string) error {
	if strings.IndexFunc(comment, unicode.IsControl) >= 0 {
		return fmt.Errorf("--comment must be a single line without control characters")
	}
	if n := len([]rune(comment)); n > maxOpenComment {
		return fmt.Errorf("--comment is %d characters long; at most %d fit a rule",
			n, maxOpenComment)
	}
	return nil
}

// validateOpenOptions checks the --open and --comment combination at start,
// before any backend is touched, so a bad hand-off fails with a message rather
// than a half-filled form.
func validateOpenOptions(opts options) error {
	if opts.comment != "" && len(opts.open.ports) == 0 {
		return fmt.Errorf("--comment only applies to --open")
	}
	if len(opts.open.ports) == 0 {
		return nil
	}
	if opts.check {
		return fmt.Errorf("--open opens the interactive form and cannot be " +
			"combined with --check")
	}
	if opts.report {
		return fmt.Errorf("--open opens the interactive form and cannot be " +
			"combined with --report")
	}
	return validateOpenComment(opts.comment)
}

// openItem is one form the --open sequence still has to show: a port, and the
// group its rule goes into.
type openItem struct {
	port  openPort
	group string
}

// openQueue is the --open sequence: the ports asked for, resolved into one
// form per port and target group once the firewall has been read.
type openQueue struct {
	ports   []openPort
	comment string
	// items is filled on the first successful load; resolved says it was.
	items    []openItem
	resolved bool
	// waiting says the firewall had no group to add to and the user was told.
	waiting bool
	// shown counts the forms opened so far, for the "1 of 2" in the title.
	shown int
}

// queueOpen arms the --open sequence. The first form opens after the first
// load, because which group a rule goes into depends on what was read.
func (a *app) queueOpen(ports []openPort, comment string) {
	if len(ports) == 0 {
		return
	}
	a.open = &openQueue{ports: ports, comment: comment}
}

// advanceOpen opens the next prefilled form when the screen is idle: the
// firewall is loaded, nothing runs, and no dialog is open. It is called after
// every message, so whatever closed the previous form or confirm — a yes, a
// no, an esc, a staged change, a failed command — leads to the next port.
func (a *app) advanceOpen() {
	q := a.open
	if q == nil || a.mode != modeTable || a.busy || a.loading ||
		a.loadFailed || !a.loaded || a.awaitingKeep {
		return
	}
	if !q.resolved {
		groups := openTargets(a.model)
		if len(groups) == 0 {
			// Nothing to add to yet (an empty nftables ruleset). The sequence
			// waits: once the user creates the chains, the next idle load
			// finds them and the forms open.
			if !q.waiting {
				q.waiting = true
				a.setStatus(ui.StatusWarn, "--open: "+noOpenTargetReason(a.model))
			}
			return
		}
		q.resolved = true
		for _, p := range q.ports {
			for _, g := range groups {
				q.items = append(q.items, openItem{port: p, group: g})
			}
		}
		if q.comment != "" && !a.caps.SupportsComments {
			a.setStatusf(ui.StatusWarn,
				"%s has no rule comments here: --comment is not used",
				a.model.Backend)
		}
	}
	if q.shown >= len(q.items) {
		a.open = nil
		return
	}
	item := q.items[q.shown]
	q.shown++
	a.openPrefilled(item, q.comment, q.shown, len(q.items))
}

// openPrefilled switches to the item's group and opens the add form filled
// in to allow its port. Enter on the focused field goes straight to the
// preview; every other field is still there to change.
func (a *app) openPrefilled(item openItem, comment string, n, total int) {
	if a.group != item.group {
		a.group = item.group
		a.cursor, a.offset = 0, 0
		a.applyFilter()
	}
	form := newRuleForm(a.caps, a.model.Services)
	form.title = fmt.Sprintf("Allow %s · %d of %d · esc skips", item.port, n, total)
	if group, ok := a.model.Group(item.group); ok && total > len(a.open.ports) {
		// Several groups per port (iptables v4 and v6): say which this is.
		form.title = fmt.Sprintf("Allow %s in %s · %d of %d · esc skips",
			item.port, group.Label(), n, total)
	}
	form.setChoice("action", string(firewall.ActionAllow))
	form.setText("ports", strconv.Itoa(item.port.port))
	form.setChoice("proto", item.port.proto)
	focus := "ports"
	switch {
	case a.caps.SupportsComments:
		form.setText("comment", comment)
		focus = "comment"
	case comment != "":
		// The status line is hidden behind the form, so the form itself says
		// where the comment went.
		form.setHelp("ports", fmt.Sprintf(
			"--comment is not used: %s has no rule comments.", a.model.Backend))
	}
	form.focusKey(focus)
	a.form = form
	a.editing = false
	a.mode = modeForm
}

// setHelp replaces the help line of the field with the given key.
func (f *ruleForm) setHelp(key, help string) {
	for i := range f.fields {
		if f.fields[i].key == key {
			f.fields[i].help = help
			return
		}
	}
}

// focusKey moves the cursor to the field with the given key.
func (f *ruleForm) focusKey(key string) {
	for i := range f.fields {
		if f.fields[i].key == key {
			f.active = i
			break
		}
	}
	f.focusActive()
}

// openTargets names the groups an inbound allow goes into on this backend:
// the single ufw rule list, the firewalld default zone (listed first), the
// input chain of the table this tool owns on nftables (or else the first
// input-hooked chain), and the filter INPUT chain of each family iptables
// has, because a v4 rule leaves the port closed over IPv6.
func openTargets(model firewall.Model) []string {
	switch model.Backend {
	case "nftables":
		own := nftables.OwnTable.String() + " / input"
		if _, ok := model.Group(own); ok {
			return []string{own}
		}
		for _, g := range model.Groups {
			if g.View == firewall.ViewRules &&
				strings.Contains(g.Description, "hook input") {
				return []string{g.Name}
			}
		}
		return nil
	case "iptables":
		var groups []string
		for _, family := range []iptables.Family{iptables.V4, iptables.V6} {
			name := iptables.GroupName(family, iptables.TableFilter, "INPUT")
			if _, ok := model.Group(name); ok {
				groups = append(groups, name)
			}
		}
		return groups
	default:
		for _, g := range model.Groups {
			if g.View == firewall.ViewRules {
				return []string{g.Name}
			}
		}
		return nil
	}
}

// noOpenTargetReason explains an empty openTargets.
func noOpenTargetReason(model firewall.Model) string {
	if model.Backend == "nftables" {
		return "no input chain yet; create the tool's table and chains " +
			"with x, then the forms open"
	}
	return "this firewall shows no rule list to add the rules to"
}
