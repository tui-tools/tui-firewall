package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-firewall/internal/firewall"
	"github.com/tui-tools/tui-firewall/internal/nftables/staging"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-kit/ui"
)

// mode is the screen the app currently shows. Only one dialog is open at a
// time, which keeps the update loop flat.
type mode int

const (
	modeTable mode = iota
	modeConfirm
	modeFilter
	modePrompt
	modePicker
	modeForm
	modeHelp
	modeLog
)

// pickerTarget says what a picker's answer applies to.
type pickerTarget int

const (
	pickerNone pickerTarget = iota
	pickerLogging
	pickerPolicySlot
	pickerPolicyValue
	pickerFormChoice
	pickerGroup
	pickerExtra
	pickerExtraStep
	pickerStagingAction
	pickerStagingDrop
)

// app is the tui-firewall Bubble Tea model.
type app struct {
	backend firewall.Backend
	theme   theme.Theme
	caps    firewall.Capabilities
	// backendCompat is what the version probe found, rendered in the header.
	backendCompat compat.Result

	model firewall.Model
	// group is the name of the group currently shown.
	group string
	// visible holds the rules left after the filter, in display order.
	visible []firewall.Rule

	width, height int
	cursor        int
	offset        int
	filter        string

	mode    mode
	confirm ui.Confirm
	input   ui.Input
	picker  ui.Picker
	form    ruleForm

	// pickerFor says what the open picker will answer.
	pickerFor pickerTarget
	// pendingSlot remembers which policy slot the user picked first.
	pendingSlot firewall.PolicyDirection
	// pendingExtra remembers the backend action being assembled.
	pendingExtra pendingExtra
	// extras is the action list the menu was built from, so a choice can be
	// matched back to the action it names.
	extras []firewall.Extra

	// staging holds the pending-changes set and the atomic-apply lifecycle. It
	// is only reachable on a backend that can snapshot its ruleset (nftables);
	// snap is that backend, or nil.
	staging   *staging.Session
	snap      snapshotter
	stagingOn bool
	// awaitingKeep reports that a staged batch was applied and is waiting for
	// the operator to confirm they still have access before it rolls back.
	awaitingKeep bool
	// keepToken guards the rollback timer against a stale tick: only the tick
	// carrying the current token may fire the rollback.
	keepToken int
	// pendingApply marks the change now at the confirm dialog as the staged
	// batch, so a yes arms the keep timer instead of just reporting success.
	pendingApply bool
	// keepTickPending asks the next load to start the rollback countdown, so
	// the applied batch is on screen before its keep window begins.
	keepTickPending bool

	// live holds the live-log view: the open stream, the events retained, and
	// whether the feed is paused. It is only reachable on the nftables backend
	// and its demo, the ones that implement logStreamer.
	live liveLog

	status     string
	statusKind ui.StatusKind
	loading    bool
	// loadFailed reports that the last Load returned an error, so the empty
	// state does not claim the firewall simply has no rules.
	loadFailed bool
	// busy blocks input while a command runs.
	busy bool
}

// loadedMsg carries the result of a Load.
type loadedMsg struct {
	model firewall.Model
	err   error
}

// ranMsg carries the result of a Run.
type ranMsg struct {
	change firewall.Change
	output string
	err    error
}

// pendingExtra is a backend action part-way through collecting its answers.
type pendingExtra struct {
	extra firewall.Extra
	// args holds the answers given so far, one per step.
	args []string
}

// newApp builds the model around a backend.
func newApp(backend firewall.Backend, th theme.Theme,
	backendCompat compat.Result) *app {
	a := &app{
		backend:       backend,
		theme:         th,
		caps:          backend.Capabilities(),
		backendCompat: backendCompat,
		width:         80,
		height:        24,
		loading:       true,
	}
	// ufw grew rule comments in 0.35. On an older one the backend would build
	// a command the firewall refuses, so the field is dropped from the add
	// form instead — and which version that is stays in the manifest, not in
	// a comparison written here.
	if !backendCompat.Caps().Has("rule-comments") {
		a.caps.SupportsComments = false
	}
	// Staging is offered only where a rollback is possible: a backend that can
	// snapshot its own ruleset. That is the nftables backend and its demo; ufw
	// and firewalld apply through their own daemons and have no such snapshot.
	if snap, ok := backend.(snapshotter); ok {
		a.snap = snap
		a.staging = staging.New(0)
	}
	if th.Warning != "" {
		a.setStatus(ui.StatusWarn, th.Warning)
	}
	return a
}

// Init starts the first load.
func (a *app) Init() tea.Cmd { return a.load() }

// load reads the firewall state in the background.
func (a *app) load() tea.Cmd {
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		model, err := backend.Load(ctx)
		return loadedMsg{model: model, err: err}
	}
}

// run executes a confirmed change in the background.
func (a *app) run(change firewall.Change) tea.Cmd {
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		out, err := backend.Run(ctx, change)
		return ranMsg{change: change, output: out, err: err}
	}
}

// setStatus records a plain message for the status line.
func (a *app) setStatus(kind ui.StatusKind, message string) {
	a.status = message
	a.statusKind = kind
}

// setStatusf records a formatted message for the status line.
func (a *app) setStatusf(kind ui.StatusKind, format string, args ...any) {
	a.setStatus(kind, fmt.Sprintf(format, args...))
}

// Update is the main event loop.
func (a *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		a.clampCursor()
		return a, nil

	case loadedMsg:
		a.loading = false
		if msg.err != nil {
			a.loadFailed = true
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, nil
		}
		a.loadFailed = false
		a.model = msg.model
		if _, ok := a.model.Group(a.group); !ok && len(a.model.Groups) > 0 {
			a.group = a.model.Groups[0].Name
		}
		a.applyFilter()
		// A batch that just applied starts its keep window now, with the applied
		// ruleset already on screen, so the operator sees what they are keeping.
		if a.keepTickPending && a.staging != nil {
			a.keepTickPending = false
			token := a.keepToken
			timeout := a.staging.Timeout()
			return a, tea.Tick(timeout, func(time.Time) tea.Msg {
				return keepExpiredMsg{token: token}
			})
		}
		return a, nil

	case ranMsg:
		a.busy = false
		wasApply := a.pendingApply
		a.pendingApply = false
		if msg.err != nil {
			if wasApply {
				// The batch was atomic: nft rejected it, so nothing changed and
				// there is nothing to keep or roll back.
				a.setStatusf(ui.StatusError,
					"the staged batch was rejected and nothing changed: %s",
					firstLine(msg.err.Error()))
				return a, a.load()
			}
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, a.load()
		}
		if wasApply {
			return a, a.armKeep()
		}
		summary := strings.TrimSpace(msg.output)
		if summary == "" {
			summary = "done"
		}
		a.setStatusf(ui.StatusOK, "%s: %s", msg.change.Description, firstLine(summary))
		a.loading = true
		return a, a.load()

	case keepExpiredMsg:
		return a, a.keepExpired(msg.token)

	case applyReadyMsg:
		if msg.err != nil {
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, nil
		}
		a.openApplyConfirm(msg.change)
		return a, nil

	case logEventMsg:
		return a, a.handleLogEvent(msg)

	case tea.KeyMsg:
		return a.handleKey(msg)
	}

	// Anything else (cursor blink, …) only concerns an open text input.
	if a.mode == modeFilter || a.mode == modePrompt {
		cmd, _ := a.input.Update(msg)
		return a, cmd
	}
	if a.mode == modeForm {
		return a, a.form.updateActive(msg)
	}
	return a, nil
}

// handleKey routes a key press to the open dialog, or to the table.
func (a *app) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// ctrl+c always quits, even mid-dialog.
	if msg.Type == tea.KeyCtrlC {
		return a, tea.Quit
	}
	if a.busy {
		// A command is running: swallow input rather than queueing surprises.
		return a, nil
	}

	switch a.mode {
	case modeConfirm:
		return a.handleConfirm(msg)
	case modeFilter:
		return a.handleFilter(msg)
	case modePrompt:
		return a.handlePrompt(msg)
	case modePicker:
		return a.handlePicker(msg)
	case modeForm:
		return a.handleForm(msg)
	case modeHelp:
		a.mode = modeTable
		return a, nil
	case modeLog:
		return a.handleLogKey(msg)
	default:
		return a.handleTableKey(msg)
	}
}

// handleConfirm resolves the confirm dialog.
func (a *app) handleConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	a.confirm.Update(msg)
	if !a.confirm.Done {
		return a, nil
	}
	a.mode = modeTable
	confirmed := a.confirm.Confirmed
	change, ok := a.confirm.Payload.(firewall.Change)
	a.confirm = ui.Confirm{}
	if !confirmed || !ok {
		// A cancelled apply must not leave the next run looking like the batch.
		a.pendingApply = false
		a.setStatus(ui.StatusInfo, "cancelled")
		return a, nil
	}
	a.busy = true
	a.setStatusf(ui.StatusInfo, "running %s…",
		firstLine(a.backend.Preview(change)))
	return a, a.run(change)
}

// handleFilter resolves the filter prompt.
func (a *app) handleFilter(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	cmd, _ := a.input.Update(msg)
	if !a.input.Done {
		// Filter as the user types.
		a.filter = a.input.Value()
		a.applyFilter()
		return a, cmd
	}
	if a.input.Accepted {
		a.filter = a.input.Value()
	} else {
		a.filter = ""
	}
	a.applyFilter()
	a.mode = modeTable
	return a, nil
}

// handlePrompt resolves a free-text answer an action asked for. It is a mode
// of its own rather than the filter prompt because the filter narrows the view
// as the user types, while this one must not act until it is submitted.
func (a *app) handlePrompt(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	cmd, _ := a.input.Update(msg)
	if !a.input.Done {
		return a, cmd
	}
	value := a.input.Value()
	accepted := a.input.Accepted
	a.input = ui.Input{}
	a.mode = modeTable
	if !accepted {
		a.pendingExtra = pendingExtra{}
		a.setStatus(ui.StatusInfo, "cancelled")
		return a, nil
	}
	return a, a.answerExtra(value)
}

// handlePicker resolves whichever picker is open.
func (a *app) handlePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	a.picker.Update(msg)
	if !a.picker.Done {
		return a, nil
	}
	choice := a.picker.Selected()
	accepted := a.picker.Accepted
	target := a.pickerFor
	a.picker = ui.Picker{}
	a.pickerFor = pickerNone

	if !accepted {
		a.mode = modeTable
		if target == pickerFormChoice {
			a.mode = modeForm
		}
		a.pendingExtra = pendingExtra{}
		return a, nil
	}

	switch target {
	case pickerLogging:
		a.mode = modeTable
		return a, a.buildAndConfirm(a.loggingLabel(), func() (firewall.Change, error) {
			return a.backend.BuildSetLogging(choice)
		})
	case pickerPolicySlot:
		a.pendingSlot = firewall.PolicyDirection(choice)
		return a, a.openPolicyValuePicker()
	case pickerPolicyValue:
		a.mode = modeTable
		slot := a.pendingSlot
		return a, a.buildAndConfirm("Change default policy", func() (firewall.Change, error) {
			return a.backend.BuildSetPolicy(a.group, slot, firewall.Policy(choice))
		})
	case pickerGroup:
		a.group = choice
		a.cursor, a.offset = 0, 0
		a.applyFilter()
		a.mode = modeTable
		return a, nil
	case pickerFormChoice:
		a.form.setActiveValue(choice)
		a.mode = modeForm
		return a, nil
	case pickerExtra:
		return a, a.startExtra(choice)
	case pickerExtraStep:
		return a, a.answerExtra(choice)
	case pickerStagingAction:
		a.mode = modeTable
		return a, a.stagingAction(choice)
	case pickerStagingDrop:
		a.mode = modeTable
		a.dropStaged(choice)
		return a, nil
	default:
		a.mode = modeTable
		return a, nil
	}
}

// handleForm routes keys to the add-rule form.
func (a *app) handleForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		a.mode = modeTable
		a.setStatus(ui.StatusInfo, "cancelled")
		return a, nil
	case "tab", "down":
		a.form.next()
		return a, nil
	case "shift+tab", "up":
		a.form.prev()
		return a, nil
	case "left":
		if a.form.activeIsChoice() {
			a.form.cycle(-1)
			return a, nil
		}
	case "right":
		if a.form.activeIsChoice() {
			a.form.cycle(1)
			return a, nil
		}
	case "enter":
		if a.form.activeIsChoice() {
			// A choice field opens a picker: better than cycling a long list.
			a.picker = ui.NewPicker(a.form.activeLabel(),
				a.form.activeOptions(), a.form.activeValue())
			a.pickerFor = pickerFormChoice
			a.mode = modePicker
			return a, nil
		}
		return a, a.submitForm()
	}
	return a, a.form.updateActive(msg)
}

// submitForm builds the add command from the form and opens the confirm dialog.
func (a *app) submitForm() tea.Cmd {
	spec, err := a.form.spec()
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	change, err := a.backend.BuildAddRule(a.group, spec)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.stageOrConfirm(change.Description, "The firewall will be changed as follows.", change)
	return nil
}

// handleTableKey handles the main screen.
func (a *app) handleTableKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		return a, tea.Quit
	case "?":
		a.mode = modeHelp
	case "j", "down":
		a.moveCursor(1)
	case "k", "up":
		// k keeps an applied batch when one is waiting; otherwise it is the
		// vi-style move up.
		if msg.String() == "k" && a.awaitingKeep {
			return a, a.keepStaged()
		}
		a.moveCursor(-1)
	case "g", "home":
		a.cursor, a.offset = 0, 0
	case "G", "end":
		a.cursor = max(len(a.visible)-1, 0)
		a.clampCursor()
	case "pgdown", "ctrl+f":
		a.moveCursor(a.tableHeight())
	case "pgup", "ctrl+b":
		a.moveCursor(-a.tableHeight())
	case "/":
		a.input = ui.NewInput("Filter rules", "port, address, comment…", a.filter)
		a.input.Help = "Matches any column. Empty clears the filter."
		a.mode = modeFilter
	case "R", "ctrl+r":
		a.loading = true
		return a, a.load()
	case "a":
		return a, a.startAdd()
	case "s":
		a.toggleStaging()
	case "S":
		return a, a.openStagingMenu()
	case "d":
		return a, a.confirmDelete()
	case "e":
		return a, a.confirmToggle()
	case "r":
		return a, a.buildAndConfirm("Reload the firewall", a.backend.BuildReload)
	case "p":
		return a, a.openPolicySlotPicker()
	case "L":
		return a, a.openLoggingPicker()
	case "l":
		return a, a.confirmToggleLog()
	case "w":
		return a, a.openLogView()
	case "x":
		return a, a.openExtrasMenu()
	case "v":
		return a, a.openGroupPicker()
	case "]", "tab":
		a.cycleGroup(1)
	case "[", "shift+tab":
		a.cycleGroup(-1)
	}
	return a, nil
}

// startAdd begins adding an entry to the view on screen. A rule view opens the
// add-rule form; the NAT and alias views hold no plain rules, so a there opens
// the actions menu those views add through — the masquerade and port-forward
// actions for NAT, the create-alias action for the aliases — instead of a
// refusal that only tells the user to press x.
func (a *app) startAdd() tea.Cmd {
	switch a.currentView() {
	case firewall.ViewNAT, firewall.ViewAliases:
		return a.openExtrasMenu()
	default:
		a.form = newRuleForm(a.caps, a.model.Services)
		a.mode = modeForm
		return nil
	}
}

// buildAndConfirm runs a command builder and opens the confirm dialog, or
// reports the builder's error in the status line.
func (a *app) buildAndConfirm(title string,
	build func() (firewall.Change, error)) tea.Cmd {
	change, err := build()
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.stageOrConfirm(title, change.Description+".", change)
	return nil
}

// openConfirm shows the preview of a change. The backend's own note about how
// the change is applied is appended to the body, because on firewalld that is
// the difference between two command lines and a reload.
func (a *app) openConfirm(title, body string, change firewall.Change) {
	if change.Note != "" {
		body = strings.TrimSpace(body + "\n" + change.Note + ".")
	}
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   title,
		Body:    body,
		Command: a.backend.Preview(change),
		Danger:  change.Destructive,
		Payload: change,
	}
}

// confirmDelete asks before deleting the selected rule.
func (a *app) confirmDelete() tea.Cmd {
	rule, ok := a.selectedRule()
	if !ok {
		a.setStatus(ui.StatusWarn, "no rule selected")
		return nil
	}
	change, err := a.backend.BuildDeleteRule(a.group, rule)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	change.Destructive = true
	a.stageOrConfirm(change.Description, "Rule: "+describeRule(rule), change)
	return nil
}

// confirmToggle asks before enabling or disabling the firewall.
func (a *app) confirmToggle() tea.Cmd {
	if !a.caps.SupportsEnable {
		hint := a.caps.EnableHint
		if hint == "" {
			hint = "this backend cannot turn the firewall on and off"
		}
		a.setStatus(ui.StatusWarn, hint)
		return nil
	}
	enable := !a.model.Enabled
	change, err := a.backend.BuildSetEnabled(enable)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	body := "The firewall will start filtering traffic with the rules below."
	if !enable {
		body = "All traffic will be allowed until the firewall is enabled again."
	}
	if enable {
		body += "\nMake sure a rule allows your SSH session before confirming."
	}
	change.Destructive = true
	a.openConfirm(change.Description, body, change)
	return nil
}

// openGroupPicker offers every group by name. It is the same navigation [ and
// ] do one step at a time, and it exists because a backend can have more
// groups than stepping through them is reasonable for: a firewalld machine
// has a dozen zones and policies, and an nftables one has a chain view per
// hooked chain plus NAT and the aliases.
func (a *app) openGroupPicker() tea.Cmd {
	if len(a.model.Groups) < 2 {
		a.setStatusf(ui.StatusInfo, "this backend has a single %s",
			strings.ToLower(a.caps.GroupLabel))
		return nil
	}
	options := make([]string, 0, len(a.model.Groups))
	for _, group := range a.model.Groups {
		options = append(options, group.Name)
	}
	a.picker = ui.NewPicker(a.caps.GroupLabel, options, a.group)
	a.pickerFor = pickerGroup
	a.mode = modePicker
	return nil
}

// openLoggingPicker offers the backend's logging levels.
func (a *app) openLoggingPicker() tea.Cmd {
	if !a.caps.SupportsLogging || len(a.caps.LogLevels) == 0 {
		a.setStatus(ui.StatusWarn, "this backend does not expose logging levels")
		return nil
	}
	a.picker = ui.NewPicker(a.loggingLabel(), a.caps.LogLevels, a.model.Logging)
	a.pickerFor = pickerLogging
	a.mode = modePicker
	return nil
}

// openPolicySlotPicker asks which default policy to change.
func (a *app) openPolicySlotPicker() tea.Cmd {
	group, ok := a.model.Group(a.group)
	if !ok || len(group.PolicySlots) == 0 {
		a.setStatus(ui.StatusWarn, "this backend has no default policies")
		return nil
	}
	options := make([]string, 0, len(group.PolicySlots))
	for _, slot := range group.PolicySlots {
		options = append(options, string(slot))
	}
	a.picker = ui.NewPicker("Default policy to change", options, "")
	a.pickerFor = pickerPolicySlot
	a.mode = modePicker
	return nil
}

// openPolicyValuePicker asks for the new value of the chosen policy slot.
func (a *app) openPolicyValuePicker() tea.Cmd {
	options := make([]string, 0, len(a.caps.Policies))
	for _, p := range a.caps.Policies {
		options = append(options, string(p))
	}
	group, _ := a.model.Group(a.group)
	a.picker = ui.NewPicker("Policy for "+string(a.pendingSlot), options,
		string(currentPolicy(group, a.pendingSlot)))
	a.pickerFor = pickerPolicyValue
	a.mode = modePicker
	return nil
}

// loggingLabel names the logging concept the way the backend does: a level
// for ufw, a log-denied value for firewalld.
func (a *app) loggingLabel() string {
	if a.caps.LoggingLabel != "" {
		return a.caps.LoggingLabel
	}
	return "Logging"
}

// openExtrasMenu lists the actions the backend offers beyond the common set.
// The UI knows none of them by name: it renders the labels, collects the
// answers and previews whatever Change comes back.
func (a *app) openExtrasMenu() tea.Cmd {
	a.extras = a.backend.Extras(a.model, a.group)
	if len(a.extras) == 0 {
		a.setStatus(ui.StatusInfo, "this backend has no actions beyond the keys above")
		return nil
	}
	labels := make([]string, 0, len(a.extras))
	for _, extra := range a.extras {
		labels = append(labels, extra.Label)
	}
	a.picker = ui.NewPicker(a.backend.Name()+" actions", labels, "")
	a.pickerFor = pickerExtra
	a.mode = modePicker
	return nil
}

// startExtra begins collecting the answers one action needs.
func (a *app) startExtra(label string) tea.Cmd {
	for _, extra := range a.extras {
		if extra.Label != label {
			continue
		}
		a.pendingExtra = pendingExtra{extra: extra}
		return a.nextExtraStep()
	}
	a.mode = modeTable
	return nil
}

// answerExtra records one answer and moves on.
func (a *app) answerExtra(value string) tea.Cmd {
	a.pendingExtra.args = append(a.pendingExtra.args, value)
	return a.nextExtraStep()
}

// nextExtraStep opens the dialog for the next unanswered step, or builds the
// change once every step has an answer.
func (a *app) nextExtraStep() tea.Cmd {
	extra := a.pendingExtra.extra
	index := len(a.pendingExtra.args)
	if index >= len(extra.Steps) {
		return a.confirmExtra()
	}

	step := extra.Steps[index]
	if len(step.Options) == 0 {
		a.input = ui.NewInput(step.Prompt, step.Placeholder, step.Current)
		a.mode = modePrompt
		return nil
	}
	a.picker = ui.NewPicker(step.Prompt, step.Options, step.Current)
	a.pickerFor = pickerExtraStep
	a.mode = modePicker
	return nil
}

// confirmExtra builds the collected action and opens the confirm dialog.
func (a *app) confirmExtra() tea.Cmd {
	extra := a.pendingExtra.extra
	args := a.pendingExtra.args
	a.pendingExtra = pendingExtra{}
	a.mode = modeTable

	change, err := a.backend.BuildExtra(a.group, extra.ID, args)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	if extra.Danger {
		change.Destructive = true
	}
	body := change.Description + "."
	if extra.Warning != "" {
		body += "\n" + extra.Warning
	}
	a.stageOrConfirm(extra.Label, body, change)
	return nil
}

// currentPolicy reads the policy currently set in a slot.
func currentPolicy(g firewall.Group, slot firewall.PolicyDirection) firewall.Policy {
	switch slot {
	case firewall.PolicyIncoming:
		return g.Default.Incoming
	case firewall.PolicyOutgoing:
		return g.Default.Outgoing
	case firewall.PolicyRouted:
		return g.Default.Routed
	case firewall.PolicyTarget:
		return firewall.Policy(g.Default.Target)
	default:
		return ""
	}
}

// cycleGroup moves to the next or previous group. It is a no-op when the
// backend exposes a single group, as ufw does.
func (a *app) cycleGroup(delta int) {
	if len(a.model.Groups) < 2 {
		return
	}
	index := 0
	for i, g := range a.model.Groups {
		if g.Name == a.group {
			index = i
			break
		}
	}
	index = (index + delta + len(a.model.Groups)) % len(a.model.Groups)
	a.group = a.model.Groups[index].Name
	a.cursor, a.offset = 0, 0
	a.applyFilter()
}

// applyFilter recomputes the visible rules from the current filter.
func (a *app) applyFilter() {
	group, ok := a.model.Group(a.group)
	if !ok {
		a.visible = nil
		return
	}
	if a.filter == "" {
		a.visible = group.Rules
		a.clampCursor()
		return
	}
	needle := strings.ToLower(a.filter)
	var kept []firewall.Rule
	for _, r := range group.Rules {
		if strings.Contains(strings.ToLower(ruleHaystack(r)), needle) {
			kept = append(kept, r)
		}
	}
	a.visible = kept
	a.clampCursor()
}

// ruleHaystack is the text the filter matches against.
func ruleHaystack(r firewall.Rule) string {
	parts := []string{
		string(r.Action), string(r.Direction), r.To, r.From, r.Ports, r.Proto,
		r.Service, r.Comment, string(r.Family), r.Raw,
	}
	return strings.Join(parts, " ")
}

// selectedRule returns the highlighted rule.
func (a *app) selectedRule() (firewall.Rule, bool) {
	if a.cursor < 0 || a.cursor >= len(a.visible) {
		return firewall.Rule{}, false
	}
	return a.visible[a.cursor], true
}

// moveCursor moves the selection and keeps the viewport in sync.
func (a *app) moveCursor(delta int) {
	a.cursor += delta
	a.clampCursor()
}

// clampCursor keeps the cursor and the scroll offset within range.
func (a *app) clampCursor() {
	if len(a.visible) == 0 {
		a.cursor, a.offset = 0, 0
		return
	}
	a.cursor = min(max(a.cursor, 0), len(a.visible)-1)

	height := a.tableHeight()
	if a.cursor < a.offset {
		a.offset = a.cursor
	}
	if a.cursor >= a.offset+height {
		a.offset = a.cursor - height + 1
	}
	a.offset = max(min(a.offset, max(len(a.visible)-height, 0)), 0)
}

// firstLine keeps status messages to one line.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
