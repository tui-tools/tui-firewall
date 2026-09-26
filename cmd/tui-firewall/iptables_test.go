package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/backends"
	"github.com/tui-tools/tui-firewall/internal/iptables"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/theme"
)

// newIptablesApp builds the app over the iptables demo, the same backend
// `--demo=iptables` runs: a cloud image whose INPUT ends in a REJECT.
func newIptablesApp(t *testing.T, width, height int) (*app, *iptables.Fake) {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	fake := iptables.NewFake()
	a := newApp(fake, theme.FromPalette(theme.TokyoNight()), compat.Result{})
	a.width, a.height = width, height
	a.Update(a.Init()())
	return a, fake
}

func TestIptablesDemoRendersTheCloudImage(t *testing.T) {
	a, _ := newIptablesApp(t, 120, 30)
	out := a.View()
	for _, want := range []string{
		"INPUT (iptables)", "REJECT", "saved", "in sync", "W persist",
		"COUNTER", "state RELATED,ESTAB",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the iptables frame should mention %q\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"enable/disable", "reload"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("the hint bar should not offer %q on iptables\n%s", unwanted, out)
		}
	}
}

func TestIptablesAddLandsBeforeTheRejectAndIsPersisted(t *testing.T) {
	a, fake := newIptablesApp(t, 120, 34)
	send(t, a, "a")
	a.form.setFieldForTest("proto", "udp")
	a.form.setFieldForTest("ports", "51820")
	send(t, a, "enter")
	if a.mode != modeConfirm {
		t.Fatalf("submitting should open the confirm dialog, mode = %v", a.mode)
	}
	view := a.View()
	for _, want := range []string{"iptables -I INPUT 5 -p udp -m udp --dport 51820 -j ACCEPT",
		"right before rule 5"} {
		if !strings.Contains(strings.Join(strings.Fields(view), " "), want) {
			t.Errorf("the preview should show %q\n%s", want, view)
		}
	}
	send(t, a, "y")
	if len(fake.Log) != 1 {
		t.Fatalf("len(Log) = %d, want 1", len(fake.Log))
	}
	if !strings.Contains(a.status, "W persists") {
		t.Errorf("status = %q, want the persist reminder", a.status)
	}
	if !strings.Contains(a.View(), "differs") {
		t.Errorf("the header should say the saved rules differ\n%s", a.View())
	}
	// The rule is fifth, the REJECT sixth.
	if a.visible[4].Ports != "51820" || a.visible[5].Action != "REJECT" {
		t.Errorf("rows 5/6 = %+v / %+v", a.visible[4], a.visible[5])
	}

	// W previews the persist with its diff, and y writes it.
	send(t, a, "W")
	if a.mode != modeConfirm {
		t.Fatalf("W should open the persist preview, mode = %v", a.mode)
	}
	if !strings.Contains(a.confirm.Command, "netfilter-persistent save") ||
		!strings.Contains(a.confirm.Command, "+-A INPUT -p udp -m udp --dport 51820 -j ACCEPT") {
		t.Errorf("persist preview =\n%s", a.confirm.Command)
	}
	send(t, a, "y")
	if !strings.Contains(a.View(), "in sync") {
		t.Errorf("after persisting the header should say in sync\n%s", a.View())
	}
	// A second W has nothing to write.
	send(t, a, "W")
	if a.mode == modeConfirm || !strings.Contains(a.status, "nothing to persist") {
		t.Errorf("W with nothing to persist: mode %v, status %q", a.mode, a.status)
	}
}

func TestIptablesStagingAppliesThroughRestoreAndRollsBack(t *testing.T) {
	a, fake := newIptablesApp(t, 120, 30)
	if a.staging == nil {
		t.Fatal("iptables can snapshot its rules, so it should stage")
	}
	send(t, a, "s")
	stageIptablesRule(t, a, "udp", "51820")
	stageIptablesRule(t, a, "tcp", "443")
	send(t, a, "S")
	send(t, a, "enter")
	if a.mode != modeConfirm {
		t.Fatalf("applying should preview a confirm, mode = %v", a.mode)
	}
	if !strings.Contains(a.confirm.Command, "# iptables-restore --noflush") ||
		!strings.Contains(a.confirm.Body, "iptables-restore") {
		t.Errorf("the apply preview should be the restore script:\n%s\n%s",
			a.confirm.Body, a.confirm.Command)
	}
	send(t, a, "y")
	if !a.awaitingKeep {
		t.Fatal("the batch should await a keep")
	}
	input, _ := fake.State().V4.Chain(iptables.TableFilter, iptables.ChainInput)
	if len(input.Rules) != 7 {
		t.Fatalf("INPUT has %d rules after the batch, want 7", len(input.Rules))
	}
	_, cmd := a.Update(keepExpiredMsg{token: a.keepToken})
	for i := 0; i < 8 && cmd != nil; i++ {
		msg, ok := runFast(cmd)
		if !ok || msg == nil {
			break
		}
		_, cmd = a.Update(msg)
	}
	input, _ = fake.State().V4.Chain(iptables.TableFilter, iptables.ChainInput)
	if len(input.Rules) != 5 {
		t.Errorf("INPUT has %d rules after the rollback, want 5", len(input.Rules))
	}
}

func TestIptablesCheckReportsTheBlock(t *testing.T) {
	fake := iptables.NewFake()
	var out bytes.Buffer
	facts := make(chan checkFacts, 1)
	facts <- checkFacts{compat: compat.Result{}, backends: backends.Inspect("demo"), selection: "demo"}
	if err := runCheck(fake, facts, &out); err != nil {
		t.Fatalf("runCheck: %v", err)
	}
	var report struct {
		Iptables struct {
			Variant     string              `json:"variant"`
			Writable    []string            `json:"writable"`
			Placement   map[string]string   `json:"placement"`
			OpenInput   map[string][]string `json:"openInput"`
			Persistence struct {
				Kind   string `json:"kind"`
				InSync bool   `json:"inSync"`
			} `json:"persistence"`
			Staging struct {
				Supported bool `json:"supported"`
			} `json:"staging"`
		} `json:"iptables"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("decoding: %v\n%s", err, out.String())
	}
	ipt := report.Iptables
	if ipt.Variant != "nf_tables" || len(ipt.Writable) != 6 ||
		ipt.Persistence.Kind != "netfilter-persistent" || !ipt.Persistence.InSync ||
		!ipt.Staging.Supported {
		t.Errorf("iptables block = %+v", ipt)
	}
	if !strings.Contains(ipt.Placement["ip filter / INPUT"], "position 5") {
		t.Errorf("placement = %v", ipt.Placement)
	}
	if strings.Join(ipt.OpenInput["v4"], ",") != "22/tcp" {
		t.Errorf("open input = %v", ipt.OpenInput)
	}
}

// stageIptablesRule adds one allow through the form while staging is on.
func stageIptablesRule(t *testing.T, a *app, proto, port string) {
	t.Helper()
	send(t, a, "a")
	a.form.setFieldForTest("proto", proto)
	a.form.setFieldForTest("ports", port)
	send(t, a, "enter")
	if a.mode == modeConfirm {
		t.Fatal("with staging on, a rule should be staged, not confirmed")
	}
}
