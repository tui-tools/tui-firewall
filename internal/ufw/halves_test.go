package ufw

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// numberedPairs is `ufw status numbered` from ufw 0.36.2 on Ubuntu 24.04 with
// three rules for both families and one IPv4-only rule.
const numberedPairs = `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] OpenSSH                    ALLOW IN    Anywhere                   # admin ssh
[ 2] 80,443/tcp                 ALLOW IN    Anywhere                   # web
[ 3] 9100/tcp                   ALLOW IN    192.0.2.0/24               # metrics, admin network
[ 4] 8080/tcp                   ALLOW IN    Anywhere                   # staging app, temporary
[ 5] OpenSSH (v6)               ALLOW IN    Anywhere (v6)              # admin ssh
[ 6] 80,443/tcp (v6)            ALLOW IN    Anywhere (v6)              # web
[ 7] 8080/tcp (v6)              ALLOW IN    Anywhere (v6)              # staging app, temporary
`

func TestMarkHalves(t *testing.T) {
	rules := rulesOf(t, MergeModels(ParseStatus("Status: active\n"), ParseStatus(numberedPairs)))
	want := map[int]string{1: HalfIPv4, 2: HalfIPv4, 3: "", 4: HalfIPv4,
		5: HalfIPv6, 6: HalfIPv6, 7: HalfIPv6}
	for _, r := range rules {
		if got := r.Extra[ExtraHalf]; got != want[r.Index] {
			t.Errorf("rule %d: half = %q, want %q", r.Index, got, want[r.Index])
		}
	}
}

// TestDeleteDialogNamesTheHalf is the regression test for two identical
// delete dialogs: deleting rule 4 and then its IPv6 twin (renumbered to 6
// after the first delete) must say which half each one removes.
func TestDeleteDialogNamesTheHalf(t *testing.T) {
	rules := rulesOf(t, MergeModels(ParseStatus("Status: active\n"), ParseStatus(numberedPairs)))

	v4, err := BuildDeleteRule(GroupName, rules[3])
	if err != nil {
		t.Fatal(err)
	}
	if v4.Description != "Delete rule 4 (IPv4 half)" || v4.String() != "ufw --force delete 4" {
		t.Errorf("v4 half: %q / %q", v4.Description, v4.String())
	}
	if !strings.Contains(v4.Note, "IPv6 half") {
		t.Errorf("v4 note = %q", v4.Note)
	}

	v6, err := BuildDeleteRule(GroupName, rules[6])
	if err != nil {
		t.Fatal(err)
	}
	if v6.Description != "Delete rule 7 (IPv6 half)" || v6.String() != "ufw --force delete 7" {
		t.Errorf("v6 half: %q / %q", v6.Description, v6.String())
	}
	if v4.Description == v6.Description || v4.Note == v6.Note {
		t.Error("the two halves still get the same dialog")
	}

	// Once one half is gone the other is a plain rule of one family.
	after := `Status: active

     To                         Action      From
     --                         ------      ----
[ 4] OpenSSH (v6)               ALLOW IN    Anywhere (v6)              # admin ssh
[ 6] 8080/tcp (v6)              ALLOW IN    Anywhere (v6)              # staging app, temporary
`
	lone := rulesOf(t, MergeModels(ParseStatus("Status: active\n"), ParseStatus(after)))
	change, err := BuildDeleteRule(GroupName, lone[1])
	if err != nil {
		t.Fatal(err)
	}
	if change.Description != "Delete rule 6 (IPv6)" || change.Note != "" {
		t.Errorf("lone v6: %q / %q", change.Description, change.Note)
	}

	// A rule of one family only keeps the plain title.
	plain, err := BuildDeleteRule(GroupName, rules[2])
	if err != nil {
		t.Fatal(err)
	}
	if plain.Description != "Delete rule 3" || plain.Note != "" {
		t.Errorf("v4 only: %q / %q", plain.Description, plain.Note)
	}
}

func TestMarkHalvesDoesNotAlias(t *testing.T) {
	in := []firewall.Rule{
		{Action: "ALLOW", To: "22/tcp", From: "Anywhere", Extra: map[string]string{"k": "v"}},
		{Action: "ALLOW", To: "22/tcp", From: "Anywhere", Family: firewall.FamilyIPv6},
	}
	out := markHalves(in)
	if in[0].Extra[ExtraHalf] != "" || in[1].Extra != nil {
		t.Error("markHalves changed its input")
	}
	if out[0].Extra[ExtraHalf] != HalfIPv4 || out[0].Extra["k"] != "v" ||
		out[1].Extra[ExtraHalf] != HalfIPv6 {
		t.Errorf("out = %+v", out)
	}
}
