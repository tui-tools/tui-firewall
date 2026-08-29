package ufw

import (
	"reflect"
	"testing"

	"github.com/edimarlnx/tui-tools/internal/firewall"
)

// Real-world `ufw status verbose` output from a Debian host.
const verboseSample = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     LIMIT IN    Anywhere
80,443/tcp (Nginx Full)    ALLOW IN    Anywhere
22/tcp (v6)                LIMIT IN    Anywhere (v6)
`

// Real-world `ufw status numbered` output, with comments, an app profile,
// a route rule and IPv6 rules.
const numberedSample = `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     LIMIT IN    Anywhere                   # ssh rate limit
[ 2] 80,443/tcp (Nginx Full)    ALLOW IN    Anywhere
[ 3] 5432/tcp                   ALLOW IN    10.0.0.0/8                 # postgres from lan
[ 4] 3306/tcp                   DENY IN     Anywhere
[ 5] Anywhere                   ALLOW FWD   192.168.1.0/24             # lan forwarding
[ 6] 2000:2100/udp              ALLOW OUT   Anywhere
[ 7] OpenSSH                    ALLOW IN    Anywhere
[ 8] 22/tcp (v6)                LIMIT IN    Anywhere (v6)              # ssh rate limit
[ 9] 137,138/udp (Samba) (v6)   REJECT IN   fd00::/8 (v6)
[10] Anywhere (v6)              ALLOW FWD   fe80::/10 (v6)
`

// rulesOf returns the rules of the single group ufw exposes.
func rulesOf(t *testing.T, m firewall.Model) []firewall.Rule {
	t.Helper()
	if len(m.Groups) != 1 {
		t.Fatalf("len(Groups) = %d, want 1", len(m.Groups))
	}
	if m.Groups[0].Name != GroupName {
		t.Fatalf("group name = %q, want %q", m.Groups[0].Name, GroupName)
	}
	return m.Groups[0].Rules
}

func TestParseStatusVerbose(t *testing.T) {
	got := ParseStatus(verboseSample)

	if got.Backend != "ufw" {
		t.Errorf("Backend = %q, want ufw", got.Backend)
	}
	if !got.Enabled {
		t.Error("Enabled = false, want true")
	}
	if !got.LoggingOn || got.Logging != LogLow {
		t.Errorf("logging = (%v, %q), want (true, low)", got.LoggingOn, got.Logging)
	}
	want := firewall.Policies{
		Incoming: firewall.PolicyDeny, Outgoing: firewall.PolicyAllow,
		RoutedDisabled: true,
	}
	if got.Groups[0].Default != want {
		t.Errorf("Default = %+v, want %+v", got.Groups[0].Default, want)
	}
	rules := rulesOf(t, got)
	if len(rules) != 3 {
		t.Fatalf("len(Rules) = %d, want 3", len(rules))
	}
	if rules[0].Index != 0 || rules[0].ID != "" {
		t.Errorf("verbose output carries no rule numbers, got %+v", rules[0])
	}
}

func TestParseStatusNumbered(t *testing.T) {
	rules := rulesOf(t, ParseStatus(numberedSample))
	if len(rules) != 10 {
		t.Fatalf("len(Rules) = %d, want 10", len(rules))
	}

	v6 := firewall.FamilyIPv6
	tests := []struct {
		name string
		idx  int
		want firewall.Rule
	}{
		{
			name: "limit rule with comment",
			idx:  0,
			want: firewall.Rule{ID: "1", Index: 1, To: "22/tcp", From: "Anywhere",
				Action: firewall.ActionLimit, Direction: firewall.DirIn,
				Ports: "22", Proto: "tcp", Comment: "ssh rate limit"},
		},
		{
			name: "app profile expanded to ports",
			idx:  1,
			want: firewall.Rule{ID: "2", Index: 2, To: "80,443/tcp (Nginx Full)",
				From: "Anywhere", Action: firewall.ActionAllow,
				Direction: firewall.DirIn, Ports: "80,443", Proto: "tcp",
				Service: "Nginx Full"},
		},
		{
			name: "source CIDR with comment",
			idx:  2,
			want: firewall.Rule{ID: "3", Index: 3, To: "5432/tcp", From: "10.0.0.0/8",
				Action: firewall.ActionAllow, Direction: firewall.DirIn,
				Ports: "5432", Proto: "tcp", Comment: "postgres from lan"},
		},
		{
			name: "deny rule",
			idx:  3,
			want: firewall.Rule{ID: "4", Index: 4, To: "3306/tcp", From: "Anywhere",
				Action: firewall.ActionDeny, Direction: firewall.DirIn,
				Ports: "3306", Proto: "tcp"},
		},
		{
			name: "route rule",
			idx:  4,
			want: firewall.Rule{ID: "5", Index: 5, To: "Anywhere",
				From: "192.168.1.0/24", Action: firewall.ActionAllow,
				Direction: firewall.DirForward, Comment: "lan forwarding"},
		},
		{
			name: "outgoing port range",
			idx:  5,
			want: firewall.Rule{ID: "6", Index: 6, To: "2000:2100/udp",
				From: "Anywhere", Action: firewall.ActionAllow,
				Direction: firewall.DirOut, Ports: "2000:2100", Proto: "udp"},
		},
		{
			name: "bare app profile name",
			idx:  6,
			want: firewall.Rule{ID: "7", Index: 7, To: "OpenSSH", From: "Anywhere",
				Action: firewall.ActionAllow, Direction: firewall.DirIn,
				Service: "OpenSSH"},
		},
		{
			name: "ipv6 rule with comment",
			idx:  7,
			want: firewall.Rule{ID: "8", Index: 8, To: "22/tcp", From: "Anywhere",
				Action: firewall.ActionLimit, Direction: firewall.DirIn,
				Ports: "22", Proto: "tcp", Family: v6, Comment: "ssh rate limit"},
		},
		{
			name: "ipv6 reject with app profile",
			idx:  8,
			want: firewall.Rule{ID: "9", Index: 9, To: "137,138/udp (Samba)",
				From: "fd00::/8", Action: firewall.ActionReject,
				Direction: firewall.DirIn, Ports: "137,138", Proto: "udp",
				Service: "Samba", Family: v6},
		},
		{
			name: "ipv6 route rule",
			idx:  9,
			want: firewall.Rule{ID: "10", Index: 10, To: "Anywhere",
				From: "fe80::/10", Action: firewall.ActionAllow,
				Direction: firewall.DirForward, Family: v6},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := rules[tc.idx]
			// Raw is the untouched source line; compare the parsed fields only.
			if got.Raw == "" {
				t.Error("Raw should keep the original rule line")
			}
			got.Raw = ""
			if got.Extra != nil {
				t.Errorf("Extra = %v, want nil for ufw rules", got.Extra)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("rule mismatch\n got: %+v\nwant: %+v", got, tc.want)
			}
		})
	}
}

func TestParseStatusInactive(t *testing.T) {
	got := ParseStatus("Status: inactive\n")
	if got.Enabled {
		t.Error("Enabled = true, want false for an inactive firewall")
	}
	if rules := rulesOf(t, got); len(rules) != 0 {
		t.Errorf("len(Rules) = %d, want 0", len(rules))
	}
}

func TestParseStatusLoggingOff(t *testing.T) {
	got := ParseStatus("Status: active\nLogging: off\n")
	if got.LoggingOn {
		t.Error("LoggingOn = true, want false")
	}
	if got.Logging != LogOff {
		t.Errorf("Logging = %q, want off", got.Logging)
	}
}

func TestParseDefaultsRoutedEnabled(t *testing.T) {
	got := parseDefaults("Default: deny (incoming), allow (outgoing), deny (routed)")
	want := firewall.Policies{
		Incoming: firewall.PolicyDeny, Outgoing: firewall.PolicyAllow,
		Routed: firewall.PolicyDeny,
	}
	if got != want {
		t.Errorf("Defaults = %+v, want %+v", got, want)
	}
}

func TestParseAppList(t *testing.T) {
	const sample = `Available applications:
  CUPS
  Nginx Full
  Nginx HTTP
  OpenSSH
  Samba
`
	got := ParseAppList(sample)
	want := []string{"CUPS", "Nginx Full", "Nginx HTTP", "OpenSSH", "Samba"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseAppList = %+v, want %+v", got, want)
	}
}

func TestParseAppListEmpty(t *testing.T) {
	if got := ParseAppList("No applications are available.\n"); len(got) != 0 {
		t.Errorf("ParseAppList = %+v, want empty", got)
	}
}

func TestMergeModels(t *testing.T) {
	merged := MergeModels(ParseStatus(verboseSample), ParseStatus(numberedSample))

	if merged.Groups[0].Default.Incoming != firewall.PolicyDeny {
		t.Error("merged model lost the defaults from the verbose output")
	}
	if merged.Logging != LogLow {
		t.Error("merged model lost the logging level from the verbose output")
	}
	rules := rulesOf(t, merged)
	if len(rules) != 10 {
		t.Fatalf("len(Rules) = %d, want 10", len(rules))
	}
	if rules[0].Index != 1 {
		t.Error("merged model should keep the numbered rules")
	}
}

func TestDescribeTarget(t *testing.T) {
	tests := []struct {
		in                    string
		ports, proto, service string
	}{
		{in: "22/tcp", ports: "22", proto: "tcp"},
		{in: "22", ports: "22"},
		{in: "80,443/tcp", ports: "80,443", proto: "tcp"},
		{in: "2000:2100/udp", ports: "2000:2100", proto: "udp"},
		{in: "80,443/tcp (Nginx Full)", ports: "80,443", proto: "tcp", service: "Nginx Full"},
		{in: "OpenSSH", service: "OpenSSH"},
		{in: "Anywhere"},
		{in: "192.168.0.0/24"},
		{in: "Anywhere on eth0"},
		{in: "192.168.0.10 22/tcp", ports: "22", proto: "tcp"},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			ports, proto, service := describeTarget(tc.in)
			if ports != tc.ports || proto != tc.proto || service != tc.service {
				t.Errorf("describeTarget(%q) = (%q, %q, %q), want (%q, %q, %q)",
					tc.in, ports, proto, service, tc.ports, tc.proto, tc.service)
			}
		})
	}
}
