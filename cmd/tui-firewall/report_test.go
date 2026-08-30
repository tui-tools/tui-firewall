package main

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-firewall/internal/backends"
)

// TestRunReportDemo checks the half of the block this tool owns. The kit's own
// tests cover the machine facts and the scrubbing; what has to be right here is
// that --demo says demo, that the imitated backend is the one the flag asked
// for rather than whatever the fake calls itself, and that no firewall was
// read to produce any of it.
func TestRunReportDemo(t *testing.T) {
	var out strings.Builder
	opts := options{demo: demoFlag{on: true, backend: backends.BackendFirewalld},
		report: true}
	if err := runReport(baseConfig(), opts, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}

	got := out.String()
	for _, want := range []string{
		"backend: demo\n",
		"mode: demo (sample data, the system was not read)\n",
		"demo backend: firewalld\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report is missing %q:\n%s", want, got)
		}
	}
	if !strings.HasPrefix(got, toolName+" ") {
		t.Errorf("report should start with the tool name:\n%s", got)
	}
}

// TestDescribeBackends renders the detector's verdict for every backend, which
// is what tells "firewalld was chosen" from "ufw is not here".
func TestDescribeBackends(t *testing.T) {
	tests := []struct {
		name   string
		states []backends.State
		want   string
	}{
		{
			name: "one active, one absent",
			states: []backends.State{
				{Name: "ufw", Installed: false},
				{Name: "firewalld", Installed: true, Active: true, Selected: true},
			},
			want: "ufw absent, firewalld active",
		},
		{
			name: "installed but stopped is not the same as absent",
			states: []backends.State{
				{Name: "ufw", Installed: true},
				{Name: "firewalld", Installed: true, Active: true},
			},
			want: "ufw installed, firewalld active",
		},
		{
			name:   "a machine with no firewall at all",
			states: nil,
			want:   "none",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := describeBackends(tc.states); got != tc.want {
				t.Errorf("describeBackends = %q, want %q", got, tc.want)
			}
		})
	}
}
