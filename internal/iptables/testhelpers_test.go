package iptables

import (
	"os"
	"path/filepath"
	"testing"
)

// fixture reads a file from testdata.
//
// The oci-* files were captured read-only from an Oracle Cloud Ubuntu 24.04
// host running iptables-nft 1.8.10 with iptables-persistent, docker and
// tailscale, then scrubbed: every address outside RFC 1918 and link-local was
// replaced with a documentation range (198.51.100.0/24, 2001:db8::/32) and the
// timestamps were normalised.
//
//	sudo iptables-save -c   > oci-iptables-save.txt
//	sudo ip6tables-save -c  > oci-ip6tables-save.txt
//	sudo cat /etc/iptables/rules.v4 > oci-rules.v4
func fixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // names are the fixtures listed in these tests
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(data)
}

// ociState is the captured host as the backend would load it: both families
// running, and the saved rules.v4 under the Debian layout.
func ociState(t *testing.T) State {
	t.Helper()
	v4, err := ParseSave(V4, fixture(t, "oci-iptables-save.txt"))
	if err != nil {
		t.Fatalf("parsing the v4 fixture: %v", err)
	}
	v6, err := ParseSave(V6, fixture(t, "oci-ip6tables-save.txt"))
	if err != nil {
		t.Fatalf("parsing the v6 fixture: %v", err)
	}
	saved, err := ParseSave(V4, fixture(t, "oci-rules.v4"))
	if err != nil {
		t.Fatalf("parsing the saved fixture: %v", err)
	}
	// The host's rules.v6 is what ip6tables-save printed at the last save:
	// the running v6 dump without the tailscale chains.
	state := State{V4: v4, V6: v6, HasV6: true}
	layout := netfilterPersistentLayout
	layout.Enabled = true
	savedV6 := stripCounters(cloneDump(v6))
	state.Persistence = Persistence{Layout: layout, SavedV4: &saved, SavedV6: &savedV6}
	state.Persistence.Drift = ComputeDrift(state)
	return state
}
