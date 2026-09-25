package firewall

import "strings"

// daemonChains maps the chain-name prefixes other daemons create — and
// recreate every time they start — to the daemon that owns them. docker,
// tailscaled and kube-proxy all write their own chains into whatever the
// machine's firewall is, which makes "whose chain is this" a question every
// backend that edits a shared ruleset has to be able to answer.
var daemonChains = []struct {
	prefix string
	daemon string
}{
	{"DOCKER", "docker"},
	{"ts-", "tailscaled"},
	{"KUBE-", "kube-proxy"},
	{"CILIUM", "cilium"},
	{"cali-", "calico"},
	{"FLANNEL", "flannel"},
	{"f2b-", "fail2ban"},
	{"LIBVIRT_", "libvirt"},
	{"CNI-", "a CNI plugin"},
	{"sshguard", "sshguard"},
}

// ChainDaemon names the daemon that owns a chain, or "" for a chain nobody
// else claims.
func ChainDaemon(chain string) string {
	for _, d := range daemonChains {
		if strings.HasPrefix(chain, d.prefix) {
			return d.daemon
		}
	}
	return ""
}
