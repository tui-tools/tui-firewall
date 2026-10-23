package ufw

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// hostFiles are the files ufw keeps its settings in. `ufw status verbose`
// reports the default policies and the logging level only while the firewall
// is active; while it is inactive the same values are read here, from the
// files ufw itself reads them from. Both are world-readable, so this needs no
// privilege and runs nothing. The paths are fields so tests can point them at
// fixtures.
type hostFiles struct {
	// Defaults is /etc/default/ufw: DEFAULT_*_POLICY and IPV6.
	Defaults string
	// Conf is /etc/ufw/ufw.conf: LOGLEVEL.
	Conf string
	// ProcNet is /proc/sys/net, where ufw looks up whether forwarding is on.
	ProcNet string
}

// systemFiles are the real locations.
var systemFiles = hostFiles{
	Defaults: "/etc/default/ufw",
	Conf:     "/etc/ufw/ufw.conf",
	ProcNet:  "/proc/sys/net",
}

// settings is what the files say about an inactive firewall.
type settings struct {
	defaults  firewall.Policies
	logging   string
	loggingOn bool
}

// readSettings loads the configured defaults and logging level. A file that
// cannot be read leaves its values empty, which the UI shows as unknown.
func readSettings(files hostFiles) settings {
	conf := map[string]string{}
	for _, path := range []string{files.Defaults, files.Conf} {
		if data, err := os.ReadFile(path); err == nil { //nolint:gosec // fixed configuration paths
			parseConf(string(data), conf)
		}
	}
	return settingsFromConf(conf, forwardingOn(files.ProcNet, conf["ipv6"] == "yes"))
}

// parseConf reads KEY=VALUE lines the way ufw does: keys are case-insensitive,
// values lose their quotes and are lower-cased.
func parseConf(text string, into map[string]string) {
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		into[strings.ToLower(strings.TrimSpace(key))] =
			strings.ToLower(strings.Trim(strings.TrimSpace(value), `"'`))
	}
}

// settingsFromConf maps the configuration to what `ufw status verbose` would
// print: ACCEPT is allow, REJECT is reject, anything else deny, and the routed
// policy reads "disabled" when the kernel is not forwarding.
func settingsFromConf(conf map[string]string, forwarding *bool) settings {
	s := settings{}
	s.defaults.Incoming = confPolicy(conf["default_input_policy"])
	s.defaults.Outgoing = confPolicy(conf["default_output_policy"])
	if forwarding != nil && !*forwarding {
		s.defaults.RoutedDisabled = true
	} else {
		s.defaults.Routed = confPolicy(conf["default_forward_policy"])
	}
	switch level := conf["loglevel"]; level {
	case "":
	case LogOff:
		s.logging = LogOff
	case LogLow, LogMedium, LogHigh, LogFull:
		s.logging, s.loggingOn = level, true
	}
	return s
}

// confPolicy translates an iptables target from /etc/default/ufw.
func confPolicy(value string) firewall.Policy {
	switch value {
	case "":
		return ""
	case "accept":
		return firewall.PolicyAllow
	case "reject":
		return firewall.PolicyReject
	default:
		return firewall.PolicyDeny
	}
}

// forwardingOn reports whether the kernel forwards packets, the test ufw uses
// to print "disabled (routed)": IPv4 forwarding, or, with IPv6 enabled in
// ufw, IPv6 forwarding on the default or on all interfaces. It returns nil
// when none of the switches can be read.
func forwardingOn(procNet string, ipv6 bool) *bool {
	paths := []string{filepath.Join(procNet, "ipv4", "ip_forward")}
	if ipv6 {
		paths = append(paths,
			filepath.Join(procNet, "ipv6", "conf", "default", "forwarding"),
			filepath.Join(procNet, "ipv6", "conf", "all", "forwarding"))
	}
	read, on := false, false
	for _, path := range paths {
		data, err := os.ReadFile(path) //nolint:gosec // fixed /proc paths
		if err != nil {
			continue
		}
		read = true
		if strings.TrimSpace(string(data)) == "1" {
			on = true
		}
	}
	if !read {
		return nil
	}
	return &on
}
