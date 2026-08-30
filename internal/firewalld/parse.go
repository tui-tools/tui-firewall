package firewalld

import (
	"bufio"
	"regexp"
	"strings"
)

// Section is one block of `firewall-cmd --list-all`, `--list-all-zones` or
// `--policy X --list-all`: a name, the flags in parentheses after it, and the
// keyed lists indented below.
//
// firewalld prints zones and policy objects in the same shape, so one parser
// reads both and the mapping to the generic model decides what a section
// means. Values arrive either inline after the key ("services: ssh mdns") or
// one per tab-indented continuation line, which is how forward-ports and rich
// rules are printed; both forms are accepted for every key, because which one
// firewalld uses has changed between releases and is not worth depending on.
type Section struct {
	// Name is the zone or policy name.
	Name string
	// Default reports the "(default)" flag, Active the "(active)" one.
	Default bool
	Active  bool
	// Fields holds every key in the order it was printed, with its values
	// already split on whitespace — except RichRules, which are whole lines.
	Fields map[string][]string
	// Order is the key order, so the model can follow the backend's own.
	Order []string
	// RichRules are kept verbatim: a rich rule is its own delete argument.
	RichRules []string
}

// Field returns the values of a key, or nil.
func (s Section) Field(key string) []string { return s.Fields[key] }

// First returns the single value of a key, or "".
func (s Section) First(key string) string {
	if v := s.Fields[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// Has reports whether the key was printed at all, empty or not. It is how the
// caller tells "this firewalld does not have the feature" from "the list is
// empty": `forward:` only appears from the release that introduced intra-zone
// forwarding.
func (s Section) Has(key string) bool {
	_, ok := s.Fields[key]
	return ok
}

// Flag reads a yes/no key ("masquerade: yes").
func (s Section) Flag(key string) bool { return s.First(key) == "yes" }

// The keys of a zone or policy block that this tool reads. They are named here
// rather than spelled inline so the mapping and the parser cannot disagree.
const (
	KeyTarget       = "target"
	KeyInterfaces   = "interfaces"
	KeySources      = "sources"
	KeyServices     = "services"
	KeyPorts        = "ports"
	KeyProtocols    = "protocols"
	KeySourcePorts  = "source-ports"
	KeyForwardPorts = "forward-ports"
	KeyICMPBlocks   = "icmp-blocks"
	KeyMasquerade   = "masquerade"
	KeyForward      = "forward"
	KeyRichRules    = "rich rules"
	KeyPriority     = "priority"
	KeyIngressZones = "ingress-zones"
	KeyEgressZones  = "egress-zones"
)

var (
	// headerRe matches a section header: a name at column 0, with the
	// optional "(default, active)" flags after it.
	headerRe = regexp.MustCompile(`^(\S+)(?:\s+\(([^)]*)\))?\s*$`)
	// fieldRe matches an indented "key: value" line. The key may contain a
	// space, because firewalld prints "rich rules:".
	fieldRe = regexp.MustCompile(`^\s+([a-z][a-z0-9 -]*):\s?(.*)$`)
)

// ParseSections reads the output of `--list-all`, `--list-all-zones` or
// `--policy X --list-all` into one Section per block.
func ParseSections(output string) []Section {
	var (
		sections []Section
		current  *Section
		lastKey  string
	)
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t")
		if strings.TrimSpace(line) == "" {
			continue
		}

		// A tab-indented line always continues the previous key. It is tested
		// before the key pattern because a rich rule is free text and could
		// otherwise be mistaken for one: firewalld indents keys with spaces
		// and continuations with a tab.
		if current != nil && lastKey != "" && line[0] == '\t' {
			current.set(lastKey, strings.TrimSpace(line))
			continue
		}
		if m := fieldRe.FindStringSubmatch(line); m != nil && current != nil {
			lastKey = strings.TrimSpace(m[1])
			current.set(lastKey, m[2])
			continue
		}
		if m := headerRe.FindStringSubmatch(line); m != nil {
			sections = append(sections, newSection(m[1], m[2]))
			current = &sections[len(sections)-1]
			lastKey = ""
		}
	}
	return sections
}

// newSection starts a block from its header line.
func newSection(name, flags string) Section {
	s := Section{Name: name, Fields: map[string][]string{}}
	for _, flag := range strings.Split(flags, ",") {
		switch strings.TrimSpace(flag) {
		case "default":
			s.Default = true
		case "active":
			s.Active = true
		}
	}
	return s
}

// set records a key's values, appending when the key continues over several
// lines. An empty value still registers the key, which is what Has reports on.
func (s *Section) set(key, value string) {
	if _, seen := s.Fields[key]; !seen {
		s.Fields[key] = []string{}
		s.Order = append(s.Order, key)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if key == KeyRichRules {
		// A rich rule is one whole line; splitting it on spaces would
		// destroy the very string `--remove-rich-rule` needs back.
		s.RichRules = append(s.RichRules, value)
		s.Fields[key] = append(s.Fields[key], value)
		return
	}
	s.Fields[key] = append(s.Fields[key], strings.Fields(value)...)
}

// ActiveZone is one entry of `firewall-cmd --get-active-zones`.
type ActiveZone struct {
	Name       string
	Default    bool
	Interfaces []string
	Sources    []string
}

// ParseActiveZones reads `firewall-cmd --get-active-zones`, whose shape is a
// zone name at column 0 followed by indented "interfaces:" and "sources:"
// lines. It is read separately from --list-all-zones because that listing
// prints every zone, active or not, and only this one says which zones are
// actually attached to something.
func ParseActiveZones(output string) []ActiveZone {
	var (
		zones   []ActiveZone
		current *ActiveZone
	)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if m := fieldRe.FindStringSubmatch(line); m != nil && current != nil {
			values := strings.Fields(m[2])
			switch strings.TrimSpace(m[1]) {
			case KeyInterfaces:
				current.Interfaces = append(current.Interfaces, values...)
			case KeySources, "ipsets":
				current.Sources = append(current.Sources, values...)
			}
			continue
		}
		if m := headerRe.FindStringSubmatch(line); m != nil {
			zones = append(zones, ActiveZone{
				Name:    m[1],
				Default: strings.Contains(m[2], "default"),
			})
			current = &zones[len(zones)-1]
		}
	}
	return zones
}

// ParseList reads a whitespace-separated list, which is how firewall-cmd
// prints `--get-zones`, `--get-services` and `--get-policies`.
func ParseList(output string) []string {
	fields := strings.Fields(output)
	if len(fields) == 0 {
		return nil
	}
	return fields
}

// richPartRe matches the `key="value"` and `group key="value"` pairs of a rich
// rule, which is enough to fill the generic columns while Raw keeps the truth.
// A rich rule is one line, so a value that spans one is not a value: the
// quoted part stops at the line break rather than swallowing it into a column
// the table then prints.
var richPartRe = regexp.MustCompile(`(?:([a-z-]+)[ \t]+)?([a-z-]+)="([^"\r\n]*)"`)

// richVerdictRe matches the trailing verdict of a rich rule.
var richVerdictRe = regexp.MustCompile(`\b(accept|reject|drop|mark)\b`)

// RichRule is a rich rule decomposed as far as it goes. Raw is always the
// original text, because that is the string `--remove-rich-rule` takes back
// and the only rendering guaranteed to be exact.
type RichRule struct {
	Raw         string
	Family      string
	Source      string
	Destination string
	Service     string
	Port        string
	Protocol    string
	Verdict     string
	Log         bool
	LogPrefix   string
}

// ParseRichRule decomposes one rich rule.
func ParseRichRule(raw string) RichRule {
	r := RichRule{Raw: raw}
	for _, m := range richPartRe.FindAllStringSubmatch(raw, -1) {
		group, key, value := m[1], m[2], m[3]
		switch {
		case key == "family":
			r.Family = value
		case group == "source" && key == "address", group == "source" && key == "ipset":
			r.Source = value
		case group == "destination" && key == "address":
			r.Destination = value
		case group == "service" && key == "name":
			r.Service = value
		case group == "port" && key == "port":
			r.Port = value
		case key == "protocol":
			// `port port="80" protocol="tcp"` writes the protocol without a
			// group of its own, because it belongs to the port element that
			// came before it.
			r.Protocol = value
		case group == "protocol" && key == "value":
			// `protocol value="esp"` is the standalone protocol element.
			r.Protocol = value
		case group == "log" && key == "prefix":
			r.LogPrefix = value
		}
	}
	// A bare `source address=…` with no quotes is not valid firewalld syntax,
	// so the pairs above cover the addressing; the verdict is a bare word.
	if m := richVerdictRe.FindStringSubmatch(raw); m != nil {
		r.Verdict = m[1]
	}
	r.Log = strings.Contains(raw, " log")
	return r
}
