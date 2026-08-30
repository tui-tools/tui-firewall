package firewalld

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tui-tools/tui-firewall/internal/firewall"
)

// The identifiers of the actions firewalld offers beyond the common set. They
// are passed back to BuildExtra and never shown to the user.
const (
	ExtraSetDefaultZone     = "set-default-zone"
	ExtraChangeInterface    = "change-interface"
	ExtraAddSource          = "add-source"
	ExtraMasqueradeOn       = "masquerade-on"
	ExtraMasqueradeOff      = "masquerade-off"
	ExtraPanicOn            = "panic-on"
	ExtraPanicOff           = "panic-off"
	ExtraRuntimeToPermanent = "runtime-to-permanent"
)

// Extras lists the firewalld-specific actions, given the state last loaded.
// The list is built from that state rather than fixed, so it never offers to
// turn on something that is already on.
func Extras(model firewall.Model, group string) []firewall.Extra {
	zones := zoneNames(model)
	_, isPolicy := ZoneName(group)

	extras := []firewall.Extra{{
		ID:    ExtraSetDefaultZone,
		Label: "Set the default zone",
		Steps: []firewall.ExtraStep{{
			Prompt:  "Default zone",
			Options: zones,
			Current: defaultZoneOf(model),
		}},
		Danger: true,
		Warning: "Traffic on every interface that is not bound to a zone of " +
			"its own will be filtered by this zone instead.",
	}}

	if !isPolicy {
		extras = append(extras,
			firewall.Extra{
				ID:    ExtraChangeInterface,
				Label: "Move an interface to another zone",
				Steps: []firewall.ExtraStep{
					{Prompt: "Interface", Options: interfaceNames(model)},
					{Prompt: "Zone", Options: zones, Current: group},
				},
				Danger: true,
				Warning: "The interface stops being filtered by its current " +
					"zone the moment this runs.",
			},
			firewall.Extra{
				ID:    ExtraAddSource,
				Label: "Bind a source address to this zone",
				Steps: []firewall.ExtraStep{{
					Prompt:      "Source",
					Placeholder: "10.0.0.0/8, fd00::/8, a MAC or ipset:name",
				}},
			},
			masqueradeExtra(model, group),
		)
	}

	extras = append(extras, panicExtra(model), firewall.Extra{
		ID:     ExtraRuntimeToPermanent,
		Label:  "Save the running configuration as permanent",
		Danger: true,
		Warning: "The permanent configuration is overwritten by what is " +
			"running now, including anything added outside this tool.",
	})
	return extras
}

// masqueradeExtra offers whichever direction the zone is not already in.
func masqueradeExtra(model firewall.Model, group string) firewall.Extra {
	if hasKind(model, group, firewall.KindMasquerade) {
		return firewall.Extra{
			ID:    ExtraMasqueradeOff,
			Label: "Turn masquerading off for this zone",
		}
	}
	return firewall.Extra{
		ID:    ExtraMasqueradeOn,
		Label: "Turn masquerading on for this zone",
		Warning: "Traffic leaving this zone will be rewritten to the " +
			"machine's own address.",
	}
}

// panicExtra offers panic mode in the direction that is not current.
func panicExtra(model firewall.Model) firewall.Extra {
	if model.Warning == PanicWarning {
		return firewall.Extra{
			ID:      ExtraPanicOff,
			Label:   "Turn panic mode OFF (stop dropping every packet)",
			Danger:  true,
			Warning: "Normal filtering resumes with the rules listed here.",
		}
	}
	return firewall.Extra{
		ID:     ExtraPanicOn,
		Label:  "Turn panic mode ON (drop every packet)",
		Danger: true,
		Warning: "EVERY incoming and outgoing packet is dropped and active " +
			"connections expire — including the SSH session you are reading " +
			"this in. Panic mode is not permanent: a firewalld restart clears it.",
	}
}

// hasKind reports whether a group holds an entry of the given kind.
func hasKind(model firewall.Model, group, kind string) bool {
	g, ok := model.Group(group)
	if !ok {
		return false
	}
	for _, rule := range g.Rules {
		if rule.Kind == kind {
			return true
		}
	}
	return false
}

// defaultZoneOf finds the zone the model marked as the default.
func defaultZoneOf(model firewall.Model) string {
	for _, g := range model.Groups {
		if strings.HasSuffix(g.Title, "(default)") {
			return g.Name
		}
	}
	return ""
}

// zoneNames lists the zone groups, policy objects excluded: a policy object is
// not somewhere an interface or the default can point.
func zoneNames(model firewall.Model) []string {
	var names []string
	for _, g := range model.Groups {
		if _, isPolicy := ZoneName(g.Name); isPolicy {
			continue
		}
		names = append(names, g.Name)
	}
	sort.Strings(names)
	return names
}

// interfaceNames lists every interface the model knows a zone for.
func interfaceNames(model firewall.Model) []string {
	seen := map[string]bool{}
	var names []string
	for _, g := range model.Groups {
		for _, rule := range g.Rules {
			if rule.Kind != firewall.KindInterface || seen[rule.Raw] {
				continue
			}
			seen[rule.Raw] = true
			names = append(names, rule.Raw)
		}
	}
	sort.Strings(names)
	return names
}

// BuildExtra turns one of the actions above, plus the answers the UI
// collected, into a Change.
func BuildExtra(group, id string, args []string) (firewall.Change, error) {
	arg := func(i int) string {
		if i < len(args) {
			return strings.TrimSpace(args[i])
		}
		return ""
	}

	switch id {
	case ExtraSetDefaultZone:
		zone := arg(0)
		if err := checkAtom("zone", zone); err != nil {
			return firewall.Change{}, err
		}
		// --set-default-zone is runtime and permanent in one call, so there
		// is no second line to show.
		return single("Set the default zone to "+zone,
			"a runtime and permanent change in one command", true,
			"--set-default-zone="+zone), nil

	case ExtraChangeInterface:
		iface, zone := arg(0), arg(1)
		if err := checkAtom("interface", iface); err != nil {
			return firewall.Change{}, err
		}
		if err := checkAtom("zone", zone); err != nil {
			return firewall.Change{}, err
		}
		return pair(fmt.Sprintf("Move interface %s to zone %s", iface, zone), true,
			[]string{"--zone=" + zone, "--change-interface=" + iface}), nil

	case ExtraAddSource:
		source := arg(0)
		if err := checkAtom("source", source); err != nil {
			return firewall.Change{}, err
		}
		scope, err := scopeArgs(group)
		if err != nil {
			return firewall.Change{}, err
		}
		return pair("Bind source "+source+" to this zone", false,
			append(scope, "--add-source="+source)), nil

	case ExtraMasqueradeOn, ExtraMasqueradeOff:
		scope, err := scopeArgs(group)
		if err != nil {
			return firewall.Change{}, err
		}
		flag, description := "--add-masquerade", "Turn masquerading on"
		if id == ExtraMasqueradeOff {
			flag, description = "--remove-masquerade", "Turn masquerading off"
		}
		return pair(description, id == ExtraMasqueradeOff,
			append(scope, flag)), nil

	case ExtraPanicOn:
		return single("Turn panic mode ON",
			"every packet is dropped until panic mode is turned off; "+
				"this is a runtime-only state", true, "--panic-on"), nil

	case ExtraPanicOff:
		return single("Turn panic mode OFF",
			"filtering resumes with the rules listed here", true, "--panic-off"), nil

	case ExtraRuntimeToPermanent:
		return single("Save the running configuration as permanent",
			"the permanent configuration is overwritten by what is running now",
			true, "--runtime-to-permanent"), nil

	default:
		return firewall.Change{}, fmt.Errorf("firewalld: no extra action %q", id)
	}
}
