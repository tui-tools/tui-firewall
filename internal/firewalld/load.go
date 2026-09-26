package firewalld

import (
	"context"
	"strings"
	"sync"
)

// readFunc runs one firewall-cmd read, given the arguments after the binary
// name, and returns its output. The real backend passes the runner; the tests
// pass a table of captured outputs.
type readFunc func(ctx context.Context, args ...string) (string, error)

// The reads Load starts together. Each is a separate firewall-cmd process, so
// what a load costs is decided here: the list is kept to whole listings, and
// none of them depends on the answer of another.
var (
	argsZones             = []string{"--list-all-zones"}
	argsPermanentZones    = []string{"--permanent", "--list-all-zones"}
	argsServices          = []string{"--get-services"}
	argsLogDenied         = []string{"--get-log-denied"}
	argsPanic             = []string{"--query-panic"}
	argsLockdown          = []string{"--query-lockdown"}
	argsPolicies          = []string{"--list-all-policies"}
	argsPermanentPolicies = []string{"--permanent", "--list-all-policies"}

	// The fallbacks, read only on a firewalld whose listings do not already
	// carry the answer.
	argsState       = []string{"--state"}
	argsDefaultZone = []string{"--get-default-zone"}
	argsActiveZones = []string{"--get-active-zones"}
	argsPolicyNames = []string{"--get-policies"}
)

// notRunning is what every firewall-cmd that needs the daemon prints, with
// exit code 252, when firewalld is stopped.
const notRunning = "FirewallD is not running"

// answer is one read's result.
type answer struct {
	out string
	err error
}

// text is the output of a read that succeeded, or "": every caller treats a
// missing answer as an absent feature rather than a broken tool.
func (a answer) text() string {
	if a.err != nil {
		return ""
	}
	return a.out
}

// readAll runs every read at once and returns the answers in the same order.
//
// The reads are independent and read-only, and nearly all of the cost of one
// is the firewall-cmd process itself (interpreter start and imports) rather
// than firewalld answering it, so running them side by side turns the sum of
// their times into roughly the longest one.
func readAll(ctx context.Context, read readFunc, reads ...[]string) []answer {
	answers := make([]answer, len(reads))
	var wg sync.WaitGroup
	for i, args := range reads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := read(ctx, args...)
			answers[i] = answer{out: out, err: err}
		}()
	}
	wg.Wait()
	return answers
}

// loadSnapshot reads the whole firewalld state and reports whether the daemon
// is running. When it is not, the snapshot is empty: firewall-cmd cannot read
// anything while the daemon is down.
//
// On a current firewalld (0.9 and later) this is one wave of eight reads, all
// started together:
//
//   - `--list-all-zones` and the same with `--permanent`. The runtime zone
//     listing is only answered by a running daemon (firewall-cmd exits 252
//     "FirewallD is not running" otherwise), so its success stands in for
//     `--state`, which is asked only when that listing fails. The runtime listing
//     flags the default zone and the active ones in its headers
//     ("public (default, active)"), computed by firewall-cmd from the same
//     daemon calls `--get-default-zone` and `--get-active-zones` make, so
//     those two are not asked separately;
//   - `--list-all-policies` and the same with `--permanent`, in place of
//     `--get-policies` plus two `--policy=X --list-all` per policy;
//   - `--get-services`, `--get-log-denied`, `--query-panic` and
//     `--query-lockdown`, which no listing carries.
//
// A firewalld that does not flag its zones, or does not know
// `--list-all-policies`, gets the older piecemeal reads for that part only,
// so the snapshot is the same either way.
func loadSnapshot(ctx context.Context, read readFunc) (Snapshot, bool) {
	wave := readAll(ctx, read,
		argsZones, argsPermanentZones, argsServices, argsLogDenied,
		argsPanic, argsLockdown, argsPolicies, argsPermanentPolicies)
	zones, permanentZones, services, logDenied, panicMode, lockdown,
		policies, permanentPolicies := wave[0], wave[1], wave[2], wave[3],
		wave[4], wave[5], wave[6], wave[7]

	if zones.err != nil {
		// A stopped daemon says so on the listing itself, after waiting
		// for it on D-Bus for about ten seconds; asking --state as well
		// would wait that long a second time.
		if strings.Contains(zones.out, notRunning) {
			return Snapshot{}, false
		}
		// Otherwise the daemon may be up and have refused this one read:
		// only --state tells the two apart, and only the first is fatal.
		state, err := read(ctx, argsState...)
		if err != nil || strings.TrimSpace(state) != "running" {
			return Snapshot{}, false
		}
	}

	snapshot := Snapshot{Running: true}
	snapshot.Zones = ParseSections(zones.text())
	snapshot.PermanentZones = ParseSections(permanentZones.text())
	snapshot.Services = ParseList(services.text())
	snapshot.LogDenied = firstLine(logDenied.text())
	snapshot.Panic = strings.TrimSpace(panicMode.text()) == "yes"
	// Lockdown was removed in firewalld 2.2, where --query-lockdown exits 0
	// and prints a deprecation sentence instead of an answer. Reading the
	// answer rather than the exit code is therefore the version-proof test:
	// only a literal "yes" means the feature exists and is on.
	snapshot.Lockdown = strings.TrimSpace(lockdown.text()) == "yes"

	if defaultZone, active, ok := ZoneFlags(snapshot.Zones); ok {
		snapshot.DefaultZone, snapshot.Active = defaultZone, active
	} else {
		fallback := readAll(ctx, read, argsDefaultZone, argsActiveZones)
		snapshot.DefaultZone = firstLine(fallback[0].text())
		snapshot.Active = ParseActiveZones(fallback[1].text())
	}

	if policies.err == nil {
		snapshot.Policies, snapshot.PermanentPolicies = PolicySections(
			ParseSections(policies.text()), ParseSections(permanentPolicies.text()))
	} else {
		readPoliciesOneByOne(ctx, read, &snapshot)
	}
	return snapshot, true
}

// ZoneFlags reads the default zone and the active zones from the headers of a
// runtime `--list-all-zones`. firewall-cmd writes "(default)" beside the zone
// `--get-default-zone` names and "(active)" beside every zone
// `--get-active-zones` lists, so the headers answer both questions without
// two more processes. ok is false when no zone carries the default flag,
// which is how a firewalld that prints no flags at all is recognised.
//
// The active zones carry the interfaces and sources of their own section,
// which is what `--get-active-zones` prints beneath each name.
func ZoneFlags(sections []Section) (defaultZone string, active []ActiveZone, ok bool) {
	for _, s := range sections {
		if s.Default {
			defaultZone, ok = s.Name, true
		}
		if s.Active {
			active = append(active, ActiveZone{
				Name:       s.Name,
				Default:    s.Default,
				Interfaces: s.Field(KeyInterfaces),
				Sources:    s.Field(KeySources),
			})
		}
	}
	if !ok {
		return "", nil, false
	}
	return defaultZone, active, true
}

// PolicySections keeps the policy objects Load shows: the runtime ones, in
// the order firewalld lists them, at most maxPolicies of them and only those
// whose name is a valid argument, each with its permanent counterpart when
// there is one. It is exactly the set the older per-policy reads produced.
func PolicySections(runtime, permanent []Section) (kept, keptPermanent []Section) {
	byName := index(permanent)
	for _, s := range runtime {
		if len(kept) == maxPolicies {
			break
		}
		if err := checkAtom("policy", s.Name); err != nil {
			continue
		}
		kept = append(kept, s)
		if p, ok := byName[s.Name]; ok {
			keptPermanent = append(keptPermanent, p)
		}
	}
	return kept, keptPermanent
}

// readPoliciesOneByOne is the policy read for a firewalld without
// `--list-all-policies`: the names, then each policy on its own. A firewalld
// older than 0.9 has no policy objects at all, `--get-policies` fails and the
// snapshot keeps none.
func readPoliciesOneByOne(ctx context.Context, read readFunc, snapshot *Snapshot) {
	names, err := read(ctx, argsPolicyNames...)
	if err != nil {
		return
	}
	list := ParseList(names)
	if len(list) > maxPolicies {
		list = list[:maxPolicies]
	}
	var reads [][]string
	var valid []string
	for _, name := range list {
		if err := checkAtom("policy", name); err != nil {
			continue
		}
		valid = append(valid, name)
		reads = append(reads,
			[]string{"--policy=" + name, "--list-all"},
			[]string{"--permanent", "--policy=" + name, "--list-all"})
	}
	answers := readAll(ctx, read, reads...)
	for i := range valid {
		snapshot.Policies = append(snapshot.Policies,
			ParseSections(answers[2*i].text())...)
		snapshot.PermanentPolicies = append(snapshot.PermanentPolicies,
			ParseSections(answers[2*i+1].text())...)
	}
}
