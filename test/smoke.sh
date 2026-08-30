#!/bin/bash
# Backend smoke test for tui-firewall, run inside a lab guest.
#
# The contract (see tui-tools/tui-lab): this script runs on the guest as the
# unprivileged lab user, escalates with `sudo -n` only, prints a short PASS/FAIL
# table and exits non-zero if anything failed. The binary under test is at
# $TUI_LAB_BIN (default: tui-firewall on PATH).
#
# What it proves is that the tool reads the machine's *real* firewall and
# agrees with the machine's own tooling — not that a fake renders. The lab
# already covers --version and a --demo frame; this covers the backend.
set -uo pipefail

bin="${TUI_LAB_BIN:-tui-firewall}"
# TOOL is the manifest name, which is what a compatibility result is keyed on.
TOOL=tui-firewall
pass=0
fail=0

# check runs one assertion. It takes a label, a command and a grep pattern the
# command's output must match. Output is captured so a failure can show it.
check() {
  local label="$1" command="$2" pattern="$3" output status
  output=$(eval "$command" 2>&1)
  status=$?
  if [[ $status -eq 0 ]] && grep -qE "$pattern" <<<"$output"; then
    printf 'PASS  %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL  %s (exit %d)\n' "$label" "$status"
    sed 's/^/      | /' <<<"$output" | head -12
    fail=$((fail + 1))
  fi
}

# --- compatibility evidence -------------------------------------------------
#
# The manifest's `tested` list is generated, not claimed: it is rebuilt from
# compat/results.jsonl by tui-kit/tools/compat-sync.py, and this is where a
# line of that file comes from. The version recorded is the one the tool itself
# probed, read back out of --check, so it describes the machine that really ran
# the suite rather than what the tester assumed was installed.
#
# The line is printed behind a `compat-result:` prefix so it survives the trip
# out of the guest through the lab's per-VM log, and appended to
# $TUI_COMPAT_RESULTS as well for a run outside the lab.
record_compat() {
  local report="$1" outcome="$2" backend version distro today block
  block=$(sed -n '/"compat": {/,/^  }/p' <<<"$report")
  backend=$(sed -n 's/.*"backend": "\([^"]*\)".*/\1/p' <<<"$block" | head -1)
  version=$(sed -n 's/.*"version": "\([^"]*\)".*/\1/p' <<<"$block" | head -1)
  if [[ -z $backend || -z $version ]]; then
    echo "      no version was probed, so no compatibility result is recorded"
    return
  fi

  distro=$(. /etc/os-release && echo "${ID}-${VERSION_ID:-rolling}")
  today=$(date -u +%Y-%m-%d)
  local line
  line=$(printf '{"backend":"%s","date":"%s","distro":"%s","result":"%s","suite":"smoke","tool":"%s","version":"%s"}' \
    "$backend" "$today" "$distro" "$outcome" "$TOOL" "$version")

  printf 'compat-result: %s\n' "$line"
  if [[ -n ${TUI_COMPAT_RESULTS:-} ]]; then
    printf '%s\n' "$line" >>"$TUI_COMPAT_RESULTS"
  fi
}

echo "--- tui-firewall smoke on $(. /etc/os-release && echo "$PRETTY_NAME")"

# Which backend this machine should be driving, decided the way the tool
# decides it: the one whose service is running, then whatever is installed.
if systemctl is-active --quiet firewalld 2>/dev/null; then
  backend=firewalld
elif systemctl is-active --quiet ufw 2>/dev/null; then
  backend=ufw
elif command -v ufw >/dev/null; then
  backend=ufw
elif command -v firewall-cmd >/dev/null; then
  backend=firewalld
else
  echo "FAIL  no supported firewall backend on this machine"
  exit 1
fi
echo "      backend=$backend"

# --- the report block ------------------------------------------------------
#
# --report is read-only and unprivileged, so it is smoked without sudo: a user
# who cannot escalate is exactly the one who most needs to be able to file a
# usable bug. What is asserted is that it agrees with the backend this machine
# should be driving, that it still answers under --demo, and that it keeps its
# privacy promise — the block goes into a public issue, so a home path or the
# host name appearing in it is a bug, not a cosmetic detail.
check "report names the selected backend" \
  "$bin --report" \
  "^backend: $backend"

check "report says the run was live" \
  "$bin --report" \
  '^mode: live$'

check "report works in demo mode too" \
  "$bin --demo --report" \
  '^backend: demo$'

check "and says so on the mode line" \
  "$bin --demo --report" \
  '^mode: demo'

# The distro and kernel lines are excluded from the host-name search rather
# than from the promise: they are built from /etc/os-release and from uname's
# release and machine fields, never from its nodename, and on a guest called
# "fedora" or "ubuntu" — which is most of them — the host name is a substring
# of the distribution's own. Everything else in the block is searched.
check "report leaks neither a home path nor the host name" \
  "$bin --report | grep -vE '^(distro|kernel): ' | grep -cE '/home/|$(uname -n)' || true" \
  '^0$'

case "$backend" in
  ufw)
    # 1. The read path works at all and names the backend it drove.
    check "check reads the ufw backend" \
      "sudo -n $bin --check" \
      '"backend": "ufw"'

    # 2. The tool's view of "is the firewall on" matches ufw's own.
    ufw_enabled=$(sudo -n ufw status | head -1 | grep -qi 'Status: active' && echo true || echo false)
    check "enabled state matches \`ufw status\` ($ufw_enabled)" \
      "sudo -n $bin --check" \
      "\"enabled\": $ufw_enabled"

    # 3. The rule count matches what ufw lists. This is the real parser test:
    #    a tool that fetched the output but failed to parse it reports zero.
    ufw_rules=$(sudo -n ufw status numbered | grep -cE '^\[[ 0-9]+\]')
    check "rule count matches \`ufw status numbered\` ($ufw_rules)" \
      "sudo -n $bin --check" \
      "\"rules\": $ufw_rules"

    # 4. The rule the lab put there is in the parsed model, with its port.
    check "the seeded 22/tcp rule is parsed" \
      "sudo -n $bin --check" \
      '"Ports": "22"'

    # 5. The default incoming policy is read, not left empty.
    check "the default incoming policy is parsed" \
      "sudo -n $bin --check" \
      '"Incoming": "(allow|deny|reject)"'
    ;;

  firewalld)
    # 1. Auto-detection lands on firewalld, and the read path works.
    check "check reads the firewalld backend" \
      "sudo -n $bin --check" \
      '"backend": "firewalld"'

    # 2. The machine really is running firewalld, and the tool agrees.
    check "firewalld is running on this machine" \
      "systemctl is-active firewalld" \
      '^active$'
    check "the tool reports the firewall as enabled" \
      "sudo -n $bin --check" \
      '"enabled": true'

    # 3. The default zone is parsed and comes first, which is what the header
    #    and the zone selector are built on.
    default_zone=$(sudo -n firewall-cmd --get-default-zone)
    check "the default zone ($default_zone) is the first group" \
      "sudo -n $bin --check" \
      "\"Name\": \"$default_zone\""
    check "the default zone is marked as such" \
      "sudo -n $bin --check" \
      "\"Title\": \"$default_zone \\(default\\)\""

    # 4. The zone target is read into the policy slot, not left empty.
    check "the zone target is parsed" \
      "sudo -n $bin --check" \
      '"Target": "(default|ACCEPT|DROP|%%REJECT%%)"'

    # 5. The lab guest allows ssh; that service must be in the parsed model as
    #    a service entry, which is the real parser test: a tool that fetched
    #    the output but failed to parse it reports no entries at all.
    check "ssh is parsed as a service entry" \
      "sudo -n $bin --check | tr -d ' \\n'" \
      '"Kind":"service","Note":"","Action":"ALLOW","Direction":"","Proto":"","Ports":"","From":"","To":"ssh"'

    # 6. A change made behind the tool's back, in the runtime configuration
    #    only, must show up marked as such — that marker is the whole reason
    #    this backend reads both configurations.
    #    The entry is checked with --list-ports rather than --query-port,
    #    because --query-port also answers yes for a port covered by a range
    #    the zone already has, and what is being tested here is the entry.
    sudo -n firewall-cmd --add-port=65530/tcp >/dev/null 2>&1
    check "firewalld took the runtime-only port" \
      "sudo -n firewall-cmd --list-ports | tr ' ' '\\n'" \
      '^65530/tcp$'
    check "and answers --query-port for it" \
      "sudo -n firewall-cmd --query-port=65530/tcp" \
      '^yes$'
    check "the tool marks it as runtime only" \
      "sudo -n $bin --check | tr -d ' \\n'" \
      '"Kind":"port","Note":"runtimeonly"'
    check "it never reached the permanent configuration" \
      "sudo -n firewall-cmd --permanent --list-ports | tr ' ' '\\n' | grep -c '^65530/tcp$' || true" \
      '^0$'

    sudo -n firewall-cmd --remove-port=65530/tcp >/dev/null 2>&1
    check "the port is gone again" \
      "sudo -n firewall-cmd --list-ports | tr ' ' '\\n' | grep -c '^65530/tcp$' || true" \
      '^0$'
    check "and the tool no longer reports it" \
      "sudo -n $bin --check | grep -c 65530 || true" \
      '^0$'

    # 7. The detector describes the backend it did not choose, rather than
    #    staying silent about it.
    check "the report names every backend it knows" \
      "sudo -n $bin --check | tr -d ' \\n'" \
      '"name":"ufw"'
    ;;
esac

# Both backends declare a version in the manifest, so whichever one this
# machine runs, the probed version is what gets recorded.
if [[ $fail -eq 0 ]]; then
  record_compat "$(sudo -n "$bin" --check 2>/dev/null)" pass
else
  record_compat "$(sudo -n "$bin" --check 2>/dev/null)" fail
fi

echo "--- tui-firewall: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
