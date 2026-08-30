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

# check_fails is the inverse: the command must fail, and its output must
# explain why. A backend that is deliberately not implemented is a result to
# assert, not a result to skip.
check_fails() {
  local label="$1" command="$2" pattern="$3" output status
  output=$(eval "$command" 2>&1)
  status=$?
  if [[ $status -ne 0 ]] && grep -qE "$pattern" <<<"$output"; then
    printf 'PASS  %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL  %s (expected failure, exit %d)\n' "$label" "$status"
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
# decides it: what is installed.
if command -v ufw >/dev/null; then
  backend=ufw
elif command -v firewall-cmd >/dev/null; then
  backend=firewalld
else
  echo "FAIL  no supported firewall backend on this machine"
  exit 1
fi
echo "      backend=$backend"

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
    # firewalld is a documented stub in tui-firewall today: internal/firewalld
    # satisfies the interface and every operation returns ErrNotImplemented.
    # The assertion is therefore that it fails, and fails legibly — so that the
    # day someone implements it, this test turns red and gets updated rather
    # than silently passing on a machine nobody checked.
    check_fails "the firewalld backend is still an explicit stub" \
      "sudo -n $bin --backend firewalld --check" \
      'not implemented yet'

    # Auto-detection must pick firewalld here (it is the only one installed)
    # and surface the same stub error, rather than claiming no firewall exists.
    check_fails "auto-detection finds firewalld and reports the stub" \
      "sudo -n $bin --check" \
      'not implemented yet'

    # The machine really is running firewalld, so the stub above is the tool's
    # limitation and not an absent backend.
    check "firewalld is running on this machine" \
      "systemctl is-active firewalld" \
      '^active$'
    ;;
esac

# The ufw backend is the one the manifest declares a version for; the firewalld
# path deliberately has none to probe, and record_compat says so and moves on.
if [[ $fail -eq 0 ]]; then
  record_compat "$(sudo -n "$bin" --check 2>/dev/null)" pass
else
  record_compat "$(sudo -n "$bin" --check 2>/dev/null)" fail
fi

echo "--- tui-firewall: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
