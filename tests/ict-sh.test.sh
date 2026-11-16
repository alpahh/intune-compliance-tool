#!/bin/bash
# Offline tests for ict.sh: fake ssh and scp stand in for the Windows clients.
# Run with the system bash on macOS (3.2), which is what ict.sh must work on.
#
# Fake hosts: ok*  = compliant (exit 0)      bad* = enrollment broken (exit 2)
#             err* = script error (exit 10)  down* = the copy fails

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
sandbox="$(mktemp -d /tmp/icttest.XXXXXX)"
trap 'rm -rf "$sandbox"' EXIT

app="$sandbox/app"
mkdir -p "$app/src" "$app/build" "$app/dist" "$sandbox/bin"
cp "$root/ict.sh" "$app/ict.sh"
touch "$app/IntuneComplianceTool.ps1" "$app/src/x" "$app/build/x"
touch -t 202001010000 "$app/IntuneComplianceTool.ps1" "$app/src/x" "$app/build/x" "$app/src" "$app/build"
touch "$app/dist/IntuneComplianceTool.ps1"

export FAKE_LOG="$sandbox/log"
cat > "$sandbox/bin/ssh" <<'EOF'
#!/bin/bash
echo "ssh $*" >> "$FAKE_LOG"
for a in "$@"; do [[ "$a" == "-O" ]] && exit 0; done
target=""; skip=false
for a in "$@"; do
  if $skip; then skip=false; continue; fi
  case "$a" in -o) skip=true ;; -*) ;; *) target="$a"; break ;; esac
done
if [[ "$*" == *COMSPEC* ]]; then
  if [[ "${FAKE_SHELL:-cmd}" == "ps" ]]; then echo '%COMSPEC%'; else echo 'C:\WINDOWS\system32\cmd.exe'; fi
  exit 0
fi
host="${target#*@}"
case "$host" in
  ok*)  printf '%s\tCompliant\t0\t0\t-\t-\n' "$host"; exit 0 ;;
  bad*) printf '%s\tEnrollmentBroken\t1\t0\tReEnroll\tMDM certificate\n' "$host"; exit 2 ;;
  err*) echo "  ERROR: boom"; exit 10 ;;
esac
exit 255
EOF
cat > "$sandbox/bin/scp" <<'EOF'
#!/bin/bash
echo "scp $*" >> "$FAKE_LOG"
if [[ "$*" == *down* ]]; then
  # Like the real scp: -q hides the ssh diagnostic, the last line says nothing useful.
  [[ " $* " == *" -q "* ]] || echo "ssh: connect to host down port 22: Connection refused" >&2
  echo "scp: Connection closed" >&2
  exit 1
fi
for last; do :; done
if [[ "$*" == *ict-diagnostics.zip* ]]; then touch "$last"; fi
exit 0
EOF
chmod +x "$sandbox/bin/ssh" "$sandbox/bin/scp"
export PATH="$sandbox/bin:$PATH"

passed=0; failed=0
pass() { passed=$((passed + 1)); echo "ok    $1"; }
fail() { failed=$((failed + 1)); echo "FAIL  $1"; [[ -n "${2:-}" ]] && echo "      $2"; }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1" "expected [$3], got [$2]"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1" "[$3] not found in: $2"; fi; }
lacks() { if [[ "$2" != *"$3"* ]]; then pass "$1"; else fail "$1" "[$3] was found in: $2"; fi; }

run() { : > "$FAKE_LOG"; output="$("$app/ict.sh" "$@" 2>&1)"; code=$?; }
decoded() {
  local b64
  b64="$(grep -- '-EncodedCommand' "$FAKE_LOG" | sed 's/.*-EncodedCommand \([A-Za-z0-9+\/=]*\).*/\1/' | tail -n 1)"
  printf '%s' "$b64" | base64 --decode | iconv -f UTF-16LE -t UTF-8
}

run
check 'no arguments: usage and 64' "$code" 64

run ok1
check 'single host: exit code passes through' "$code" 0
contains 'single host: output' "$output" 'Compliant'
contains 'default user is masteruser' "$(cat "$FAKE_LOG")" 'masteruser@ok1'
contains 'copies into the profile folder' "$(cat "$FAKE_LOG")" 'masteruser@ok1:ict-run.ps1'

run bad1
check 'single host: exit code 2' "$code" 2

run admin@ok1
contains 'user@host is respected' "$(cat "$FAKE_LOG")" 'admin@ok1'
lacks 'user@host replaces the default user' "$(cat "$FAKE_LOG")" 'masteruser@'

ICT_SSH_USER=svc run ok1
contains 'ICT_SSH_USER is respected' "$(cat "$FAKE_LOG")" 'svc@ok1'

run down1
check 'copy failure: exit 12' "$code" 12

run ok1 -Remediate -EnrollmentMethod DeviceCredential -OutputDirectory "C:\\Users\\O'Brien\\x"
wrapper="$(decoded)"
contains 'switches stay bare' "$wrapper" ' -Remediate'
contains 'values are quoted' "$wrapper" "-EnrollmentMethod 'DeviceCredential'"
contains 'apostrophes are doubled' "$wrapper" "'C:\\Users\\O''Brien\\x'"
contains 'hint names the host' "$wrapper" "-CommandHint './ict.sh ok1'"
contains 'wrapper removes the script' "$wrapper" 'Remove-Item -LiteralPath $p'
lacks 'cmd.exe gets no exit suffix' "$(grep -- '-EncodedCommand' "$FAKE_LOG")" 'exit $LASTEXITCODE'

FAKE_SHELL='ps' run ok1
contains 'a PowerShell default shell gets the exit suffix' "$(grep -- '-EncodedCommand' "$FAKE_LOG")" '; exit $LASTEXITCODE'

run ok1 -Force "$(printf 'O\xe2\x80\x99Neil')"
check 'typographic quotes are refused' "$code" 64

run ok1 -CollectDiagnostics
wrapper="$(decoded)"
contains 'an old diagnostics ZIP is removed first' "$wrapper" "ict-diagnostics.zip') -Force"
contains 'the ZIP is fetched' "$(cat "$FAKE_LOG")" 'masteruser@ok1:ict-diagnostics.zip'
contains 'and reported' "$output" 'Diagnostics copied'

run ok1 -collectdiagnostics
contains 'flags are case-insensitive like PowerShell' "$(cat "$FAKE_LOG")" 'ict-diagnostics.zip'

run err1 -CollectDiagnostics
check 'script error: exit 10' "$code" 10
lacks 'no fetch after a script error' "$(cat "$FAKE_LOG")" 'masteruser@err1:ict-diagnostics.zip'

run ok1,ok2
check 'several hosts: all compliant' "$code" 0
contains 'several hosts: summary switch' "$(grep -- '-EncodedCommand' "$FAKE_LOG" | head -n 1)" 'BatchMode=yes'
wrapper="$(decoded)"
contains 'several hosts: -Summary is passed' "$wrapper" '-Summary'

run ok1,bad2,down3,err4
check 'several hosts: highest exit code' "$code" 12
contains 'table header' "$output" 'FAILED CHECKS'
contains 'table: enrollment broken' "$output" 'EnrollmentBroken'
contains 'table: unreachable row' "$output" 'UNREACHABLE'
contains 'table: unreachable reason' "$output" 'Connection refused'
err_row="$(printf '%s\n' "$output" | grep '^err4')"
contains 'table: error row has the ERROR status' "$err_row" 'ERROR'
header_col="$(printf '%s\n' "$output" | awk 'index($0, "FAILED CHECKS") { print index($0, "FAILED CHECKS") }')"
error_col="$(printf '%s\n' "$err_row" | awk '{ print index($0, "ERROR: boom") }')"
check 'table: the error text is trimmed and in its column' "$error_col" "$header_col"

run ok1,bad2
check 'several hosts: exit 2' "$code" 2

printf 'ok1\n# comment\n\nbad2' > "$sandbox/hosts.txt"
run -f "$sandbox/hosts.txt"
check 'host file: last line without newline counts' "$code" 2
contains 'host file: first host' "$output" 'ok1'
contains 'host file: last host' "$output" 'bad2'

run -f "$sandbox/nope.txt"
check 'host file missing: 64' "$code" 64

echo
echo "$passed passed, $failed failed"
[[ $failed -eq 0 ]]
