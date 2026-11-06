#!/usr/bin/env bash
# Runs IntuneComplianceTool on a Windows client over SSH and shows the result here.
#
#   ./ict.sh <host> [tool options]
#
#   ./ict.sh PC-0421
#   ./ict.sh PC-0421 -Detailed
#   ./ict.sh PC-0421 -Remediate -WhatIf
#   ./ict.sh PC-0421 -Remediate
#   ./ict.sh PC-0421 -Json | jq .Evaluation.OverallStatus
#
# Connects as masteruser unless the host is given as user@host or ICT_SSH_USER is set.
# Builds the single-file script, copies it to C:\ProgramData\IntuneComplianceTool on
# the client, runs it with Windows PowerShell, removes it again and exits with the
# tool's exit code (0 compliant, 1 not compliant, 2 enrollment broken, 3 repair
# failed, 10 error). One SSH connection is reused, so a password is asked only once.

set -euo pipefail

if [[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
  exit 64
fi

host="$1"
shift
target="$host"
if [[ "$host" != *@* ]]; then
  target="${ICT_SSH_USER:-masteruser}@$host"
fi
host_only="${host#*@}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pwsh_bin="$(command -v pwsh || true)"
if [[ -z "$pwsh_bin" && -x "$HOME/.local/pwsh/pwsh" ]]; then
  pwsh_bin="$HOME/.local/pwsh/pwsh"
fi
if [[ -z "$pwsh_bin" ]]; then
  echo "pwsh (PowerShell 7) is needed on this Mac to build the script." >&2
  exit 69
fi
"$pwsh_bin" -NoProfile -File "$here/build/Build-IntuneComplianceTool.ps1" -Quiet
bundle="$here/dist/IntuneComplianceTool.ps1"

control_dir="$(mktemp -d "${TMPDIR:-/tmp}/ict.XXXXXX")"
ssh_opts=(-o ControlMaster=auto -o "ControlPath=$control_dir/%C" -o ControlPersist=60)
cleanup() {
  ssh "${ssh_opts[@]}" -O exit "$target" >/dev/null 2>&1 || true
  rm -rf "$control_dir"
}
trap cleanup EXIT

remote_dir='C:\ProgramData\IntuneComplianceTool'
remote_file='C:\ProgramData\IntuneComplianceTool\IntuneComplianceTool.ps1'

# Works whether the client's OpenSSH default shell is cmd.exe or PowerShell.
ssh "${ssh_opts[@]}" "$target" "powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '$remote_dir' | Out-Null\""
scp -q "${ssh_opts[@]}" "$bundle" "$target:C:/ProgramData/IntuneComplianceTool/IntuneComplianceTool.ps1"

tty_opt=(-T)
json=false
for arg in "$@"; do
  [[ "$arg" == "-Json" || "$arg" == "-json" ]] && json=true
done
if [[ -t 1 && "$json" == false ]]; then
  tty_opt=(-t)
fi

set +e
ssh "${tty_opt[@]}" "${ssh_opts[@]}" "$target" \
  powershell -NoProfile -ExecutionPolicy Bypass -File "\"$remote_file\"" -CommandHint "\"./ict.sh $host_only\"" "$@"
status=$?
set -e

ssh "${ssh_opts[@]}" "$target" "powershell -NoProfile -Command \"Remove-Item -LiteralPath '$remote_file' -Force -ErrorAction SilentlyContinue\"" >/dev/null 2>&1 || true

exit "$status"
