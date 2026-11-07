#!/usr/bin/env bash
# Runs IntuneComplianceTool on Windows clients over SSH and shows the result here.
#
#   ./ict.sh <host> [tool options]              one device, full output
#   ./ict.sh <host1>,<host2>,... [options]      several devices, summary table
#   ./ict.sh -f hosts.txt [options]             hosts from a file (one per line, # comments)
#
#   ./ict.sh PC-0421 -Detailed
#   ./ict.sh PC-0421 -Remediate -WhatIf
#   ./ict.sh PC-0421 -Remediate
#   ./ict.sh PC-0421 -CollectDiagnostics        also copies the MDM diagnostics ZIP here
#   ./ict.sh PC-0421 -Json | jq .OverallStatus
#
# Connects as masteruser unless a host is given as user@host or ICT_SSH_USER is set.
# Several hosts run in parallel (ICT_PARALLEL, default 4) and need key-based SSH login.
# Exit code: the tool's (0 compliant, 1 not compliant, 2 enrollment broken, 3 repair
# failed, 10 error), 12 if the script could not be copied, 255 if ssh failed.
# For several hosts: the highest code of all hosts.

set -euo pipefail

usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 64; }
[[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]] && usage

hosts=()
if [[ "$1" == "-f" ]]; then
  [[ $# -ge 2 && -r "$2" ]] || { echo "ict: cannot read host file '${2:-}'" >&2; exit 64; }
  while IFS= read -r line || [[ -n "$line" ]]; do   # also the last line without a newline
    line="${line%%#*}"; line="$(echo "$line" | tr -d '[:space:]')"
    [[ -n "$line" ]] && hosts+=("$line")
  done < "$2"
  shift 2
else
  IFS=',' read -r -a hosts <<< "$1"
  shift
fi
[[ ${#hosts[@]} -gt 0 ]] || usage
tool_args=("$@")
# PowerShell also ends single-quoted strings on typographic quotes (U+2018-U+201B); refuse them.
for a in "$@"; do
  case "$a" in *$'\xe2\x80\x98'*|*$'\xe2\x80\x99'*|*$'\xe2\x80\x9a'*|*$'\xe2\x80\x9b'*)
    echo "ict: typographic quotes are not supported in arguments: $a" >&2; exit 64 ;;
  esac
done
lower_args=" $(printf '%s ' "$@" | tr '[:upper:]' '[:lower:]')"
wants_json=false; [[ "$lower_args" == *" -json "* || "$lower_args" == *" -json:"* ]] && wants_json=true
wants_diag=false; [[ "$lower_args" == *" -collectd"* ]] && wants_diag=true

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bundle="$here/dist/IntuneComplianceTool.ps1"

# Build the single-file script when it is missing or older than its sources.
if [[ ! -f "$bundle" || -n "$(find "$here/src" "$here/build" "$here/IntuneComplianceTool.ps1" -newer "$bundle" -print -quit)" ]]; then
  pwsh_bin="$(command -v pwsh || true)"
  [[ -z "$pwsh_bin" && -x "$HOME/.local/pwsh/pwsh" ]] && pwsh_bin="$HOME/.local/pwsh/pwsh"
  [[ -n "$pwsh_bin" ]] || { echo "ict: PowerShell 7 (pwsh) is needed on this Mac to build the script." >&2; exit 69; }
  "$pwsh_bin" -NoProfile -File "$here/build/Build-IntuneComplianceTool.ps1" -Quiet
fi

# A short base path: macOS limits socket paths to 104 bytes, and ssh adds a 17-character suffix.
work_dir="$(mktemp -d /tmp/ict.XXXXXX)"
trap 'for s in "$work_dir"/c*; do [[ -S "$s" ]] && ssh -o ControlPath="$s" -O exit x >/dev/null 2>&1; done; rm -rf "$work_dir"' EXIT

# PowerShell single-quoted literal (a variable for the quote: bash 3.2 mangles it inline).
ps_quote() { local q="'"; local v="${1//$q/$q$q}"; printf "'%s'" "$v"; }

# The remote command, base64-encoded (UTF-16LE) so no shell on either side can mangle it.
encoded_command() {
  local hint="$1"; shift
  local args="" a
  for a in "$@"; do
    if [[ "$a" =~ ^-[A-Za-z][A-Za-z0-9]*(:\$(true|false))?$ ]]; then args+=" $a"; else args+=" $(ps_quote "$a")"; fi
  done
  local cleanup=""
  # An old diagnostics ZIP must never be fetched as the current one.
  $wants_diag && cleanup="Remove-Item -LiteralPath (Join-Path \$env:USERPROFILE 'ict-diagnostics.zip') -Force -ErrorAction SilentlyContinue; "
  local script="\$p = Join-Path \$env:USERPROFILE 'ict-run.ps1'; \$code = 10; $cleanup
try { & \$p -CommandHint $(ps_quote "$hint")$args; \$code = \$LASTEXITCODE }
catch { Write-Host ('  ERROR: ' + \$_.Exception.Message) -ForegroundColor Red; \$code = 10 }
finally { Remove-Item -LiteralPath \$p -Force -ErrorAction SilentlyContinue }
exit \$code"
  printf '%s' "$script" | iconv -f UTF-8 -t UTF-16LE | base64 | tr -d '\n'
}

# run_host <host> <index> <extra args...>: copies the script, runs it, returns its exit code.
run_host() {
  local host="$1" index="$2"; shift 2
  local target="$host"
  [[ "$host" != *@* ]] && target="${ICT_SSH_USER:-masteruser}@$host"
  local short="${host#*@}"
  local opts=(-o ControlMaster=auto -o "ControlPath=$work_dir/c$index" -o ControlPersist=60
              -o ServerAliveInterval=30 -o ServerAliveCountMax=4 -o ConnectTimeout=15)
  [[ ${#hosts[@]} -gt 1 ]] && opts+=(-o BatchMode=yes)

  # Relative target = the account's profile folder, which only it and admins can write to.
  scp -q "${opts[@]}" "$bundle" "$target:ict-run.ps1" || { echo "ict: copying the script to $short failed" >&2; return 12; }

  # cmd.exe expands %COMSPEC%, PowerShell prints it literally.
  local shell_probe suffix=""
  shell_probe="$(ssh "${opts[@]}" "$target" 'echo %COMSPEC%' 2>/dev/null || true)"
  [[ "$shell_probe" == *%COMSPEC%* ]] && suffix='; exit $LASTEXITCODE'

  local tty=(-T)
  [[ -t 1 && ${#hosts[@]} -eq 1 ]] && ! $wants_json && tty=(-t)
  local status=0
  ssh "${tty[@]}" "${opts[@]}" "$target" \
    "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $(encoded_command "./ict.sh $short" "$@")$suffix" || status=$?

  if $wants_diag && (( status <= 3 )); then
    mkdir -p "$here/diagnostics"
    local local_zip="$here/diagnostics/${short}-$(date +%Y%m%d-%H%M%S).zip"
    if scp -q "${opts[@]}" "$target:ict-diagnostics.zip" "$local_zip" 2>/dev/null; then
      echo "  Diagnostics copied to $local_zip" >&2
    fi
  fi
  return "$status"
}

if [[ ${#hosts[@]} -eq 1 ]]; then
  status=0
  run_host "${hosts[0]}" 0 "${tool_args[@]+"${tool_args[@]}"}" || status=$?
  exit "$status"
fi

# Several hosts: run in parallel with -Summary and print one table.
parallel="${ICT_PARALLEL:-4}"
pids=()
for i in "${!hosts[@]}"; do
  (
    code=0
    run_host "${hosts[$i]}" "$i" -Summary -NoColor "${tool_args[@]+"${tool_args[@]}"}" > "$work_dir/out$i" 2> "$work_dir/err$i" || code=$?
    echo "$code" > "$work_dir/code$i"
  ) &
  pids+=($!)
  if (( ${#pids[@]} >= parallel )); then wait "${pids[0]}"; pids=("${pids[@]:1}"); fi
done
wait

worst=0
table="$work_dir/table"
printf 'HOST\tSTATUS\tFAIL\tWARN\tACTIONS\tFAILED CHECKS\tEXIT\n' > "$table"
for i in "${!hosts[@]}"; do
  code="$(cat "$work_dir/code$i" 2>/dev/null || echo 255)"
  if (( code > worst )); then worst=$code; fi
  line="$(tr -d '\r' < "$work_dir/out$i" 2>/dev/null | awk 'NF { l = $0 } END { print l }')"
  if [[ -z "$line" ]]; then
    reason="$(tr -d '\r' < "$work_dir/err$i" 2>/dev/null | awk 'NF { l = $0 } END { print l }')"
    line="$(printf '%s\tUNREACHABLE\t-\t-\t-\t%s' "${hosts[$i]#*@}" "${reason:-ssh failed}")"
  elif [[ "$line" != *$'\t'* ]]; then
    line="$(printf '%s\tERROR\t-\t-\t-\t%s' "${hosts[$i]#*@}" "$line")"
  fi
  printf '%s\t%s\n' "$line" "$code" >> "$table"
done
column -t -s $'\t' < "$table"
exit "$worst"
