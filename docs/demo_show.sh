#!/bin/bash
set -euo pipefail

report="${ADPF_DEMO_REPORT:-sample_reports/training.local_domain_audit.txt}"
line_delay="${ADPF_DEMO_LINE_DELAY:-0.035}"
page_delay="${ADPF_DEMO_PAGE_DELAY:-2.7}"
stats_delay="${ADPF_DEMO_STATS_DELAY:-4.8}"
start_delay="${ADPF_DEMO_START_DELAY:-0}"

sleep "$start_delay"

style_output() {
  awk '
    BEGIN {
      esc = sprintf("%c", 27)
      reset = esc "[0m"
      bold = esc "[1m"
      cyan = esc "[1;38;5;81m"
      red = esc "[1;38;5;203m"
      amber = esc "[1;38;5;214m"
      yellow = esc "[1;38;5;220m"
      blue = esc "[1;38;5;117m"
      white = esc "[1;38;2;255;255;255m"
      severity = ""
      stats = 0
    }
    /^$/ { print ""; next }
    /^Risk Profile Statistics:/ { stats = 1; severity = ""; print cyan $0 reset; next }
    /^Critical Risk Profiles:$/ { stats = 0; severity = "critical"; print red $0 reset; next }
    /^High Risk Profiles:$/ { stats = 0; severity = "high"; print amber $0 reset; next }
    /^Medium Risk Profiles:$/ { stats = 0; severity = "medium"; print yellow $0 reset; next }
    /^Low Risk Profiles:$/ || /^Info Risk Profiles:$/ { stats = 0; severity = "low"; print blue $0 reset; next }
    /^Critical:/ { print red $0 reset; next }
    /^High:/ { print amber $0 reset; next }
    /^Medium:/ { print yellow $0 reset; next }
    /^Low:/ || /^Info:/ { print blue $0 reset; next }
    stats && /^  / { print white $0 reset; next }
    /^  (Default Groups|Non-admin Users|SCCM Privilege Escalation|ESC1|ESC4|ESC6|ESC7|SCCM Hierarchy)/ { severity = "critical"; print red $0 reset; next }
    /^  (Computers with Escalation Paths|Computers with SMB Signing Disabled and Escalation Paths|Computers with WebClient and Escalation Paths|Computer with Unconstrained Delegation|MSSQL Privilege Escalation|MSSQL Server Vulnerable to NTLM Relay|SCCM Infrastructure SMB Relay|User with Unconstrained Delegation|ESC2|ESC3|ESC8|ESC9)/ { severity = "high"; print amber $0 reset; next }
    /^  (Computer with Constrained Delegation|Computers with SMB Signing Disabled|KRBTGT Password Older Than 6 Months|MSSQL Login|MSSQL Login Impersonation|SCCM Management Point)/ { severity = "medium"; print yellow $0 reset; next }
    /^    (Users|Computers) with Shared Path/ {
      print white $0 reset
      next
    }
    { print white $0 reset }
  '
}

show_page() {
  clear
  sed -n "${1},${2}p" "$report" | style_output
  sleep "${3:-$page_delay}"
}

show_range() {
  clear
  sed -n "${1},${2}p" "$report" | style_output | awk -v delay="$line_delay" '{ print; fflush(); system("sleep " delay) }'
  sleep "$page_delay"
}

show_ranges() {
  clear
  while [ "$#" -gt 0 ]; do
    sed -n "${1},${2}p" "$report" | style_output | awk -v delay="$line_delay" '{ print; fflush(); system("sleep " delay) }'
    shift 2
  done
  sleep "$page_delay"
}

show_ranges_now() {
  clear
  while [ "$#" -gt 0 ]; do
    sed -n "${1},${2}p" "$report" | style_output
    shift 2
  done
}

if [ "$#" -gt 0 ]; then
  show_ranges_now "$@"
  exit 0
fi

show_page 1 38 "$stats_delay"
show_range 44 61
show_range 62 91
show_range 92 107
show_range 117 135
show_range 137 154
show_ranges 156 174 176 187 201 206
show_range 303 319
show_ranges 342 348 350 355 363 367 375 386
