#!/usr/bin/env bash
#
# take-a-squizv6.sh — Multi-stage subdomain recon & security audit pipeline
#                       ♡ pink/purple "hack the planet" edition ♡
#
# Pipeline:
#   1) Subdomain discovery
#   2) Permutation generation
#   3) Resolution (+ wildcard detection)
#   4) Port scanning
#   5) HTTP probing + crawling
#   6) Nuclei
#   7) Archive / historical URLs
#   8) HTML report
#
# Controls while an external tool is running:
#   s        Skip ONLY the current tool/target and continue the pipeline
#   S        Skip the current tool AND the rest of this stage
#   Ctrl-C   Abort the ENTIRE pipeline (resume hint is printed on exit)
#
# What changed in v6 (based on v13):
#   * Stage 4 naabu targets are editable, and wildcard-filtered IPs can be
#     added back (interactively, in the TUI pane with CTRL-A, or via
#     --naabu-add-wildcard-ips) so a single-wildcard-IP domain no longer
#     ends up as "0 candidates".
#   * When wildcard DNS is detected you are ASKED whether to HTTP-probe it,
#     instead of silently excluding it unless --probe-wildcards was passed.
#     The answer is written back to the run manifest so --resume keeps it.
#   * Richer live status: per-target progress (3/120), elapsed + ETA from
#     previous runs, output-line counters, and a periodic heartbeat showing
#     the tool's own last line of output (nuclei/httpx/naabu -stats).
#   * Stall detection: a tool producing no new output for --stall-warn
#     seconds warns, and for --stall-kill seconds is terminated instead of
#     hanging forever. Per-tool timeouts for nuclei/waymore/gau/katana.
#   * Archive stage host cap (--archive-max-hosts) because waymore/gau over
#     hundreds of hosts is what usually "hangs" for hours.
#   * Resume state kept and extended: per-stage completion, per-stage
#     durations, and a timings cache used for ETAs.
#
# Designed to work with the Bash shipped with macOS (Bash 3.2).
#
set -uo pipefail
IFS=$'\n\t'
# Captured before the arg-parsing loop below consumes "$@" -- needed to
# re-exec this same script (minus/plus a couple of internal flags) as the
# two tmux panes when --tui is used. See tui_launch_and_attach().
ORIGINAL_ARGS=("$@")
# ───────────────────────────── Globals / UI ─────────────────────────────────
SCRIPT_NAME="take-a-squizv6.sh"
TS="$(date +%Y%m%d_%H%M%S)"
BASE_OUT=""
RUN_DIR=""
LOG_FILE=""
ASSUME_YES=0
NON_INTERACTIVE=0
COMMAND_TIMEOUT=7200
AUTO_MODULES=0
MODULES_CSV=""
RUN_START_TS="$(date +%s)"

# ───────────────────────── Hang / stall handling ─────────────────────────────
# A tool is "stalled" when neither its log nor its output file has grown for
# this long. STALL_WARN just tells you (so you can press s/S); STALL_KILL
# terminates it and lets the pipeline continue. Per-tool timeouts below are
# upper bounds for the tools that historically run away.
STALL_WARN=120
STALL_KILL=900
HEARTBEAT_SECS=30
NUCLEI_TIMEOUT=5400
WAYMORE_TIMEOUT=900
GAU_TIMEOUT=600
KATANA_TIMEOUT=2400
SCREENSHOT_TIMEOUT=1200
SCREENSHOT_THREADS=8
SKIP_SCREENSHOTS=0
HTTPX_TIMEOUT=3600
NAABU_TIMEOUT=5400
PUREDNS_TIMEOUT=3600
SHUFFLEDNS_TIMEOUT=3600
DNSX_TIMEOUT=3600
NUCLEI_RATE=150
ARCHIVE_MAX_HOSTS=50

# ───────────────────────────── TUI mode ──────────────────────────────────────
# --tui (outer, user-facing): parse target/output as normal, then hand off to
#   tui_launch_and_attach(), which builds a tmux session with this same
#   script re-exec'd in two panes, and never runs the pipeline itself.
# --tui-inner RUN_DIR (internal, used by the left/log pane): reuses a RUN_DIR
#   the outer process already created instead of making a new one, and makes
#   run_spinner/section TUI-aware (status file + live log tee).
# --tui-editor RUN_DIR (internal, used by the right/candidates pane): runs
#   ONLY the fzf-based candidate browser/editor loop and never touches the
#   pipeline at all.
TUI_REQUESTED=0
TUI_MODE=0
TUI_INNER_RUN_DIR=""
TUI_EDITOR_RUN_DIR=""
# ───────────────────────────── Resume ────────────────────────────────────────
# --resume RUN_DIR / --resume-latest: continue a previously cancelled scan
# instead of starting fresh. See load_resume_manifest() below.
RESUME_DIR=""
RESUME_LATEST=0
WORDLIST_DEFAULT="/Users/kupteraz/Documents/hax0ring/WORDLISTS/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
RESOLVERS_DEFAULT="/Users/kupteraz/Documents/hax0ring/WORDLISTS/SecLists/resolvers.txt"
PORT_SCOPE_DEFAULT="top1000"
EXTRA_PORTS_DEFAULT="8080,8000,8008,8081,8888,3000,5000,5001,8009,9000,9090,9443,10443,10000"
EXTRA_PORTS_ENABLED=1
# "" = let naabu auto-pick (SYN if it has raw-socket privileges, else CONNECT).
NAABU_SCAN_TYPE=""
# "" = naabu's own default (1000 pkt/s). Lower this if obvious open ports
# (80, 443, ...) go missing — it's almost always packet loss from scanning
# too fast for the path (VPN, Wi-Fi, a rate-limiting firewall), not a bug
# in naabu's target/port parsing.
NAABU_RATE=""
# "" = naabu's own default (3). Bump this for the same reason as NAABU_RATE.
NAABU_RETRIES=""
WILDCARD_FILTER=1
# PROBE_WILDCARDS is a *default*, not a decision: unless the user passed
# --probe-wildcards / --no-probe-wildcards (which set PROBE_WILDCARDS_SET=1),
# stage 3 asks at the moment wildcard DNS is actually detected.
PROBE_WILDCARDS=1
PROBE_WILDCARDS_SET=0
NAABU_ADD_WILDCARD_IPS=""   # ""=ask, 1=always add, 0=never add
WAYMORE_CONFIG=""

# ───────────────────────────── Theme (pink/purple) ───────────────────────────
C_RESET="\033[0m"
C_BOLD="\033[1m"
C_DIM="\033[2m"
C_PINK="\033[38;5;213m"
C_HOT="\033[38;5;198m"
C_PURPLE="\033[38;5;141m"
C_VIOLET="\033[38;5;99m"
C_LILAC="\033[38;5;183m"
C_MINT="\033[38;5;121m"
C_ROSE="\033[38;5;204m"
C_CREAM="\033[38;5;224m"
# Back-compat aliases so any older code path still colours sensibly.
C_RED="$C_ROSE"
C_GREEN="$C_MINT"
C_YEL="$C_PINK"
C_BLUE="$C_PURPLE"
C_MAG="$C_HOT"
C_CYAN="$C_LILAC"

banner() {
  local -a art=(
'  ______      __        ___   _____             _'
' /_  __/___ _/ /_____  /   | / ___/____ ___  __(_)___'
'  / / / __ `/ //_/ _ \/ /| | \__ \/ __ `/ / / / /_  /'
' / / / /_/ / ,< /  __/ ___ |___/ / /_/ / /_/ / / / /_'
'/_/  \__,_/_/|_|\___/_/  |_/____/\__, /\__,_/_/ /___/'
'                                   /_/'
  )
  local -a grad=("$C_HOT" "$C_PINK" "$C_LILAC" "$C_PURPLE" "$C_VIOLET" "$C_PURPLE")
  local i=0 line
  echo -e "${C_PINK}  ･ ｡ﾟ☆: *.☽ .* ✧ ･ﾟ*☆ ｡･ ✧ .* ☾.* :☆ﾟ･ ｡${C_RESET}"
  for line in "${art[@]}"; do
    echo -e "${grad[$i]}${C_BOLD}${line}${C_RESET}"
    i=$(( (i + 1) % ${#grad[@]} ))
  done
  echo -e "${C_LILAC}     ♡ hack the planet ♡  ${C_DIM}v13 — pink & purple edition${C_RESET}"
  echo -e "${C_DIM}   discovery ${C_PINK}→${C_DIM} permutations ${C_PINK}→${C_DIM} resolution ${C_PINK}→${C_DIM} ports ${C_PINK}→${C_DIM} http ${C_PINK}→${C_DIM} nuclei ${C_PINK}→${C_DIM} archive ${C_PINK}→${C_DIM} report${C_RESET}"
  echo
}
log() {
  [[ -n "$LOG_FILE" ]] || return 0
  echo -e "$(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE" >/dev/null
}
info() {
  echo -e "${C_PURPLE}[*]${C_RESET} $*"
  log "[INFO] $*"
}
ok() {
  echo -e "${C_MINT}[♡]${C_RESET} $*"
  log "[OK] $*"
}
warn() {
  echo -e "${C_PINK}[!]${C_RESET} $*"
  log "[WARN] $*"
}
err() {
  echo -e "${C_ROSE}[✗]${C_RESET} $*"
  log "[ERR] $*"
}
section() {
  echo -e "\n${C_HOT}${C_BOLD}✧ ── $* ── ✧${C_RESET}"
  log "==== $* ===="
  # In TUI mode the bottom status bar reads this file; give it something
  # sensible to show between tool runs (run_spinner overwrites it the moment
  # a tool actually starts).
  if [[ "$TUI_MODE" -eq 1 && -n "$RUN_DIR" ]]; then
    printf '%s\n' "$*" > "$RUN_DIR/.status" 2>/dev/null || true
  fi
}

# ───────────────────────────── Duration helpers ──────────────────────────────
fmt_dur() {
  local s="${1:-0}"
  [[ "$s" =~ ^[0-9]+$ ]] || s=0
  if [[ "$s" -lt 60 ]]; then
    printf '%ds' "$s"
  elif [[ "$s" -lt 3600 ]]; then
    printf '%dm%02ds' $((s / 60)) $((s % 60))
  else
    printf '%dh%02dm' $((s / 3600)) $(((s % 3600) / 60))
  fi
}
elapsed_since() {
  local s="$1"
  local now
  now="$(date +%s)"
  fmt_dur $((now - s))
}

# ─────────────────────── Timing cache (for ETA estimates) ────────────────────
#
# A flat key=seconds file (no associative arrays — macOS Bash 3.2) kept in
# BASE_OUT so estimates survive across runs against the same scope. Written
# only on a tool's successful completion, read to print "~ETA" while the
# next run of that same tool is in flight.
TIMINGS_FILE=""
timing_key() {
  echo "$1" |
    tr '[:upper:]' '[:lower:]' |
    sed -E 's/\([^)]*\)//g; s/[^a-z0-9]+/_/g; s/^_+//; s/_+$//'
}
timing_lookup() {
  local k v
  [[ -n "$TIMINGS_FILE" && -f "$TIMINGS_FILE" ]] || return 1
  k="$(timing_key "$1")"
  [[ -n "$k" ]] || return 1
  v="$(grep -E "^${k}=" "$TIMINGS_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2)"
  [[ "$v" =~ ^[0-9]+$ ]] || return 1
  echo "$v"
}
timing_record() {
  local k="" v="$2" tmp
  [[ -n "$TIMINGS_FILE" ]] || return 0
  k="$(timing_key "$1")"
  [[ -n "$k" ]] || return 0
  tmp="$(mktemp)"
  grep -vE "^${k}=" "$TIMINGS_FILE" 2>/dev/null > "$tmp" || true
  echo "${k}=${v}" >> "$tmp"
  mv "$tmp" "$TIMINGS_FILE" 2>/dev/null || rm -f "$tmp"
}
# Per-stage durations, used by the end-of-run summary and the HTML report.
record_stage_time() {
  [[ -n "$RUN_DIR" ]] || return 0
  printf '%s|%s|%s\n' "$1" "$2" "$3" >> "$RUN_DIR/.stage_times"
}

# ───────────────────────── Module selection ──────────────────────────────────
module_enabled() {
local name="$1"
local item
  [[ "$AUTO_MODULES" -eq 0 ]] && return 0
local old_ifs="$IFS"
  IFS=','
local -a requested=()
  read -r -a requested <<< "$MODULES_CSV"
  IFS="$old_ifs"
for item in "${requested[@]}"; do
    item="$(echo "$item" | tr '[:upper:]' '[:lower:]' | xargs)"
case "$item" in
      all|"$name")
return 0
;;
      1|discovery)
        [[ "$name" =~ ^(subfinder|assetfinder|shuffledns|puredns|recursive-dns)$ ]] && return 0
;;
      2|permutations)
        [[ "$name" == "alterx" ]] && return 0
;;
      3|resolution)
        [[ "$name" == "dnsx" ]] && return 0
;;
      4|ports)
        [[ "$name" == "naabu" ]] && return 0
;;
      5|http)
        [[ "$name" =~ ^(httpx|katana|gowitness)$ ]] && return 0
;;
      6|nuclei)
        [[ "$name" == "nuclei" ]] && return 0
;;
      7|archive)
        [[ "$name" =~ ^(waymore|gau)$ ]] && return 0
;;
      8|report)
        [[ "$name" == "report" ]] && return 0
;;
esac
done
return 1
}
stage_selected() {
local stage="$1"
local m
  [[ "$AUTO_MODULES" -eq 0 ]] && return 0
case "$stage" in
    discovery)
for m in subfinder assetfinder shuffledns puredns recursive-dns; do
if module_enabled "$m"; then
return 0
fi
done
;;
    permutations)
if module_enabled alterx; then
return 0
fi
;;
    resolution)
if module_enabled dnsx; then
return 0
fi
;;
    ports)
if module_enabled naabu; then
return 0
fi
;;
    http)
for m in httpx katana gowitness; do
if module_enabled "$m"; then
return 0
fi
done
;;
    nuclei)
if module_enabled nuclei; then
return 0
fi
;;
    archive)
for m in waymore gau; do
if module_enabled "$m"; then
return 0
fi
done
;;
    report)
if module_enabled report; then
return 0
fi
;;
esac
return 1
}
# ───────────────────────────── Prompt helpers ────────────────────────────────
#
# Low-level prompt shared by confirm() and the stage-gate decision below.
# Sets the global PROMPT_CHOICE_RESULT to one of: yes | no | back.
#   a/A  — answer yes to this AND set ASSUME_YES=1, so every remaining
#          prompt for the rest of THIS run is auto-answered yes without
#          asking again ("yes to all for this round").
#   b/B  — only offered when allow_back=1 (stage gates): signals the caller
#          to go back and re-ask the PREVIOUS stage's prompt, so a
#          mis-pressed y/n can be corrected instead of living with it.
# Respects ASSUME_YES/NON_INTERACTIVE exactly as before (no prompt shown,
# answer derived from $default) when either is already set.
#
# IMPORTANT: this is a plain function call, never invoked via $(...). The
# whole point of 'a' is to mutate ASSUME_YES for the rest of the running
# script -- command substitution runs in a subshell, and an assignment made
# there is silently lost the moment that subshell exits.
PROMPT_CHOICE_RESULT=""
prompt_choice() {
  local prompt="$1" default="${2:-y}" allow_back="${3:-0}"
  if [[ "$ASSUME_YES" -eq 1 || "$NON_INTERACTIVE" -eq 1 ]]; then
    if [[ "$default" == "y" ]]; then PROMPT_CHOICE_RESULT="yes"; else PROMPT_CHOICE_RESULT="no"; fi
    return
  fi
  local hint
  if [[ "$allow_back" -eq 1 ]]; then
    hint="[Y/n/a/b]"; [[ "$default" == "n" ]] && hint="[y/N/a/b]"
  else
    hint="[Y/n/a]"; [[ "$default" == "n" ]] && hint="[y/N/a]"
  fi
  local ans
  read -e -r -p "$(echo -e "${C_PINK}♡?${C_RESET} ${prompt} ${C_DIM}${hint}${C_RESET} ")" ans
  ans="${ans:-$default}"
  case "$ans" in
    [Aa])
      ASSUME_YES=1
      info "Saying yes to everything else for this run."
      PROMPT_CHOICE_RESULT="yes"
;;
    [Bb])
      if [[ "$allow_back" -eq 1 ]]; then PROMPT_CHOICE_RESULT="back"; else PROMPT_CHOICE_RESULT="no"; fi
;;
    [Yy]) PROMPT_CHOICE_RESULT="yes" ;;
    *) PROMPT_CHOICE_RESULT="no" ;;
  esac
}
confirm() {
local prompt="$1"
local default="${2:-y}"
  prompt_choice "$prompt" "$default" 0
  [[ "$PROMPT_CHOICE_RESULT" == "yes" ]]
}
# True only when there is a human to answer a question. -m/-y/-n all mean
# "run unattended", so any NEW mid-pipeline question (the wildcard-probe
# decision, the naabu add-back decision) must consult this first and fall
# back to the flag/default instead of blocking forever on a tty.
can_ask() {
  [[ "$AUTO_MODULES" -eq 0 && "$ASSUME_YES" -eq 0 && "$NON_INTERACTIVE" -eq 0 ]]
}
module_confirm() {
local module="$1"
local prompt="$2"
local default="${3:-y}"
if [[ "$AUTO_MODULES" -eq 1 ]]; then
    module_enabled "$module"
return $?
fi
  confirm "$prompt" "$default"
}
ask() {
local prompt="$1"
local default="${2:-}"
local ans
if [[ "$NON_INTERACTIVE" -eq 1 ||
        "$ASSUME_YES" -eq 1 ||
        "$AUTO_MODULES" -eq 1 ]]; then
    echo "$default"
return
fi
  read -e -r -p "$(echo -e "${C_PINK}♡?${C_RESET} ${prompt}${default:+ ${C_DIM}[$default]${C_RESET}}: ")" ans
  echo "${ans:-$default}"
}
# ───────────────────────────── Tool helpers ──────────────────────────────────
init_tool_path() {
local d
local pybin
for d in \
    "$HOME/.pdtm/go/bin" \
    "$HOME/go/bin" \
    "$HOME/.local/bin" \
    "/opt/homebrew/bin" \
    "/usr/local/bin" \
    "/usr/local/sbin" \
    "/opt/local/bin"
do
    [[ -d "$d" ]] && PATH="$d:$PATH"
done
if command -v python3 >/dev/null 2>&1; then
    pybin="$(
      python3 -c 'import site; print(site.getuserbase()+"/bin")' \
2>/dev/null || true
    )"
    [[ -d "$pybin" ]] && PATH="$pybin:$PATH"
fi
export PATH
}
tool_path() {
local name="$1"
case "$name" in
*)
      command -v "$name" 2>/dev/null || return 1
;;
esac
}
have() {
  tool_path "$1" >/dev/null 2>&1
}
count_lines() {
if [[ -f "$1" ]]; then
    wc -l < "$1" | tr -d ' '
else
    echo 0
fi
}

# Portable ANSI-escape stripper. NOTE: `sed -E 's/\x1b\[...//'` (as used in
# v11) only works with GNU sed -- BSD/macOS sed treats \x as a literal "x",
# so on macOS the strip silently did nothing and could even mangle text
# containing "x1b[". Matching a real ESC byte held in a variable works with
# both. Reads stdin, or the files given as arguments.
ESC_CHAR="$(printf '\033')"
strip_ansi() {
  sed -E "s/${ESC_CHAR}\[[0-9;]*[a-zA-Z]//g" "$@"
}

# ───────────────────────────── Resume state ──────────────────────────────────
#
# mark_stage_complete appends to RUN_DIR/.completed_stages as each stage
# finishes successfully. stage_was_already_complete checks a STATIC snapshot
# taken once at startup (RESUMED_COMPLETED_STAGES, populated right after
# RUN_DIR is settled) -- not the live-growing file -- so that:
#   - a --resume/--resume-latest run correctly skips whatever a PRIOR,
#     separate invocation already finished, and
#   - 'b' (back) navigation within the SAME run is never confused with
#     resumed state: a stage this run just completed a moment ago must still
#     be revisitable if the user backs up to it, not silently auto-skipped.
RESUMED_COMPLETED_STAGES=""
mark_stage_complete() {
  [[ -n "$RUN_DIR" ]] || return 0
  echo "$1" >> "$RUN_DIR/.completed_stages"
}
stage_was_already_complete() {
  [[ "$RESUMED_COMPLETED_STAGES" == *" $1 "* ]]
}

# Rewrites a single key in the run manifest, so a decision made mid-run
# (notably the wildcard-probe answer in stage 3) is what --resume picks back
# up with, instead of re-asking or silently reverting to the flag default.
update_manifest() {
  local key="$1" val="$2" manifest tmp
  [[ -n "$RUN_DIR" ]] || return 0
  manifest="$RUN_DIR/run_manifest.txt"
  [[ -f "$manifest" ]] || return 0
  tmp="$(mktemp)"
  grep -vE "^${key}=" "$manifest" 2>/dev/null > "$tmp" || true
  echo "${key}=${val}" >> "$tmp"
  mv "$tmp" "$manifest" 2>/dev/null || rm -f "$tmp"
}

# Which settings were given explicitly on THIS invocation's command line.
# A flag passed alongside --resume must beat the stored manifest value --
# otherwise `--resume-latest -m all` silently keeps the previous run's
# narrower module list and does nothing at all.
CLI_SET=""
cli_set() { CLI_SET="${CLI_SET} $1 "; }
cli_was_set() { [[ "$CLI_SET" == *" $1 "* ]]; }

# Reloads a prior run's settings (target, modules, port scope, wildcard
# decisions, timeouts, etc.) from its run_manifest.txt so --resume doesn't
# ask for anything already known, and points RUN_DIR/TS/LOG_FILE/BASE_OUT at
# the existing directory instead of creating a new one. Does NOT read
# .completed_stages itself -- that happens once, later, into
# RESUMED_COMPLETED_STAGES.
load_resume_manifest() {
  local dir="$1"
  dir="${dir%/}"
  if [[ ! -d "$dir" ]]; then
    err "Resume directory not found: $dir"
    exit 1
  fi
  if [[ ! -f "$dir/run_manifest.txt" ]]; then
    err "$dir has no run_manifest.txt — can't resume it (was it created by an older version, or is this not a run directory?)."
    exit 1
  fi
  # Every branch below is skipped when the same setting was passed as a flag
  # on this command line (cli_was_set), so CLI beats manifest.
  local key val
  while IFS='=' read -r key val; do
    cli_was_set "$key" && continue
    case "$key" in
      target_input) TARGET_INPUT="$val" ;;
      modules) [[ "$val" != "interactive" && -n "$val" ]] && { MODULES_CSV="$val"; AUTO_MODULES=1; } ;;
      wordlist) [[ -n "$val" ]] && WORDLIST_DEFAULT="$val" ;;
      resolvers) [[ "$val" != "default/prompt" && -n "$val" ]] && RESOLVERS_DEFAULT="$val" ;;
      port_scope) [[ -n "$val" ]] && PORT_SCOPE_DEFAULT="$val" ;;
      extra_ports) EXTRA_PORTS_DEFAULT="$val" ;;
      extra_ports_enabled) [[ "$val" =~ ^[01]$ ]] && EXTRA_PORTS_ENABLED="$val" ;;
      naabu_scan_type) [[ "$val" =~ ^(s|c)$ ]] && NAABU_SCAN_TYPE="$val" ;;
      naabu_rate) [[ "$val" =~ ^[0-9]+$ ]] && NAABU_RATE="$val" ;;
      naabu_retries) [[ "$val" =~ ^[0-9]+$ ]] && NAABU_RETRIES="$val" ;;
      wildcard_filter) [[ "$val" =~ ^[01]$ ]] && WILDCARD_FILTER="$val" ;;
      probe_wildcards) [[ "$val" =~ ^[01]$ ]] && PROBE_WILDCARDS="$val" ;;
      probe_wildcards_set) cli_was_set probe_wildcards || { [[ "$val" =~ ^[01]$ ]] && PROBE_WILDCARDS_SET="$val"; } ;;
      naabu_add_wildcard_ips) [[ "$val" =~ ^[01]$ ]] && NAABU_ADD_WILDCARD_IPS="$val" ;;
      archive_max_hosts) [[ "$val" =~ ^[0-9]+$ ]] && ARCHIVE_MAX_HOSTS="$val" ;;
      stall_warn) [[ "$val" =~ ^[0-9]+$ ]] && STALL_WARN="$val" ;;
      stall_kill) [[ "$val" =~ ^[0-9]+$ ]] && STALL_KILL="$val" ;;
      command_timeout) [[ "$val" =~ ^[0-9]+$ ]] && COMMAND_TIMEOUT="$val" ;;
    esac
  done < "$dir/run_manifest.txt"
  if [[ -z "$TARGET_INPUT" ]]; then
    err "$dir/run_manifest.txt has no target_input — can't resume it."
    exit 1
  fi
  RUN_DIR="$dir"
  TS="$(basename "$dir" | sed -E 's/^run_//')"
  LOG_FILE="$dir/recon.log"
  BASE_OUT="$(dirname "$dir")"
}

# Generic "let the user hand-edit a file before it's used" helper. A no-op
# in TUI mode (editing happens in the candidates pane there instead) and in
# any non-interactive mode (-y/-n/-m) where there's no prompt to hang one
# off of. Otherwise asks once, and if accepted, opens $EDITOR/$VISUAL (or
# nano, falling back to vi) on the file in place.
maybe_edit_file_interactively() {
  local file="$1" label="${2:-list}"
  [[ "$TUI_MODE" -eq 1 ]] && return 0
  [[ "$ASSUME_YES" -eq 1 || "$NON_INTERACTIVE" -eq 1 || "$AUTO_MODULES" -eq 1 ]] && return 0
  confirm "Edit the $label ($(count_lines "$file") lines) before continuing?" "n" || return 0
  local editor="${VISUAL:-${EDITOR:-nano}}"
  have "$editor" || editor="vi"
  if ! have "$editor"; then
    warn "No editor found ($editor) — skipping edit. Set \$EDITOR or edit $file by hand, then re-run."
    return 0
  fi
  "$editor" "$file"
  sort -u "$file" -o "$file" 2>/dev/null || true
  info "$label now has $(count_lines "$file") line(s)."
}

# ───────────────────────────── TUI: candidates pane ──────────────────────────
#
# set_active_candidates points the right-hand (candidates) tmux pane at
# whichever file is the most relevant "list of things about to be used next"
# at this moment in the pipeline, and optionally at a POOL file: a superset
# of extra rows that can be ADDED back with CTRL-A (this is how
# wildcard-filtered IPs get back into the naabu target list). No-op outside
# TUI mode, so it's safe to sprinkle through the pipeline unconditionally.
#
# Editing happens opportunistically: every stage re-reads its input fresh
# from disk, so rows deleted (or added) in the candidates pane before the
# "Run Stage N?" prompt is answered 'y' genuinely take effect. TUI mode
# therefore pairs best with the normal interactive per-stage confirmations.
set_active_candidates() {
  [[ "$TUI_MODE" -eq 1 && -n "$RUN_DIR" ]] || return 0
  printf '%s\n' "$1" > "$RUN_DIR/.active_candidates" 2>/dev/null || true
  if [[ -n "${2:-}" ]]; then
    printf '%s\n' "$2" > "$RUN_DIR/.candidate_pool" 2>/dev/null || true
  else
    : > "$RUN_DIR/.candidate_pool" 2>/dev/null || true
  fi
}

# Builds the tmux session for --tui: a left/main pane re-running this same
# script (with --tui-inner RUN_DIR) and a right pane running the candidates
# editor (--tui-editor RUN_DIR). The bottom status bar is tmux's own native
# status line, refreshed from $RUN_DIR/.status once a second -- that file is
# written by run_spinner/section whenever TUI_MODE=1.
tui_launch_and_attach() {
  if ! have tmux; then
    err "--tui requires tmux, which isn't installed."
    err "Install it: brew install tmux   (macOS)   /   apt install tmux   (Debian/Ubuntu)"
    exit 1
  fi
  if ! have fzf; then
    warn "fzf not found — the candidates pane will be read-only (view only, no select/delete/add)."
    warn "Install it for interactive editing: brew install fzf   /   apt install fzf"
  fi

  # Resolve $0 to an absolute path once, so the generated pane scripts work
  # regardless of tmux's own working directory.
  local self_path
  self_path="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

  # Rebuild the args to forward to the inner pipeline pane: everything from
  # the original invocation EXCEPT --tui itself and -t/-o (which are
  # re-supplied explicitly below using the already-resolved TARGET_INPUT and
  # BASE_OUT, so the inner process doesn't re-prompt for them inside the
  # pane if they weren't passed as flags originally).
  local -a forwarded=()
  local skip_next=0 a
  for a in "${ORIGINAL_ARGS[@]:-}"; do
    [[ -z "$a" ]] && continue
    if [[ "$skip_next" -eq 1 ]]; then skip_next=0; continue; fi
    case "$a" in
      --tui) continue ;;
      -t|-o) skip_next=1; continue ;;
      *) forwarded+=("$a") ;;
    esac
  done

  local session="squiz_${TS}"
  tmux kill-session -t "$session" 2>/dev/null || true

  local inner_script="$RUN_DIR/.tui_inner_cmd.sh"
  {
    echo '#!/usr/bin/env bash'
    printf '%q ' bash "$self_path" -t "$TARGET_INPUT" -o "$BASE_OUT" "${forwarded[@]}" --tui-inner "$RUN_DIR"
    echo
  } > "$inner_script"
  chmod +x "$inner_script"

  local editor_script="$RUN_DIR/.tui_editor_cmd.sh"
  {
    echo '#!/usr/bin/env bash'
    printf '%q ' bash "$self_path" --tui-editor "$RUN_DIR"
    echo
  } > "$editor_script"
  chmod +x "$editor_script"

  : > "$RUN_DIR/.status"
  echo "♡ idle" > "$RUN_DIR/.status"

  # A detached session needs an explicit size before any client has
  # attached, or later layout operations have nothing to compute against.
  local term_cols term_lines right_cols
  term_cols="$(tput cols 2>/dev/null || echo 200)"
  term_lines="$(tput lines 2>/dev/null || echo 50)"
  [[ "$term_cols" =~ ^[0-9]+$ ]] || term_cols=200
  [[ "$term_lines" =~ ^[0-9]+$ ]] || term_lines=50
  right_cols=$(( term_cols * 35 / 100 ))
  [[ "$right_cols" -lt 20 ]] && right_cols=20

  tmux new-session -d -s "$session" -n main -x "$term_cols" -y "$term_lines" "$inner_script"
  # NOTE: split-window's percentage sizing (-p) resolves against the
  # window's "live" size as tracked by an attached client; issued against a
  # session with no client attached yet, that resolution can fail outright
  # ("size missing") depending on the tmux build/platform. An absolute
  # column count (-l) needs no such resolution and is reliable here.
  tmux split-window -h -t "${session}:main" -l "$right_cols" "$editor_script"
  tmux select-pane -t "${session}:main.0"
  tmux set-option -t "$session" status on
  tmux set-option -t "$session" status-interval 1
  tmux set-option -t "$session" status-style "bg=colour53,fg=colour218"
  tmux set-option -t "$session" status-left-length 240
  tmux set-option -t "$session" status-right-length 80
  tmux set-option -t "$session" pane-border-style "fg=colour97"
  tmux set-option -t "$session" pane-active-border-style "fg=colour213"
  tmux set-option -t "$session" status-left "#[fg=colour218,bold] ♡ squiz #[fg=colour225]#(cat '$RUN_DIR/.status' 2>/dev/null || echo idle)"
  tmux set-option -t "$session" status-right "#[fg=colour183]s skip tool · S skip stage · pane C-b o · detach C-b d"

  info "Launching TUI — left: pipeline log, right: candidates (TAB mark, ENTER delete, CTRL-A add from pool, CTRL-R refresh), bottom: live status."
  info "Detach with Ctrl-B then d; reattach later with: tmux attach -t $session"
  # -u forces tmux to treat the terminal as UTF-8, so the status bar's
  # spinner frames and ♡ render instead of being mangled when LANG/LC_ALL
  # isn't a UTF-8 locale.
  tmux -u attach-session -t "$session"
}

# The right-hand pane process (run standalone via --tui-editor RUN_DIR).
# Loops forever: reads .active_candidates to find the current file, shows it
# in fzf (scrollable, multi-select with TAB); lines accepted with ENTER are
# deleted from that file in place, and CTRL-A opens a second picker over
# .candidate_pool (minus what's already in the file) to ADD rows back —
# which is how wildcard-filtered IPs are returned to naabu's target list.
# Falls back to a read-only `less`-ish view when fzf isn't installed.
#
# Known limitation: fzf has no "watch this file for live appends" mode, so a
# file that grows while a view is open won't show new rows until that view is
# reloaded (CTRL-R forces a reload without leaving fzf).
FZF_THEME="fg:218,hl:212,fg+:225,bg+:53,hl+:213,info:141,prompt:213,pointer:198,marker:121,header:183,border:141,spinner:213"
run_candidate_editor() {
  local run_dir="$1"
  local pointer="$run_dir/.active_candidates"
  local pool_pointer="$run_dir/.candidate_pool"

  if ! have fzf; then
    echo "fzf not found -- candidates pane is read-only."
    echo "Install it for interactive select/delete/add: https://github.com/junegunn/fzf"
    echo
    local last_target=""
    while true; do
      local target=""
      [[ -f "$pointer" ]] && target="$(cat "$pointer" 2>/dev/null)"
      if [[ -n "$target" && -s "$target" ]]; then
        clear
        echo "=== ♡ $(basename "$target") ($(count_lines "$target") lines, read-only) ==="
        nl -ba "$target" 2>/dev/null | tail -n 200
      elif [[ "$target" != "$last_target" ]]; then
        clear
        echo "Waiting for candidates..."
      fi
      last_target="$target"
      sleep 2
    done
    return
  fi

  while true; do
    local target="" pool=""
    [[ -f "$pointer" ]] && target="$(cat "$pointer" 2>/dev/null)"
    [[ -f "$pool_pointer" ]] && pool="$(cat "$pool_pointer" 2>/dev/null)"
    if [[ -z "$target" || ! -f "$target" ]]; then
      clear
      echo "♡ waiting for candidates..."
      sleep 1
      continue
    fi
    local header="[♡ $(basename "$target")] TAB mark · ENTER delete · CTRL-R refresh · ESC reload"
    [[ -n "$pool" && -f "$pool" ]] && header="$header · CTRL-A add from pool"
    local out key chosen
    # IMPORTANT: do not redirect fzf's own stderr to /dev/null here. With
    # its stdin redirected from a file (`< "$target"`, not the terminal
    # directly), fzf renders its entire interactive UI to stderr rather than
    # /dev/tty -- discarding stderr silently throws away the whole picker.
    # Only stdout (the key line + selected lines) is captured.
    out="$(
      fzf --multi --height=100% --reverse --border \
        --expect=ctrl-a \
        --color="$FZF_THEME" \
        --header="$header" \
        --bind "ctrl-r:reload(cat '$target' 2>/dev/null)" \
        --prompt="♡ candidates> " \
        < "$target"
    )"
    key="$(printf '%s\n' "$out" | head -n 1)"
    chosen="$(printf '%s\n' "$out" | tail -n +2)"
    if [[ "$key" == "ctrl-a" ]]; then
      if [[ -n "$pool" && -f "$pool" ]]; then
        local addable add
        addable="$(mktemp)"
        if [[ -s "$target" ]]; then
          grep -vxFf "$target" "$pool" 2>/dev/null | sort -u > "$addable" || true
        else
          sort -u "$pool" > "$addable" 2>/dev/null || true
        fi
        if [[ -s "$addable" ]]; then
          add="$(
            fzf --multi --height=100% --reverse --border \
              --color="$FZF_THEME" \
              --header="[♡ add from pool → $(basename "$target")] TAB mark · ENTER add · ESC cancel" \
              --prompt="♡ add> " \
              < "$addable" || true
          )"
          if [[ -n "$add" ]]; then
            # Pool rows may be "host,ip" while the target is a bare IP list;
            # take the last comma-separated field in that case so adding a
            # resolved pair contributes a usable target.
            printf '%s\n' "$add" | awk -F, '{print (NF>1 ? $NF : $0)}' >> "$target"
            sort -u "$target" -o "$target" 2>/dev/null || true
          fi
        fi
        rm -f "$addable"
      fi
      continue
    fi
    if [[ -n "$chosen" ]]; then
      local tmp; tmp="$(mktemp)"
      grep -vFxf <(printf '%s\n' "$chosen") "$target" > "$tmp" 2>/dev/null
      mv "$tmp" "$target"
    fi
    sleep 0.3
  done
}

# Extract clean "host,ip" pairs from dnsx output.
#
# Root cause of the naabu "no valid ipv4 or ipv6 targets" failure: dnsx's
# text "-resp" mode wraps each resolved IP in ANSI colour codes
# (ESC[32m<ip>ESC[0m) inside the *file* it writes via -o, not just on the
# terminal. The old bracket-stripping awk left the invisible ESC byte and
# the "32m" colour parameter glued onto the front of the address, and naabu
# then rejected the whole line.
#
# Fix: prefer dnsx's -json output instead of -resp. JSON string values are
# never colourised, so there is nothing to regex apart -- jq flattens it.
#
# A host with multiple A/AAAA records legitimately produces multiple
# host,ip rows (round-robin/CDN DNS) -- correct, not a duplicate bug.
extract_dnsx_host_ip() {
  local input="$1"
  local output="$2"
  : > "$output"
  [[ -s "$input" ]] || return 0

  if have jq; then
    jq -r '
      select(.host != null) |
      .host as $h |
      ((.a // []) + (.aaaa // []))[] |
      $h + "," + .
    ' "$input" 2>/dev/null | sort -u > "$output"
    return
  fi

  warn "jq not installed — falling back to text-mode dnsx parsing (less robust; install jq for clean multi-IP resolution via -json)."
  local clean; clean="$(mktemp)"
  strip_ansi "$input" > "$clean"
  awk '{
    host=$1
    line=$0
    gsub(/[\[\],]/," ",line)
    n=split(line,a,/ +/)
    for (i=2;i<=n;i++) {
      gsub(/^\[/,"",a[i]); gsub(/\]$/,"",a[i]);
      if (a[i] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ || a[i] ~ /^[0-9a-fA-F:]+$/) print host "," a[i]
    }
  }' "$clean" | sed 's/\.$//' | sort -u > "$output"
  rm -f "$clean"
}

# Strict validator: true only for a syntactically valid IPv4/IPv6 literal or
# CIDR. Used as a last line of defense right before naabu ever sees a target
# list -- including AFTER the user has hand-edited it.
is_valid_ip_or_cidr() {
  local v="$1"
  if [[ "$v" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
    return 0
  fi
  if [[ "$v" == *:* && "$v" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; then
    return 0
  fi
  return 1
}

# Keep only valid IP/CIDR rows in FILE, moving anything else to REJECT file.
# Run both before and after any interactive edit of naabu's target list: one
# malformed line used to be enough to abort naabu entirely.
filter_valid_ip_file() {
  local file="$1" rejected="$2"
  : > "$rejected"
  [[ -s "$file" ]] || return 0
  local clean line
  clean="$(mktemp)"
  : > "$clean"
  while IFS= read -r line; do
    line="$(echo "$line" | strip_ansi | xargs)"
    [[ -z "$line" ]] && continue
    if is_valid_ip_or_cidr "$line"; then
      echo "$line" >> "$clean"
    else
      echo "$line" >> "$rejected"
    fi
  done < "$file"
  sort -u "$clean" -o "$clean" 2>/dev/null || true
  mv "$clean" "$file"
  if [[ -s "$rejected" ]]; then
    warn "Dropped $(count_lines "$rejected") malformed target(s) (see $rejected):"
    sed 's/^/      /' "$rejected" | head -n 5
  else
    rm -f "$rejected"
  fi
}

# Defense-in-depth for candidate/hostname files: strips ANSI escapes and
# drops any line that isn't a plausible hostname or IP/CIDR, logging what it
# removed, so contamination never reaches alterx/dnsx and makes them choke
# on the whole list instead of one bad line.
sanitize_host_list() {
  local file="$1"
  [[ -s "$file" ]] || return 0
  local clean rejected
  clean="$(mktemp)"
  rejected="${file%.txt}.rejected.txt"
  : > "$rejected"
  strip_ansi "$file" | while IFS= read -r line; do
    line="$(echo "$line" | xargs)"
    [[ -z "$line" ]] && continue
    # Leading underscore is valid and common (_dmarc., _dkim., _domainkey.,
    # _sip. etc. for DMARC/SPF/DKIM/SRV-style records) -- do not reject those.
    if [[ "$line" =~ ^[A-Za-z0-9_]([A-Za-z0-9._*-]*[A-Za-z0-9_])?$ ]] || is_valid_ip_or_cidr "$line"; then
      echo "$line"
    else
      echo "$line" >> "$rejected"
    fi
  done > "$clean"
  mv "$clean" "$file"
  if [[ -s "$rejected" ]]; then
    warn "Dropped $(count_lines "$rejected") non-hostname line(s) from $(basename "$file") (see $rejected):"
    sed 's/^/      /' "$rejected" | head -n 5
  else
    rm -f "$rejected"
  fi
}
# ───────────────────────────── Tool inventory ────────────────────────────────
#
# Deliberately NOT an associative array.
# macOS ships Bash 3.2, which does not support `declare -A`.
TOOL_FOR_STAGE_1="subfinder assetfinder shuffledns puredns dnsx"
TOOL_FOR_STAGE_2="alterx"
TOOL_FOR_STAGE_3="dnsx"
TOOL_FOR_STAGE_4="naabu"
TOOL_FOR_STAGE_5="httpx katana"
TOOL_FOR_STAGE_6="nuclei"
TOOL_FOR_STAGE_7="waymore gau"
stage_tools() {
local stage="$1"
case "$stage" in
    1) echo "$TOOL_FOR_STAGE_1" ;;
    2) echo "$TOOL_FOR_STAGE_2" ;;
    3) echo "$TOOL_FOR_STAGE_3" ;;
    4) echo "$TOOL_FOR_STAGE_4" ;;
    5) echo "$TOOL_FOR_STAGE_5" ;;
    6) echo "$TOOL_FOR_STAGE_6" ;;
    7) echo "$TOOL_FOR_STAGE_7" ;;
*) echo "" ;;
esac
}
MISSING_TOOLS=()
check_tools() {
  section "Checking installed tools"
local -a all=(
    subfinder
    assetfinder
    shuffledns
    puredns
    dnsx
    alterx
    waymore
    gau
    naabu
    httpx
    katana
    gowitness
    nuclei
    jq
  )
local t
for t in "${all[@]}"; do
if have "$t"; then
      printf "  ${C_MINT}✓${C_RESET} %-16s ${C_DIM}%s${C_RESET}\n" \
        "$t" "$(tool_path "$t")"
else
if [[ "$t" == "jq" || "$t" == "gowitness" ]]; then
        printf "  ${C_PINK}·${C_RESET} %-16s optional/not found\n" "$t"
else
        printf "  ${C_ROSE}✗${C_RESET} %-16s not found\n" "$t"
        MISSING_TOOLS+=("$t")
fi
fi
done
  printf "  ${C_DIM}PATH:${C_RESET} %s\n" "$PATH"
if have shuffledns; then
if have massdns; then
      printf "  ${C_MINT}✓${C_RESET} %-16s ${C_DIM}%s${C_RESET}\n" \
        "massdns" "$(tool_path massdns)"
else
      printf "  ${C_PINK}·${C_RESET} %-16s required by shuffledns (not found)\n" \
        "massdns"
fi
fi
  echo
if [[ "${#MISSING_TOOLS[@]}" -gt 0 ]]; then
    warn "Missing: ${MISSING_TOOLS[*]}"
    warn "Stages/sub-tools needing missing dependencies will be skipped."
    echo -e "${C_DIM}    ProjectDiscovery:${C_RESET}"
    echo -e "${C_DIM}    go install github.com/projectdiscovery/{subfinder/v2/cmd/subfinder,shuffledns/cmd/shuffledns,dnsx/cmd/dnsx,naabu/v2/cmd/naabu,httpx/cmd/httpx,katana/cmd/katana,nuclei/v3/cmd/nuclei}@latest${C_RESET}"
    echo -e "${C_DIM}    go install github.com/tomnomnom/assetfinder@latest${C_RESET}"
    echo -e "${C_DIM}    go install github.com/projectdiscovery/alterx/cmd/alterx@latest${C_RESET}"
    echo -e "${C_DIM}    go install github.com/d3mondev/puredns/v2@latest${C_RESET}"
    echo -e "${C_DIM}    go install github.com/lc/gau/v2/cmd/gau@latest${C_RESET}"
    echo -e "${C_DIM}    pip install waymore${C_RESET}"
fi
if ! have gowitness; then
    echo -e "${C_DIM}    (optional, for stage 5 screenshots) go install github.com/sensepost/gowitness@latest${C_RESET}"
fi
}
stage_available() {
local stage="$1"
local missing=0
local t
local tools
  tools="$(stage_tools "$stage")"
local old_ifs="$IFS"
  IFS=' '
for t in $tools; do
    have "$t" || missing=1
done
  IFS="$old_ifs"
return "$missing"
}
# ───────────────────────────── Command runner ────────────────────────────────
#
# While a tool runs:
#   s       = skip this tool / this target, continue the pipeline  (rc 130)
#   S       = skip this tool AND the rest of the stage             (rc 131)
#   Ctrl-C  = abort the entire pipeline
# Automatic:
#   per-call timeout                                               (rc 124)
#   stall (no new output for SPIN_STALL_KILL seconds)               (rc 125)
#
# Per-call knobs are passed through globals (Bash 3.2-friendly) and reset
# after every call by spin_reset:
#   SPIN_WATCH        file whose line count is the tool's real progress
#   SPIN_WATCH_LABEL  what those lines are ("findings", "urls", ...)
#   SPIN_PROGRESS     caller-side position, e.g. "host 12/340: foo.com"
#   SPIN_TIMEOUT      override COMMAND_TIMEOUT for this call
#   SPIN_STALL_KILL   override STALL_KILL for this call
#
# External command stdin is /dev/null, so tools such as gau/waymore never
# eat the keyboard input this loop is reading.
SPIN_CHARS='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
SPIN_WATCH=""
SPIN_WATCH_LABEL=""
SPIN_PROGRESS=""
SPIN_TIMEOUT=""
SPIN_STALL_KILL=""
SKIP_STAGE=0
stage_skipping() { [[ "$SKIP_STAGE" -eq 1 ]]; }
stage_skip_reset() { SKIP_STAGE=0; }
spin_reset() {
  SPIN_WATCH=""
  SPIN_WATCH_LABEL=""
  SPIN_PROGRESS=""
  SPIN_TIMEOUT=""
  SPIN_STALL_KILL=""
}
tui_status() {
  [[ "$TUI_MODE" -eq 1 && -n "$RUN_DIR" ]] || return 0
  printf '%s\n' "$1" > "$RUN_DIR/.status" 2>/dev/null || true
}
spin_kill() {
  local pid="$1" g=0
  if command -v setsid >/dev/null 2>&1; then
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  else
    kill -TERM "$pid" 2>/dev/null || true
  fi
  while kill -0 "$pid" 2>/dev/null && [[ "$g" -lt 20 ]]; do
    sleep 0.1
    g=$((g + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    if command -v setsid >/dev/null 2>&1; then
      kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
    else
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  wait "$pid" 2>/dev/null || true
}
run_spinner() {
  local label="$1"; shift
  local out_log="$1"; shift
  local start now dur pid rc i=0 key=""
  local cancel_requested=0 skip_stage_requested=0 timeout_requested=0 stalled=0
  local old_stty="" stty_ok=0
  local eff_timeout="${SPIN_TIMEOUT:-$COMMAND_TIMEOUT}"
  local eff_stall="${SPIN_STALL_KILL:-$STALL_KILL}"
  local watch="$SPIN_WATCH"
  local watch_label="${SPIN_WATCH_LABEL:-lines}"
  local progress="$SPIN_PROGRESS"
  local eta=""
  [[ "$eff_timeout" =~ ^[0-9]+$ ]] || eff_timeout=0
  [[ "$eff_stall" =~ ^[0-9]+$ ]] || eff_stall=0
  eta="$(timing_lookup "$label" 2>/dev/null || true)"

  mkdir -p "$(dirname "$out_log")"
  : > "$out_log"
  start="$(date +%s)"

  local head_line="${C_HOT}▸${C_RESET} ${C_BOLD}${label}${C_RESET}"
  [[ -n "$progress" ]] && head_line="$head_line ${C_LILAC}[${progress}]${C_RESET}"
  [[ -n "$eta" ]] && head_line="$head_line ${C_DIM}(last time: $(fmt_dur "$eta"))${C_RESET}"
  echo -e "$head_line"
  echo -e "${C_DIM}    log: $out_log  ·  s = skip this one  ·  S = skip rest of stage  ·  Ctrl-C = quit${C_RESET}"
  log "[RUN] $label ${progress:+($progress)} timeout=${eff_timeout}s stall_kill=${eff_stall}s"

  # Start child with stdin disconnected from the terminal.
  #
  # TUI mode: stream the command's real output live into this pane via
  # process substitution (NOT a literal `| tee` pipeline) in addition to
  # capturing it into out_log. Process substitution keeps "$!" bound to the
  # actual wrapped command/setsid group -- a literal pipe would make "$!"
  # the tee process and break the kill -TERM -- "-$pid" group logic.
  if [[ "$TUI_MODE" -eq 1 ]]; then
    if command -v setsid >/dev/null 2>&1; then
      setsid "$@" </dev/null > >(tee "$out_log") 2>&1 &
    else
      "$@" < /dev/null > >(tee "$out_log") 2>&1 &
    fi
  else
    if command -v setsid >/dev/null 2>&1; then
      setsid "$@" </dev/null >"$out_log" 2>&1 &
    else
      "$@" < /dev/null >"$out_log" 2>&1 &
    fi
  fi
  pid=$!

  # Ctrl-C means EXIT THE ENTIRE SCRIPT (the EXIT trap prints the resume
  # command). $pid resolves at signal time, while it's still in scope.
  # The handler restores the terminal itself: the loop below puts it in
  # -icanon -echo so single keypresses can be read, and bailing out without
  # restoring leaves the user's shell with no echo at all after Ctrl-C.
  # It also prints the resume hint directly rather than relying on the EXIT
  # trap running before the terminal goes away.
  trap '
    if [[ -n "$old_stty" ]]; then stty "$old_stty" 2>/dev/null || true; fi
    printf "\r\033[K"
    err "Ctrl-C received — aborting entire pipeline"
    spin_kill "$pid"
    trap - INT
    print_resume_hint
    exit 131
  ' INT

  # Character-at-a-time keyboard mode (only possible on a real terminal).
  if [[ -t 0 ]]; then
    old_stty="$(stty -g 2>/dev/null || true)"
    if [[ -n "$old_stty" ]]; then
      stty -icanon -echo min 0 time 1 2>/dev/null || true
      stty_ok=1
    fi
  fi

  local last_change="$start" last_sample="$start" last_beat="$start"
  local last_size=0 last_count=0 size=0 count=0 warned_stall=0
  local pct="" eta_txt="" count_txt="" lastline=""

  while kill -0 "$pid" 2>/dev/null; do
    now="$(date +%s)"
    dur=$((now - start))

    if [[ "$eff_timeout" -gt 0 && "$dur" -ge "$eff_timeout" ]]; then
      timeout_requested=1
      break
    fi

    # Sample progress/stall roughly every 2s rather than every tick.
    if [[ $((now - last_sample)) -ge 2 ]]; then
      last_sample="$now"
      size="$(wc -c < "$out_log" 2>/dev/null | tr -d ' ')"
      [[ "$size" =~ ^[0-9]+$ ]] || size=0
      count=0
      if [[ -n "$watch" && -f "$watch" ]]; then
        count="$(count_lines "$watch")"
      fi
      if [[ "$size" != "$last_size" || "$count" != "$last_count" ]]; then
        last_size="$size"
        last_count="$count"
        last_change="$now"
        warned_stall=0
      fi
      count_txt=""
      [[ -n "$watch" && "$count" -gt 0 ]] && count_txt=" · ${count} ${watch_label}"
      eta_txt=""
      if [[ -n "$eta" && "$eta" -gt 0 ]]; then
        if [[ "$dur" -lt "$eta" ]]; then
          eta_txt=" · ~$(fmt_dur $((eta - dur))) left"
        else
          eta_txt=" · over last time by $(fmt_dur $((dur - eta)))"
        fi
      fi

      # Stall: warn so the operator knows it's wedged rather than slow, and
      # kill it rather than hanging the whole pipeline forever.
      if [[ "$STALL_WARN" -gt 0 && $((now - last_change)) -ge "$STALL_WARN" && "$warned_stall" -eq 0 ]]; then
        warned_stall=1
        [[ "$TUI_MODE" -eq 0 ]] && printf "\r\033[K"
        warn "$label: no new output for $(fmt_dur $((now - last_change))) — press s to skip it, S to skip the stage.${eff_stall:+ (auto-kill at $(fmt_dur "$eff_stall") idle)}"
      fi
      if [[ "$eff_stall" -gt 0 && $((now - last_change)) -ge "$eff_stall" ]]; then
        stalled=1
        break
      fi

      # Periodic heartbeat with the tool's own last line of output: this is
      # what shows e.g. nuclei's -stats line ("templates 420/1200, hosts
      # 3/18") or waymore's current provider, so a long run is legible.
      if [[ "$HEARTBEAT_SECS" -gt 0 && $((now - last_beat)) -ge "$HEARTBEAT_SECS" ]]; then
        last_beat="$now"
        lastline="$(tail -n 1 "$out_log" 2>/dev/null | strip_ansi | tr -d '\r' | cut -c1-110)"
        [[ "$TUI_MODE" -eq 0 ]] && printf "\r\033[K"
        echo -e "    ${C_LILAC}↳${C_RESET} ${C_DIM}$(fmt_dur "$dur") elapsed${eta_txt}${count_txt}${lastline:+ · $lastline}${C_RESET}"
        log "[PROGRESS] $label ${dur}s${count_txt} ${lastline}"
      fi
    fi

    # One keyboard character (also paces the loop at ~20Hz).
    key=""
    if [[ "$stty_ok" -eq 1 ]]; then
      IFS= read -r -n 1 -t 0.05 key 2>/dev/null || true
    else
      sleep 0.2
    fi
    case "$key" in
      s) cancel_requested=1 ;;
      S) cancel_requested=1; skip_stage_requested=1 ;;
    esac
    [[ "$cancel_requested" -eq 1 ]] && break

    i=$(( (i + 1) % ${#SPIN_CHARS} ))
    if [[ "$TUI_MODE" -eq 1 ]]; then
      tui_status "$(printf '%s %s%s  %s%s%s  (s/S skip, ^C quit)' \
        "${SPIN_CHARS:$i:1}" "$label" "${progress:+ [$progress]}" \
        "$(fmt_dur "$dur")" "$(echo "$eta_txt" | strip_ansi)" \
        "$(echo "$count_txt" | strip_ansi)")"
    elif [[ -t 1 ]]; then
      printf "\r\033[K${C_PINK}%s${C_RESET} %-44s ${C_LILAC}%6s${C_RESET}${C_DIM}%s%s${C_RESET}" \
        "${SPIN_CHARS:$i:1}" \
        "${label}${progress:+ [$progress]}" \
        "$(fmt_dur "$dur")" \
        "$eta_txt" \
        "$count_txt"
    fi
  done

  if [[ "$stty_ok" -eq 1 ]]; then
    stty "$old_stty" 2>/dev/null || true
  fi
  now="$(date +%s)"
  dur=$((now - start))
  [[ "$TUI_MODE" -eq 0 ]] && printf "\r\033[K"

  # ── abnormal endings: skip / skip-stage / timeout / stall ─────────────────
  if [[ "$cancel_requested" -eq 1 || "$timeout_requested" -eq 1 || "$stalled" -eq 1 ]]; then
    spin_kill "$pid"
    trap - INT
    [[ "$TUI_MODE" -eq 0 ]] && printf "\r\033[K"
    if [[ "$timeout_requested" -eq 1 ]]; then
      warn "$label hit its time limit ($(fmt_dur "$eff_timeout")) — terminated, continuing."
      log "[TIMEOUT] '$label' exceeded ${eff_timeout}s"
      tui_status "✗ timed out: $label ($(fmt_dur "$dur"))"
      spin_reset
      return 124
    fi
    if [[ "$stalled" -eq 1 ]]; then
      warn "$label produced no output for $(fmt_dur "$eff_stall") — treated as hung, terminated, continuing."
      log "[STALL] '$label' idle ${eff_stall}s after ${dur}s"
      tui_status "✗ stalled: $label ($(fmt_dur "$dur"))"
      spin_reset
      return 125
    fi
    if [[ "$skip_stage_requested" -eq 1 ]]; then
      SKIP_STAGE=1
      warn "$label cancelled — skipping the rest of this stage."
      log "[SKIP-STAGE] user skipped stage during '$label' after ${dur}s"
      tui_status "⏭ stage skipped during $label"
      spin_reset
      return 131
    fi
    warn "$label cancelled — continuing to the next step."
    log "[CANCEL] user cancelled '$label' after ${dur}s"
    tui_status "⏭ skipped: $label ($(fmt_dur "$dur"))"
    spin_reset
    return 130
  fi

  # ── normal completion ─────────────────────────────────────────────────────
  wait "$pid"
  rc=$?
  trap - INT
  if [[ "$rc" -eq 0 ]]; then
    ok "$label ${C_DIM}($(fmt_dur "$dur")${count_txt})${C_RESET}"
    timing_record "$label" "$dur"
    tui_status "♡ done: $label ($(fmt_dur "$dur"))"
  else
    err "$label failed after $(fmt_dur "$dur") (rc=$rc) — see $out_log"
    if [[ -s "$out_log" ]]; then
      echo -e "${C_DIM}    last output:${C_RESET}"
      tail -n 5 "$out_log" | sed 's/^/      /'
    fi
    tui_status "✗ $label failed (rc=$rc)"
  fi
  spin_reset
  return "$rc"
}

# Sub-tool gate used throughout the stages. Returns false (so the caller
# skips the tool) when:
#   - the stage is being skipped wholesale ('S' was pressed earlier), or
#   - the binary isn't installed, or
#   - the user/module selection says no.
tool_ready() {
  local module="$1" bin="$2" prompt="$3" def="${4:-y}"
  if stage_skipping; then
    return 1
  fi
  if [[ -n "$bin" ]] && ! have "$bin"; then
    warn "$bin not installed — skipping $module."
    return 1
  fi
  module_confirm "$module" "$prompt" "$def"
}
# ───────────────────────────── Target parsing ────────────────────────────────
DOMAINS=()
EXCLUDED=()
CIDRS=()
RAW_IPS=()
parse_targets() {
local input="$1"
local raw
local line
#
# Bash 3.2 does NOT have mapfile/readarray.
# Read files line-by-line instead.
#
if [[ -f "$input" ]]; then
while IFS= read -r raw || [[ -n "$raw" ]]; do
      line="$(echo "$raw" | xargs)"
      [[ -z "$line" ]] && continue
      [[ "$line" == \#* ]] && continue
if [[ "$line" == !* ]]; then
        EXCLUDED+=("${line#!}")
elif [[ "$line" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]; then
        CIDRS+=("$line")
elif [[ "$line" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        RAW_IPS+=("$line")
else
        line="${line#\*.}"
        DOMAINS+=("$line")
fi
done < "$input"
else
local old_ifs="$IFS"
    IFS=','
local -a lines=()
    read -r -a lines <<< "$input"
    IFS="$old_ifs"
for raw in "${lines[@]}"; do
      line="$(echo "$raw" | xargs)"
      [[ -z "$line" ]] && continue
      [[ "$line" == \#* ]] && continue
if [[ "$line" == !* ]]; then
        EXCLUDED+=("${line#!}")
elif [[ "$line" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]; then
        CIDRS+=("$line")
elif [[ "$line" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        RAW_IPS+=("$line")
else
        line="${line#\*.}"
        DOMAINS+=("$line")
fi
done
fi
}
print_target_summary() {
  section "Target summary"
  [[ "${#DOMAINS[@]}" -gt 0 ]] &&
    echo -e "  Domains  : ${C_BOLD}${C_PINK}${DOMAINS[*]}${C_RESET}"
  [[ "${#EXCLUDED[@]}" -gt 0 ]] &&
    echo -e "  Excluded : ${C_ROSE}${EXCLUDED[*]}${C_RESET}"
  [[ "${#CIDRS[@]}" -gt 0 ]] &&
    echo -e "  CIDRs    : ${C_BOLD}${C_LILAC}${CIDRS[*]}${C_RESET}"
  [[ "${#RAW_IPS[@]}" -gt 0 ]] &&
    echo -e "  IPs      : ${C_BOLD}${C_LILAC}${RAW_IPS[*]}${C_RESET}"
  echo
}
apply_exclusions() {
local file="$1"
  [[ "${#EXCLUDED[@]}" -eq 0 || ! -s "$file" ]] && return
local tmp
  tmp="$(mktemp)"
  cp "$file" "$tmp"
local ex
for ex in "${EXCLUDED[@]}"; do
    grep -vE \
      "(^|\.)$(printf '%s' "$ex" | sed 's/\./\\./g')\$" \
      "$tmp" > "${tmp}.new" || true
    mv "${tmp}.new" "$tmp"
done
  mv "$tmp" "$file"
}
# ───────────────────────────── Stage 1 ───────────────────────────────────────
stage1_dir=""
stage1_combined=""
run_stage1() {
  section "STAGE 1 — Subdomain asset discovery"
  stage_skip_reset
  stage1_dir="$RUN_DIR/1_discovery"
  mkdir -p "$stage1_dir"
  stage1_combined="$stage1_dir/all_subdomains.txt"
  : > "$stage1_combined"
  if [[ "${#DOMAINS[@]}" -eq 0 ]]; then
    warn "No domains provided — skipping subdomain discovery."
    return
  fi
  local domains_file="$stage1_dir/input_domains.txt"
  printf '%s\n' "${DOMAINS[@]}" > "$domains_file"
  local rc=0 domain idx total_d="${#DOMAINS[@]}"

  # ── subfinder ─────────────────────────────────────────────────────────────
  if tool_ready subfinder subfinder "Run subfinder for passive subdomain enumeration?"; then
    SPIN_WATCH="$stage1_dir/subfinder.txt"
    SPIN_WATCH_LABEL="subdomains"
    run_spinner "subfinder" "$stage1_dir/subfinder.log" \
      subfinder -dL "$domains_file" -all -silent -o "$stage1_dir/subfinder.txt"
    cat "$stage1_dir/subfinder.txt" 2>/dev/null >> "$stage1_combined" || true
  else
    warn "Skipping subfinder"
  fi

  # ── assetfinder ───────────────────────────────────────────────────────────
  if tool_ready assetfinder assetfinder "Run assetfinder for additional passive discovery?"; then
    : > "$stage1_dir/assetfinder.txt"
    idx=0
    for domain in "${DOMAINS[@]}"; do
      idx=$((idx + 1))
      SPIN_PROGRESS="domain $idx/$total_d: $domain"
      SPIN_WATCH="$stage1_dir/assetfinder_${domain}.txt"
      SPIN_WATCH_LABEL="subdomains"
      SPIN_TIMEOUT=600
      run_spinner "assetfinder" "$stage1_dir/assetfinder_${domain}.txt" \
        assetfinder --subs-only "$domain"
      rc=$?
      cat "$stage1_dir/assetfinder_${domain}.txt" 2>/dev/null >> "$stage1_dir/assetfinder.txt" || true
      [[ "$rc" -eq 131 ]] && break
    done
    sort -u "$stage1_dir/assetfinder.txt" -o "$stage1_dir/assetfinder.txt" 2>/dev/null || true
    ok "assetfinder ($(count_lines "$stage1_dir/assetfinder.txt") lines)"
    cat "$stage1_dir/assetfinder.txt" >> "$stage1_combined"
  else
    warn "Skipping assetfinder"
  fi

  # ── shuffledns ────────────────────────────────────────────────────────────
  if tool_ready shuffledns shuffledns "Run shuffledns active DNS brute force?"; then
    local wordlist resolver_file
    wordlist="$(ask "Path to subdomain wordlist" "$WORDLIST_DEFAULT")"
    resolver_file="$RESOLVERS_DEFAULT"
    if [[ -z "$resolver_file" ]]; then
      resolver_file="$(ask "Path to resolver list" "$HOME/resolvers.txt")"
    fi
    if [[ -f "$wordlist" && -f "$resolver_file" ]] && have massdns; then
      : > "$stage1_dir/shuffledns.txt"
      idx=0
      for domain in "${DOMAINS[@]}"; do
        idx=$((idx + 1))
        SPIN_PROGRESS="domain $idx/$total_d: $domain"
        SPIN_WATCH="$stage1_dir/shuffledns_${domain}.txt"
        SPIN_WATCH_LABEL="hits"
        SPIN_TIMEOUT="$SHUFFLEDNS_TIMEOUT"
        run_spinner "shuffledns bruteforce" "$stage1_dir/shuffledns_${domain}.log" \
          shuffledns -d "$domain" -w "$wordlist" -r "$resolver_file" \
            -mode bruteforce -silent -o "$stage1_dir/shuffledns_${domain}.txt"
        rc=$?
        cat "$stage1_dir/shuffledns_${domain}.txt" 2>/dev/null >> "$stage1_dir/shuffledns.txt" || true
        [[ "$rc" -eq 131 ]] && break
      done
      sort -u "$stage1_dir/shuffledns.txt" -o "$stage1_dir/shuffledns.txt"
      cat "$stage1_dir/shuffledns.txt" >> "$stage1_combined"
      ok "shuffledns found $(count_lines "$stage1_dir/shuffledns.txt") active candidates"
    else
      warn "shuffledns needs a wordlist, resolver list and massdns; skipping."
    fi
  else
    warn "Skipping shuffledns"
  fi

  # ── puredns ───────────────────────────────────────────────────────────────
  if tool_ready puredns puredns "Run DNS brute force with puredns?"; then
    local wordlist2 puredns_resolvers
    wordlist2="$(ask "Path to subdomain wordlist" "$WORDLIST_DEFAULT")"
    puredns_resolvers="$RESOLVERS_DEFAULT"
    if [[ -z "$puredns_resolvers" || ! -f "$puredns_resolvers" ]]; then
      puredns_resolvers="$(ask "Path to resolver list for puredns" "$HOME/.config/puredns/resolvers.txt")"
    fi
    if [[ -f "$wordlist2" ]]; then
      : > "$stage1_dir/bruteforce.txt"
      idx=0
      for domain in "${DOMAINS[@]}"; do
        idx=$((idx + 1))
        # NOTE: do not redirect run_spinner's own stdout here with `>>`.
        # run_spinner already redirects the WRAPPED command's real
        # stdout/stderr into its own .log file; an outer `>>` on this whole
        # statement would instead capture run_spinner's own UI text —
        # spinner frames, the "log: ..." line, heartbeats, and the
        # cancel/stall warnings — straight into bruteforce.txt and from
        # there into stage1_combined, your master hostname list. Append the
        # real log afterwards instead.
        SPIN_PROGRESS="domain $idx/$total_d: $domain"
        SPIN_WATCH="$stage1_dir/puredns_${domain}.log"
        SPIN_WATCH_LABEL="hosts"
        SPIN_TIMEOUT="$PUREDNS_TIMEOUT"
        run_spinner "puredns bruteforce" "$stage1_dir/puredns_${domain}.log" \
          puredns bruteforce "$wordlist2" "$domain" -q -r "$puredns_resolvers"
        rc=$?
        cat "$stage1_dir/puredns_${domain}.log" 2>/dev/null >> "$stage1_dir/bruteforce.txt" || true
        [[ "$rc" -eq 131 ]] && break
      done
      cat "$stage1_dir/bruteforce.txt" >> "$stage1_combined"
    else
      warn "Wordlist not found at '$wordlist2' — skipping DNS brute force."
    fi
  else
    warn "Skipping puredns"
  fi

  # ── recursive DNS expansion ───────────────────────────────────────────────
  if [[ -s "$stage1_combined" ]] &&
     tool_ready recursive-dns dnsx "Run recursive DNS expansion pass?"; then
    local prefixes=(dev staging stage api test uat qa admin internal vpn beta preprod)
    local recur_in="$stage1_dir/recursive_candidates.txt"
    : > "$recur_in"
    sort -u "$stage1_combined" | head -n 500 | while read -r h; do
      [[ -z "$h" ]] && continue
      local p
      for p in "${prefixes[@]}"; do
        echo "${p}.${h}"
      done
    done > "$recur_in"
    # No -resp/-resp-only/-json here on purpose: dnsx's plain default output
    # (just -silent -no-color) prints exactly the hostnames that resolved,
    # one per line. -resp-only would print ONLY the IP with the hostname
    # stripped, which is the wrong shape for a HOSTNAME list.
    SPIN_WATCH="$stage1_dir/recursive_resolved.txt"
    SPIN_WATCH_LABEL="resolved"
    SPIN_TIMEOUT="$DNSX_TIMEOUT"
    run_spinner "dnsx recursive-expansion resolve" "$stage1_dir/recursive_dnsx.log" \
      dnsx -l "$recur_in" -silent -no-color -o "$stage1_dir/recursive_resolved.txt"
    cat "$stage1_dir/recursive_resolved.txt" 2>/dev/null >> "$stage1_combined" || true
  else
    warn "Skipping recursive DNS expansion pass"
  fi

  sort -u "$stage1_combined" -o "$stage1_combined"
  sanitize_host_list "$stage1_combined"
  apply_exclusions "$stage1_combined"
  {
    echo "host"
    awk 'NF{ gsub(/"/, "\"\"", $0); print "\"" $0 "\"" }' "$stage1_combined"
  } > "$stage1_dir/assets.csv"
  ok "Stage 1 combined total: $(count_lines "$stage1_combined") unique hosts"
  set_active_candidates "$stage1_combined"
}
# ───────────────────────────── Stage 2 ───────────────────────────────────────
stage2_combined=""
run_stage2() {
  section "STAGE 2 — Permutation generation (alterx)"
  stage_skip_reset
  local stage2_dir="$RUN_DIR/2_permutations"
  mkdir -p "$stage2_dir"
  stage2_combined="$stage2_dir/alterx_permutations.txt"
  : > "$stage2_combined"
  if [[ ! -s "$stage1_combined" ]]; then
    warn "No stage 1 output to permute — skipping stage 2."
    return
  fi
  if ! tool_ready alterx alterx "Generate permutations with alterx?"; then
    warn "Skipping alterx"
    return
  fi
  SPIN_WATCH="$stage2_combined"
  SPIN_WATCH_LABEL="permutations"
  run_spinner "alterx" "$stage2_dir/alterx.log" \
    alterx -l "$stage1_combined" -o "$stage2_combined"
  sanitize_host_list "$stage2_combined"
  ok "alterx generated $(count_lines "$stage2_combined") candidate permutations"
  set_active_candidates "$stage2_combined"
}
# ───────────────────────────── Stage 3 ───────────────────────────────────────
stage3_resolved=""
stage3_resolved_ips=""
stage3_all_resolved=""
stage3_host_ip_all=""
stage3_wildcard_hosts=""
run_stage3() {
  section "STAGE 3 — Resolution check (dnsx + wildcard detection)"
  stage_skip_reset
  local stage3_dir="$RUN_DIR/3_resolved"
  mkdir -p "$stage3_dir"
  stage3_resolved="$stage3_dir/resolved_hosts.txt"
  stage3_resolved_ips="$stage3_dir/resolved_hosts_ips.txt"
  stage3_all_resolved="$stage3_dir/resolved_hosts_all.txt"
  stage3_host_ip_all="$stage3_dir/host_ip.csv"
  stage3_wildcard_hosts="$stage3_dir/wildcard_hosts.txt"
  local total_list="$stage3_dir/total_candidates.txt"
  local raw="$stage3_dir/dnsx_raw.txt"
  local wildcard_map="$stage3_dir/wildcard_domain_ip.csv"
  local wildcard_ips="$stage3_dir/wildcard_ips.txt"
  local wildcard_host_ip="$stage3_dir/wildcard_host_ip.csv"
  : > "$stage3_resolved"; : > "$stage3_resolved_ips"; : > "$stage3_all_resolved"
  : > "$stage3_host_ip_all"; : > "$stage3_wildcard_hosts"; : > "$wildcard_map"; : > "$wildcard_ips"; : > "$wildcard_host_ip"

  cat "$stage1_combined" "$stage2_combined" 2>/dev/null | sort -u > "$total_list" || true
  local ip
  for ip in "${RAW_IPS[@]:-}"; do
    [[ -n "$ip" ]] && echo "$ip" >> "$total_list"
  done
  sort -u "$total_list" -o "$total_list"
  sanitize_host_list "$total_list"
  set_active_candidates "$total_list"
  if [[ ! -s "$total_list" ]]; then
    warn "No candidates to resolve — skipping stage 3."
    return
  fi
  if ! have dnsx; then
    warn "dnsx not installed — passing candidates through unresolved."
    cp "$total_list" "$stage3_resolved"
    cp "$stage3_resolved" "$stage3_all_resolved"
    return
  fi
  if ! module_confirm dnsx "Resolve $(count_lines "$total_list") candidates with dnsx?"; then
    warn "Skipping dnsx resolution"
    cp "$total_list" "$stage3_resolved"
    cp "$stage3_resolved" "$stage3_all_resolved"
    return
  fi
  # Prefer -json (clean, structured, never colourised) over -resp; -no-color
  # is passed either way as a belt-and-suspenders measure.
  local -a dnsx_fmt_flag=()
  if have jq; then dnsx_fmt_flag=(-json); else dnsx_fmt_flag=(-resp); fi
  SPIN_WATCH="$raw"
  SPIN_WATCH_LABEL="records"
  SPIN_TIMEOUT="$DNSX_TIMEOUT"
  run_spinner "dnsx resolve" "$stage3_dir/dnsx.log" \
    dnsx -l "$total_list" -silent -no-color -a -aaaa "${dnsx_fmt_flag[@]}" -o "$raw"
  if [[ ! -s "$raw" ]]; then
    : > "$stage3_resolved"; : > "$stage3_resolved_ips"
    : > "$stage3_all_resolved"; : > "$stage3_host_ip_all"
    warn "dnsx returned no resolved candidates."
    return
  fi
  extract_dnsx_host_ip "$raw" "$stage3_host_ip_all"
  cut -d, -f1 "$stage3_host_ip_all" | sort -u > "$stage3_all_resolved"
  cp "$stage3_host_ip_all" "$stage3_resolved_ips"

  # ── wildcard detection (always run when we have domains: it's cheap, and
  #    the decision about what to DO with wildcards is taken below) ──────────
  if [[ "${#DOMAINS[@]}" -gt 0 ]] && ! stage_skipping; then
    local domain random_label wraw wmap idx=0 total_d="${#DOMAINS[@]}" rc=0
    for domain in "${DOMAINS[@]}"; do
      idx=$((idx + 1))
      random_label="__squiz_wildcard_${RANDOM}${RANDOM}.${domain}"
      wraw="$stage3_dir/wildcard_${domain}.raw.txt"
      wmap="$stage3_dir/wildcard_${domain}.csv"
      printf '%s\n' "$random_label" > "$stage3_dir/wildcard_query.txt"
      SPIN_PROGRESS="domain $idx/$total_d: $domain"
      SPIN_TIMEOUT=120
      run_spinner "dnsx wildcard check" "$stage3_dir/wildcard_${domain}.log" \
        dnsx -l "$stage3_dir/wildcard_query.txt" -silent -no-color -a -aaaa "${dnsx_fmt_flag[@]}" -o "$wraw"
      rc=$?
      extract_dnsx_host_ip "$wraw" "$wmap"
      if [[ -s "$wmap" ]]; then
        cut -d, -f2 "$wmap" | sort -u | while read -r ip; do
          [[ -n "$ip" ]] && echo "$domain,$ip"
        done >> "$wildcard_map"
      fi
      [[ "$rc" -eq 131 ]] && break
    done
    sort -u "$wildcard_map" -o "$wildcard_map"
    cut -d, -f2 "$wildcard_map" | sort -u > "$wildcard_ips"

    if [[ -s "$wildcard_map" ]]; then
      awk -F, -v map="$wildcard_map" '
        BEGIN { while ((getline < map) > 0) { split($0,a,","); w[a[1] SUBSEP a[2]]=1 } close(map) }
        {
          host=$1; ip=$2; isw=0
          for (d in w) {
            split(d,a,SUBSEP); domain=a[1]; wip=a[2]
            if (ip==wip && (host==domain || host ~ ("\\." domain "$") )) { isw=1; break }
          }
          if (isw) print host "," ip
        }
      ' "$stage3_host_ip_all" | sort -u > "$wildcard_host_ip"
      cut -d, -f1 "$wildcard_host_ip" | sort -u > "$stage3_wildcard_hosts"
    fi
  fi

  # ── what to do about the wildcards: ASK, don't assume ─────────────────────
  # Previously wildcard hosts were simply dropped unless --probe-wildcards
  # had been passed up front. Now, if neither --probe-wildcards nor
  # --no-probe-wildcards was given, the question is asked here, at the point
  # where the answer actually matters, and the answer is written back to the
  # manifest so --resume keeps it.
  if [[ -s "$wildcard_map" ]]; then
    warn "Wildcard DNS detected for: $(cut -d, -f1 "$wildcard_map" | sort -u | tr '\n' ' ')"
    info "Wildcard IP(s): $(tr '\n' ' ' < "$wildcard_ips")"
    info "$(count_lines "$stage3_wildcard_hosts") of $(count_lines "$stage3_all_resolved") resolved host(s) look like catch-all results."
    if [[ "$PROBE_WILDCARDS_SET" -eq 0 ]] && ! can_ask; then
      info "Unattended run — keeping the wildcard defaults (http-probe=$PROBE_WILDCARDS, dns-filter=$WILDCARD_FILTER). Pass --probe-wildcards / --no-probe-wildcards / --no-wildcard-filter to decide up front."
      PROBE_WILDCARDS_SET=1
    fi
    if [[ "$PROBE_WILDCARDS_SET" -eq 0 ]]; then
      if confirm "HTTP-probe the wildcard hosts anyway (keep them so httpx can fingerprint and only then discard the true catch-alls)?" y; then
        PROBE_WILDCARDS=1
      else
        PROBE_WILDCARDS=0
      fi
      if confirm "Also keep wildcard hosts in the normal live-host list (turn the DNS wildcard filter OFF)?" n; then
        WILDCARD_FILTER=0
      else
        WILDCARD_FILTER=1
      fi
      PROBE_WILDCARDS_SET=1
      update_manifest probe_wildcards "$PROBE_WILDCARDS"
      update_manifest probe_wildcards_set 1
      update_manifest wildcard_filter "$WILDCARD_FILTER"
    fi
    info "Wildcard handling: dns-filter=$([[ "$WILDCARD_FILTER" -eq 1 ]] && echo on || echo off), http-probe=$([[ "$PROBE_WILDCARDS" -eq 1 ]] && echo on || echo off)"
  else
    info "No wildcard DNS detected."
  fi

  if [[ "$WILDCARD_FILTER" -eq 1 && -s "$stage3_wildcard_hosts" ]]; then
    grep -Fvx -f "$stage3_wildcard_hosts" "$stage3_all_resolved" > "$stage3_resolved" || true
    awk -F, 'NR==FNR {bad[$1]=1; next} !bad[$1]' "$stage3_wildcard_hosts" "$stage3_host_ip_all" | sort -u > "$stage3_resolved_ips" || true
    ok "Stage 3 resolved: $(count_lines "$stage3_all_resolved") DNS-live; $(count_lines "$stage3_wildcard_hosts") wildcard candidates filtered; $(count_lines "$stage3_resolved") retained"
    if [[ ! -s "$stage3_resolved" ]]; then
      warn "Every resolved host looked like a wildcard, so the filtered list is EMPTY. Stage 4 will fall back to the full resolved-IP set (and you can add/remove IPs there)."
    fi
  else
    cp "$stage3_all_resolved" "$stage3_resolved"
    ok "Stage 3 resolved: $(count_lines "$stage3_resolved") live hostnames (wildcard filter inactive/not triggered)"
  fi
  apply_exclusions "$stage3_resolved"
  if [[ -s "$stage3_host_ip_all" && -s "$stage3_resolved" ]]; then
    awk -F, 'NR==FNR {keep[$1]=1; next} keep[$1]' "$stage3_resolved" "$stage3_host_ip_all" | sort -u > "$stage3_resolved_ips"
  else
    : > "$stage3_resolved_ips"
  fi
  {
    echo "host,ip"
    cat "$stage3_resolved_ips"
  } > "$stage3_dir/resolved_hosts_ips.csv"
  set_active_candidates "$stage3_resolved" "$stage3_all_resolved"
}

# ───────────────────────────── Stage 4 ───────────────────────────────────────
# Port scanning is intentionally BEFORE HTTP/archive.
stage5_hostports=""
run_stage4() {
  section "STAGE 4 — Port scanning (naabu)"
  stage_skip_reset
  local stage4_dir="$RUN_DIR/4_ports"
  mkdir -p "$stage4_dir"
  stage5_hostports="$stage4_dir/naabu_hostports.txt"
  local target_list="$stage4_dir/naabu_ip_targets.txt"
  local naabu_input="$stage4_dir/naabu_input.txt"
  local pool_ips="$stage4_dir/naabu_ip_pool.txt"
  local ipports="$stage4_dir/naabu_ipports.txt"
  : > "$stage5_hostports"; : > "$target_list"; : > "$naabu_input"; : > "$ipports"; : > "$pool_ips"

  local scan_hosts="$stage4_dir/scan_hosts.txt"
  : > "$scan_hosts"
  # Naabu expects IP/CIDR targets for this scan mode. The hostname -> IP
  # mapping is kept separately so every IP:port result can later be mapped
  # back to every hostname that resolves to that IP.
  cat "$stage3_resolved" 2>/dev/null | sort -u > "$scan_hosts" || true
  if [[ -s "$stage3_host_ip_all" && -s "$scan_hosts" ]]; then
    awk -F, 'NR==FNR {keep[$1]=1; next} keep[$1] {print $2}' "$scan_hosts" "$stage3_host_ip_all" |
      sed -E 's/^\[//; s/\]$//' | awk 'NF' | sort -u >> "$target_list"
  fi
  local ip cidr
  for ip in "${RAW_IPS[@]:-}"; do [[ -n "$ip" ]] && echo "$ip" >> "$target_list"; done
  for cidr in "${CIDRS[@]:-}"; do [[ -n "$cidr" ]] && echo "$cidr" >> "$target_list"; done
  sort -u "$target_list" -o "$target_list"
  cp "$target_list" "$naabu_input"

  # The POOL: every IP dnsx ever resolved, wildcard-flagged or not, plus any
  # literal IPs/CIDRs from the target spec. This is what CTRL-A in the TUI
  # pane (and the prompt below) adds back from.
  {
    cut -d, -f2 "$stage3_host_ip_all" 2>/dev/null | sed -E 's/^\[//; s/\]$//'
    for ip in "${RAW_IPS[@]:-}"; do echo "$ip"; done
    for cidr in "${CIDRS[@]:-}"; do echo "$cidr"; done
  } | awk 'NF' | sort -u > "$pool_ips" 2>/dev/null || true

  # Wildcard filtering can legitimately leave NOTHING to scan: if every
  # hostname resolves to the same single IP (common for a CDN/single-origin
  # domain), stage 3's filter treats all of them as catch-all noise and
  # stage3_resolved ends up empty -- even though that one IP is very likely
  # the real server and worth scanning. Rather than reporting "0 candidates",
  # fall back to the full unfiltered resolved-IP pool.
  if [[ ! -s "$naabu_input" && -s "$pool_ips" ]]; then
    warn "Wildcard filtering left naabu with 0 candidate IPs (every resolved hostname looked like a catch-all) — falling back to the full unfiltered resolved-IP set ($(count_lines "$pool_ips") IP(s)) instead of skipping the stage."
    cp "$pool_ips" "$naabu_input"
  fi

  # Offer to add the wildcard-filtered IPs back even when the input is NOT
  # empty (e.g. 1 real IP + 3 filtered ones). --naabu-add-wildcard-ips /
  # --no-naabu-add-wildcard-ips skip the question.
  local extra_file extra_n=0
  extra_file="$(mktemp)"
  if [[ -s "$pool_ips" ]]; then
    if [[ -s "$naabu_input" ]]; then
      grep -vxFf "$naabu_input" "$pool_ips" 2>/dev/null | awk 'NF' > "$extra_file" || true
    else
      cp "$pool_ips" "$extra_file"
    fi
    extra_n="$(count_lines "$extra_file")"
  fi
  if [[ "$extra_n" -gt 0 ]]; then
    info "$extra_n resolved IP(s) are being held back by the wildcard filter (full pool: $pool_ips)."
    local add_them=0
    case "$NAABU_ADD_WILDCARD_IPS" in
      1) add_them=1 ;;
      0) add_them=0 ;;
      *)
        if can_ask; then
          confirm "Add those $extra_n wildcard-filtered IP(s) to the naabu target list?" n && add_them=1
        else
          info "Unattended run — leaving them out. Pass --naabu-add-wildcard-ips to include them automatically."
        fi
;;
    esac
    if [[ "$add_them" -eq 1 ]]; then
      cat "$extra_file" >> "$naabu_input"
      sort -u "$naabu_input" -o "$naabu_input"
      ok "naabu target list is now $(count_lines "$naabu_input") IP/CIDR entries."
    fi
  fi
  rm -f "$extra_file"

  # Let the user change exactly what is about to be scanned:
  #   TUI mode:     right pane — TAB mark, ENTER delete, CTRL-A add from the
  #                 full resolved-IP pool.
  #   non-TUI mode: $EDITOR/$VISUAL (or nano/vi) on naabu_input directly.
  set_active_candidates "$naabu_input" "$pool_ips"
  maybe_edit_file_interactively "$naabu_input" "naabu IP target list"

  # Last line of defense, AFTER any editing: only ever hand naabu
  # syntactically valid IPv4/IPv6 literals or CIDRs. One malformed line used
  # to be enough to abort the whole scan with "no valid ipv4 or ipv6 targets
  # were found", even when every other line was fine.
  filter_valid_ip_file "$naabu_input" "$stage4_dir/naabu_input_rejected.txt"

  if [[ ! -s "$naabu_input" ]]; then warn "No resolved IPv4/IPv6/CIDR targets available for naabu — skipping stage 4."; return; fi
  if ! have naabu; then warn "naabu not installed — skipping stage 4."; return; fi
  if ! module_confirm naabu "Run naabu port scan on $(count_lines "$naabu_input") unique IP/CIDR targets?"; then warn "Skipping naabu"; return; fi

  local scope; scope="$(ask "Port scope: [top100 / top1000 / all / custom range]" "$PORT_SCOPE_DEFAULT")"
  # Sanitize custom ranges: port 0 isn't a real TCP port, and a leading
  # "0-N" (e.g. someone typing "0-3000" expecting "all ports up to 3000")
  # can make naabu choke on or silently mis-handle the range. Rewrite it to
  # the equivalent valid range instead of silently losing ports.
  if [[ "$scope" =~ ^0+-([0-9]+)$ ]]; then
    local fixed_scope="1-${BASH_REMATCH[1]}"
    warn "Port scope '$scope' starts at port 0 (not a valid TCP port) — using '$fixed_scope' instead."
    scope="$fixed_scope"
  fi
  local -a port_flag=()
  case "$scope" in
    top100) port_flag=(-top-ports 100) ;;
    top1000) port_flag=(-top-ports 1000) ;;
    all) port_flag=(-p -) ;;
    *) port_flag=(-p "$scope") ;;
  esac
  # Reliability flags, shared by every naabu invocation below:
  #  -Pn / -skip-host-discovery — naabu's pre-scan "is this host alive" check
  #     needs the same raw-socket privileges as a SYN scan, and silently
  #     fails closed (host treated as dead, 0 ports reported — even obvious
  #     ones like 80/443) when it doesn't have them, or when ICMP/SYN-ACK is
  #     simply filtered on the path. Skipping it means naabu always actually
  #     probes every requested port on every target instead of trusting an
  #     unreliable pre-check — the #1 cause of "naabu misses obvious ports".
  #  -scan-type / -rate / -retries — optional overrides (--naabu-scan-type,
  #     --naabu-rate, --naabu-retries) for when packet loss from scanning too
  #     fast, or a non-root SYN/raw-socket limitation, is dropping real ports.
  local -a naabu_reliability_flags=(-Pn)
  [[ -n "$NAABU_SCAN_TYPE" ]] && naabu_reliability_flags+=(-scan-type "$NAABU_SCAN_TYPE")
  [[ -n "$NAABU_RATE" ]] && naabu_reliability_flags+=(-rate "$NAABU_RATE")
  [[ -n "$NAABU_RETRIES" ]] && naabu_reliability_flags+=(-retries "$NAABU_RETRIES")
  info "naabu targets: $(count_lines "$naabu_input") unique IP/CIDR entries"
  info "naabu primary port scope: $scope"
  # -stats makes naabu print its own periodic progress, which the heartbeat
  # surfaces, so a slow scan is visibly slow rather than apparently hung.
  SPIN_WATCH="$stage4_dir/naabu_primary.txt"
  SPIN_WATCH_LABEL="open ports"
  SPIN_TIMEOUT="$NAABU_TIMEOUT"
  run_spinner "naabu (${scope})" "$stage4_dir/naabu_primary.log" \
    naabu -list "$naabu_input" "${port_flag[@]}" "${naabu_reliability_flags[@]}" -stats -silent -no-color -o "$stage4_dir/naabu_primary.txt"
  local rc=$?
  [[ "$rc" -eq 131 ]] && { warn "Rest of stage 4 skipped."; }
  if [[ "$rc" -ne 0 && "$rc" -ne 130 && "$rc" -ne 124 && "$rc" -ne 125 && "$rc" -ne 131 ]]; then
    err "naabu primary scan failed (rc=$rc)"
  fi

  if ! stage_skipping &&
     [[ "$EXTRA_PORTS_ENABLED" -eq 1 && -n "$EXTRA_PORTS_DEFAULT" && "$scope" != "all" && "$scope" != "1-65535" ]]; then
    SPIN_WATCH="$stage4_dir/naabu_extra.txt"
    SPIN_WATCH_LABEL="open ports"
    SPIN_TIMEOUT="$NAABU_TIMEOUT"
    run_spinner "naabu (extra/common non-standard ports)" "$stage4_dir/naabu_extra.log" \
      naabu -list "$naabu_input" -p "$EXTRA_PORTS_DEFAULT" "${naabu_reliability_flags[@]}" -stats -silent -no-color -o "$stage4_dir/naabu_extra.txt"
    rc=$?
    [[ "$rc" -ne 0 && "$rc" -ne 130 && "$rc" -ne 131 && "$rc" -ne 124 && "$rc" -ne 125 ]] && warn "naabu extra-port scan failed (rc=$rc)"
  else
    : > "$stage4_dir/naabu_extra.txt"
  fi

  cat "$stage4_dir/naabu_primary.txt" "$stage4_dir/naabu_extra.txt" 2>/dev/null | sort -u > "$ipports" || true
  if [[ -s "$ipports" ]]; then ok "naabu found $(count_lines "$ipports") open IP:port pairs"; else warn "naabu found no open ports."; fi

  # Map every naabu IP:port result back to EVERY DNS-resolved hostname.
  # Naabu scans IPs efficiently, but HTTP needs the original hostname for
  # Host/SNI-based virtual hosting. Wildcard candidates are retained here so
  # httpx can validate them instead of losing them in DNS.
  local all_hostports="$stage4_dir/naabu_hostports_all.txt"
  local hostport port
  : > "$all_hostports"
  if [[ -s "$ipports" && -s "$stage3_host_ip_all" ]]; then
    while IFS= read -r hostport; do
      [[ -z "$hostport" ]] && continue
      port="${hostport##*:}"
      ip="${hostport%:$port}"
      ip="${ip#[}"
      ip="${ip%]}"
      [[ -z "$ip" || -z "$port" ]] && continue
      awk -F, -v ip="$ip" -v port="$port" '($2==ip) {print $1 ":" port}' \
        "$stage3_host_ip_all" >> "$all_hostports"
    done < "$ipports"
    sort -u "$all_hostports" -o "$all_hostports"
  fi
  # A literal IP target with no hostname still deserves probing.
  if [[ -s "$ipports" && ! -s "$all_hostports" ]]; then
    cp "$ipports" "$all_hostports"
  fi

  # Keep the conservative DNS-filtered set separately for reporting.
  if [[ -s "$all_hostports" && -s "$stage3_wildcard_hosts" ]]; then
    awk -F: 'NR==FNR {w[$1]=1; next} {h=$1; if (!w[h]) print}' \
      "$stage3_wildcard_hosts" "$all_hostports" | sort -u > "$stage5_hostports"
  else
    cp "$all_hostports" "$stage5_hostports" 2>/dev/null || true
  fi

  {
    echo "host,port"
    awk -F: 'NF>=2 {p=$NF; $NF=""; h=$0; sub(/:$/, "", h); print h "," p}' "$all_hostports" 2>/dev/null
  } > "$stage4_dir/naabu_hostports_all.csv"
  {
    echo "host,port"
    awk -F: 'NF>=2 {p=$NF; $NF=""; h=$0; sub(/:$/, "", h); print h "," p}' "$stage5_hostports" 2>/dev/null
  } > "$stage4_dir/open_ports.csv"

  ok "Generated $(count_lines "$all_hostports") hostname:port HTTP candidates from naabu results"
  if [[ -s "$stage3_wildcard_hosts" ]]; then
    info "Wildcard DNS candidates are included in HTTP validation, not discarded before httpx."
    info "Conservative non-wildcard hostname:port set: $(count_lines "$stage5_hostports")"
  fi
  # all_hostports (not the conservative stage5_hostports) is what stage 5
  # reads as its httpx input, so that's the file worth editing next.
  set_active_candidates "$all_hostports" "$stage4_dir/naabu_hostports_all.txt"
}

# ───────────────────────────── Stage 5 ───────────────────────────────────────
stage6_httpx=""
stage6_katana=""
stage6_screenshots_jsonl=""
stage6_screenshots_dir=""
run_stage5() {
  section "STAGE 5 — HTTP probing (wildcard fingerprinting + httpx) & crawling (katana)"
  stage_skip_reset
  local stage5_dir="$RUN_DIR/5_http"
  mkdir -p "$stage5_dir"
  stage6_httpx="$stage5_dir/httpx.txt"
  stage6_katana="$stage5_dir/katana_links.txt"
  stage6_screenshots_jsonl="$stage5_dir/gowitness.jsonl"
  stage6_screenshots_dir="$stage5_dir/screenshots"
  : > "$stage6_httpx"
  : > "$stage6_katana"

  local httpx_input="$RUN_DIR/4_ports/naabu_hostports_all.txt"
  local all_http_targets="$stage5_dir/httpx_targets.txt"
  local filtered_http_targets="$stage5_dir/httpx_targets_filtered.txt"
  : > "$all_http_targets"
  : > "$filtered_http_targets"

  if [[ -s "$httpx_input" ]]; then
    sort -u "$httpx_input" > "$all_http_targets"
  elif [[ -s "$stage3_resolved" ]]; then
    warn "No naabu hostname:port candidates — falling back to resolved hostnames."
    cp "$stage3_resolved" "$all_http_targets" 2>/dev/null || true
  elif [[ -s "$stage3_all_resolved" ]]; then
    warn "No naabu candidates and no retained hosts (wildcard filtering) — falling back to the full unfiltered DNS-live host set."
    cp "$stage3_all_resolved" "$all_http_targets" 2>/dev/null || true
  fi
  sort -u "$all_http_targets" -o "$all_http_targets"
  httpx_input="$all_http_targets"

  if [[ ! -s "$httpx_input" ]]; then
    warn "Nothing available to probe — skipping stage 5."
    return
  fi

  # --------------------------------------------------------------------------
  # HTTP wildcard fingerprinting
  # --------------------------------------------------------------------------
  # DNS wildcarding is not enough: a wildcard host can return a perfectly
  # valid HTTP response. Probe a guaranteed-random hostname on every
  # discovered web port and use its response as the per-IP:port baseline. A
  # candidate is removed only when its own response fingerprint matches that
  # baseline for the same underlying IP:port.
  local wildcard_fp="$stage5_dir/http_wildcard_fingerprints.csv"
  local wildcard_targets="$stage5_dir/http_wildcard_targets.txt"
  : > "$wildcard_fp"; : > "$wildcard_targets"
  echo "ip,port,random_host,status,size,content_type,location,body_sha256" > "$wildcard_fp"

  if [[ "$PROBE_WILDCARDS" -eq 1 && -s "$RUN_DIR/3_resolved/wildcard_domain_ip.csv" && -s "$RUN_DIR/4_ports/naabu_ipports.txt" ]]; then
    if have curl && have shasum; then
      info "HTTP wildcard fingerprinting: probing random hostnames on each open port to build catch-all baselines."
      local domain ip port random_host url tmpdir body meta sha status size ctype location
      tmpdir="$stage5_dir/.wildcard_tmp"
      rm -rf "$tmpdir"; mkdir -p "$tmpdir"
      while IFS=, read -r domain ip; do
        [[ -z "$domain" || -z "$ip" ]] && continue
        while IFS=: read -r nip port; do
          [[ "$nip" != "$ip" || -z "$port" ]] && continue
          random_host="__squiz_nonexistent_${RANDOM}${RANDOM}${RANDOM}.${domain}"
          printf '%s:%s\n' "$random_host" "$port" >> "$wildcard_targets"
          body="$tmpdir/body"
          meta="$tmpdir/meta"
          rm -f "$body" "$meta"
          # curl's -k is intentional: a wildcard baseline must work even when
          # the random hostname isn't covered by the certificate.
          url="http://${random_host}:${port}"
          case "$port" in
            443|8443|9443|10443) url="https://${random_host}:${port}" ;;
          esac
          curl -k -sS -L --max-time 12 --connect-timeout 5 \
            -o "$body" -w '%{http_code}\t%{size_download}\t%{content_type}\t%{url_effective}' \
            "$url" > "$meta" 2>/dev/null || true
          if [[ -s "$meta" && -f "$body" ]]; then
            IFS=$'\t' read -r status size ctype location < "$meta"
            sha="$(shasum -a 256 "$body" 2>/dev/null | awk '{print $1}')"
            [[ -z "$sha" ]] && continue
            location="${location//$'\n'/}"
            location="${location//,/;}"
            ctype="${ctype//,/;}"
            printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
              "$ip" "$port" "$random_host" "$status" "$size" "$ctype" "$location" "$sha" >> "$wildcard_fp"
          fi
        done < <(awk -F: -v ip="$ip" '$0 ~ "^" ip ":" {print}' "$RUN_DIR/4_ports/naabu_ipports.txt" | sort -u)
      done < "$RUN_DIR/3_resolved/wildcard_domain_ip.csv"
      rm -rf "$tmpdir"
      sort -u "$wildcard_targets" -o "$wildcard_targets" 2>/dev/null || true
      ok "Built $(( $(count_lines "$wildcard_fp") - 1 )) HTTP wildcard baseline(s)."
      # Do not discard candidates before httpx: the candidate's own response
      # is required to compare against the baseline.
      cp "$all_http_targets" "$filtered_http_targets"
    else
      cp "$all_http_targets" "$filtered_http_targets"
      warn "HTTP wildcard fingerprinting requires curl and shasum — retaining all candidates."
    fi
  else
    cp "$all_http_targets" "$filtered_http_targets"
    if [[ "$PROBE_WILDCARDS" -eq 1 ]]; then
      info "No wildcard DNS/IP + open-port combinations available for HTTP fingerprinting."
    else
      info "Wildcard HTTP probing is off for this run (wildcard hosts were excluded in stage 3)."
    fi
  fi

  httpx_input="$filtered_http_targets"
  info "httpx candidates: $(count_lines "$httpx_input") hostname:port combinations"
  set_active_candidates "$httpx_input" "$all_http_targets"

  # --------------------------------------------------------------------------
  # httpx
  # --------------------------------------------------------------------------
  if tool_ready httpx httpx "Run httpx against $(count_lines "$httpx_input") targets?"; then
    mkdir -p "$stage5_dir/screenshots"
    SPIN_WATCH="$stage6_httpx"
    SPIN_WATCH_LABEL="responses"
    SPIN_TIMEOUT="$HTTPX_TIMEOUT"
    run_spinner "httpx" "$stage5_dir/httpx.log" \
      httpx \
        -l "$httpx_input" \
        -title -sc -ct -cl -location -fr -cdn -asn -td -rt -tls-grab -probe \
        -ss -srd "$stage5_dir/screenshots" -hash sha256 \
        -timeout 10 -retries 1 -stats -silent -o "$stage6_httpx" -json -no-color

    # -probe makes httpx also print a row for every FAILED probe (failed:true).
    # Keep the full set for reference, but only let successful responses
    # through as "live" so katana/gowitness/nuclei don't chew
    # through dead ports (Cloudflare 2052/2082/..., http on 8443, etc.).
    if have jq && [[ -s "$stage6_httpx" ]]; then
      cp "$stage6_httpx" "$stage5_dir/httpx_all_probes.txt"
      if jq -c 'select(.failed != true)' "$stage5_dir/httpx_all_probes.txt" > "$stage5_dir/.httpx_ok.tmp" 2>/dev/null; then
        mv "$stage5_dir/.httpx_ok.tmp" "$stage6_httpx"
        info "httpx: dropped $(( $(count_lines "$stage5_dir/httpx_all_probes.txt") - $(count_lines "$stage6_httpx") )) failed probe(s); $(count_lines "$stage6_httpx") responded."
      else
        rm -f "$stage5_dir/.httpx_ok.tmp"
        warn "Could not filter failed httpx probes (jq error) — keeping all rows."
      fi
    fi

    # Remove responses which exactly match a wildcard baseline for the same
    # IP:port. Intentionally conservative: status + size + content type +
    # body hash must ALL match. Anything different survives.
    local filtered_httpx="$stage5_dir/httpx_filtered.txt"
    : > "$filtered_httpx"
    local suppressed=0
    if [[ "$PROBE_WILDCARDS" -eq 1 && -s "$wildcard_fp" && -s "$stage6_httpx" ]] && have jq; then
      local line url ip status size ctype hash port host
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        url="$(jq -r '.url // empty' <<< "$line")"
        ip="$(jq -r '.host_ip // empty' <<< "$line")"
        status="$(jq -r '.status_code // empty' <<< "$line")"
        size="$(jq -r '.content_length // empty' <<< "$line")"
        ctype="$(jq -r '.content_type // empty' <<< "$line")"
        hash="$(jq -r '(.hash.sha256 // .hash // empty)' <<< "$line")"
        port=""
        host=""
        if [[ "$url" =~ ^https?://([^/:]+)(:([0-9]+))? ]]; then
          host="${BASH_REMATCH[1]}"
          port="${BASH_REMATCH[3]}"
        fi
        [[ -z "$port" ]] && { [[ "$url" =~ ^https:// ]] && port=443 || port=80; }
        if [[ -z "$ip" || -z "$hash" || -z "$status" || -z "$size" ]]; then
          echo "$line" >> "$filtered_httpx"
          continue
        fi
        if awk -F, -v ip="$ip" -v p="$port" -v st="$status" -v sz="$size" -v ct="$ctype" -v h="$hash" \
          'NR>1 && $1==ip && $2==p && $4==st && $5==sz && $6==ct && $8==h {found=1; exit} END{exit !found}' "$wildcard_fp"; then
          suppressed=$((suppressed + 1))
        else
          echo "$line" >> "$filtered_httpx"
        fi
      done < "$stage6_httpx"
      mv "$filtered_httpx" "$stage6_httpx"
      info "HTTP wildcard fingerprinting suppressed $suppressed matching catch-all response(s)"
    fi

    if have jq && [[ -s "$stage6_httpx" ]]; then
      jq -r 'select(.url) | [(.url // ""),(.status_code // ""),(.title // ""),(.content_type // ""),(.content_length // ""),(.host_ip // ""),((.tech // []) | join("|")),(.cdn_name // ""),(.location // "")] | @csv' \
        "$stage6_httpx" > "$stage5_dir/httpx_summary.csv" 2>/dev/null || true
      jq -r 'select(.url != null) | .url' "$stage6_httpx" 2>/dev/null | sort -u > "$stage5_dir/httpx_live_urls.txt" || true
    else
      : > "$stage5_dir/httpx_live_urls.txt"
    fi
    ok "httpx wrote $(count_lines "$stage6_httpx") retained result lines; $(count_lines "$stage5_dir/httpx_live_urls.txt") live URLs"
    set_active_candidates "$stage5_dir/httpx_live_urls.txt"
  else
    : > "$stage5_dir/httpx_live_urls.txt"
    warn "Skipping httpx"
  fi

  # --------------------------------------------------------------------------
  # katana — only URLs that survived httpx + wildcard filtering
  # --------------------------------------------------------------------------
  if tool_ready katana katana "Run katana to crawl live web hosts with -jsl?"; then
    local katana_targets="$stage5_dir/katana_targets.txt"
    : > "$katana_targets"
    if [[ -s "$stage5_dir/httpx_live_urls.txt" ]]; then
      cp "$stage5_dir/httpx_live_urls.txt" "$katana_targets"
    fi
    maybe_edit_file_interactively "$katana_targets" "katana crawl target list"
    if [[ ! -s "$katana_targets" ]]; then
      warn "httpx produced no live URLs — skipping katana."
    else
      SPIN_WATCH="$stage6_katana"
      SPIN_WATCH_LABEL="links"
      SPIN_TIMEOUT="$KATANA_TIMEOUT"
      run_spinner "katana (-jsl)" "$stage5_dir/katana.log" \
        katana -list "$katana_targets" -jsl -timeout 10 -silent -o "$stage6_katana"
      ok "katana extracted $(count_lines "$stage6_katana") links/endpoints"
    fi
  else
    warn "Skipping katana"
  fi

  # --------------------------------------------------------------------------
  # gowitness — screenshot every live URL httpx found. Go binary, drives
  # headless Chrome directly (no Selenium/Playwright overhead), so it's
  # markedly faster than eyewitness/aquatone for large host counts.
  # --------------------------------------------------------------------------
  : > "$stage6_screenshots_jsonl"
  mkdir -p "$stage6_screenshots_dir"
  if [[ "$SKIP_SCREENSHOTS" -eq 1 ]]; then
    info "Screenshots disabled (--no-screenshots)."
  elif tool_ready gowitness gowitness "Screenshot $(count_lines "$stage5_dir/httpx_live_urls.txt") live URLs with gowitness?"; then
    if [[ ! -s "$stage5_dir/httpx_live_urls.txt" ]]; then
      warn "httpx produced no live URLs — skipping screenshots."
    else
      SPIN_WATCH="$stage6_screenshots_jsonl"
      SPIN_WATCH_LABEL="screenshots"
      SPIN_TIMEOUT="$SCREENSHOT_TIMEOUT"
      run_spinner "gowitness" "$stage5_dir/gowitness.log" \
        gowitness scan file \
          -f "$stage5_dir/httpx_live_urls.txt" \
          --threads "$SCREENSHOT_THREADS" \
          --timeout 20 \
          --screenshot-path "$stage6_screenshots_dir" \
          --screenshot-format jpeg \
          --write-jsonl --write-jsonl-file "$stage6_screenshots_jsonl"
      # gowitness's chromedp driver logs every CDP event type it doesn't
      # specifically handle (page.EventFrameSubtreeWillBeDetached,
      # dom.EventScrollableFlagUpdated, ...) straight to stderr as "ERROR:
      # unhandled ... event". These are harmless — they fire on practically
      # every page load and don't affect whether a screenshot gets taken —
      # but they can drown out the handful of actually useful "INFO result"
      # lines in both the live pane and the saved log. Strip them from the
      # saved log after the run so the log (and the report's log viewer)
      # stay readable; nothing about the scan itself is affected.
      if [[ -s "$stage5_dir/gowitness.log" ]]; then
        grep -Ev '^[0-9/: ]+ERROR: unhandled (page|node) event ' \
          "$stage5_dir/gowitness.log" > "$stage5_dir/gowitness.log.tmp" 2>/dev/null &&
          mv "$stage5_dir/gowitness.log.tmp" "$stage5_dir/gowitness.log"
      fi
      ok "gowitness captured $(count_lines "$stage6_screenshots_jsonl") screenshot(s) -> $stage6_screenshots_dir"
    fi
  else
    warn "Skipping screenshots"
  fi
}
# ───────────────────────────── Stage 6 ───────────────────────────────────────
stage7_md=""
run_stage6() {
  section "STAGE 6 — Vulnerability scanning (nuclei)"
  stage_skip_reset
  local stage6_dir="$RUN_DIR/6_nuclei"
  mkdir -p "$stage6_dir"
  stage7_md="$stage6_dir/nuclei_findings.md"
  local nuclei_raw="$stage6_dir/nuclei_raw.txt"
  local input_file=""
  # Prefer live HTTP URLs from httpx.
  if have jq && [[ -s "$stage6_httpx" ]]; then
    input_file="$stage6_dir/nuclei_targets.txt"
    jq -r 'select(.url != null) | .url' "$stage6_httpx" 2>/dev/null | sort -u > "$input_file"
  fi
  # Fallbacks, in descending order of confidence. The last two exist because
  # wildcard filtering can empty the conservative lists entirely (see stage
  # 4's "0 candidates" fallback) — a scan with no targets is worse than a
  # scan against the unfiltered set.
  if [[ -z "$input_file" || ! -s "$input_file" ]]; then
    [[ -s "$stage5_hostports" ]] && input_file="$stage5_hostports"
  fi
  if [[ -z "$input_file" || ! -s "$input_file" ]]; then
    [[ -s "$RUN_DIR/4_ports/naabu_hostports_all.txt" ]] && input_file="$RUN_DIR/4_ports/naabu_hostports_all.txt"
  fi
  if [[ -z "$input_file" || ! -s "$input_file" ]]; then
    [[ -s "$stage3_resolved" ]] && input_file="$stage3_resolved"
  fi
  if [[ -z "$input_file" || ! -s "$input_file" ]]; then
    [[ -s "$stage3_all_resolved" ]] && input_file="$stage3_all_resolved"
  fi
  if [[ -z "$input_file" || ! -s "$input_file" ]]; then
    warn "No targets available for nuclei — skipping stage 6."
    return
  fi
  if ! have nuclei; then
    warn "nuclei not installed — skipping stage 6."
    return
  fi
  set_active_candidates "$input_file"
  maybe_edit_file_interactively "$input_file" "nuclei target list"
  if ! module_confirm nuclei "Run nuclei against $(count_lines "$input_file") targets?"; then
    warn "Skipping nuclei"
    return
  fi

  # Hang mitigation + visibility for the stage that hangs most:
  #   -stats -si 30   nuclei prints its own progress (templates/hosts/req),
  #                   which the heartbeat surfaces every 30s
  #   -timeout/-retries/-mhe  bound per-request and per-host misbehaviour
  #   -rl             rate limit, so a slow target can't wedge the scan
  #   SPIN_TIMEOUT    hard ceiling (NUCLEI_TIMEOUT, default 90m)
  #   SPIN_WATCH      findings counter, so "no findings yet" is visible
  info "nuclei: s = cancel the scan and keep whatever it has written so far; S = that plus skip the rest of the stage."
  SPIN_WATCH="$nuclei_raw"
  SPIN_WATCH_LABEL="findings"
  SPIN_TIMEOUT="$NUCLEI_TIMEOUT"
  run_spinner "nuclei (all templates)" "$stage6_dir/nuclei.log" \
    nuclei \
      -l "$input_file" \
      -no-interactsh \
      -stats -si 30 \
      -timeout 10 -retries 1 -mhe 10 -rl "$NUCLEI_RATE" \
      -silent \
      -markdown-export "$stage6_dir/md" \
      -jsonl-export "$stage6_dir/nuclei.jsonl" \
      -o "$nuclei_raw"

  # Combine markdown findings (partial output from a cancelled/timed-out run
  # is still worth keeping).
  if [[ -d "$stage6_dir/md" ]]; then
    {
      echo "# Nuclei Findings"
      echo
      local f
      for f in "$stage6_dir"/md/*.md; do
        [[ -e "$f" ]] || continue
        cat "$f"
        echo
        echo "---"
        echo
      done
    } > "$stage7_md"
  else
    cp "$nuclei_raw" "$stage7_md" 2>/dev/null || true
  fi
  ok "nuclei stage complete — $(count_lines "$nuclei_raw") finding line(s)"
}
# A deliberately small heuristic list of common two-label public-suffix TLDs
# (co.uk, com.au, ...) — not a full public suffix list, just enough so
# base_domain_of() doesn't truncate e.g. "foo.co.uk" down to "co.uk".
_TWO_LABEL_TLDS=" co.uk org.uk gov.uk ac.uk me.uk net.uk ltd.uk plc.uk sch.uk nhs.uk police.uk \
co.nz net.nz org.nz govt.nz ac.nz \
co.za org.za gov.za net.za \
co.jp ne.jp or.jp ac.jp go.jp \
co.kr or.kr ne.kr \
co.in net.in org.in gov.in ac.in \
co.id or.id go.id ac.id \
co.th or.th in.th ac.th go.th \
com.au net.au org.au edu.au gov.au asn.au id.au \
com.br net.br org.br gov.br \
com.mx gob.mx org.mx \
com.sg net.sg org.sg edu.sg gov.sg \
com.hk org.hk gov.hk edu.hk net.hk \
com.tw org.tw gov.tw edu.tw net.tw \
com.cn net.cn org.cn gov.cn edu.cn \
co.il org.il net.il gov.il ac.il \
com.tr org.tr gov.tr edu.tr net.tr \
com.ar gob.ar org.ar net.ar \
com.ua co.ve co.ke co.tz com.ng com.pk com.eg "
# Collapses a hostname down to its registrable base domain, e.g.
# "blog.dev.foo.example.com" -> "example.com", "foo.co.uk" -> "foo.co.uk".
# Used so waymore (see below) is queried once per unique apex domain instead
# of once per resolved subdomain.
base_domain_of() {
local host; host="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
local -a labels
  IFS='.' read -r -a labels <<< "$host"
local n=${#labels[@]}
if (( n <= 2 )); then printf '%s\n' "$host"; return; fi
local last2="${labels[$((n-2))]}.${labels[$((n-1))]}"
if [[ " $_TWO_LABEL_TLDS " == *" $last2 "* ]]; then
if (( n <= 3 )); then printf '%s\n' "$host"; return; fi
    printf '%s\n' "${labels[$((n-3))]}.${labels[$((n-2))]}.${labels[$((n-1))]}"
else
    printf '%s\n' "$last2"
fi
}
# ───────────────────────────── Stage 7 ───────────────────────────────────────
#
# Archive is intentionally late in the pipeline so these (slow, provider
# rate-limited) tools don't delay the network/HTTP work.
stage8_archive_dir=""
run_stage7() {
  section "STAGE 7 — Archived/historical URL discovery"
  stage_skip_reset
  stage8_archive_dir="$RUN_DIR/7_archive"
  local stage5_dir="$RUN_DIR/5_http"
  mkdir -p "$stage8_archive_dir"

  # stage5_dir is local to run_stage5, so re-derive it here (also needed
  # when stage 5 was completed by a previous invocation and we are resuming).
  local stage5_dir="$RUN_DIR/5_http"

  # The real cause of "waymore/gau hangs for hours" is usually volume: one
  # slow provider request per host, times hundreds of hosts. Cap the host
  # list (0 = no cap) and let it be edited before anything runs.
  local archive_hosts="$stage8_archive_dir/archive_hosts.txt"
  : > "$archive_hosts"
  # Same starvation trap as naabu's "0 candidates": when every hostname looks
  # like a wildcard, stage3_resolved is empty even though there are plenty of
  # DNS-live hosts (and, after stage 5, confirmed live HTTP ones). Fall back
  # rather than skipping the stage.
  if [[ -s "$stage3_resolved" ]]; then
    sort -u "$stage3_resolved" > "$archive_hosts"
  elif [[ -s "$RUN_DIR/5_http/httpx_live_urls.txt" ]]; then
    warn "Stage 3's retained host list is empty (wildcard filtering) — using the hosts httpx confirmed live instead."
    sed -E 's#^[a-zA-Z]+://##; s#[:/].*$##' "$RUN_DIR/5_http/httpx_live_urls.txt" | awk 'NF' | sort -u > "$archive_hosts"
  elif [[ -s "$stage3_all_resolved" ]]; then
    warn "Stage 3's retained host list is empty (wildcard filtering) — using the full unfiltered DNS-live host set instead."
    sort -u "$stage3_all_resolved" > "$archive_hosts"
  fi
  if [[ ! -s "$archive_hosts" ]]; then
    warn "No hosts available from earlier stages — skipping archive stage."
    return
  fi
  local available cap
  available="$(count_lines "$archive_hosts")"
  cap="$(ask "Archive stage: how many of the $available resolved hosts should waymore/gau process? (0 = all)" "$ARCHIVE_MAX_HOSTS")"
  [[ "$cap" =~ ^[0-9]+$ ]] || cap="$ARCHIVE_MAX_HOSTS"
  if [[ "$cap" -gt 0 && "$available" -gt "$cap" ]]; then
    head -n "$cap" "$archive_hosts" > "${archive_hosts}.capped"
    mv "${archive_hosts}.capped" "$archive_hosts"
    warn "Archive host list capped to $cap of $available hosts (raise it with --archive-max-hosts, or 0 for all)."
  fi
  set_active_candidates "$archive_hosts" "$stage3_resolved"
  maybe_edit_file_interactively "$archive_hosts" "archive host list"
  local total_h
  total_h="$(count_lines "$archive_hosts")"
  info "Archive stage will process $total_h host(s). Per-host limits: waymore $(fmt_dur "$WAYMORE_TIMEOUT"), gau $(fmt_dur "$GAU_TIMEOUT"); s = skip the current host, S = skip the rest of the stage."

  local host idx rc=0

  # ── waymore ───────────────────────────────────────────────────────────────
  # waymore's own docs call out passing a file of subdomains as "a common
  # mistake" — a bare apex domain (no -n/--no-subs) already pulls archived
  # URLs for every subdomain the Wayback/CDX-style providers know about in
  # ONE query, so looping it per resolved subdomain just repeats the same
  # work $n times and hammers the providers. Run it once per target domain
  # instead (the apex domains the run was actually pointed at, i.e. $DOMAINS
  # — not every individual resolved subdomain host).
  if tool_ready waymore waymore "Run waymore to pull archived URLs?"; then
    local wm_out="$stage8_archive_dir/waymore_urls.txt"
    : > "$wm_out"
    if [[ "${#DOMAINS[@]}" -eq 0 ]]; then
      warn "No target domains available (IP/CIDR-only run) — skipping waymore."
    else
      # Collapse $DOMAINS down to unique base/apex domains before looping —
      # if the run was pointed at subdomains directly (e.g. a host list from
      # an earlier recon pass: blog.foo.com, dev.foo.com, docs.foo.com, ...)
      # this still queries waymore once per apex (foo.com), not once per
      # subdomain, which is both faster and what waymore's own docs
      # recommend (see comment above).
      local -a waymore_base_domains=()
      local _wd _bd
      {
        for _wd in "${DOMAINS[@]}"; do
          [[ -z "$_wd" ]] && continue
          base_domain_of "$_wd"
        done
      } | sort -u > "$stage8_archive_dir/waymore_base_domains.txt"
      while IFS= read -r _bd; do
        [[ -z "$_bd" ]] && continue
        waymore_base_domains+=("$_bd")
      done < "$stage8_archive_dir/waymore_base_domains.txt"
      if [[ "${#waymore_base_domains[@]}" -lt "${#DOMAINS[@]}" ]]; then
        info "Collapsed ${#DOMAINS[@]} target domain(s) down to ${#waymore_base_domains[@]} unique base domain(s) for waymore."
      fi
      local total_d="${#waymore_base_domains[@]}"
      idx=0
      for host in "${waymore_base_domains[@]}"; do
        [[ -z "$host" ]] && continue
        idx=$((idx + 1))
        local -a waymore_args=(
          -i "$host"
          -mode U
          -oU "$stage8_archive_dir/waymore_${host}.txt"
        )
        if [[ -n "$WAYMORE_CONFIG" ]]; then
          waymore_args=(-c "$WAYMORE_CONFIG" "${waymore_args[@]}")
        fi
        SPIN_PROGRESS="domain $idx/$total_d: $host"
        SPIN_WATCH="$stage8_archive_dir/waymore_${host}.txt"
        SPIN_WATCH_LABEL="urls"
        SPIN_TIMEOUT="$WAYMORE_TIMEOUT"
        SPIN_STALL_KILL="$WAYMORE_TIMEOUT"
        run_spinner "waymore" "$stage8_archive_dir/waymore_${host}.log" \
          waymore "${waymore_args[@]}"
        rc=$?
        cat "$stage8_archive_dir/waymore_${host}.txt" 2>/dev/null >> "$wm_out" || true
        [[ "$rc" -eq 131 ]] && break
      done
    fi
    sort -u "$wm_out" -o "$wm_out"
    ok "waymore total archived URLs: $(count_lines "$wm_out")"
  else
    warn "Skipping waymore"
    : > "$stage8_archive_dir/waymore_urls.txt"
  fi

  # ── gau ───────────────────────────────────────────────────────────────────
  if tool_ready gau gau "Run gau to collect historical URLs?"; then
    local gau_out="$stage8_archive_dir/gau_urls.txt"
    : > "$gau_out"
    idx=0
    while read -r host; do
      [[ -z "$host" ]] && continue
      idx=$((idx + 1))
      SPIN_PROGRESS="host $idx/$total_h: $host"
      SPIN_WATCH="$stage8_archive_dir/gau_${host}.txt"
      SPIN_WATCH_LABEL="urls"
      SPIN_TIMEOUT="$GAU_TIMEOUT"
      SPIN_STALL_KILL="$GAU_TIMEOUT"
      run_spinner "gau" "$stage8_archive_dir/gau_${host}.log" \
        gau \
          --subs \
          --threads 5 \
          --blacklist png,jpg,jpeg,gif,svg,woff,ttf,ico \
          --o "$stage8_archive_dir/gau_${host}.txt" \
          "$host"
      rc=$?
      cat "$stage8_archive_dir/gau_${host}.txt" 2>/dev/null >> "$gau_out" || true
      [[ "$rc" -eq 131 ]] && break
    done < "$archive_hosts"
    sort -u "$gau_out" -o "$gau_out"
    ok "gau total historical URLs: $(count_lines "$gau_out")"
  else
    warn "Skipping gau"
    : > "$stage8_archive_dir/gau_urls.txt"
  fi

  # ── unified URL corpus ────────────────────────────────────────────────────
  cat \
    "$stage8_archive_dir/waymore_urls.txt" \
    "$stage8_archive_dir/gau_urls.txt" \
    2>/dev/null |
    sed '/^[[:space:]]*$/d' |
    sort -u > "$stage8_archive_dir/all_urls.txt" || true
  if [[ -s "$stage8_archive_dir/all_urls.txt" ]]; then
    grep -Eai '\.(js)(\?|$)' "$stage8_archive_dir/all_urls.txt" | sort -u > "$stage8_archive_dir/javascript_urls.txt" || true
    grep -Eai '(admin|login|signin|auth|oauth|sso|api|graphql|swagger|openapi|actuator|debug|internal|upload|download|redirect|callback|token|key|secret)' \
      "$stage8_archive_dir/all_urls.txt" | sort -u > "$stage8_archive_dir/interesting_urls.txt" || true
    grep -Eai '\?[^ ]*=' "$stage8_archive_dir/all_urls.txt" | sort -u > "$stage8_archive_dir/parameterized_urls.txt" || true
  else
    : > "$stage8_archive_dir/javascript_urls.txt"
    : > "$stage8_archive_dir/interesting_urls.txt"
    : > "$stage8_archive_dir/parameterized_urls.txt"
  fi
  {
    echo "url"
    awk 'NF{ gsub(/"/, "\"\"", $0); print "\"" $0 "\"" }' "$stage8_archive_dir/all_urls.txt"
  } > "$stage8_archive_dir/all_urls.csv"
  ok "Unified URL corpus: $(count_lines "$stage8_archive_dir/all_urls.txt") URLs"
}
# ───────────────────────────── HTML report ───────────────────────────────────
html_escape() {
  sed \
    -e 's/&/&amp;/g' \
    -e 's/</&lt;/g' \
    -e 's/>/&gt;/g'
}
build_table_rows() {
local file="$1"
local max="${2:-500}"
if [[ ! -s "$file" ]]; then
    echo "<tr><td colspan=99><em>no data</em></td></tr>"
return
fi
  head -n "$max" "$file" |
while read -r line; do
      echo "<tr><td>$(echo "$line" | html_escape)</td></tr>"
done
}
build_timing_rows() {
  local f="$RUN_DIR/.stage_times"
  if [[ ! -s "$f" ]]; then
    echo "<tr><td colspan=3><em>no stage timings recorded</em></td></tr>"
    return
  fi
  local n name secs
  while IFS='|' read -r n name secs; do
    [[ -z "$n" ]] && continue
    printf '<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
      "$(echo "$n" | html_escape)" \
      "$(echo "$name" | html_escape)" \
      "$(fmt_dur "$secs")"
  done < "$f"
}
# Builds <tr> rows for the gowitness screenshot gallery. img src is relative
# to $RUN_DIR (where report.html lives), e.g. 5_http/screenshots/foo.jpeg,
# so the report stays portable if the whole $RUN_DIR is copied/zipped together.
build_screenshot_rows() {
  local jsonl="$1"
  local shots_dir="$2"
  if [[ ! -s "$jsonl" ]] || ! have jq; then
    echo "<tr><td colspan=4><em>no screenshot metadata / jq missing</em></td></tr>"
    return
  fi

  local shots_rel="screenshots"
  local row_count=0
  # Gowitness versions differ in the JSONL key used for the image path. Resolve
  # all known variants, then fall back to a filename match against the URL host.
  while IFS= read -r json_line || [[ -n "$json_line" ]]; do
    [[ -n "$json_line" ]] || continue
    local s_url s_code s_title s_file fname img_cell host host_key candidate candidate_key
    s_url="$(printf '%s\n' "$json_line" | jq -r '.url // .target // "-"' 2>/dev/null)"
    s_code="$(printf '%s\n' "$json_line" | jq -r '(.response_code // .status_code // .status // "-") | tostring' 2>/dev/null)"
    s_title="$(printf '%s\n' "$json_line" | jq -r '.title // .page_title // "-"' 2>/dev/null)"
    s_file="$(printf '%s\n' "$json_line" | jq -r '.filename // .screenshot_file // .screenshot_path // .screenshotPath // .screenshot // .path // .file // .file_path // .image // empty' 2>/dev/null)"
    fname=""
    if [[ -n "$s_file" ]]; then
      fname="$(basename "$s_file" 2>/dev/null)"
      [[ -f "$shots_dir/$fname" ]] || fname=""
    fi

    # Some gowitness releases omit the screenshot path from JSONL entirely.
    # Match the host against saved image names (gowitness commonly sanitises
    # URL punctuation in filenames); this keeps the metadata row useful.
    if [[ -z "$fname" && "$s_url" != "-" ]]; then
      host="$(printf '%s' "$s_url" | sed -E 's#^[A-Za-z]+://##; s#[/?#].*$##; s#:[0-9]+$##' | tr '[:upper:]' '[:lower:]')"
      host_key="$(printf '%s' "$host" | sed -E 's/[^A-Za-z0-9]+/_/g')"
      while IFS= read -r candidate; do
        [[ -f "$candidate" ]] || continue
        candidate_key="$(basename "$candidate" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/_/g')"
        if [[ -n "$host_key" && "$candidate_key" == *"$host_key"* ]]; then
          fname="$(basename "$candidate")"
          break
        fi
      done < <(find "$shots_dir" -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.webp' \) 2>/dev/null)
    fi

    if [[ -n "$fname" && -f "$shots_dir/$fname" ]]; then
      img_cell="<a href=\"5_http/${shots_rel}/$(echo "$fname" | html_escape)\" target=\"_blank\"><img class=\"shot-thumb\" loading=\"lazy\" src=\"5_http/${shots_rel}/$(echo "$fname" | html_escape)\" alt=\"Screenshot of $(echo "$s_url" | html_escape)\"></a>"
    else
      img_cell="<em>capture saved, image path not matched</em>"
    fi
    printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
      "$img_cell" \
      "$(echo "$s_url" | html_escape)" \
      "$(echo "$s_code" | html_escape)" \
      "$(echo "$s_title" | html_escape)"
    row_count=$((row_count + 1))
  done < "$jsonl"

  if [[ "$row_count" -eq 0 ]]; then
    echo "<tr><td colspan=4><em>no valid screenshot metadata rows</em></td></tr>"
  fi
}
# Builds collapsible <pre> log viewers for every file matching a glob
# pattern (e.g. "$RUN_DIR/5_http/httpx*.log"). Each gets its own toggle
# button; logs are embedded inline (tail -n 400) so the report stays a
# single, offline-readable file. $1 = glob pattern, $2 = unique id prefix.
build_log_panels() {
local pattern="$1"
local prefix="$2"
local f base safe_id total body note idx=0 any=0
local out=""
  shopt -s nullglob
local -a files=( $pattern )
  shopt -u nullglob
for f in "${files[@]}"; do
    [[ -f "$f" ]] || continue
    any=1
    idx=$((idx+1))
    base="$(basename "$f")"
    safe_id="${prefix}-${idx}-$(echo "$base" | tr -c 'A-Za-z0-9' '-')"
    total="$(wc -l < "$f" 2>/dev/null | tr -d ' ')"
    note=""
    [[ "${total:-0}" -gt 400 ]] && note="[showing last 400 of ${total} lines]
"
    body="$(tail -n 400 "$f" 2>/dev/null | html_escape)"
    out+="<div class=\"logblock\">
<button type=\"button\" class=\"win95-btn logtoggle\" onclick=\"toggleLog('${safe_id}')\">&#128196; ${base}</button>
<pre id=\"${safe_id}\" class=\"logpre\" style=\"display:none\">${note}${body}</pre>
</div>
"
done
if [[ "$any" -eq 0 ]]; then
    echo "<p class=\"dim\"><em>No log files captured for this stage.</em></p>"
else
    echo "$out"
fi
}
run_report() {
  section "STAGE 8 — Building HTML summary report"
  stage_skip_reset
local report="$RUN_DIR/report.html"
local d6="$RUN_DIR/6_nuclei"
local d7="$RUN_DIR/7_archive"
local n_sub n_perm n_resolved n_ports n_httpx n_katana n_nuclei n_archive n_gau n_urls n_screenshots
  n_sub="$(count_lines "$stage1_combined")"
  n_perm="$(count_lines "$stage2_combined")"
  n_resolved="$(count_lines "$stage3_resolved")"
  n_ports="$(count_lines "$stage5_hostports")"
  n_httpx="$(count_lines "$stage6_httpx")"
  n_katana="$(count_lines "$stage6_katana")"
  n_screenshots="$(count_lines "$stage6_screenshots_jsonl")"
  n_archive="$(count_lines "$d7/waymore_urls.txt")"
  n_gau="$(count_lines "$d7/gau_urls.txt")"
  n_urls="$(count_lines "$d7/all_urls.txt")"
  n_nuclei="$(count_lines "$d6/nuclei_raw.txt")"
local total_dur
  total_dur="$(fmt_dur $(( $(date +%s) - RUN_START_TS )))"
local httpx_rows=""
local nuclei_block=""
if [[ -s "$stage6_httpx" ]] && have jq; then
    httpx_rows="$(
      jq -r '
        select(.url)
        |
        [
          (.url),
          (.status_code // "-" | tostring),
          (.title // "-"),
          (.content_type // "-"),
          (.content_length // "-" | tostring),
          (.cdn_name // "-"),
          (.location // "-")
        ]
        | @tsv
      ' "$stage6_httpx" 2>/dev/null |
while IFS=$'\t' read -r f_url f_sc f_title f_ct f_cl f_cdn f_loc; do
        printf \
          '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
          "$(echo "$f_url" | html_escape)" \
          "$(echo "$f_sc" | html_escape)" \
          "$(echo "$f_title" | html_escape)" \
          "$(echo "$f_ct" | html_escape)" \
          "$(echo "$f_cl" | html_escape)" \
          "$(echo "$f_cdn" | html_escape)" \
          "$(echo "$f_loc" | html_escape)"
done
    )"
fi
if [[ -s "$stage7_md" ]]; then
    nuclei_block="<pre class='box'>$(cat "$stage7_md" | html_escape)</pre>"
else
    nuclei_block="<p><em>No nuclei findings / stage skipped.</em></p>"
fi
  cat > "$report" <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>♡ Recon Report — ${TS}</title>
<style>
:root{
  --desktop:#190c29;
  --face:#dcb3e8;
  --face-hi:#f8e8ff;
  --face-lo:#7a4a8a;
  --face-lo2:#4a1f5c;
  --win-bg:#f3e3fa;
  --win-bg2:#e9cdf2;
  --titlebar1:#8a1f7a;
  --titlebar2:#36123f;
  --text:#2a0f36;
  --dim:#6a4476;
  --acc:#ff57b0;
  --acc2:#9b3fd1;
  --link:#7a1d9e;
  --good:#1f7a4a;
  --warn:#8a5a00;
  --bad:#a3144f;
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0;
  background:
    repeating-linear-gradient(135deg,#140825 0 2px,#190c29 2px 4px);
  color:var(--text);
  font-family:Tahoma,"MS Sans Serif",Geneva,sans-serif;
  font-size:12px;
}
.desktop{min-height:100vh;display:flex;flex-direction:column}
/* top app titlebar */
.titlebar{
  background:linear-gradient(90deg,var(--titlebar1),var(--titlebar2) 85%);
  color:#ffe3f6;
  padding:5px 8px;
  display:flex;align-items:center;justify-content:space-between;
  font-weight:bold;letter-spacing:.3px;
  border-bottom:2px solid #230a2c;
  text-shadow:1px 1px 0 #2a0a33;
}
.titlebar-btns{display:flex;gap:4px}
.tb-btn{
  width:18px;height:16px;line-height:14px;text-align:center;
  background:var(--face);color:var(--text);font-weight:bold;font-size:11px;
  border-top:1px solid var(--face-hi);border-left:1px solid var(--face-hi);
  border-right:1px solid var(--face-lo2);border-bottom:1px solid var(--face-lo2);
  cursor:default;
}
.tb-close{color:#5c0022}
.shell{flex:1;display:flex;min-height:0}
/* sidebar */
.sidebar{
  width:208px;flex:0 0 208px;
  background:var(--face);
  border-right:2px solid var(--face-lo2);
  padding:8px;
  overflow-y:auto;
}
.sidebar-head{
  background:linear-gradient(90deg,var(--titlebar1),var(--titlebar2) 85%);
  color:#ffe3f6;font-weight:bold;padding:4px 6px;margin-bottom:8px;
  border:1px solid var(--face-lo2);
}
.navbtn{
  display:block;width:100%;text-align:left;
  background:var(--face);color:var(--text);
  font-family:inherit;font-size:12px;
  padding:6px 8px;margin-bottom:4px;cursor:pointer;
  border-top:1px solid var(--face-hi);border-left:1px solid var(--face-hi);
  border-right:1px solid var(--face-lo2);border-bottom:1px solid var(--face-lo2);
}
.navbtn:hover{background:var(--win-bg2)}
.navbtn.active{
  background:var(--win-bg2);
  border-color:var(--face-lo2) var(--face-hi) var(--face-hi) var(--face-lo2);
  font-weight:bold;
  color:var(--acc2);
}
/* main content */
.content{flex:1;min-width:0;overflow-y:auto;padding:16px}
.panel{display:none}
.window{
  background:var(--win-bg);
  border-top:2px solid var(--face-hi);border-left:2px solid var(--face-hi);
  border-right:2px solid var(--face-lo2);border-bottom:2px solid var(--face-lo2);
  margin-bottom:16px;
}
.window-title{
  background:linear-gradient(90deg,var(--titlebar1),var(--titlebar2) 85%);
  color:#ffe3f6;font-weight:bold;padding:5px 8px;
  display:flex;justify-content:space-between;align-items:center;
  text-shadow:1px 1px 0 #2a0a33;
}
.window-title .tb-btn{transform:scale(.9)}
.window-body{padding:12px}
h2{font-size:14px;margin:0 0 10px;color:var(--text)}
p.dim{color:var(--dim)}
code{color:var(--acc2);background:var(--win-bg2);padding:0 3px}
/* stat tiles (overview) */
.stats{display:flex;flex-wrap:wrap;gap:10px}
.stat{
  background:var(--face);min-width:118px;padding:10px 12px;
  border-top:1px solid var(--face-hi);border-left:1px solid var(--face-hi);
  border-right:1px solid var(--face-lo2);border-bottom:1px solid var(--face-lo2);
}
.stat b{display:block;font-size:19px;color:var(--acc2)}
.stat span{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
/* tables -> classic inset listbox */
.scroll{
  max-height:440px;overflow:auto;background:#fff;
  border-top:1px solid var(--face-lo2);border-left:1px solid var(--face-lo2);
  border-right:1px solid var(--face-hi);border-bottom:1px solid var(--face-hi);
}
table{width:100%;border-collapse:collapse;font-size:12px;background:#fff}
th{
  background:var(--win-bg2);text-align:left;padding:6px 8px;
  color:var(--text);font-weight:bold;border-bottom:1px solid var(--face-lo2);
  position:sticky;top:0;
}
td{padding:5px 8px;border-top:1px solid #eadcf0;word-break:break-all}
tr:nth-child(even) td{background:#faf2fc}
tr:hover td{background:#f0d8f7}
.shot-thumb{display:block;max-width:200px;max-height:130px;object-fit:cover;
  border-top:1px solid var(--face-lo2);border-left:1px solid var(--face-lo2);
  border-right:1px solid var(--face-hi);border-bottom:1px solid var(--face-hi);}
.box{
  white-space:pre-wrap;background:#fff;font-size:12px;padding:12px;max-height:480px;overflow:auto;
  border-top:1px solid var(--face-lo2);border-left:1px solid var(--face-lo2);
  border-right:1px solid var(--face-hi);border-bottom:1px solid var(--face-hi);
}
/* win95 buttons + log viewer */
.win95-btn{
  font-family:inherit;font-size:12px;background:var(--face);color:var(--text);
  padding:5px 10px;cursor:pointer;margin:2px 4px 2px 0;
  border-top:1px solid var(--face-hi);border-left:1px solid var(--face-hi);
  border-right:1px solid var(--face-lo2);border-bottom:1px solid var(--face-lo2);
}
.win95-btn:active{
  border-color:var(--face-lo2) var(--face-hi) var(--face-hi) var(--face-lo2);
}
.logs-wrap{margin-top:14px;border-top:1px dashed var(--face-lo);padding-top:10px}
.logs-head{font-weight:bold;color:var(--dim);margin-bottom:6px;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
.logpre{
  margin-top:6px;background:#1c0e26;color:#f3cdee;font-family:"Consolas","Courier New",monospace;
  font-size:11px;white-space:pre-wrap;padding:10px;max-height:360px;overflow:auto;
  border-top:1px solid var(--face-lo2);border-left:1px solid var(--face-lo2);
  border-right:1px solid var(--face-hi);border-bottom:1px solid var(--face-hi);
}
/* taskbar */
.taskbar{
  background:linear-gradient(90deg,var(--titlebar1),var(--titlebar2) 85%);
  color:#ffe3f6;padding:5px 10px;display:flex;justify-content:space-between;align-items:center;
  border-top:2px solid #c879e0;font-size:11px;
}
.start{font-weight:bold;background:var(--face);color:var(--text);padding:3px 10px;
  border-top:1px solid var(--face-hi);border-left:1px solid var(--face-hi);
  border-right:1px solid var(--face-lo2);border-bottom:1px solid var(--face-lo2);}
::-webkit-scrollbar{width:16px;height:16px}
::-webkit-scrollbar-track{background:var(--face)}
::-webkit-scrollbar-thumb{background:var(--win-bg2);border:1px solid var(--face-lo2)}
</style>
</head>
<body>
<div class="desktop">
<div class="titlebar">
<span>&#9825; recon-report.exe — ${TS}</span>
<span class="titlebar-btns"><span class="tb-btn">_</span><span class="tb-btn">&#9633;</span><span class="tb-btn tb-close">&times;</span></span>
</div>
<div class="shell">
<nav class="sidebar">
<div class="sidebar-head">Recon Stages</div>
<button id="nav-overview" class="navbtn active" onclick="showPanel('overview')">&#128421; Overview</button>
<button id="nav-discovery" class="navbtn" onclick="showPanel('discovery')">&#128269; Stage 1–2 · Discovery</button>
<button id="nav-resolved" class="navbtn" onclick="showPanel('resolved')">&#128246; Stage 3 · Resolved</button>
<button id="nav-ports" class="navbtn" onclick="showPanel('ports')">&#128268; Stage 4 · Ports</button>
<button id="nav-http" class="navbtn" onclick="showPanel('http')">&#127760; Stage 5 · HTTP</button>
<button id="nav-screenshots" class="navbtn" onclick="showPanel('screenshots')">&#128444; Stage 5 · Screenshots</button>
<button id="nav-crawled" class="navbtn" onclick="showPanel('crawled')">&#128375; Stage 5 · Crawled</button>
<button id="nav-nuclei" class="navbtn" onclick="showPanel('nuclei')">&#9762; Stage 6 · Nuclei</button>
<button id="nav-archive" class="navbtn" onclick="showPanel('archive')">&#128451; Stage 7 · Archive</button>
<button id="nav-timings" class="navbtn" onclick="showPanel('timings')">&#9201; Timings</button>
</nav>
<main class="content">

<section id="panel-overview" class="panel" style="display:block">
<div class="window">
<div class="window-title"><span>Overview.exe</span><span class="tb-btn">&times;</span></div>
<div class="window-body">
<p>
Run: <code>${TS}</code>
&nbsp;|&nbsp; Wall clock: <code>${total_dur}</code><br>
Targets: <code>$(printf '%s ' "${DOMAINS[@]:-}" "${CIDRS[@]:-}" "${RAW_IPS[@]:-}" | html_escape)</code>
</p>
<div class="stats">
<div class="stat"><b>${n_sub}</b><span>Subdomains</span></div>
<div class="stat"><b>${n_perm}</b><span>Permutations</span></div>
<div class="stat"><b>${n_resolved}</b><span>Resolved live</span></div>
<div class="stat"><b>${n_ports}</b><span>Open host:ports</span></div>
<div class="stat"><b>${n_httpx}</b><span>HTTP responses</span></div>
<div class="stat"><b>${n_screenshots}</b><span>Screenshots</span></div>
<div class="stat"><b>${n_katana}</b><span>Crawled links</span></div>
<div class="stat"><b>${n_nuclei}</b><span>Nuclei findings</span></div>
<div class="stat"><b>${n_archive}</b><span>Waymore URLs</span></div>
<div class="stat"><b>${n_gau}</b><span>gau URLs</span></div>
<div class="stat"><b>${n_urls}</b><span>Unique URLs</span></div>
</div>
</div>
</div>
</section>

<section id="panel-discovery" class="panel">
<div class="window">
<div class="window-title"><span>Discovery.exe</span><span class="tb-btn">&times;</span></div>
<div class="window-body">
<h2>Stage 1–2 · Discovered / Permuted Hosts</h2>
<div class="scroll">
<table><tbody>
$(build_table_rows "$stage1_combined" 300)
</tbody></table>
</div>
<div class="logs-wrap">
<div class="logs-head">Logs</div>
$(build_log_panels "$RUN_DIR/1_discovery/*.log" "log-disc1")
$(build_log_panels "$RUN_DIR/2_permutations/*.log" "log-disc2")
</div>
</div>
</div>
</section>

<section id="panel-resolved" class="panel">
<div class="window">
<div class="window-title"><span>Resolved.exe</span><span class="tb-btn">&times;</span></div>
<div class="window-body">
<h2>Stage 3 · Resolved Live Hosts</h2>
<div class="scroll">
<table><thead><tr><th>host</th></tr></thead><tbody>
$(build_table_rows "$stage3_resolved" 500)
</tbody></table>
</div>
<div class="logs-wrap">
<div class="logs-head">Logs</div>
$(build_log_panels "$RUN_DIR/3_resolved/*.log" "log-resolved")
</div>
</div>
</div>
</section>

<section id="panel-ports" class="panel">
<div class="window">
<div class="window-title"><span>Ports.exe</span><span class="tb-btn">&times;</span></div>
<div class="window-body">
<h2>Stage 4 · Open Host:Ports (naabu)</h2>
<div class="scroll">
<table><thead><tr><th>host:port</th></tr></thead><tbody>
$(build_table_rows "$stage5_hostports" 500)
</tbody></table>
</div>
<div class="logs-wrap">
<div class="logs-head">Logs</div>
$(build_log_panels "$RUN_DIR/4_ports/*.log" "log-ports")
</div>
</div>
</div>
</section>

<section id="panel-http" class="panel">
<div class="window">
<div class="window-title"><span>Http.exe</span><span class="tb-btn">&times;</span></div>
<div class="window-body">
<h2>Stage 5 · HTTP Probe Results (httpx)</h2>
<div class="scroll">
<table>
<thead>
<tr><th>URL</th><th>Status</th><th>Title</th><th>Content-Type</th><th>Length</th><th>CDN</th><th>Redirect</th></tr>
</thead>
<tbody>
${httpx_rows:-"<tr><td colspan=7><em>no data / jq missing</em></td></tr>"}
</tbody>
</table>
</div>
<div class="logs-wrap">
<div class="logs-head">Logs</div>
$(build_log_panels "$RUN_DIR/5_http/httpx*.log" "log-http")
</div>
</div>
</div>
</section>

<section id="panel-screenshots" class="panel">
<div class="window">
<div class="window-title"><span>Screenshots.exe</span><span class="tb-btn">&times;</span></div>
<div class="window-body">
<h2>Stage 5 · Screenshots (gowitness)</h2>
<div class="scroll">
<table>
<thead>
<tr><th>Preview</th><th>URL</th><th>Status</th><th>Title</th></tr>
</thead>
<tbody>
$(build_screenshot_rows "$stage6_screenshots_jsonl" "$stage6_screenshots_dir")
</tbody>
</table>
</div>
<div class="logs-wrap">
<div class="logs-head">Logs</div>
$(build_log_panels "$RUN_DIR/5_http/gowitness*.log" "log-shots")
</div>
</div>
</div>
</section>

<section id="panel-crawled" class="panel">
<div class="window">
<div class="window-title"><span>Crawled.exe</span><span class="tb-btn">&times;</span></div>
<div class="window-body">
<h2>Stage 5 · Crawled Links / JS (katana -jsl)</h2>
<div class="scroll">
<table><tbody>
$(build_table_rows "$stage6_katana" 400)
</tbody></table>
</div>
<div class="logs-wrap">
<div class="logs-head">Logs</div>
$(build_log_panels "$RUN_DIR/5_http/katana*.log" "log-crawled")
</div>
</div>
</div>
</section>

<section id="panel-nuclei" class="panel">
<div class="window">
<div class="window-title"><span>Nuclei.exe</span><span class="tb-btn">&times;</span></div>
<div class="window-body">
<h2>Stage 6 · Nuclei Findings</h2>
${nuclei_block}
<div class="logs-wrap">
<div class="logs-head">Logs</div>
$(build_log_panels "$d6/*.log" "log-nuclei")
</div>
</div>
</div>
</section>

<section id="panel-archive" class="panel">
<div class="window">
<div class="window-title"><span>Archive.exe</span><span class="tb-btn">&times;</span></div>
<div class="window-body">
<h2>Stage 7 · Archived URLs / Extracted Links</h2>
<div class="scroll">
<table><tbody>
$(build_table_rows "$d7/waymore_urls.txt" 300)
</tbody></table>
</div>
<div class="logs-wrap">
<div class="logs-head">Logs</div>
$(build_log_panels "$d7/*.log" "log-archive")
</div>
</div>
</div>
</section>

<section id="panel-timings" class="panel">
<div class="window">
<div class="window-title"><span>Timings.exe</span><span class="tb-btn">&times;</span></div>
<div class="window-body">
<h2>Stage durations</h2>
<table>
<thead><tr><th>stage</th><th>name</th><th>duration</th></tr></thead>
<tbody>
$(build_timing_rows)
</tbody>
</table>
</div>
</div>
</section>

</main>
</div>
<div class="taskbar">
<div class="start">&#9825; Start</div>
<div class="taskbar-info">
Generated by ${SCRIPT_NAME} on $(date). Raw files under <code>${RUN_DIR}</code>.
Resume: <code>bash ${SCRIPT_NAME} --resume ${RUN_DIR}</code>
</div>
</div>
</div>
<script>
function showPanel(id){
  var panels=document.getElementsByClassName('panel');
  for(var i=0;i<panels.length;i++){panels[i].style.display='none';}
  var target=document.getElementById('panel-'+id);
  if(target){target.style.display='block';}
  var btns=document.getElementsByClassName('navbtn');
  for(var i=0;i<btns.length;i++){btns[i].classList.remove('active');}
  var btn=document.getElementById('nav-'+id);
  if(btn){btn.classList.add('active');}
}
function toggleLog(id){
  var p=document.getElementById(id);
  if(!p){return;}
  p.style.display = (p.style.display==='block') ? 'none' : 'block';
}
</script>
</body>
</html>
HTMLEOF
  ok "Report written -> $report"
}
# ─────────────────────────────── Usage ───────────────────────────────────────
usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [-t target] [-o output_dir] [-m modules] [-w waymore_config] [-T seconds] [-y] [-n] [-h]

  -t target
      Single host, comma-separated list, or path to target file.
      Supports:  *.example.com   !dev.example.com   192.168.1.10   192.168.1.0/24
  -o output_dir
      Base output directory. Default: ./recon_out
  -m modules / --modules
      Comma-separated modules/stages to run without prompts.
      Stage aliases: discovery permutations resolution ports http nuclei archive report
  -w waymore_config
      Path to waymore config.yml.
  -T seconds / --timeout
      Default maximum runtime per external tool. Default: $COMMAND_TIMEOUT (0 = unlimited)
  -y / --yes                Assume yes to prompts.
  -n / --non-interactive    Use defaults for prompts.
  --wordlist PATH           DNS brute-force wordlist.
  --resolvers PATH          Resolver list for shuffledns/puredns.
  --ports SCOPE             Primary port scope (top100, top1000, all, 1-65535, 80,443,8080).
  --extra-ports PORTS       Also scan these ports after the primary scope.
  --naabu-scan-type TYPE    syn | connect. Default: let naabu auto-pick (SYN if it
                            has raw-socket privileges, else CONNECT). Force
                            "connect" if obvious open ports (80, 443, ...) are
                            going missing — it's slower but doesn't depend on
                            privileges or a kernel that lets SYN replies through.
  --naabu-rate N            Packets/sec for naabu. Default: naabu's own (1000).
                            Lower it (e.g. 200-300) if scans are dropping real
                            open ports — that's packet loss, not a parsing bug.
  --naabu-retries N         Per-port retries for naabu. Default: naabu's own (3).
  --no-extra-ports          Disable the additional non-standard port pass.

 Wildcard handling
  --no-wildcard-filter      Keep DNS wildcard-resolved names in the live-host list.
  --probe-wildcards         HTTP-probe wildcard candidates and suppress only those
                            matching the random-host fingerprint on the same IP:port.
  --no-probe-wildcards      Never HTTP-probe wildcard candidates.
      With NEITHER of the last two flags, stage 3 ASKS you at the moment a
      wildcard is actually detected, and remembers the answer for --resume.
  --naabu-add-wildcard-ips / --no-naabu-add-wildcard-ips
      Answer in advance the stage-4 question "add the wildcard-filtered IPs
      back into naabu's target list?". Default: ask. Stage 4 also falls back
      to the full resolved-IP set automatically if filtering left 0 targets,
      and the list is editable (TUI pane CTRL-A, or \$EDITOR) before scanning.

 Hangs, timeouts and progress
  --stall-warn SECS         Warn when a tool emits no output for this long. Default: $STALL_WARN (0 = off)
  --stall-kill SECS         Terminate a tool idle for this long. Default: $STALL_KILL (0 = off)
  --no-stall-kill           Never auto-terminate an idle tool.
  --heartbeat SECS          How often to print elapsed/ETA/last-output. Default: $HEARTBEAT_SECS (0 = off)
  --nuclei-timeout SECS     Default: $NUCLEI_TIMEOUT
  --nuclei-rate N           nuclei -rl rate limit. Default: $NUCLEI_RATE
  --waymore-timeout SECS    Per host. Default: $WAYMORE_TIMEOUT
  --gau-timeout SECS        Per host. Default: $GAU_TIMEOUT
  --katana-timeout SECS     Default: $KATANA_TIMEOUT
  --screenshot-timeout SECS Default: $SCREENSHOT_TIMEOUT
  --screenshot-threads N    Concurrent gowitness Chrome workers. Default: $SCREENSHOT_THREADS
  --no-screenshots          Skip gowitness screenshotting in stage 5.
  --archive-max-hosts N     Cap hosts handed to waymore/gau. Default: $ARCHIVE_MAX_HOSTS (0 = all)

 Resume
  --resume RUN_DIR          Continue a previous run directory (settings come from its manifest).
  --resume-latest           Continue the newest run_* directory under -o.
      Completed stages are skipped; delete RUN_DIR/.completed_stages (or a
      single line in it) to force a rerun of a stage.

 TUI
  --tui
      Split-screen TUI (requires tmux; fzf optional but needed for an editable
      candidates pane, otherwise read-only):
        left   — the pipeline's live log, same prompts/output as normal
        right  — the current stage's candidate list:
                   TAB    mark several
                   ENTER  delete marked/selected lines
                   CTRL-A add rows back from the stage's pool (e.g. the
                          wildcard-filtered IPs, for naabu)
                   CTRL-R refresh
        bottom — status bar: current tool, progress, elapsed + ETA, counters
      Detach with Ctrl-B then d; reattach with: tmux attach -t squiz_<ts>
      Editing works best with the normal interactive per-stage prompts (no -y/-m),
      since those prompts are the pause point to prune before answering 'y'.
  -h / --help               Show this help.

While a tool is running:
  s        Skip the current tool/target and continue the pipeline.
  S        Skip the current tool AND the rest of this stage.
  Ctrl-C   Abort the entire pipeline (a --resume command is printed on exit).
EOF
}
# ─────────────────────────────── Arguments ───────────────────────────────────
TARGET_INPUT=""
while [[ $# -gt 0 ]]; do
case "$1" in
    -t) TARGET_INPUT="${2:-}"; cli_set target_input; shift 2 ;;
    -o) BASE_OUT="${2:-}"; shift 2 ;;
    -m|--modules) MODULES_CSV="${2:-}"; AUTO_MODULES=1; cli_set modules; shift 2 ;;
    -w|--waymore-config) WAYMORE_CONFIG="${2:-}"; shift 2 ;;
    -T|--timeout) COMMAND_TIMEOUT="${2:-}"; cli_set command_timeout; shift 2 ;;
    -y|--yes) ASSUME_YES=1; shift ;;
    -n|--non-interactive) NON_INTERACTIVE=1; shift ;;
    --wordlist) WORDLIST_DEFAULT="${2:-}"; cli_set wordlist; shift 2 ;;
    --resolvers) RESOLVERS_DEFAULT="${2:-}"; cli_set resolvers; shift 2 ;;
    --ports) PORT_SCOPE_DEFAULT="${2:-top1000}"; cli_set port_scope; shift 2 ;;
    --extra-ports) EXTRA_PORTS_DEFAULT="${2:-}"; EXTRA_PORTS_ENABLED=1; cli_set extra_ports; cli_set extra_ports_enabled; shift 2 ;;
    --no-extra-ports) EXTRA_PORTS_ENABLED=0; cli_set extra_ports_enabled; shift ;;
    --naabu-scan-type)
      case "${2:-}" in
        syn) NAABU_SCAN_TYPE="s"; cli_set naabu_scan_type ;;
        connect) NAABU_SCAN_TYPE="c"; cli_set naabu_scan_type ;;
        *) warn "--naabu-scan-type must be 'syn' or 'connect' — ignoring '${2:-}'." ;;
      esac
      shift 2 ;;
    --naabu-rate) [[ "${2:-}" =~ ^[0-9]+$ ]] && { NAABU_RATE="$2"; cli_set naabu_rate; }; shift 2 ;;
    --naabu-retries) [[ "${2:-}" =~ ^[0-9]+$ ]] && { NAABU_RETRIES="$2"; cli_set naabu_retries; }; shift 2 ;;
    --no-wildcard-filter) WILDCARD_FILTER=0; cli_set wildcard_filter; shift ;;
    --probe-wildcards) PROBE_WILDCARDS=1; PROBE_WILDCARDS_SET=1; cli_set probe_wildcards; shift ;;
    --no-probe-wildcards) PROBE_WILDCARDS=0; PROBE_WILDCARDS_SET=1; cli_set probe_wildcards; shift ;;
    --naabu-add-wildcard-ips) NAABU_ADD_WILDCARD_IPS=1; cli_set naabu_add_wildcard_ips; shift ;;
    --no-naabu-add-wildcard-ips) NAABU_ADD_WILDCARD_IPS=0; cli_set naabu_add_wildcard_ips; shift ;;
    --stall-warn) STALL_WARN="${2:-0}"; cli_set stall_warn; shift 2 ;;
    --stall-kill) STALL_KILL="${2:-0}"; cli_set stall_kill; shift 2 ;;
    --no-stall-kill) STALL_KILL=0; cli_set stall_kill; shift ;;
    --heartbeat) HEARTBEAT_SECS="${2:-30}"; shift 2 ;;
    --nuclei-timeout) NUCLEI_TIMEOUT="${2:-0}"; shift 2 ;;
    --nuclei-rate) NUCLEI_RATE="${2:-150}"; shift 2 ;;
    --waymore-timeout) WAYMORE_TIMEOUT="${2:-0}"; shift 2 ;;
    --gau-timeout) GAU_TIMEOUT="${2:-0}"; shift 2 ;;
    --katana-timeout) KATANA_TIMEOUT="${2:-0}"; shift 2 ;;
    --screenshot-timeout) SCREENSHOT_TIMEOUT="${2:-0}"; shift 2 ;;
    --screenshot-threads) SCREENSHOT_THREADS="${2:-8}"; shift 2 ;;
    --no-screenshots) SKIP_SCREENSHOTS=1; shift ;;
    --archive-max-hosts) ARCHIVE_MAX_HOSTS="${2:-0}"; cli_set archive_max_hosts; shift 2 ;;
    --tui) TUI_REQUESTED=1; shift ;;
    --tui-inner) TUI_MODE=1; TUI_INNER_RUN_DIR="${2:-}"; shift 2 ;;
    --tui-editor) TUI_EDITOR_RUN_DIR="${2:-}"; shift 2 ;;
    --resume) RESUME_DIR="${2:-}"; shift 2 ;;
    --resume-latest) RESUME_LATEST=1; shift ;;
    -h|--help) usage; exit 0 ;;
*)
      err "Unknown argument: $1"
      usage
      exit 1
;;
esac
done
# ─────────────────────────────── TUI editor-pane dispatch ────────────────────
# --tui-editor is a self-contained mode: it never touches the recon pipeline,
# target parsing, or RUN_DIR creation -- just the candidates browser/editor
# loop against a RUN_DIR an outer process already created.
if [[ -n "$TUI_EDITOR_RUN_DIR" ]]; then
  run_candidate_editor "$TUI_EDITOR_RUN_DIR"
  exit 0
fi
# ─────────────────────────────── Validation ──────────────────────────────────
for _v in COMMAND_TIMEOUT STALL_WARN STALL_KILL HEARTBEAT_SECS NUCLEI_TIMEOUT \
          WAYMORE_TIMEOUT GAU_TIMEOUT KATANA_TIMEOUT ARCHIVE_MAX_HOSTS NUCLEI_RATE; do
  eval "_val=\"\$$_v\""
  if ! [[ "$_val" =~ ^[0-9]+$ ]]; then
    err "Invalid value for $_v: '$_val' (must be an integer)"
    exit 1
  fi
done
unset _v _val
# ─────────────────────────────── Initialisation ──────────────────────────────
init_tool_path
# Keep puredns/waymore resolver configuration consistent with this run.
if [[ -n "$RESOLVERS_DEFAULT" && -f "$RESOLVERS_DEFAULT" ]]; then
  mkdir -p "$HOME/.config/puredns" 2>/dev/null || true
  if [[ ! -f "$HOME/.config/puredns/resolvers.txt" ]]; then
    cp "$RESOLVERS_DEFAULT" "$HOME/.config/puredns/resolvers.txt" 2>/dev/null || true
  fi
fi
#
# waymore config.
#
if [[ -z "$WAYMORE_CONFIG" && -f "$HOME/.config/waymore/config.yml" ]]; then
  WAYMORE_CONFIG="$HOME/.config/waymore/config.yml"
fi
if [[ -n "$WAYMORE_CONFIG" && "$WAYMORE_CONFIG" == ~/* ]]; then
  WAYMORE_CONFIG="$HOME/${WAYMORE_CONFIG#~/}"
fi
if [[ -n "$WAYMORE_CONFIG" && ! -f "$WAYMORE_CONFIG" ]]; then
  warn "waymore config not found: $WAYMORE_CONFIG"
  warn "waymore will run without -c"
  WAYMORE_CONFIG=""
fi
banner
# ─────────────────────────────── Resume resolution ────────────────────────────
# --resume-latest picks the newest run_* dir under BASE_OUT (prompting for
# BASE_OUT first if it wasn't given, same default as a fresh run would use).
if [[ "$RESUME_LATEST" -eq 1 && -z "$RESUME_DIR" ]]; then
  if [[ -z "$BASE_OUT" ]]; then
    BASE_OUT="$(ask "Base output directory to look for a previous run in" "./recon_out")"
  fi
  RESUME_DIR="$(ls -dt "${BASE_OUT%/}"/run_*/ 2>/dev/null | head -n1)"
  RESUME_DIR="${RESUME_DIR%/}"
  if [[ -z "$RESUME_DIR" ]]; then
    err "No previous run_* directory found under ${BASE_OUT%/} to resume."
    exit 1
  fi
fi
# ─────────────────────────────── Target input ─────────────────────────────────
if [[ -n "$RESUME_DIR" && -z "$TUI_INNER_RUN_DIR" ]]; then
  # --resume / --resume-latest: everything needed (target, modules, port
  # scope, wildcard decisions...) comes back from the prior run's manifest.
  load_resume_manifest "$RESUME_DIR"
  parse_targets "$TARGET_INPUT"
  if [[ "${#DOMAINS[@]}" -eq 0 && "${#CIDRS[@]}" -eq 0 && "${#RAW_IPS[@]}" -eq 0 ]]; then
    err "Could not parse any valid targets from the resumed manifest."
    exit 1
  fi
  info "Resuming run: $RUN_DIR"
elif [[ -n "$TUI_INNER_RUN_DIR" ]]; then
  # We are the left/log pane, re-exec'd by tui_launch_and_attach() (which
  # itself may have been resumed). Reuse that RUN_DIR/TS rather than
  # recomputing a timestamp or truncating the log it already started.
  if [[ -z "$TARGET_INPUT" ]]; then
    err "Internal error: --tui-inner given without a target. This should not happen."
    exit 1
  fi
  parse_targets "$TARGET_INPUT"
  RUN_DIR="$TUI_INNER_RUN_DIR"
  TS="$(basename "$RUN_DIR" | sed -E 's/^run_//')"
  LOG_FILE="$RUN_DIR/recon.log"
  BASE_OUT="$(dirname "$RUN_DIR")"
  mkdir -p "$RUN_DIR"
else
  if [[ -z "$TARGET_INPUT" ]]; then
    TARGET_INPUT="$(ask "Target host, comma-separated list, or path to target file")"
  fi
  if [[ -z "$TARGET_INPUT" ]]; then
    err "No target provided. Exiting."
    exit 1
  fi
  if [[ -z "$BASE_OUT" ]]; then
    BASE_OUT="$(ask "Base output directory" "./recon_out")"
  fi
  mkdir -p "$BASE_OUT"
  parse_targets "$TARGET_INPUT"
  if [[ "${#DOMAINS[@]}" -eq 0 && "${#CIDRS[@]}" -eq 0 && "${#RAW_IPS[@]}" -eq 0 ]]; then
    err "Could not parse any valid targets."
    exit 1
  fi
  RUN_NAME="run_${TS}"
  RUN_DIR="${BASE_OUT%/}/${RUN_NAME}"
  mkdir -p "$RUN_DIR"
  LOG_FILE="$RUN_DIR/recon.log"
  : > "$LOG_FILE"
  cat > "$RUN_DIR/run_manifest.txt" <<EOF
run_timestamp=$TS
target_input=$TARGET_INPUT
modules=${MODULES_CSV:-interactive}
wordlist=$WORDLIST_DEFAULT
resolvers=${RESOLVERS_DEFAULT:-default/prompt}
port_scope=$PORT_SCOPE_DEFAULT
extra_ports=$EXTRA_PORTS_DEFAULT
extra_ports_enabled=$EXTRA_PORTS_ENABLED
naabu_scan_type=$NAABU_SCAN_TYPE
naabu_rate=$NAABU_RATE
naabu_retries=$NAABU_RETRIES
wildcard_filter=$WILDCARD_FILTER
probe_wildcards=$PROBE_WILDCARDS
probe_wildcards_set=$PROBE_WILDCARDS_SET
naabu_add_wildcard_ips=${NAABU_ADD_WILDCARD_IPS:-ask}
archive_max_hosts=$ARCHIVE_MAX_HOSTS
stall_warn=$STALL_WARN
stall_kill=$STALL_KILL
command_timeout=$COMMAND_TIMEOUT
tui=$TUI_REQUESTED
script=$SCRIPT_NAME
EOF
fi

# Timing cache lives beside the run directories so ETAs survive across runs.
if [[ -n "$BASE_OUT" ]]; then
  TIMINGS_FILE="${BASE_OUT%/}/.squiz_timings"
  [[ -f "$TIMINGS_FILE" ]] || : > "$TIMINGS_FILE" 2>/dev/null || TIMINGS_FILE=""
fi

# Snapshot of stages a PRIOR invocation already completed, if resuming --
# see stage_was_already_complete() for why this is a static snapshot rather
# than a live read of the (possibly still-growing) file.
if [[ -f "$RUN_DIR/.completed_stages" ]]; then
  RESUMED_COMPLETED_STAGES=" $(tr '\n' ' ' < "$RUN_DIR/.completed_stages") "
fi
# If the pipeline is cancelled (Ctrl-C at a prompt, between stages, or via
# run_spinner's own handler) rather than finishing normally, print how to
# pick back up. PIPELINE_COMPLETED is set right before the final "Done"
# section, so this never fires on a clean finish.
PIPELINE_COMPLETED=0
RESUME_HINT_PRINTED=0
# Printed either by the EXIT trap or directly by the Ctrl-C handler,
# whichever gets there first; the once-guard keeps it from doubling up.
print_resume_hint() {
  [[ "$RESUME_HINT_PRINTED" -eq 1 ]] && return 0
  [[ -n "${RUN_DIR:-}" ]] || return 0
  RESUME_HINT_PRINTED=1
  echo -e "\n${C_PINK}♡ Stopped before finishing.${C_RESET} Resume this scan later with:" >&2
  echo -e "  ${C_LILAC}bash \"$0\" --resume \"$RUN_DIR\"${C_RESET}" >&2
  echo -e "  ${C_DIM}(or: bash \"$0\" --resume-latest -o \"${BASE_OUT:-.}\")${C_RESET}" >&2
}
print_resume_hint_on_exit() {
  [[ "$PIPELINE_COMPLETED" -eq 1 ]] && return 0
  print_resume_hint
}
trap print_resume_hint_on_exit EXIT
# --tui (and not already the re-exec'd inner process): hand off to the tmux
# launcher and stop here -- the launcher's re-exec'd copy of this script
# (with --tui-inner) is what actually runs the pipeline, in the left pane.
if [[ "$TUI_REQUESTED" -eq 1 && "$TUI_MODE" -eq 0 ]]; then
  tui_launch_and_attach
  exit 0
fi
print_target_summary
if [[ -n "$RESUMED_COMPLETED_STAGES" ]]; then
  info "Already completed in this run directory:${RESUMED_COMPLETED_STAGES}"
fi
check_tools
info "Output directory for this run: $RUN_DIR"
info "Live controls: ${C_BOLD}s${C_RESET} skip current tool/target · ${C_BOLD}S${C_RESET} skip rest of stage · ${C_BOLD}Ctrl-C${C_RESET} abort (resumable)"
info "Idle tools warn after $(fmt_dur "$STALL_WARN")$([[ "$STALL_KILL" -gt 0 ]] && echo " and are terminated after $(fmt_dur "$STALL_KILL")")."
echo
# ─────────────────────────────── Stage gate ──────────────────────────────────
#
# Sets the global STAGE_GATE_RESULT to one of: run | skip | back. Like
# prompt_choice, this is a plain function call (never $(...)) so that 'a'
# (yes to all) correctly mutates ASSUME_YES in the real running script.
STAGE_GATE_RESULT=""
gate_decision() {
  local n="$1" name="$2" alias="$3"
  if [[ "$AUTO_MODULES" -eq 1 ]]; then
    if stage_selected "$alias"; then STAGE_GATE_RESULT="run"; else STAGE_GATE_RESULT="skip"; fi
    return
  fi
  if ! stage_available "$n"; then
    warn "Stage $n ($name) is missing one or more tools."
    warn "Expected: $(stage_tools "$n")"
    warn "Available sub-tools will still be attempted."
  fi
  local est
  est="$(timing_lookup "stage_${n}" 2>/dev/null || true)"
  prompt_choice "Run Stage $n — ${name}?${est:+ (took $(fmt_dur "$est") last time)}" y 1
  case "$PROMPT_CHOICE_RESULT" in
    yes) STAGE_GATE_RESULT="run" ;;
    back) STAGE_GATE_RESULT="back" ;;
    *) STAGE_GATE_RESULT="skip" ;;
  esac
}

# ───────────────────── Stage skip-default / resume-restore helpers ───────────
#
# *_skip_defaults: when a stage is answered 'n', set its output variables to
# an empty/fresh file so later stages see "nothing produced" rather than
# erroring on an unset variable.
#
# *_resume_restore: used ONLY when resuming a stage a PRIOR run already
# completed -- point the same variables at the SAME files WITHOUT truncating
# them, so the real prior output survives for downstream stages.
stage1_skip_defaults() { stage1_combined="$RUN_DIR/1_discovery/all_subdomains.txt"; mkdir -p "$RUN_DIR/1_discovery"; : > "$stage1_combined"; }
stage1_resume_restore() { stage1_combined="$RUN_DIR/1_discovery/all_subdomains.txt"; }

stage2_skip_defaults() { stage2_combined="$RUN_DIR/2_permutations/alterx_permutations.txt"; mkdir -p "$RUN_DIR/2_permutations"; : > "$stage2_combined"; }
stage2_resume_restore() { stage2_combined="$RUN_DIR/2_permutations/alterx_permutations.txt"; }

stage3_skip_defaults() {
  stage3_resolved="$RUN_DIR/3_resolved/resolved_hosts.txt"
  stage3_host_ip_all="$RUN_DIR/3_resolved/host_ip.csv"
  stage3_all_resolved="$RUN_DIR/3_resolved/resolved_hosts_all.txt"
  stage3_wildcard_hosts="$RUN_DIR/3_resolved/wildcard_hosts.txt"
  mkdir -p "$RUN_DIR/3_resolved"
  cat "$stage1_combined" "$stage2_combined" 2>/dev/null | sort -u > "$stage3_resolved"
  [[ -f "$stage3_host_ip_all" ]] || : > "$stage3_host_ip_all"
  [[ -f "$stage3_all_resolved" ]] || : > "$stage3_all_resolved"
  [[ -f "$stage3_wildcard_hosts" ]] || : > "$stage3_wildcard_hosts"
}
stage3_resume_restore() {
  stage3_resolved="$RUN_DIR/3_resolved/resolved_hosts.txt"
  stage3_resolved_ips="$RUN_DIR/3_resolved/resolved_hosts_ips.txt"
  stage3_all_resolved="$RUN_DIR/3_resolved/resolved_hosts_all.txt"
  stage3_host_ip_all="$RUN_DIR/3_resolved/host_ip.csv"
  stage3_wildcard_hosts="$RUN_DIR/3_resolved/wildcard_hosts.txt"
}

stage4_skip_defaults() { stage5_hostports="$RUN_DIR/4_ports/naabu_hostports.txt"; mkdir -p "$RUN_DIR/4_ports"; : > "$stage5_hostports"; }
stage4_resume_restore() { stage5_hostports="$RUN_DIR/4_ports/naabu_hostports.txt"; }

stage5_skip_defaults() {
  stage6_httpx="$RUN_DIR/5_http/httpx.txt"
  stage6_katana="$RUN_DIR/5_http/katana_links.txt"
  stage6_screenshots_jsonl="$RUN_DIR/5_http/gowitness.jsonl"
  stage6_screenshots_dir="$RUN_DIR/5_http/screenshots"
  mkdir -p "$RUN_DIR/5_http" "$stage6_screenshots_dir"
  : > "$stage6_httpx"
  : > "$stage6_katana"
  : > "$stage6_screenshots_jsonl"
}
stage5_resume_restore() {
  stage6_httpx="$RUN_DIR/5_http/httpx.txt"
  stage6_katana="$RUN_DIR/5_http/katana_links.txt"
  stage6_screenshots_jsonl="$RUN_DIR/5_http/gowitness.jsonl"
  stage6_screenshots_dir="$RUN_DIR/5_http/screenshots"
}

stage6_skip_defaults() { stage7_md="$RUN_DIR/6_nuclei/nuclei_findings.md"; mkdir -p "$RUN_DIR/6_nuclei"; : > "$stage7_md"; }
stage6_resume_restore() { stage7_md="$RUN_DIR/6_nuclei/nuclei_findings.md"; }

stage7_skip_defaults() { stage8_archive_dir="$RUN_DIR/7_archive"; mkdir -p "$stage8_archive_dir"; }
stage7_resume_restore() { stage8_archive_dir="$RUN_DIR/7_archive"; }

stage8_skip_defaults() { :; }
stage8_resume_restore() { :; }

# ───────────────────────────── Pipeline ──────────────────────────────────────
#
# Archive is deliberately LAST before the report:
#   1 discovery · 2 permutations · 3 resolution · 4 ports
#   5 HTTP · 6 nuclei · 7 archive · 8 report
#
# Driven as a loop (not a flat sequence) so a stage prompt answered 'b'
# (back) can step to the PREVIOUS stage's prompt, and so --resume can skip
# whatever a prior invocation already finished.
STAGE_NUMS=(1 2 3 4 5 6 7 8)
STAGE_NAMES=("Subdomain discovery" "Permutation generation" "Resolution (dnsx)" "Port scanning (naabu)" "HTTP probe + crawl" "Nuclei scan" "Archive / historical URL discovery" "HTML summary report")
STAGE_ALIASES=(discovery permutations resolution ports http nuclei archive report)
STAGE_RUN_FUNCS=(run_stage1 run_stage2 run_stage3 run_stage4 run_stage5 run_stage6 run_stage7 run_report)
STAGE_SKIP_FUNCS=(stage1_skip_defaults stage2_skip_defaults stage3_skip_defaults stage4_skip_defaults stage5_skip_defaults stage6_skip_defaults stage7_skip_defaults stage8_skip_defaults)
STAGE_RESUME_FUNCS=(stage1_resume_restore stage2_resume_restore stage3_resume_restore stage4_resume_restore stage5_resume_restore stage6_resume_restore stage7_resume_restore stage8_resume_restore)

pipeline_idx=0
pipeline_total=${#STAGE_NUMS[@]}
while [[ "$pipeline_idx" -lt "$pipeline_total" ]]; do
  snum="${STAGE_NUMS[$pipeline_idx]}"
  sname="${STAGE_NAMES[$pipeline_idx]}"
  salias="${STAGE_ALIASES[$pipeline_idx]}"
  srun="${STAGE_RUN_FUNCS[$pipeline_idx]}"
  sskip="${STAGE_SKIP_FUNCS[$pipeline_idx]}"
  sresume="${STAGE_RESUME_FUNCS[$pipeline_idx]}"

  if stage_was_already_complete "$snum"; then
    info "Stage $snum ($sname) already completed in this run directory — resuming past it. Delete $RUN_DIR/.completed_stages (or that stage's line) to force a rerun."
    "$sresume"
    pipeline_idx=$((pipeline_idx + 1))
    continue
  fi

  gate_decision "$snum" "$sname" "$salias"
  case "$STAGE_GATE_RESULT" in
    run)
      stage_start="$(date +%s)"
      "$srun"
      stage_dur=$(( $(date +%s) - stage_start ))
      record_stage_time "$snum" "$sname" "$stage_dur"
      timing_record "stage_${snum}" "$stage_dur"
      ok "Stage $snum finished in $(fmt_dur "$stage_dur") ${C_DIM}(total so far: $(fmt_dur $(( $(date +%s) - RUN_START_TS ))))${C_RESET}"
      mark_stage_complete "$snum"
      stage_skip_reset
      pipeline_idx=$((pipeline_idx + 1))
;;
    back)
      if [[ "$pipeline_idx" -gt 0 ]]; then
        pipeline_idx=$((pipeline_idx - 1))
      else
        warn "Already at the first stage."
      fi
;;
    *)
      warn "Stage $snum ($sname) skipped entirely"
      "$sskip"
      pipeline_idx=$((pipeline_idx + 1))
;;
  esac
done
# ───────────────────────────────── Done ──────────────────────────────────────
PIPELINE_COMPLETED=1
section "Done ♡"
if [[ -s "$RUN_DIR/.stage_times" ]]; then
  echo -e "${C_LILAC}  stage durations:${C_RESET}"
  while IFS='|' read -r _n _name _secs; do
    [[ -z "$_n" ]] && continue
    printf "    ${C_PINK}%s${C_RESET} %-38s ${C_LILAC}%s${C_RESET}\n" "$_n" "$_name" "$(fmt_dur "$_secs")"
  done < "$RUN_DIR/.stage_times"
fi
ok "Total wall clock: $(fmt_dur $(( $(date +%s) - RUN_START_TS )))"
ok "All artifacts under: $RUN_DIR"
if [[ -f "$RUN_DIR/report.html" ]]; then
  ok "Open the report: $RUN_DIR/report.html"
fi
echo -e "${C_PINK}  ･ ｡ﾟ☆: *.☽ .* ✧ hack the planet ✧ *. ☾.* :☆ﾟ･ ｡${C_RESET}"
