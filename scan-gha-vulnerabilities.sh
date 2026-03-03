#!/usr/bin/env bash
# scan-gha-vulnerabilities.sh
#
# Scans all repos under specified GitHub orgs/users for GitHub Actions
# workflow vulnerabilities exploited by the hackerbot-claw campaign.
#
# Checks for 5 attack patterns:
#   1. Pwn Request: pull_request_target + checkout of PR head code
#   2. Script Injection: unescaped ${{ }} expressions in run: blocks
#   3. Unprivileged comment triggers: issue_comment without author_association check
#   4. Excessive permissions: contents: write on PR-triggered workflows
#   5. Unsafe AI/bot triggers: claude-code-action with allowed_non_write_users: '*'
#
# Usage: ./scan-gha-vulnerabilities.sh [--fix] [--org ORG ...] [--user USER ...]
#
# Requires: gh CLI (authenticated)

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ORGS=()
USERS=()
REPOS=()
FINDINGS=()
TOTAL_VULNS=0
TOTAL_REPOS_SCANNED=0
TOTAL_REPOS_VULNERABLE=0

usage() {
  echo "Usage: $0 [--org ORG ...] [--user USER ...]"
  echo ""
  echo "Scans GitHub Actions workflows for hackerbot-claw attack patterns."
  echo ""
  echo "Options:"
  echo "  --org ORG    GitHub organization to scan (can be repeated)"
  echo "  --user USER  GitHub user to scan (can be repeated)"
  echo "  -h, --help   Show this help"
  exit 0
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --org)   ORGS+=("$2"); shift 2 ;;
      --user)  USERS+=("$2"); shift 2 ;;
      -h|--help) usage ;;
      *) echo "Unknown option: $1"; usage ;;
    esac
  done

  if [[ ${#ORGS[@]} -eq 0 && ${#USERS[@]} -eq 0 ]]; then
    echo "Error: specify at least one --org or --user"
    exit 1
  fi
}

gather_repos() {
  if [[ ${#ORGS[@]} -gt 0 ]]; then
    for org in "${ORGS[@]}"; do
      while IFS= read -r repo; do
        REPOS+=("$repo")
      done < <(gh repo list "$org" --limit 200 --json nameWithOwner --jq '.[].nameWithOwner' 2>/dev/null)
    done
  fi
  if [[ ${#USERS[@]} -gt 0 ]]; then
    for user in "${USERS[@]}"; do
      while IFS= read -r repo; do
        REPOS+=("$repo")
      done < <(gh repo list "$user" --limit 200 --json nameWithOwner --jq '.[].nameWithOwner' 2>/dev/null)
    done
  fi
}

add_finding() {
  local repo="$1" workflow="$2" severity="$3" pattern="$4" detail="$5"
  FINDINGS+=("${severity}|${repo}|${workflow}|${pattern}|${detail}")
  ((TOTAL_VULNS++)) || true
}

# --- Pattern checks ---

check_pwn_request() {
  local repo="$1" workflow_path="$2" content="$3"

  # Pattern 1: pull_request_target + checkout of PR head
  if echo "$content" | grep -q 'pull_request_target'; then
    # Check if it checks out the PR head (untrusted code)
    if echo "$content" | grep -qE 'github\.event\.pull_request\.head\.(sha|ref)'; then
      add_finding "$repo" "$workflow_path" "CRITICAL" "PWN_REQUEST" \
        "Uses pull_request_target and checks out PR head code. Attacker can execute arbitrary code with repo permissions."
    fi
  fi
}

check_script_injection() {
  local repo="$1" workflow_path="$2" content="$3"

  # Pattern 2: Unescaped ${{ }} with attacker-controlled values in run: blocks
  # Look for dangerous expression contexts in shell commands
  local dangerous_expressions=(
    'github\.event\.pull_request\.title'
    'github\.event\.pull_request\.body'
    'github\.event\.pull_request\.head\.ref'
    'github\.event\.pull_request\.head\.label'
    'github\.event\.issue\.title'
    'github\.event\.issue\.body'
    'github\.event\.comment\.body'
    'github\.event\.review\.body'
    'github\.event\.pages\.\*\.page_name'
    'github\.event\.commits\.\*\.message'
    'github\.event\.commits\.\*\.author\.name'
    'github\.event\.head_commit\.message'
    'github\.event\.head_commit\.author\.name'
    'github\.event\.workflow_run\.head_branch'
    'github\.event\.workflow_run\.head_commit\.message'
    'github\.head_ref'
    'github\.event\.discussion\.title'
    'github\.event\.discussion\.body'
  )

  # Extract run: blocks and check for unescaped expressions
  # We look for ${{ <dangerous_expr> }} that appears inside run: blocks
  for expr in "${dangerous_expressions[@]}"; do
    if echo "$content" | grep -qE "\\\$\{\{.*${expr}.*\}\}"; then
      # Check if this expression appears in a run: context (rough heuristic)
      if echo "$content" | grep -B5 -E "\\\$\{\{.*${expr}.*\}\}" | grep -q 'run:'; then
        local clean_expr
        clean_expr=$(echo "$expr" | sed 's/\\//g')
        add_finding "$repo" "$workflow_path" "HIGH" "SCRIPT_INJECTION" \
          "Unescaped \${{ ${clean_expr} }} in run: block. Attacker can inject shell commands via PR title, body, branch name, etc."
        break  # One finding per workflow for this pattern
      fi
    fi
  done
}

check_comment_trigger() {
  local repo="$1" workflow_path="$2" content="$3"

  # Pattern 3: issue_comment trigger without author_association check
  if echo "$content" | grep -q 'issue_comment'; then
    if ! echo "$content" | grep -qE 'author_association|OWNER|MEMBER|COLLABORATOR'; then
      # Check if it does anything privileged (checkout, run scripts, etc.)
      if echo "$content" | grep -qE 'actions/checkout|run:'; then
        add_finding "$repo" "$workflow_path" "HIGH" "UNAUTH_COMMENT_TRIGGER" \
          "issue_comment trigger without author_association check. Any GitHub user can trigger this workflow via comments."
      fi
    fi
  fi
}

check_excessive_permissions() {
  local repo="$1" workflow_path="$2" content="$3"

  # Pattern 4: pull_request_target with write permissions
  if echo "$content" | grep -q 'pull_request_target'; then
    if echo "$content" | grep -qE 'contents:\s*write|permissions:\s*write-all'; then
      add_finding "$repo" "$workflow_path" "HIGH" "EXCESSIVE_PERMS" \
        "pull_request_target workflow with contents: write. Fork PRs get write access to the repo."
    fi
    # Also flag if no permissions block at all (defaults may be permissive)
    if ! echo "$content" | grep -q 'permissions:'; then
      add_finding "$repo" "$workflow_path" "MEDIUM" "NO_PERMISSIONS_BLOCK" \
        "pull_request_target workflow without explicit permissions block. Default permissions may be overly broad."
    fi
  fi
}

check_unsafe_ai_triggers() {
  local repo="$1" workflow_path="$2" content="$3"

  # Pattern 5: AI code review with lax access
  if echo "$content" | grep -q 'claude-code-action'; then
    if echo "$content" | grep -qE "allowed_non_write_users.*['\"]\\*['\"]"; then
      add_finding "$repo" "$workflow_path" "CRITICAL" "UNSAFE_AI_TRIGGER" \
        "claude-code-action with allowed_non_write_users: '*'. Any user can trigger AI with repo write access."
    fi
    # Check if it checks out PR head code (prompt injection via CLAUDE.md)
    if echo "$content" | grep -qE 'github\.event\.pull_request\.head\.(sha|ref)'; then
      add_finding "$repo" "$workflow_path" "HIGH" "AI_PROMPT_INJECTION" \
        "claude-code-action checks out PR head code. Attacker can inject via modified CLAUDE.md or code files."
    fi
  fi
}

check_workflow_dispatch_injection() {
  local repo="$1" workflow_path="$2" content="$3"

  # Bonus: workflow_dispatch/workflow_call inputs used unsafely
  if echo "$content" | grep -qE 'workflow_dispatch|workflow_call'; then
    if echo "$content" | grep -qE '\$\{\{.*(inputs|github\.event\.inputs)\.[^}]+\}\}'; then
      if echo "$content" | grep -B5 -E '\$\{\{.*(inputs|github\.event\.inputs)\.[^}]+\}\}' | grep -q 'run:'; then
        add_finding "$repo" "$workflow_path" "MEDIUM" "INPUT_INJECTION" \
          "workflow_dispatch/workflow_call inputs used in run: blocks without sanitization."
      fi
    fi
  fi
}

scan_repo() {
  local repo="$1"
  local has_vulns=false

  # Get list of workflow files
  local workflows
  workflows=$(gh api "repos/${repo}/contents/.github/workflows" --jq '.[].name' 2>/dev/null || true)

  if [[ -z "$workflows" ]]; then
    return
  fi

  ((TOTAL_REPOS_SCANNED++)) || true

  while IFS= read -r wf; do
    [[ -z "$wf" ]] && continue
    [[ "$wf" != *.yml && "$wf" != *.yaml ]] && continue

    local content
    content=$(gh api "repos/${repo}/contents/.github/workflows/${wf}" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null || true)

    if [[ -z "$content" ]]; then
      continue
    fi

    local prev_vulns=$TOTAL_VULNS

    check_pwn_request "$repo" "$wf" "$content"
    check_script_injection "$repo" "$wf" "$content"
    check_comment_trigger "$repo" "$wf" "$content"
    check_excessive_permissions "$repo" "$wf" "$content"
    check_unsafe_ai_triggers "$repo" "$wf" "$content"
    check_workflow_dispatch_injection "$repo" "$wf" "$content"

    if [[ $TOTAL_VULNS -gt $prev_vulns ]]; then
      has_vulns=true
    fi
  done <<< "$workflows"

  if $has_vulns; then
    ((TOTAL_REPOS_VULNERABLE++)) || true
  fi
}

print_report() {
  echo ""
  echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  GitHub Actions Security Scan — hackerbot-claw Patterns${NC}"
  echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
  echo ""
  echo -e "  Repos scanned:     ${CYAN}${TOTAL_REPOS_SCANNED}${NC}"
  echo -e "  Repos vulnerable:  ${RED}${TOTAL_REPOS_VULNERABLE}${NC}"
  echo -e "  Total findings:    ${RED}${TOTAL_VULNS}${NC}"
  echo ""

  if [[ $TOTAL_VULNS -eq 0 ]]; then
    echo -e "  ${GREEN}No vulnerabilities found. All repos look clean.${NC}"
    echo ""
    return
  fi

  # Group by severity
  for severity in CRITICAL HIGH MEDIUM; do
    local sev_color
    case "$severity" in
      CRITICAL) sev_color="$RED" ;;
      HIGH)     sev_color="$YELLOW" ;;
      MEDIUM)   sev_color="$CYAN" ;;
    esac

    local has_findings=false
    [[ ${#FINDINGS[@]} -eq 0 ]] && continue
    for finding in "${FINDINGS[@]}"; do
      local f_sev f_repo f_wf f_pattern f_detail
      IFS='|' read -r f_sev f_repo f_wf f_pattern f_detail <<< "$finding"
      if [[ "$f_sev" == "$severity" ]]; then
        if ! $has_findings; then
          echo -e "  ${sev_color}${BOLD}── ${severity} ──${NC}"
          has_findings=true
        fi
        echo -e "  ${sev_color}[${severity}]${NC} ${BOLD}${f_repo}${NC} → ${f_wf}"
        echo -e "          Pattern: ${f_pattern}"
        echo -e "          ${f_detail}"
        echo ""
      fi
    done
  done

  echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
  echo ""
  echo -e "${BOLD}Remediation Guide:${NC}"
  echo ""
  echo "  PWN_REQUEST:"
  echo "    - Never checkout PR head code in pull_request_target workflows"
  echo "    - Use pull_request (not _target) when you need to run PR code"
  echo "    - If you must use _target, only checkout the base branch"
  echo ""
  echo "  SCRIPT_INJECTION:"
  echo "    - Never use \${{ github.event.* }} directly in run: blocks"
  echo "    - Pass values through environment variables instead:"
  echo "      env:"
  echo "        PR_TITLE: \${{ github.event.pull_request.title }}"
  echo "      run: echo \"\$PR_TITLE\"  # safe — shell variable, not template"
  echo ""
  echo "  UNAUTH_COMMENT_TRIGGER:"
  echo "    - Add: if: github.event.comment.author_association == 'MEMBER'"
  echo "    - Or restrict to specific users/teams"
  echo ""
  echo "  EXCESSIVE_PERMS / NO_PERMISSIONS_BLOCK:"
  echo "    - Always add explicit permissions: block"
  echo "    - Use minimum required: contents: read, pull-requests: read"
  echo "    - Set org default to read-only in GitHub Settings"
  echo ""
  echo "  UNSAFE_AI_TRIGGER / AI_PROMPT_INJECTION:"
  echo "    - Never set allowed_non_write_users: '*'"
  echo "    - Don't checkout PR head in AI review workflows"
  echo "    - Use pull_request event (not _target) for AI code review"
  echo ""
}

main() {
  parse_args "$@"

  echo -e "${CYAN}Gathering repositories...${NC}"
  gather_repos

  echo -e "${CYAN}Found ${#REPOS[@]} repositories to scan${NC}"
  echo ""

  for repo in "${REPOS[@]}"; do
    printf "  Scanning %-50s" "$repo"
    scan_repo "$repo"
    local repo_findings=0
    if [[ ${#FINDINGS[@]} -gt 0 ]]; then
      for finding in "${FINDINGS[@]}"; do
        if echo "$finding" | grep -q "|${repo}|"; then
          ((repo_findings++)) || true
        fi
      done
    fi
    if [[ $repo_findings -gt 0 ]]; then
      echo -e " ${RED}${repo_findings} finding(s)${NC}"
    else
      echo -e " ${GREEN}clean${NC}"
    fi
  done

  print_report
}

main "$@"
