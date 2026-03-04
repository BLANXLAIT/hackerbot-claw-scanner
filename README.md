# hackerbot-claw-scanner

A shell script that scans GitHub Actions workflows across your orgs and user accounts for the vulnerability patterns exploited by the [hackerbot-claw campaign](https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation) (Feb–Mar 2026).

## Background

In February 2026, an autonomous bot named **hackerbot-claw** systematically exploited insecure GitHub Actions configurations across major open-source projects including Microsoft, DataDog, CNCF, and Aqua Security (Trivy). The bot used five distinct attack techniques, each targeting a different workflow misconfiguration pattern. See the [StepSecurity writeup](https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation) and [Upwind analysis](https://www.upwind.io/feed/hackerbot-claw-github-actions-pull-request-rce) for full details.

This scanner checks for all five patterns across every repo in your GitHub orgs and user accounts.

## What it checks

| Pattern | Severity | Description |
|---------|----------|-------------|
| `PWN_REQUEST` | CRITICAL | `pull_request_target` + checkout of PR head code — attacker executes arbitrary code with repo permissions |
| `UNSAFE_AI_TRIGGER` | CRITICAL | `claude-code-action` with `allowed_non_write_users: '*'` — any user can trigger AI with repo write access |
| `SCRIPT_INJECTION` | HIGH | Unescaped `${{ github.event.* }}` in `run:` blocks — attacker injects shell commands via PR title, body, branch name, etc. |
| `UNAUTH_COMMENT_TRIGGER` | HIGH | `issue_comment` trigger without `author_association` check — any GitHub user can trigger workflows via comments |
| `EXCESSIVE_PERMS` | HIGH | `pull_request_target` with `contents: write` — fork PRs get write access to the repo |
| `AI_PROMPT_INJECTION` | HIGH | AI code review action checks out PR head — attacker can inject via modified config files |
| `NO_PERMISSIONS_BLOCK` | MEDIUM | `pull_request_target` without explicit `permissions:` block — defaults may be overly broad |
| `INPUT_INJECTION` | MEDIUM | `workflow_dispatch`/`workflow_call` inputs used directly in `run:` blocks without sanitization |

## Requirements

- [GitHub CLI (`gh`)](https://cli.github.com/) — authenticated with access to the orgs/users you want to scan
- Bash 4+

## Usage

```bash
# Scan a single org
./scan-gha-vulnerabilities.sh --org my-org

# Scan a user account
./scan-gha-vulnerabilities.sh --user my-username

# Scan multiple orgs and users at once
./scan-gha-vulnerabilities.sh --org org1 --org org2 --user user1
```

## Example output

```
═══════════════════════════════════════════════════════════════
  GitHub Actions Security Scan — hackerbot-claw Patterns
═══════════════════════════════════════════════════════════════

  Repos scanned:     60
  Repos vulnerable:  2
  Total findings:    3

  ── HIGH ──
  [HIGH] my-org/my-repo → claude.yml
          Pattern: UNAUTH_COMMENT_TRIGGER
          issue_comment trigger without author_association check.
          Any GitHub user can trigger this workflow via comments.

  ── MEDIUM ──
  [MEDIUM] my-org/other-repo → deploy.yml
          Pattern: INPUT_INJECTION
          workflow_dispatch/workflow_call inputs used in run: blocks
          without sanitization.
```

## Remediation quick reference

**PWN_REQUEST** — Never checkout PR head code in `pull_request_target` workflows. Use `pull_request` instead when you need to run PR code.

**SCRIPT_INJECTION** — Pass event data through environment variables:
```yaml
# UNSAFE
run: echo "${{ github.event.pull_request.title }}"

# SAFE
env:
  PR_TITLE: ${{ github.event.pull_request.title }}
run: echo "$PR_TITLE"
```

**UNAUTH_COMMENT_TRIGGER** — Restrict comment-triggered workflows to authorized users:
```yaml
if: >
  github.event.comment.author_association == 'OWNER' ||
  github.event.comment.author_association == 'MEMBER' ||
  github.event.comment.author_association == 'COLLABORATOR'
```

**EXCESSIVE_PERMS** — Always add explicit `permissions:` with minimum required access:
```yaml
permissions:
  contents: read
  pull-requests: read
```

## Further reading

- [StepSecurity: hackerbot-claw exploitation analysis](https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation)
- [Upwind: hackerbot-claw pull_request_target RCE](https://www.upwind.io/feed/hackerbot-claw-github-actions-pull-request-rce)
- [GitHub Blog: How to catch workflow injections](https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/)
- [Trivy security incident discussion](https://github.com/aquasecurity/trivy/discussions/10265)

## License

MIT
