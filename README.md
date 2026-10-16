# snykfix

Collapses many Snyk tickets in Azure DevOps into a few root-cause fixes, fixes them with Claude Code,
verifies with Snyk, and propagates shared-library fixes to consumer repos as PRs.

```
ADO tickets ─► snyk test (every repo) ─► group by dependency path ─► LLM plan ─► agent fix ─► snyk re-scan ─► PR
                                               │                                                          │
                                               └─ shared lib? fix once ─► release ─► bump PRs, wave by wave ┘
```

Supports npm/yarn/pnpm, Maven, Gradle, NuGet and pip/poetry. Runs as a scheduled GitHub Action.

## How it works

1. **Ingest**: a WIQL query pulls open Snyk work items from your ADO project/board. Repo, Snyk IDs and CVEs
   are extracted from each ticket.
2. **Scan**: `snyk test --all-projects` on every ticket repo, every shared lib repo and every `extra_repos`
   entry. The scan is the source of truth, because ticket text is lossy.
3. **Group**: for each vulnerable path `app > @acme/sdk > @acme/http > axios`, the fix goes in the internal
   package closest to the vulnerable one (`@acme/http`). The libs between it and the app are bumped in waves
   (`@acme/sdk` = wave 1, `app` = wave 2). Paths with no internal lib become single-repo campaigns.
4. **Plan (LLM)**: Opus picks target versions, rates risk, writes fix notes, and may propose merges.
   A merge is only applied if the target lib is on every vulnerable path.
5. **Fix (agent)**: Claude Code runs headless in a fresh clone with the Snyk MCP server. It upgrades the
   dependencies (using overrides where needed), builds, tests, fixes breakages, and bumps the lib's version.
6. **Verify**: Snyk re-scan before pushing. The PR opens as a **draft** if a targeted vuln remains.
   Snyk's GitHub PR check runs on top of that.
7. **Propagate**: once the lib has a GitHub Release published after its fix PR merged, bump PRs open in
   consumers, wave by wave.
8. **Close the loop**: PRs reference `AB#<id>`, tickets get a link and a comment, and tickets whose vuln no
   longer appears in a scan are moved to `resolved_state`.

Nothing is stored between runs. Each run reads state from GitHub (branch names `snykfix/...`, PRs, releases)
and Snyk, so it's safe to re-run. No more than `max_prs_per_run` PRs open per run. **Nothing is merged or
published automatically.**

## Setup

### 1. Config
Copy `config.example.yaml` to `config.yaml` and set:
- `ado_org`, `ado_project`, `wiql`: which board to read. Filter by `[System.AreaPath] UNDER '...'`,
  tags, work item type, etc.
- `internal_patterns`: how to recognise your own packages (`@acme/*`, `com.acme*`, `Acme.*`, `acme-*`).
- `lib_repos`: each internal package mapped to the GitHub repo that builds it.
- `resolved_state`: must be a valid state in your ADO process (`Resolved`, `Done`, ...).

`config.yaml` is gitignored by default. If you want the workflow to use it, remove that line from
`.gitignore` and commit it. It holds no secrets.

### 2. Secrets (GitHub → Settings → Secrets and variables → Actions)

| Name | Type | What / how |
|---|---|---|
| `ADO_PAT` | secret | ADO → User settings → Personal access tokens. Scope **Work Items (Read & Write)**. Use a bot account. Max lifetime is 1 year. |
| `SNYK_TOKEN` | secret | Snyk → Org settings → **Service accounts** (role: Org Collaborator). |
| `SNYK_CFG_ORG` | variable | Your Snyk org slug. |
| `ANTHROPIC_API_KEY` | secret | console.anthropic.com → API keys. |
| `SNYKFIX_GH_TOKEN` | secret | GitHub App installation token or fine-grained PAT with **Contents R/W**, **Pull requests R/W**, **Metadata R** on all target repos. The default `GITHUB_TOKEN` can't reach other repos. |

Using a GitHub App (recommended): store `SNYKFIX_APP_ID` and `SNYKFIX_APP_KEY`, then add this step before Run
and set `GH_TOKEN: ${{ steps.app.outputs.token }}`:
```yaml
- id: app
  uses: actions/create-github-app-token@v1
  with:
    app-id: ${{ secrets.SNYKFIX_APP_ID }}
    private-key: ${{ secrets.SNYKFIX_APP_KEY }}
    owner: ${{ github.repository_owner }}
```

### 3. Snyk on GitHub
Import the repos through Snyk's GitHub integration and enable **PR status checks**. Disable Snyk's own
automatic fix PRs so they don't duplicate snykfix's.

### 4. Run
Actions → snykfix → Run workflow with `dry_run: true`. Review the campaign report in the job summary and the
`snykfix-report` artifact. Then run with `dry_run: false`, or let the weekday schedule take over. Use `only`
to act on a single campaign, e.g. `lib:@acme/http-client`.

## Local use
```bash
pip install -e '.[dev]'
cp .env.example .env    # fill in
set -a; source .env; set +a
snykfix plan --config config.yaml           # dry run, writes snykfix-report.md/.json
snykfix run  --config config.yaml --only lib:@acme/http-client
pytest
```
Requires `snyk`, `gh` and `claude` (`npm i -g snyk @anthropic-ai/claude-code`) on PATH, plus the toolchains
your repos need.

## Layout
```
snykfix/ado.py       ADO WIQL query, ticket parsing, link/comment/resolve
snykfix/scan.py      snyk CLI wrapper -> Finding
snykfix/grouping.py  root-cause grouping, waves, validated merges
snykfix/llm.py       Claude planning pass (structured output)
snykfix/agent.py     Claude Code headless fix/bump prompts
snykfix/gh.py        gh/git: clone, PRs, releases
snykfix/cli.py       orchestration + report
```

## Known limits
- npm libs: the lib's own lockfile can be clean while consumers still resolve an old version through a
  loose range. The agent is told to raise the declared minimum, but check this in review.
- Release detection reads GitHub Releases tagged `v1.2.3` or `pkg@1.2.3`. Adapt `gh.release_after` if you
  publish without releases.
- Reads one ADO project per run.
- The agent runs with `bypassPermissions`, which is acceptable only on ephemeral CI runners.
