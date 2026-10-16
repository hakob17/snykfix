"""Runs Claude Code headless inside a cloned repo to make the actual fix."""
import json
import os
import subprocess
import tempfile

from .grouping import Campaign

MCP = {"mcpServers": {"snyk": {"command": "snyk", "args": ["mcp", "-t", "stdio"]}}}

COMMON = """
How to work:
1. Detect the ecosystem(s) and build tool(s) in this repo (npm/yarn/pnpm, Maven, Gradle, NuGet/dotnet, pip/poetry/uv).
2. Change manifests AND lockfiles using the ecosystem's own tooling (npm install pkg@ver, mvn versions:use-dep-version,
   gradle dependency update, dotnet add package, poetry add / pip-compile). Never hand-edit lockfiles.
3. If a vulnerable package is transitive and no parent version fixes it, use the ecosystem's override mechanism
   (npm "overrides", yarn "resolutions", Maven <dependencyManagement>, Gradle constraints, NuGet direct
   PackageReference / Central Package Management, pip constraints).
4. Build and run the test suite. Fix compile/test failures caused by the upgrade. Do not disable tests.
5. Verify with the Snyk MCP SCA scan tool (or `snyk test --all-projects`) that the listed vulns are gone.
6. Do not commit, push, or edit CI configuration.
Finish with a short markdown summary: what changed, test results, anything unresolved."""


def _vuln_table(c: Campaign) -> str:
    rows = {(f.vuln_id, f.package, f.version, ", ".join(f.fixed_in) or "none", f.severity) for f in c.findings}
    return "\n".join(f"- {v} {p}@{ver} (fixed in: {fx}; {sev})" for v, p, ver, fx, sev in sorted(rows))


def _guidance(c: Campaign) -> str:
    p = c.plan or {}
    targets = "\n".join(f"- {t['package']} -> {t['version']} ({t.get('reason', '')})" for t in p.get("targets", []))
    return f"Planner targets:\n{targets or '- none, choose yourself'}\nPlanner notes: {p.get('notes', '')}"


def fix_prompt(c: Campaign) -> str:
    if c.kind == "lib":
        head = (f"This repository builds the shared internal library `{c.package}`. Downstream repos receive the "
                f"vulnerabilities below through it. Upgrade this library's dependencies so none remain, with the "
                f"smallest safe changes, then bump the library's own version (patch, or minor if its public API "
                f"changed) following the repo's conventions so a release can be cut.")
    else:
        head = "Fix the Snyk vulnerabilities below in this repository with the smallest safe dependency upgrades."
    return f"{head}\n\nVulnerabilities:\n{_vuln_table(c)}\n\n{_guidance(c)}\n{COMMON}"


def bump_prompt(c: Campaign, version: str) -> str:
    paths = sorted({" > ".join(f.path) for f in c.findings})[:10]
    return (f"The internal library `{c.package}` released version {version}, which fixes these vulnerabilities:\n"
            f"{_vuln_table(c)}\n\nThis repo reaches them via paths like:\n" + "\n".join(f"- {p}" for p in paths) +
            f"\n\nMake this repo resolve `{c.package}` >= {version}. If it depends on `{c.package}` directly, bump it. "
            f"If it gets it through another internal library, bump that library to its newest version (which already "
            f"includes the fix). If this repo is itself a library, also bump its own version so it can be released.\n"
            f"{COMMON}")


def run(repo_dir: str, prompt: str, model: str, max_turns: int) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as mcp:
        json.dump(MCP, mcp)
    try:
        # bypassPermissions is acceptable only because this runs on an ephemeral CI runner.
        p = subprocess.run(
            ["claude", "-p", prompt, "--model", model, "--mcp-config", mcp.name,
             "--permission-mode", "bypassPermissions", "--max-turns", str(max_turns), "--output-format", "json"],
            cwd=repo_dir, capture_output=True, text=True, timeout=3600,
        )
    finally:
        os.unlink(mcp.name)
    try:
        return json.loads(p.stdout).get("result", "")
    except json.JSONDecodeError:
        return f"(agent exited {p.returncode})\n{(p.stderr or p.stdout)[-2000:]}"
