import fnmatch
from dataclasses import dataclass, field

import yaml


@dataclass
class Config:
    ado_org: str
    ado_project: str
    wiql: str
    # Regex with one group that captures "owner/repo" from the ticket title/description.
    repo_regex: str = r"github\.com/([\w.-]+/[\w.-]+)"
    # Glob patterns that identify your own packages, any ecosystem:
    # "@acme/*" (npm), "com.acme*" (maven group:artifact), "Acme.*" (nuget), "acme-*" (pip)
    internal_patterns: list[str] = field(default_factory=list)
    # Internal package -> GitHub repo that builds it. Needed to fix a shared lib.
    lib_repos: dict[str, str] = field(default_factory=dict)
    # Repos to scan even if they have no open ticket (catches consumers of shared libs).
    extra_repos: list[str] = field(default_factory=list)
    # Glob -> shell command, run before `snyk test` when the glob matches (restore deps).
    prescan: dict[str, str] = field(default_factory=dict)
    max_prs_per_run: int = 5
    auto_resolve: bool = True
    resolved_state: str = "Resolved"
    planner_model: str = "claude-opus-5-5"
    fix_model: str = "claude-sonnet-5-5"
    fix_max_turns: int = 80

    def is_internal(self, pkg: str) -> bool:
        return any(fnmatch.fnmatch(pkg, p) for p in self.internal_patterns)

    @property
    def repo_to_lib(self) -> dict[str, str]:
        return {repo: pkg for pkg, repo in self.lib_repos.items()}


def load(path: str) -> Config:
    with open(path) as f:
        return Config(**yaml.safe_load(f))
