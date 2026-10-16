"""Deterministic root-cause grouping.

For every vulnerable path  app -> A -> B -> vuln,  the fix belongs in the internal package
closest to the vulnerable one (B). Everything between the app and B must be bumped after B
is released, in waves: A (wave 1), then app (wave 2).
"""
from dataclasses import dataclass, field

from .ado import Ticket
from .config import Config
from .scan import Finding, pkg_name

SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Campaign:
    key: str                     # "lib:@acme/http" or "repo:acme/web"
    kind: str                    # "lib" | "repo"
    fix_repo: str                # where the code change happens
    package: str | None = None   # internal package for lib campaigns
    findings: list[Finding] = field(default_factory=list)
    tickets: set[int] = field(default_factory=set)
    consumers: dict[str, int] = field(default_factory=dict)  # repo -> wave
    notes: list[str] = field(default_factory=list)
    plan: dict = field(default_factory=dict)                 # filled by the LLM planner

    @property
    def vuln_ids(self) -> set[str]:
        return {f.vuln_id for f in self.findings}

    @property
    def worst(self) -> int:
        return min((SEVERITY.get(f.severity, 9) for f in self.findings), default=9)


def _matches(t: Ticket, f: Finding) -> bool:
    return t.repo == f.repo and bool(t.vuln_ids & f.ids)


def group(findings: list[Finding], tickets: list[Ticket], cfg: Config) -> list[Campaign]:
    camps: dict[str, Campaign] = {}
    repo_to_lib = cfg.repo_to_lib

    def get(key: str, kind: str, fix_repo: str, package: str | None = None) -> Campaign:
        return camps.setdefault(key, Campaign(key, kind, fix_repo, package))

    for f in findings:
        internal = [p for p in map(pkg_name, f.path[1:-1]) if cfg.is_internal(p)]
        root = next((p for p in reversed(internal) if p in cfg.lib_repos), None)

        if root:
            c = get(f"lib:{root}", "lib", cfg.lib_repos[root], root)
            chain = internal[:internal.index(root)]  # internal libs between app and root
            for depth, lib in enumerate(chain):
                if lib in cfg.lib_repos:
                    repo = cfg.lib_repos[lib]
                    c.consumers[repo] = max(c.consumers.get(repo, 0), len(chain) - depth)
                else:
                    c.notes.append(f"{lib} sits between {f.repo} and {root} but has no lib_repos entry")
            if f.repo != c.fix_repo:
                c.consumers[f.repo] = max(c.consumers.get(f.repo, 0), len(chain) + 1)
        elif f.repo in repo_to_lib:
            # A shared lib's own direct/transitive vuln: same campaign as its consumers' findings.
            lib = repo_to_lib[f.repo]
            c = get(f"lib:{lib}", "lib", f.repo, lib)
        else:
            c = get(f"repo:{f.repo}", "repo", f.repo)
            for p in internal:
                c.notes.append(f"path goes through internal {p} which has no lib_repos entry")

        c.findings.append(f)
        c.tickets |= {t.id for t in tickets if _matches(t, f)}

    for c in camps.values():
        c.notes = sorted(set(c.notes))
    return sorted(camps.values(), key=lambda c: (c.kind != "lib", c.worst, -len(c.tickets)))


def unmatched_tickets(tickets: list[Ticket], findings: list[Finding], scanned: set[str]) -> list[Ticket]:
    """Open tickets whose vuln no longer appears in a successful scan of their repo."""
    return [t for t in tickets
            if t.repo in scanned and t.vuln_ids
            and not any(_matches(t, f) for f in findings)]


def merge(camps: list[Campaign], src_key: str, dst_key: str) -> bool:
    """Merge src into dst only if dst's root package is on every path in src (LLM-proposed merges)."""
    by = {c.key: c for c in camps}
    src, dst = by.get(src_key), by.get(dst_key)
    if not src or not dst or src is dst or dst.kind != "lib":
        return False
    if not all(dst.package in map(pkg_name, f.path) for f in src.findings):
        return False
    dst.findings += src.findings
    dst.tickets |= src.tickets
    for repo, wave in src.consumers.items():
        dst.consumers[repo] = max(dst.consumers.get(repo, 0), wave)
    if src.fix_repo != dst.fix_repo:
        dst.consumers.setdefault(src.fix_repo, 1)
    camps.remove(src)
    return True
