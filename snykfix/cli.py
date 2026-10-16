"""snykfix plan | run

plan: pull ADO tickets, scan repos with Snyk, group by root cause, LLM review, write report.
run:  plan + act. Every action is derived from current GitHub/Snyk state, so it is safe to re-run:
  - lib campaign, lib still vulnerable      -> agent fixes the lib, opens PR (draft if Snyk still flags it)
  - lib fixed + released                    -> open bump PRs in consumers, wave by wave
  - repo campaign                           -> agent fixes the repo, opens PR
  - open ticket whose vuln is gone          -> resolve ticket
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from dataclasses import asdict

from . import agent, gh, llm
from .ado import Ado, Ticket
from .config import Config, load
from .grouping import Campaign, group, unmatched_tickets
from .scan import Finding, ScanError, prescan, scan_repo


def slug(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", s).strip("-").lower()


def short_hash(ids: set[str]) -> str:
    return hashlib.sha1(",".join(sorted(ids)).encode()).hexdigest()[:8]


class Runner:
    def __init__(self, cfg: Config, workdir: str, use_llm: bool):
        self.cfg, self.workdir, self.use_llm = cfg, workdir, use_llm
        self.ado = Ado(cfg.ado_org, cfg.ado_project)
        self.log: list[str] = []
        self.budget = cfg.max_prs_per_run

    def say(self, msg: str) -> None:
        print(msg, flush=True)
        self.log.append(msg)

    def checkout(self, repo: str, kind: str) -> str:
        d = os.path.join(self.workdir, kind, repo.replace("/", "__"))
        shutil.rmtree(d, ignore_errors=True)
        gh.clone(repo, d)
        return d

    def scan(self, repo: str, d: str) -> list[Finding]:
        prescan(d, self.cfg.prescan)
        return scan_repo(d, repo)

    # ---------- plan ----------
    def plan(self) -> None:
        self.tickets = self.ado.query(self.cfg.wiql, self.cfg.repo_regex)
        self.by_id = {t.id: t for t in self.tickets}
        no_repo = [t.id for t in self.tickets if not t.repo]
        if no_repo:
            self.say(f"tickets with no repo found by repo_regex: {no_repo}")

        repos = sorted({t.repo for t in self.tickets if t.repo} | set(self.cfg.extra_repos)
                       | set(self.cfg.lib_repos.values()))
        self.findings: list[Finding] = []
        self.scanned: set[str] = set()
        for repo in repos:
            try:
                self.findings += self.scan(repo, self.checkout(repo, "scan"))
                self.scanned.add(repo)
            except (ScanError, Exception) as e:  # one broken repo must not stop the run
                self.say(f"scan failed {repo}: {e}")

        self.camps = group(self.findings, self.tickets, self.cfg)
        if self.use_llm:
            self.log += llm.review(self.camps, self.cfg.planner_model)
        self.stale = unmatched_tickets(self.tickets, self.findings, self.scanned)
        self.say(f"{len(self.tickets)} tickets -> {len(self.camps)} campaigns; {len(self.stale)} tickets look fixed")

    # ---------- act ----------
    def act(self, only: str | None) -> None:
        if self.cfg.auto_resolve:
            for t in self.stale:
                self.ado.resolve(t.id, self.cfg.resolved_state,
                                 f"snykfix: latest Snyk scan of {t.repo} no longer reports {', '.join(sorted(t.vuln_ids))}.")
                self.say(f"resolved AB#{t.id}")
        for c in self.camps:
            if only and c.key != only:
                continue
            try:
                self.handle(c)
            except Exception as e:
                self.say(f"{c.key}: error {e}")

    def handle(self, c: Campaign) -> None:
        own = {f.vuln_id for f in c.findings if f.repo == c.fix_repo}
        if c.kind == "repo" or own or c.fix_repo not in self.scanned:
            branch = f"snykfix/{slug(c.key)}-{short_hash(own or c.vuln_ids)}"
            pr = gh.find_pr(c.fix_repo, branch)
            if pr:
                self.say(f"{c.key}: fix PR {pr['state'].lower()} {pr['url']}")
                return
            self.open_pr(c, c.fix_repo, branch, f"fix(security): {c.key} Snyk remediation",
                         agent.fix_prompt(c), c.vuln_ids, c.tickets)
            return

        # Lib's default branch is clean: propagate once a release exists.
        last = json.loads(gh.sh("gh", "pr", "list", "--repo", c.fix_repo, "--state", "merged", "--limit", "1",
                                "--search", "head:snykfix/", "--json", "mergedAt") or "[]")
        version = gh.release_after(c.fix_repo, last[0]["mergedAt"] if last else "1970-01-01T00:00:00Z")
        if not version:
            self.say(f"{c.key}: fixed on default branch, waiting for a release of {c.fix_repo}")
            return
        self.propagate(c, version)

    def propagate(self, c: Campaign, version: str) -> None:
        branch = f"snykfix/bump-{slug(c.package)}-{slug(version)}"
        for wave in sorted(set(c.consumers.values())):
            pending = False
            for repo in sorted(r for r, w in c.consumers.items() if w == wave):
                pr = gh.find_pr(repo, branch)
                if pr is None:
                    ids = {f.vuln_id for f in c.findings if f.repo == repo}
                    tix = {t for t in c.tickets if self.by_id[t].repo == repo}
                    self.open_pr(c, repo, branch, f"chore(deps): bump {c.package} to {version} (security)",
                                 agent.bump_prompt(c, version), ids, tix)
                    pending = True
                elif pr["state"] != "MERGED":
                    pending = True
                elif repo in self.cfg.repo_to_lib and not gh.release_after(repo, pr["mergedAt"]):
                    self.say(f"{c.key}: wave {wave} lib {repo} merged, waiting for its release")
                    pending = True
            if pending:
                self.say(f"{c.key}: wave {wave} in progress, later waves wait")
                return

    def open_pr(self, c: Campaign, repo: str, branch: str, title: str, prompt: str,
                expected: set[str], ticket_ids: set[int]) -> None:
        if self.budget <= 0:
            self.say(f"{c.key}: PR budget exhausted, skipping {repo}")
            return
        d = self.checkout(repo, "fix")
        summary = agent.run(d, prompt, self.cfg.fix_model, self.cfg.fix_max_turns)
        if not gh.has_changes(d):
            self.say(f"{c.key}: agent made no changes in {repo}\n{summary[-500:]}")
            return
        refs = " ".join(f"AB#{t}" for t in sorted(ticket_ids))
        gh.commit(d, branch, f"{title}\n\n{refs}")

        try:
            remaining = expected & {f.vuln_id for f in self.scan(repo, d)}
            verdict = "✅ Snyk re-scan: all targeted vulnerabilities resolved" if not remaining else \
                f"⚠️ Snyk re-scan still reports: {', '.join(sorted(remaining))}"
        except ScanError as e:
            remaining, verdict = expected, f"⚠️ Snyk re-scan failed: {e}"

        gh.push(d, branch)
        risk = c.plan.get("risk", "unknown")
        body = (f"Automated by **snykfix** — campaign `{c.key}` (risk: {risk}).\n\n{verdict}\n\n"
                f"### Vulnerabilities\n{agent._vuln_table(c)}\n\n### Agent summary\n{summary}\n\n"
                f"Work items: {refs or 'none'}")
        url = gh.create_pr(repo, d, branch, title, body, draft=bool(remaining))
        self.budget -= 1
        self.say(f"{c.key}: opened {'draft ' if remaining else ''}PR {url}")
        for t in ticket_ids:
            self.ado.link(t, url)
            self.ado.comment(t, f"snykfix opened <a href='{url}'>{url}</a> (campaign {c.key}). {verdict}")

    # ---------- report ----------
    def report(self, path: str) -> None:
        rows = ["| Campaign | Fix repo | Tickets | Vulns | Consumers (wave) | Risk |", "|---|---|---|---|---|---|"]
        for c in self.camps:
            cons = ", ".join(f"{r} ({w})" for r, w in sorted(c.consumers.items())) or "-"
            rows.append(f"| `{c.key}` | {c.fix_repo} | {len(c.tickets)} | {len(c.vuln_ids)} | {cons} | "
                        f"{c.plan.get('risk', '-')} |")
        md = "# snykfix report\n\n" + "\n".join(rows) + "\n\n## Log\n" + "\n".join(f"- {l}" for l in self.log)
        with open(path + ".md", "w") as f:
            f.write(md)
        with open(path + ".json", "w") as f:
            json.dump({"campaigns": [asdict(c) for c in self.camps],
                       "stale_tickets": [asdict(t) for t in self.stale], "log": self.log},
                      f, indent=2, default=list)


def main() -> None:
    ap = argparse.ArgumentParser(prog="snykfix")
    ap.add_argument("command", choices=["plan", "run"])
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--only", help="act on a single campaign key, e.g. lib:@acme/http")
    ap.add_argument("--workdir", default="work")
    ap.add_argument("--report", default="snykfix-report")
    ap.add_argument("--no-llm", action="store_true")
    a = ap.parse_args()

    r = Runner(load(a.config), a.workdir, use_llm=not a.no_llm)
    r.plan()
    if a.command == "run":
        r.act(a.only)
    r.report(a.report)


if __name__ == "__main__":
    sys.exit(main())
