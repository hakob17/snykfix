"""LLM planning pass: reviews the deterministic grouping, picks target versions, flags risk.

The model may propose merging campaigns, but merges are only applied if grouping.merge()
can prove the target lib is on every vulnerable path.
"""
import json

import anthropic

from .grouping import Campaign, merge

SYSTEM = """You are a dependency-security engineer planning remediation of Snyk findings across many repositories.
Campaigns were grouped by dependency path: a "lib" campaign fixes a shared internal library once and then
propagates a version bump to consumer repos; a "repo" campaign fixes a single repository's own dependencies.
For each campaign decide:
- target versions: the smallest version of each vulnerable (or parent) package that fixes all listed vulns;
  prefer staying within the current major version; use your knowledge of the package's changelog.
- risk: low (patch/minor, no known breaking changes), medium, high (major bump or known breaking changes).
- notes: concrete guidance for the engineer doing the change (breaking APIs, config renames, override strategy).
- merge_into: another campaign key only if that campaign's library fix would also remove ALL of this campaign's
  vulns (e.g. the vulnerable package is pulled in via that library). Otherwise null.
Call submit_plan exactly once."""

TOOL = {
    "name": "submit_plan",
    "description": "Submit the remediation plan for all campaigns.",
    "input_schema": {
        "type": "object",
        "properties": {"campaigns": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "risk": {"type": "string", "enum": ["low", "medium", "high"]},
                "targets": {"type": "array", "items": {
                    "type": "object",
                    "properties": {"package": {"type": "string"}, "version": {"type": "string"},
                                   "reason": {"type": "string"}},
                    "required": ["package", "version"]}},
                "notes": {"type": "string"},
                "merge_into": {"type": ["string", "null"]},
            },
            "required": ["key", "risk", "targets"]}}},
        "required": ["campaigns"],
    },
}


def _summary(c: Campaign) -> dict:
    vulns = {}
    for f in c.findings:
        v = vulns.setdefault(f.vuln_id, {"package": f.package, "versions": set(), "fixed_in": f.fixed_in,
                                         "severity": f.severity, "ecosystem": f.ecosystem, "paths": []})
        v["versions"].add(f.version)
        if len(v["paths"]) < 3:
            v["paths"].append(" > ".join(f.path))
    for v in vulns.values():
        v["versions"] = sorted(v["versions"])
    return {"key": c.key, "kind": c.kind, "fix_repo": c.fix_repo, "package": c.package,
            "consumers": c.consumers, "tickets": len(c.tickets), "vulns": vulns, "notes": c.notes}


def review(camps: list[Campaign], model: str) -> list[str]:
    """Attach plans to campaigns in place; returns a log of applied/rejected merges."""
    if not camps:
        return []
    msg = anthropic.Anthropic().messages.create(
        model=model, max_tokens=16000, system=SYSTEM, tools=[TOOL],
        tool_choice={"type": "tool", "name": "submit_plan"},
        messages=[{"role": "user", "content": json.dumps([_summary(c) for c in camps], default=list)}],
    )
    plan = next(b.input for b in msg.content if b.type == "tool_use")
    by = {c.key: c for c in camps}
    log = []
    for p in plan["campaigns"]:
        if p["key"] in by:
            by[p["key"]].plan = p
    for p in plan["campaigns"]:
        if p.get("merge_into"):
            ok = merge(camps, p["key"], p["merge_into"])
            log.append(f"{'merged' if ok else 'rejected merge'} {p['key']} -> {p['merge_into']}")
    return log
