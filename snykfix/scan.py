"""Run the Snyk CLI and normalise its output. Ticket text is lossy; this is the source of truth."""
import glob
import json
import shutil
import subprocess
from dataclasses import dataclass


class ScanError(RuntimeError):
    pass


@dataclass(frozen=True)
class Finding:
    repo: str
    target: str            # manifest file, e.g. package.json, pom.xml, Api.csproj
    ecosystem: str         # npm, maven, gradle, nuget, pip, ...
    vuln_id: str           # SNYK-JS-AXIOS-1234
    cves: tuple[str, ...]
    package: str
    version: str
    severity: str
    path: tuple[str, ...]  # ("app@1.0.0", "@acme/http@2.1.0", "axios@0.21.1")
    fixed_in: tuple[str, ...]

    @property
    def ids(self) -> set[str]:
        return {self.vuln_id, *self.cves}


def pkg_name(coord: str) -> str:
    """'@acme/http@2.1.0' -> '@acme/http', 'com.acme:core@1.2' -> 'com.acme:core'."""
    i = coord.rfind("@")
    return coord[:i] if i > 0 else coord


def prescan(repo_dir: str, commands: dict[str, str]) -> None:
    for pattern, cmd in commands.items():
        if glob.glob(pattern, root_dir=repo_dir, recursive=True):
            subprocess.run(cmd, shell=True, cwd=repo_dir, check=False)


def scan_repo(repo_dir: str, repo: str) -> list[Finding]:
    p = subprocess.run([shutil.which("snyk") or "snyk", "test", "--all-projects", "--json"], cwd=repo_dir,
                       capture_output=True, text=True)
    if p.returncode not in (0, 1):  # 1 = vulns found; 2/3 = failure / no supported manifests
        raise ScanError(f"{repo}: snyk exit {p.returncode}: {(p.stderr or p.stdout)[:1500]}")
    data = json.loads(p.stdout)
    findings = []
    for proj in data if isinstance(data, list) else [data]:
        for v in proj.get("vulnerabilities", []):
            findings.append(Finding(
                repo=repo,
                target=proj.get("displayTargetFile") or proj.get("targetFile", ""),
                ecosystem=proj.get("packageManager", ""),
                vuln_id=v["id"],
                cves=tuple(v.get("identifiers", {}).get("CVE", [])),
                package=v["packageName"],
                version=v["version"],
                severity=v.get("severity", ""),
                path=tuple(v.get("from", [])),
                fixed_in=tuple(v.get("fixedIn", [])),
            ))
    return findings
