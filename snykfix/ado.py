"""Azure DevOps Boards: read Snyk work items, link PRs, comment, resolve."""
import base64
import html
import os
import re
from dataclasses import dataclass, field

import requests

API = "7.1"
SNYK_ID = re.compile(r"SNYK-[A-Z0-9]+-[A-Z0-9_.\-]+-\d+")
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")
TEXT_FIELDS = ("System.Title", "System.Description", "Microsoft.VSTS.TCM.ReproSteps", "System.Tags")


@dataclass
class Ticket:
    id: int
    title: str
    state: str
    repo: str | None
    vuln_ids: set[str] = field(default_factory=set)  # Snyk IDs and CVEs


class Ado:
    def __init__(self, org: str, project: str):
        token = base64.b64encode(f":{os.environ['ADO_PAT']}".encode()).decode()
        self.base = f"https://dev.azure.com/{org}/{project}/_apis/wit"
        self.s = requests.Session()
        self.s.headers["Authorization"] = f"Basic {token}"

    def query(self, wiql: str, repo_regex: str) -> list[Ticket]:
        r = self.s.post(f"{self.base}/wiql", params={"api-version": API}, json={"query": wiql})
        r.raise_for_status()
        ids = [w["id"] for w in r.json()["workItems"]]
        tickets = []
        for i in range(0, len(ids), 200):
            r = self.s.get(f"{self.base}/workitems", params={
                "ids": ",".join(map(str, ids[i:i + 200])),
                "fields": ",".join(("System.State",) + TEXT_FIELDS),
                "api-version": API,
            })
            r.raise_for_status()
            tickets += [parse(item, repo_regex) for item in r.json()["value"]]
        return tickets

    def comment(self, wid: int, text: str) -> None:
        self.s.post(f"{self.base}/workItems/{wid}/comments", params={"api-version": "7.1-preview.4"},
                    json={"text": text}).raise_for_status()

    def _patch(self, wid: int, ops: list[dict]) -> requests.Response:
        return self.s.patch(f"{self.base}/workitems/{wid}", params={"api-version": API}, json=ops,
                            headers={"Content-Type": "application/json-patch+json"})

    def link(self, wid: int, url: str) -> None:
        # 400 when the link already exists; that's fine.
        self._patch(wid, [{"op": "add", "path": "/relations/-",
                           "value": {"rel": "Hyperlink", "url": url}}])

    def resolve(self, wid: int, state: str, note: str) -> None:
        self._patch(wid, [{"op": "add", "path": "/fields/System.State", "value": state}]).raise_for_status()
        self.comment(wid, note)


def parse(item: dict, repo_regex: str) -> Ticket:
    f = item["fields"]
    text = html.unescape(re.sub(r"<[^>]+>", " ", " ".join(str(f.get(k, "")) for k in TEXT_FIELDS)))
    m = re.search(repo_regex, text)
    return Ticket(
        id=item["id"],
        title=f.get("System.Title", ""),
        state=f.get("System.State", ""),
        repo=m.group(1).removesuffix(".git") if m else None,
        vuln_ids=set(SNYK_ID.findall(text)) | set(CVE_ID.findall(text)),
    )
