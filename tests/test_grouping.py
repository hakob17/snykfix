from snykfix.ado import Ticket, parse
from snykfix.config import Config
from snykfix.grouping import group, merge, unmatched_tickets
from snykfix.scan import Finding, pkg_name

CFG = Config(ado_org="o", ado_project="p", wiql="",
             internal_patterns=["@acme/*", "com.acme*"],
             lib_repos={"@acme/http": "acme/http", "@acme/sdk": "acme/sdk", "com.acme:core": "acme/core"})


def f(repo, path, vid="SNYK-JS-AXIOS-1", sev="high"):
    name = pkg_name(path[-1])
    return Finding(repo, "package.json", "npm", vid, ("CVE-2023-1",), name, path[-1].rsplit("@", 1)[1],
                   sev, tuple(path), ("1.6.0",))


def test_pkg_name():
    assert pkg_name("@acme/http@2.1.0") == "@acme/http"
    assert pkg_name("com.acme:core@1.2") == "com.acme:core"
    assert pkg_name("lodash") == "lodash"


def test_shared_lib_collapses_many_repos():
    fs = [f(r, [f"{r}@1.0.0", "@acme/http@2.1.0", "axios@0.21.1"]) for r in ("acme/a", "acme/b", "acme/c")]
    tix = [Ticket(i, "", "New", r, {"SNYK-JS-AXIOS-1"}) for i, r in enumerate(("acme/a", "acme/b", "acme/c"))]
    (c,) = group(fs, tix, CFG)
    assert c.key == "lib:@acme/http" and c.fix_repo == "acme/http"
    assert c.consumers == {"acme/a": 1, "acme/b": 1, "acme/c": 1}
    assert c.tickets == {0, 1, 2}


def test_nested_libs_get_waves_and_deepest_lib_is_root():
    fs = [f("acme/app", ["app@1", "@acme/sdk@3", "@acme/http@2", "axios@0.21.1"])]
    (c,) = group(fs, [], CFG)
    assert c.key == "lib:@acme/http"
    assert c.consumers == {"acme/sdk": 1, "acme/app": 2}


def test_lib_own_scan_joins_lib_campaign_and_direct_deps_are_repo_campaigns():
    fs = [f("acme/http", ["@acme/http@2", "axios@0.21.1"]),
          f("acme/web", ["web@1", "lodash@4.17.0"], vid="SNYK-JS-LODASH-1", sev="critical")]
    camps = group(fs, [], CFG)
    assert [c.key for c in camps] == ["lib:@acme/http", "repo:acme/web"]  # libs first
    assert camps[0].consumers == {}


def test_merge_only_when_lib_on_every_path():
    fs = [f("acme/a", ["a@1", "@acme/http@2", "axios@0.21.1"]),
          f("acme/b", ["b@1", "lodash@4.17.0"], vid="SNYK-JS-LODASH-1")]
    camps = group(fs, [], CFG)
    assert not merge(camps, "repo:acme/b", "lib:@acme/http")
    assert len(camps) == 2


def test_stale_tickets_detected():
    tix = [Ticket(1, "", "New", "acme/a", {"SNYK-JS-GONE-9"}), Ticket(2, "", "New", "acme/z", {"X"})]
    stale = unmatched_tickets(tix, [f("acme/a", ["a@1", "axios@0.21.1"])], scanned={"acme/a"})
    assert [t.id for t in stale] == [1]  # acme/z not scanned -> not touched


def test_parse_ticket():
    item = {"id": 7, "fields": {"System.Title": "Snyk: SNYK-JS-AXIOS-6032459 in axios",
                                "System.State": "New",
                                "System.Description": "<p>Project https://github.com/acme/web.git &amp; CVE-2023-45857</p>"}}
    t = parse(item, CFG.repo_regex)
    assert t.repo == "acme/web" and t.vuln_ids == {"SNYK-JS-AXIOS-6032459", "CVE-2023-45857"}
