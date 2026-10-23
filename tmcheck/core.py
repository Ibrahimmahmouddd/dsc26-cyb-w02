"""tmcheck: a checker for threat models kept as YAML in the repository."""
from __future__ import annotations

import re
from dataclasses import dataclass

import yaml


class ModelError(Exception):
    """The file cannot be read as a threat model."""


@dataclass(frozen=True, order=True)
class Issue:
    ref: str
    code: str
    message: str = ""


@dataclass(frozen=True, order=True)
class Gap:
    ref: str
    category: str


@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str


SECTIONS = ("zones", "elements", "flows", "threats")
STRIDE_ORDER = "STRIDE"
KINDS = {"external_entity", "process", "data_store"}
STATUSES = {"open", "mitigated", "accepted"}
ENCRYPTED = {"https", "tls", "mtls", "sftp", "ssh"}


def load_model(path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except (OSError, UnicodeDecodeError) as e:
        raise ModelError(f"cannot read {path}: {e}") from e
    except yaml.YAMLError as e:
        raise ModelError(f"invalid YAML in {path}: {e}") from e

    if not isinstance(data, dict):
        raise ModelError("top level of the model must be a mapping")

    for name in SECTIONS:
        value = data.get(name)
        if value is None:
            data[name] = []
        elif not isinstance(value, list):
            raise ModelError(f"section '{name}' must be a list")
    return data


_APPLICABLE = {
    "external_entity": {"S", "R"},
    "process": {"S", "T", "R", "I", "D", "E"},
    "data_store": {"T", "I", "D"},
    "data_flow": {"T", "I", "D"},
}


def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    if kind not in _APPLICABLE:
        raise ValueError(f"unknown kind: {kind!r}")
    result = set(_APPLICABLE[kind])
    if kind == "data_store" and is_log:
        result.add("R")
    return result


def _valid_score(x) -> bool:
    return type(x) is int and 1 <= x <= 5


def _has_text(x) -> bool:
    return isinstance(x, str) and x.strip() != ""


def _items(model: dict, section: str) -> list[dict]:
    return [i for i in model.get(section, []) if isinstance(i, dict)]


def validate(model: dict) -> list[Issue]:
    issues: set[Issue] = set()
    zones = _items(model, "zones")
    elements = _items(model, "elements")
    flows = _items(model, "flows")
    threats = _items(model, "threats")

    # one id space for the whole model
    seen: set = set()
    for item in zones + elements + flows + threats:
        i = item.get("id")
        if i in seen:
            issues.add(Issue(str(i), "DUPLICATE_ID", "id used more than once"))
        seen.add(i)

    zone_ids = {z.get("id") for z in zones}
    elem = {e.get("id"): e for e in elements}
    flow_ids = {f.get("id") for f in flows}

    for e in elements:
        eid = str(e.get("id"))
        if e.get("kind") not in KINDS:
            issues.add(Issue(eid, "BAD_KIND", "unknown element kind"))
        if e.get("zone") not in zone_ids:
            issues.add(Issue(eid, "UNKNOWN_ZONE", "zone is not defined"))

    for f in flows:
        fid = str(f.get("id"))
        s, t = f.get("source"), f.get("target")
        if s not in elem or t not in elem:
            issues.add(Issue(fid, "UNKNOWN_REF", "source or target is not an element"))
            continue
        if s == t or (elem[s].get("kind") != "process" and elem[t].get("kind") != "process"):
            issues.add(Issue(fid, "INVALID_FLOW", "needs a process on at least one end, no self-loop"))

    for t in threats:
        tid = str(t.get("id"))
        target = t.get("target")
        if target not in elem and target not in flow_ids:
            issues.add(Issue(tid, "UNKNOWN_REF", "target is not an element or flow"))
        cat = t.get("category")
        if not (isinstance(cat, str) and len(cat) == 1 and cat in STRIDE_ORDER):
            issues.add(Issue(tid, "BAD_CATEGORY", "category must be one of S T R I D E"))
        elif target in elem:
            e = elem[target]
            try:
                ok = cat in applicable(e.get("kind"), is_log=bool(e.get("is_log", False)))
            except ValueError:
                ok = True  # bad kind is reported as BAD_KIND
            if not ok:
                issues.add(Issue(tid, "INAPPLICABLE_CATEGORY", "category does not apply to this element"))
        elif target in flow_ids:
            if cat not in applicable("data_flow"):
                issues.add(Issue(tid, "INAPPLICABLE_CATEGORY", "category does not apply to a flow"))
        for field in ("likelihood", "impact"):
            if not _valid_score(t.get(field)):
                issues.add(Issue(tid, "BAD_SCORE", f"{field} must be an integer from 1 to 5"))
        status = t.get("status")
        if status not in STATUSES:
            issues.add(Issue(tid, "BAD_STATUS", "unknown status"))
        elif status == "mitigated" and not _has_text(t.get("mitigation")):
            issues.add(Issue(tid, "MISSING_MITIGATION", "mitigated needs mitigation text"))
        elif status == "accepted" and not _has_text(t.get("justification")):
            issues.add(Issue(tid, "MISSING_JUSTIFICATION", "accepted needs justification text"))

    return sorted(issues)


def crossing_flows(model: dict) -> list[str]:
    zone_of = {e.get("id"): e.get("zone") for e in _items(model, "elements")}
    result = []
    for f in _items(model, "flows"):
        s, t = f.get("source"), f.get("target")
        if s not in zone_of or t not in zone_of:
            continue
        if zone_of[s] != zone_of[t]:
            result.append(f.get("id"))
    return result


def coverage_gaps(model: dict) -> list[Gap]:
    elements = {e.get("id"): e for e in _items(model, "elements")}
    flows = {f.get("id"): f for f in _items(model, "flows")}

    scope = {}
    for fid in crossing_flows(model):
        f = flows[fid]
        scope[fid] = ("data_flow", False)
        for end in (f.get("source"), f.get("target")):
            e = elements[end]
            scope[end] = (e.get("kind"), bool(e.get("is_log", False)))

    covered = {(t.get("target"), t.get("category")) for t in _items(model, "threats")}

    gaps = []
    for ref, (kind, is_log) in scope.items():
        try:
            cats = applicable(kind, is_log=is_log)
        except ValueError:
            continue
        for c in cats:
            if (ref, c) not in covered:
                gaps.append(Gap(str(ref), c))
    gaps.sort(key=lambda g: (g.ref, STRIDE_ORDER.index(g.category)))
    return gaps


def policy_findings(model: dict) -> list[Issue]:
    zones = {z.get("id"): z.get("trust") for z in _items(model, "zones")}
    zone_of = {e.get("id"): e.get("zone") for e in _items(model, "elements")}
    flows = {f.get("id"): f for f in _items(model, "flows")}
    findings: set[Issue] = set()

    for fid in crossing_flows(model):
        f = flows[fid]
        proto = str(f.get("protocol", "")).strip().lower()
        if proto not in ENCRYPTED:
            findings.add(Issue(str(fid), "UNENCRYPTED_CROSSING", "crossing flow is not encrypted"))
        src_trust = zones.get(zone_of[f.get("source")])
        dst_trust = zones.get(zone_of[f.get("target")])
        if (isinstance(src_trust, int) and isinstance(dst_trust, int)
                and dst_trust > src_trust and f.get("authenticated") is not True):
            findings.add(Issue(str(fid), "UNAUTHENTICATED_INBOUND", "inbound crossing is not authenticated"))

    i_targets = {t.get("target") for t in _items(model, "threats") if t.get("category") == "I"}
    for e in _items(model, "elements"):
        if e.get("kind") == "data_store" and e.get("holds_pii") is True and e.get("id") not in i_targets:
            findings.add(Issue(str(e.get("id")), "PII_STORE_WITHOUT_I_THREAT",
                               "personal data store has no information-disclosure threat"))
    return sorted(findings, key=lambda i: (i.ref, i.code))


def _level(score: int) -> str:
    if score >= 15:
        return "high"
    if score >= 8:
        return "medium"
    return "low"


def _natural_key(s: str):
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", str(s))]


def rank(model: dict) -> list[RankedThreat]:
    result = []
    for t in _items(model, "threats"):
        if t.get("status") != "open":
            continue
        lik, imp = t.get("likelihood"), t.get("impact")
        if not (_valid_score(lik) and _valid_score(imp)):
            continue
        score = lik * imp
        result.append((RankedThreat(str(t.get("id")), score, _level(score)), imp))
    result.sort(key=lambda p: (-p[0].score, -p[1], _natural_key(p[0].id)))
    return [p[0] for p in result]