from dataclasses import dataclass

import yaml


class ModelError(Exception):
    pass


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

def crossing_flows(model: dict) -> list[str]:
    zone_of = {e["id"]: e["zone"] for e in model["elements"]}
    result = []
    for f in model["flows"]:
        src, dst = f["source"], f["target"]
        if src not in zone_of or dst not in zone_of:
            continue
        if zone_of[src] != zone_of[dst]:
            result.append(f["id"])
    return result