from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Principal:
    kind: str                   # "user" | "role"
    name: str
    arn: str
    documents: List[Dict[str, Any]]
    managed_arns: List[str]     # ARNs of managed policies attached (needed for CreatePolicyVersion paths)
    groups: List[str] = field(default_factory=list)
    trust: Dict[str, Any] = field(default_factory=dict)
    acct: Any = field(default=None, repr=False, compare=False)   # back-reference set by load_account
    boundary: List[Dict[str, Any]] = field(default_factory=list)   # permissions boundary documents (empty = none)

    @property
    def node(self) -> str:
        return f"{self.kind}:{self.name}"


@dataclass
class Account:
    id: str
    principals: Dict[str, Principal]    # by node id
    groups: Dict[str, Dict[str, Any]]
    overlays: List[Dict[str, Any]] = field(default_factory=list)   # org-level Deny overlays (SCP-style, Deny statements only)
    policy_versions: Optional[Dict[str, List[Dict[str, Any]]]] = None  # managed policy ARN -> NON-default version documents; None = unknown


def validate_policy(doc):
    if not isinstance(doc, dict):
        raise ValueError("policy must be an object")
    statements = doc.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        raise ValueError("policy Statement must be an object or array")
    for st in statements:
        if not isinstance(st, dict) or st.get("Effect") not in ("Allow", "Deny"):
            raise ValueError("policy statement must have Allow or Deny Effect")
        if ("Action" in st) == ("NotAction" in st):
            raise ValueError("policy statement requires Action or NotAction, not both")
        for key in ("Action", "NotAction", "Resource", "NotResource"):
            if key in st:
                values = st[key] if isinstance(st[key], list) else [st[key]]
                if not values or any(not isinstance(v, str) or not v for v in values):
                    raise ValueError(key + " must contain nonempty strings")
        if "Condition" in st and not isinstance(st["Condition"], dict):
            raise ValueError("Condition must be an object")
    return doc


def _docs(policies) -> (list, list):
    docs, arns = [], []
    for p in policies or []:
        docs.append(validate_policy(p["document"]))
        if p.get("arn"):
            arns.append(p["arn"])
    return docs, arns


def load_account(data: Dict[str, Any]) -> Account:
    if not isinstance(data, dict):
        raise ValueError("snapshot must be an object")
    acct = str(data["account"])
    groups = {g["name"]: g for g in data.get("groups", [])}
    out: Dict[str, Principal] = {}
    for u in data.get("users", []):
        docs, arns = _docs(u.get("policies"))
        for gname in u.get("groups", []):
            g = groups.get(gname)
            if g:
                gd, ga = _docs(g.get("policies"))
                docs += gd
                arns += ga
        p = Principal("user", u["name"], u.get("arn", f"arn:aws:iam::{acct}:user/{u['name']}"), docs, arns, u.get("groups", []),
                      boundary=[validate_policy(u["permissions_boundary"])] if "permissions_boundary" in u else [])
        out[p.node] = p
    for r in data.get("roles", []):
        docs, arns = _docs(r.get("policies"))
        p = Principal("role", r["name"], r.get("arn", f"arn:aws:iam::{acct}:role/{r['name']}"), docs, arns, trust=validate_policy(r["trust"]) if "trust" in r else {"Statement": []},
                      boundary=[validate_policy(r["permissions_boundary"])] if "permissions_boundary" in r else [])
        out[p.node] = p
    overlays = data.get("deny_overlays", [])
    if not isinstance(overlays, list):
        raise ValueError("deny_overlays must be an array of policy documents")
    for doc in overlays:
        validate_policy(doc)
    for doc in overlays:
        for st in (doc.get("Statement") if isinstance(doc.get("Statement"), list) else [doc.get("Statement")]):
            if st and st.get("Effect") != "Deny":
                raise ValueError("deny_overlays may only contain Deny statements (allow-list SCPs are not modelled)")
    account = Account(acct, out, groups, overlays, data.get("policy_versions"))
    for pr in out.values():
        pr.acct = account
    return account


def load_file(path: str) -> Account:
    with open(path, encoding="utf-8") as f:
        return load_account(json.load(f))
