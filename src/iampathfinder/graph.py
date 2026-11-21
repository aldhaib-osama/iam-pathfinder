"""Builds a principal graph where an edge P -> Q means "P can become / act as Q" through a known technique,
then finds shortest escalation paths to an admin principal. Technique list follows publicly documented
IAM privilege-escalation research (for example Rhino Security Labs' catalogue); it is a subset."""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional

from .model import Account, Principal
from .policy import evaluate, is_admin, trust_decision, deny_state

ADMIN = "ADMIN"


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    technique: str
    conditional: bool = False


def _can(p: Principal, action: str, resource: str):
    """Effective permission: identity policies AND permissions boundary AND no org Deny overlay.
    Returns (possible, conditional). Anything unresolved is reported as conditional, never as certain."""
    r = evaluate(p.documents, action, resource)
    if r in ("none", "deny"):
        return False, False
    cond = r == "conditional"
    if p.boundary:
        b = evaluate(p.boundary, action, resource)
        if b in ("none", "deny"):
            return False, False
        cond |= b == "conditional"
    if p.acct is not None and p.acct.overlays:
        o = deny_state(p.acct.overlays, action, resource)
        if o == "deny":
            return False, False
        cond |= o == "conditional"
    return True, cond


IAM_PROBES = ("iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:CreatePolicyVersion", "iam:CreateAccessKey", "sts:AssumeRole")


def _org_restricts_iam(acct):
    """Conservative terminal check, including resource-specific and conditional Deny.

    An overlay denying unrelated service actions does not constrain an IAM admin
    terminal. Unrecognised patterns are treated as potentially restrictive.
    """
    for doc in acct.overlays if acct else []:
        statements = doc.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        for st in statements:
            actions = st.get("Action", [])
            if not isinstance(actions, list):
                actions = [actions]
            if "NotAction" in st or any(":" not in a or a.split(":", 1)[0].lower() in ("iam", "sts", "*") or any(c in a.split(":", 1)[0] for c in "*?[") for a in actions):
                return True
    return False


def _admin(p: Principal) -> bool:
    """Conservative IAM-admin terminal, not a complete account administrator."""
    return (is_admin(p.documents) and (not p.boundary or is_admin(p.boundary))
            and not _org_restricts_iam(p.acct))


def _trust_limits(p, role_arn):
    """Direct same-account trust bypasses identity implicit Deny, never explicit Deny.

    This subset conservatively requires a boundary Allow when one exists, even
    for a directly named user. AWS has principal-type-specific exceptions.
    """
    status = deny_state(p.documents, "sts:AssumeRole", role_arn)
    if status == "deny":
        return False, False
    cond = status == "conditional"
    if p.boundary:
        boundary = evaluate(p.boundary, "sts:AssumeRole", role_arn)
        if boundary in ("deny", "none"):
            return False, False
        cond |= boundary == "conditional"
    overlay = deny_state(p.acct.overlays if p.acct else [], "sts:AssumeRole", role_arn)
    return overlay != "deny", cond or overlay == "conditional"


def _self_admin_possible(p):
    # Editing identity policies cannot remove a boundary or an organisation Deny.
    return (not p.boundary or is_admin(p.boundary)) and not _org_restricts_iam(p.acct)


def _all(p: Principal, checks):
    ok, cond = True, False
    for action, res in checks:
        a, c = _can(p, action, res)
        ok &= a
        cond |= c
    return ok, cond


def build_edges(acct: Account) -> List[Edge]:
    edges: List[Edge] = []
    ps = acct.principals
    for p in ps.values():
        if _admin(p):
            edges.append(Edge(p.node, ADMIN, "already admin"))
            continue
        # Self-escalation: change own permissions.
        own_checks = []
        if p.kind == "user":
            own_checks += [("iam:AttachUserPolicy", p.arn, "iam:AttachUserPolicy on self"),
                           ("iam:PutUserPolicy", p.arn, "iam:PutUserPolicy on self")]
            for g in p.groups:
                garn = acct.groups.get(g, {}).get("arn", f"arn:aws:iam::{acct.id}:group/{g}")
                own_checks += [("iam:AttachGroupPolicy", garn, f"iam:AttachGroupPolicy on group {g}"),
                               ("iam:PutGroupPolicy", garn, f"iam:PutGroupPolicy on group {g}")]
        else:
            own_checks += [("iam:AttachRolePolicy", p.arn, "iam:AttachRolePolicy on self"),
                           ("iam:PutRolePolicy", p.arn, "iam:PutRolePolicy on self")]
        for m in p.managed_arns:
            own_checks += [("iam:CreatePolicyVersion", m, f"iam:CreatePolicyVersion on {m}"),
                           ("iam:SetDefaultPolicyVersion", m, f"iam:SetDefaultPolicyVersion on {m}")]
        for action, res, label in own_checks:
            ok, c = _can(p, action, res)
            if not _self_admin_possible(p):
                continue
            if ok and action == "iam:SetDefaultPolicyVersion" and acct.policy_versions is not None:
                # Prerequisite known from the export: only useful if an existing non-default version is admin-level.
                if not any(is_admin([d]) for d in acct.policy_versions.get(res, [])):
                    continue
                edges.append(Edge(p.node, ADMIN, label + " (existing admin-level version found)", c or any(st.get("Effect") == "Deny" for doc in p.documents for st in (doc.get("Statement", []) if isinstance(doc.get("Statement", []), list) else [doc["Statement"]]))))
                continue
            if ok:
                edges.append(Edge(p.node, ADMIN, label, c or (action == "iam:SetDefaultPolicyVersion" and acct.policy_versions is None) or any(st.get("Effect") == "Deny" for doc in p.documents for st in (doc.get("Statement", []) if isinstance(doc.get("Statement", []), list) else [doc["Statement"]]))))
        for q in ps.values():
            if q.node == p.node:
                continue
            if q.kind == "user":
                for action in ("iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile"):
                    ok, c = _can(p, action, q.arn)
                    if ok:
                        edges.append(Edge(p.node, q.node, action, c))
            else:
                mode, trust_cond = trust_decision(q.trust, p.arn, acct.id)
                trust_ok, limits_cond = _trust_limits(p, q.arn)
                identity_deny = deny_state(p.documents, "sts:AssumeRole", q.arn)
                if mode == "direct" and trust_ok:
                    edges.append(Edge(p.node, q.node, "sts:AssumeRole (named in trust policy)", trust_cond or limits_cond))
                elif mode == "account":
                    ok, c = _can(p, "sts:AssumeRole", q.arn)
                    if ok:
                        edges.append(Edge(p.node, q.node, "sts:AssumeRole (account-wide trust + identity allow)", c or trust_cond))
                ok, c = _can(p, "iam:UpdateAssumeRolePolicy", q.arn)
                if ok and trust_ok:
                    edges.append(Edge(p.node, q.node, "iam:UpdateAssumeRolePolicy then sts:AssumeRole", c or limits_cond))
                for svc, extra in (("lambda.amazonaws.com", ["lambda:CreateFunction", "lambda:InvokeFunction"]),
                                   ("ec2.amazonaws.com", ["ec2:RunInstances"])):
                    svc_mode, svc_cond = trust_decision(q.trust, svc, "", service=True)
                    if svc_mode:
                        ok, c = _all(p, [("iam:PassRole", q.arn)] + [(a, "*") for a in extra])
                        if ok:
                            edges.append(Edge(p.node, q.node, f"iam:PassRole + {' + '.join(extra)}", c or svc_cond))
    return edges


def find_paths(acct: Account, include_conditional: bool = True) -> Dict[str, Optional[List[Edge]]]:
    """Shortest escalation path (list of edges) for every non-admin principal, or None if none found."""
    edges = [e for e in build_edges(acct) if include_conditional or not e.conditional]
    adj: Dict[str, List[Edge]] = {}
    for e in edges:
        adj.setdefault(e.src, []).append(e)
    result: Dict[str, Optional[List[Edge]]] = {}
    for start in acct.principals:
        if any(e.technique == "already admin" for e in adj.get(start, [])):
            continue
        prev: Dict[str, Edge] = {}
        seen = {start}
        dq = deque([start])
        found = None
        while dq and not found:
            n = dq.popleft()
            for e in adj.get(n, []):
                if e.dst in seen:
                    continue
                seen.add(e.dst)
                prev[e.dst] = e
                if e.dst == ADMIN or any(x.technique == "already admin" for x in adj.get(e.dst, [])):
                    found = e.dst
                    break
                dq.append(e.dst)
        if found:
            path, cur = [], found
            while cur != start:
                path.append(prev[cur])
                cur = prev[cur].src
            path.reverse()
            if path[-1].dst != ADMIN:
                path.append(next(x for x in adj[path[-1].dst] if x.technique == "already admin"))
            result[start] = path
        else:
            result[start] = None
    return result


def to_dot(acct: Account) -> str:
    lines = ["digraph iam {", "  rankdir=LR;"]
    for e in build_edges(acct):
        style = ' style=dashed' if e.conditional else ''
        import json
        lines.append(f'  {json.dumps(e.src)} -> {json.dumps(e.dst)} [label={json.dumps(e.technique)}{style}];')
    lines.append("}")
    return "\n".join(lines)
