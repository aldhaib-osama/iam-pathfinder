"""Minimal IAM policy evaluation: Allow/Deny, Action/NotAction, Resource/NotResource, wildcards.

Graph applies simplified boundaries and deny-only overlays. Not modelled: full SCPs, session policies, resource policies (other than role trust),
and most condition operators. A statement with a Condition is reported as 'conditional' rather than
silently treated as unconditional."""
from __future__ import annotations
from fnmatch import fnmatchcase
from typing import Any, Dict, Iterable, List


def _l(x) -> List[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _match_action(patterns: Iterable[str], action: str) -> bool:
    a = action.lower()
    return any(fnmatchcase(a, p.lower()) for p in patterns)


def _match_resource(patterns: Iterable[str], resource: str) -> bool:
    return any(fnmatchcase(resource, p) for p in patterns)


def statement_applies(st: Dict[str, Any], action: str, resource: str) -> bool:
    if "Action" in st:
        if not _match_action(_l(st["Action"]), action):
            return False
    elif "NotAction" in st:
        if _match_action(_l(st["NotAction"]), action):
            return False
    else:
        return False
    if "Resource" in st:
        return _match_resource(_l(st["Resource"]), resource)
    if "NotResource" in st:
        return not _match_resource(_l(st["NotResource"]), resource)
    return False


def evaluate(documents: Iterable[Dict[str, Any]], action: str, resource: str) -> str:
    """Returns 'deny', 'allow', 'conditional' or 'none'. Explicit unconditional Deny always wins."""
    result = "none"
    possible_deny = False
    for doc in documents:
        for st in _l(doc.get("Statement")):
            if not statement_applies(st, action, resource):
                continue
            eff = st.get("Effect")
            if eff == "Deny":
                if "Condition" not in st:
                    return "deny"
                possible_deny = True
            if eff == "Allow":
                if "Condition" in st:
                    result = "conditional" if result == "none" else result
                else:
                    result = "allow"
    return "conditional" if result == "allow" and possible_deny else result


def deny_state(documents, action, resource):
    """Deny effects even where a resource trust supplies the Allow."""
    conditional = False
    for doc in documents:
        for st in _l(doc.get("Statement")):
            if st.get("Effect") == "Deny" and statement_applies(st, action, resource):
                if "Condition" not in st:
                    return "deny"
                conditional = True
    return "conditional" if conditional else "none"


def is_admin(documents: Iterable[Dict[str, Any]]) -> bool:
    docs = list(documents)
    # Conservative terminal: a blanket grant without any potentially limiting Deny.
    # Evaluating action="*" alone misses denies on individual actions/resources.
    if any(st.get("Effect") == "Deny" for doc in docs for st in _l(doc.get("Statement"))):
        return False
    return any(st.get("Effect") == "Allow" and "Condition" not in st
               and "*" in _l(st.get("Action")) and "*" in _l(st.get("Resource"))
               for doc in docs for st in _l(doc.get("Statement")))


def trust_decision(trust, principal, account, service=False):
    """Return (mode, uncertain). Conditions are unknown, never silently granted.

    Only exact principals, account-root and '*' are modelled. Unsupported
    NotPrincipal can only increase uncertainty, not grant an edge.
    """
    grants = []
    uncertain_deny = False
    for st in _l(trust.get("Statement")):
        if not _match_action(_l(st.get("Action")), "sts:AssumeRole"):
            continue
        raw = st.get("Principal")
        vals = _l(raw.get("Service" if service else "AWS")) if isinstance(raw, dict) else _l(raw)
        mode = "direct" if principal in vals else ""
        if not service and any(x in vals for x in (f"arn:aws:iam::{account}:root", account, "*")):
            mode = mode or "account"
        if service and "*" in vals:
            mode = "direct"
        if "NotPrincipal" in st:
            if st.get("Effect") == "Deny":
                uncertain_deny = True
            continue
        if not mode:
            continue
        if st.get("Effect") == "Deny":
            if "Condition" not in st:
                return "", False
            uncertain_deny = True
        elif st.get("Effect") == "Allow":
            grants.append((mode, "Condition" in st))
    if not grants:
        return "", False
    mode, cond = min(grants, key=lambda pair: (pair[0] != "direct", pair[1]))
    return mode, cond or uncertain_deny


def trust_allows(trust, principal_arn, account):
    return trust_decision(trust, principal_arn, account)[0]


def trust_allows_service(trust, service):
    return bool(trust_decision(trust, service, "", service=True)[0])
