"""Convert raw `aws iam get-account-authorization-details` output into the snapshot format.

Read-only offline conversion: this module never calls AWS. Produce the input yourself, for example:
    aws iam get-account-authorization-details --output json > auth.json
Handles URL-encoded policy documents (as returned by the raw API), inline and attached managed policies,
group membership, permissions boundaries and non-default managed policy versions."""
from __future__ import annotations
import json
import urllib.parse
from typing import Any, Dict, List, Optional
from .model import validate_policy


def _doc(d: Any) -> Dict[str, Any]:
    if isinstance(d, str):
        d = json.loads(urllib.parse.unquote(d))
    if not isinstance(d, dict) or "Statement" not in d:
        raise ValueError("policy document has no Statement")
    return validate_policy(d)


def _account_from_arn(arn: str) -> str:
    parts = arn.split(":")
    if len(parts) < 5 or not parts[4]:
        raise ValueError(f"cannot read account id from ARN {arn!r}")
    return parts[4]


def from_authorization_details(raw: Dict[str, Any], deny_overlays: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("export must be an object")
    if raw.get("IsTruncated") or raw.get("Marker"):
        raise ValueError("paginated export is incomplete; combine all pages first")
    users, roles, groups_raw = raw.get("UserDetailList", []), raw.get("RoleDetailList", []), raw.get("GroupDetailList", [])
    if not (users or roles or groups_raw):
        raise ValueError("input has no UserDetailList/RoleDetailList/GroupDetailList (is it get-account-authorization-details output?)")
    for collection in (users, roles, groups_raw, raw.get("Policies", [])):
        if not isinstance(collection, list) or any(not isinstance(item, dict) for item in collection):
            raise ValueError("export collections must be arrays of objects")
    sample = (users or roles or groups_raw)[0]["Arn"]
    account = _account_from_arn(sample)

    for item in users + roles + groups_raw:
        if _account_from_arn(item["Arn"]) != account:
            raise ValueError("mixed-account export is not supported")
    managed: Dict[str, Dict[str, Any]] = {}      # arn -> {"default": doc, "others": [docs]}
    for pol in raw.get("Policies", []):
        arn = pol["Arn"]
        default_id = pol.get("DefaultVersionId")
        entry = {"default": None, "others": []}
        for v in pol.get("PolicyVersionList", []):
            doc = _doc(v["Document"])
            if v.get("IsDefaultVersion") or v.get("VersionId") == default_id:
                if entry["default"] is not None:
                    raise ValueError("multiple default policy versions in export")
                entry["default"] = doc
            else:
                entry["others"].append(doc)
        managed[arn] = entry

    def policies(inline, attached):
        out = []
        for ip in inline or []:
            out.append({"name": ip["PolicyName"], "document": _doc(ip["PolicyDocument"])})
        for ap in attached or []:
            m = managed.get(ap["PolicyArn"])
            if m and m["default"]:
                out.append({"name": ap["PolicyName"], "arn": ap["PolicyArn"], "document": m["default"]})
            else:   # AWS-managed policy not included, or no default version in export: be explicit, do not guess
                out.append({"name": ap["PolicyName"], "arn": ap["PolicyArn"], "document": {"Statement": []}, "unresolved": True})
        return out

    def boundary(item) -> Optional[Dict[str, Any]]:
        b = item.get("PermissionsBoundary") or {}
        arn = b.get("PermissionsBoundaryArn")
        if not arn:
            return None
        m = managed.get(arn)
        if m and m["default"]:
            return m["default"]
        # Unknown boundary: restrict nothing is unsafe, restrict everything hides paths. Fail loudly instead.
        raise ValueError(f"permissions boundary {arn} is not present in Policies; re-export including it")

    snap: Dict[str, Any] = {"account": account, "groups": [], "users": [], "roles": [],
                            "policy_versions": {a: m["others"] for a, m in managed.items()}}
    for g in groups_raw:
        snap["groups"].append({"name": g["GroupName"], "arn": g["Arn"], "policies": policies(g.get("GroupPolicyList"), g.get("AttachedManagedPolicies"))})
    for u in users:
        e = {"name": u["UserName"], "arn": u["Arn"], "groups": u.get("GroupList", []),
             "policies": policies(u.get("UserPolicyList"), u.get("AttachedManagedPolicies"))}
        b = boundary(u)
        if b:
            e["permissions_boundary"] = b
        snap["users"].append(e)
    for r in roles:
        e = {"name": r["RoleName"], "arn": r["Arn"], "trust": _doc(r["AssumeRolePolicyDocument"]),
             "policies": policies(r.get("RolePolicyList"), r.get("AttachedManagedPolicies"))}
        b = boundary(r)
        if b:
            e["permissions_boundary"] = b
        snap["roles"].append(e)
    if deny_overlays:
        snap["deny_overlays"] = deny_overlays
    return snap


def unresolved_attachments(snap: Dict[str, Any]) -> List[str]:
    """Managed policies referenced but not contained in the export (typically AWS-managed). Their permissions are NOT evaluated."""
    out = []
    for kind in ("users", "roles", "groups"):
        for item in snap.get(kind, []):
            for p in item.get("policies", []):
                if p.get("unresolved"):
                    out.append(f"{kind[:-1]}:{item['name']} -> {p['arn']}")
    return out
