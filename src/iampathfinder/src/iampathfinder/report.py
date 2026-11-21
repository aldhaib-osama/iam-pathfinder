"""Markdown report with per-edge remediation hints. Hints are starting points for a human reviewer, not verified fixes."""
from __future__ import annotations
from typing import Dict, List, Optional

from .graph import Edge

HINTS = [
    ("already admin", "Confirm this principal is meant to be an administrator; if not, replace the blanket grant with scoped permissions."),
    ("PassRole", "Scope iam:PassRole to the specific role ARNs needed and add a condition on iam:PassedToService; avoid combining it with lambda:CreateFunction/InvokeFunction or ec2:RunInstances on *."),
    ("CreatePolicyVersion", "Remove iam:CreatePolicyVersion/SetDefaultPolicyVersion from principals that the policy applies to; manage policy changes through a separate admin pipeline."),
    ("SetDefaultPolicyVersion", "Delete old policy versions that grant broad access and remove iam:SetDefaultPolicyVersion from the principal."),
    ("AttachUserPolicy", "Deny self-modification of IAM permissions (iam:Attach*/Put*) with a permissions boundary or an org-level deny."),
    ("PutUserPolicy", "Deny self-modification of IAM permissions (iam:Attach*/Put*) with a permissions boundary or an org-level deny."),
    ("AttachRolePolicy", "Deny self-modification of IAM permissions (iam:Attach*/Put*) with a permissions boundary or an org-level deny."),
    ("PutRolePolicy", "Deny self-modification of IAM permissions (iam:Attach*/Put*) with a permissions boundary or an org-level deny."),
    ("AttachGroupPolicy", "Restrict iam:AttachGroupPolicy/PutGroupPolicy to a small admin set."),
    ("PutGroupPolicy", "Restrict iam:AttachGroupPolicy/PutGroupPolicy to a small admin set."),
    ("CreateAccessKey", "Limit iam:CreateAccessKey to the caller's own user (resource arn:aws:iam::*:user/${aws:username}); same for CreateLoginProfile/UpdateLoginProfile."),
    ("LoginProfile", "Limit iam:CreateLoginProfile/UpdateLoginProfile to the caller's own user."),
    ("UpdateAssumeRolePolicy", "Remove iam:UpdateAssumeRolePolicy from non-admin principals."),
    ("sts:AssumeRole", "Narrow the role's trust policy to the exact principals that need it, and add conditions such as MFA or aws:PrincipalOrgID."),
]


def hint_for(technique: str) -> str:
    for key, text in HINTS:
        if key in technique:
            return text
    return "Review whether this permission is required for the principal."


def render(paths: Dict[str, Optional[List[Edge]]], unresolved: Optional[List[str]] = None) -> str:
    lines = ["# IAM escalation candidates", "",
             "Candidate paths within a simplified model. They are hypotheses to verify, not proven exploits. 'No path' means none within the modelled techniques.", ""]
    if unresolved:
        lines += ["## Not evaluated (managed policies missing from the export)", ""] + [f"- {u}" for u in unresolved] + [""]
    found = {k: v for k, v in sorted(paths.items()) if v}
    lines.append(f"{len(found)} principal(s) with a candidate path, {sum(1 for v in paths.values() if v is None)} without.")
    lines.append("")
    for node, path in found.items():
        steps = [e for e in path if e.technique != "already admin"]
        lines.append(f"## {node} ({len(steps)} step(s))")
        for e in steps:
            tag = " (unresolved condition or prerequisite)" if e.conditional else ""
            lines.append(f"- {e.src} -> {e.dst}: {e.technique}{tag}")
            lines.append(f"  - Fix idea: {hint_for(e.technique)}")
        lines.append("")
    return "\n".join(lines)
