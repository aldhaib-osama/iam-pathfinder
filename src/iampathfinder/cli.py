from __future__ import annotations
import argparse
import json
import sys

from .graph import find_paths, to_dot
from .model import load_file, load_account
from .awsexport import from_authorization_details, unresolved_attachments
from .report import render


def _main(argv=None):
    ap = argparse.ArgumentParser(prog="iampathfinder", description="Find IAM privilege-escalation paths in an offline account snapshot")
    ap.add_argument("snapshot", help="JSON snapshot (see examples/)")
    ap.add_argument("--aws-export", action="store_true", help="input is raw `aws iam get-account-authorization-details` JSON")
    ap.add_argument("--overlay", help="JSON file with a list of Deny-only policy documents applied account-wide (SCP-style)")
    ap.add_argument("--report", metavar="FILE.md", help="write a Markdown report with remediation hints")
    ap.add_argument("--dot", action="store_true", help="print Graphviz DOT of all edges")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-conditional", action="store_true", help="exclude paths with unresolved conditions or prerequisites")
    a = ap.parse_args(argv)
    with open(a.snapshot, encoding="utf-8") as f:
        data = json.load(f)
    unresolved = []
    overlays = None
    if a.overlay:
        with open(a.overlay, encoding="utf-8") as f:
            overlays = json.load(f)
    if a.aws_export:
        data = from_authorization_details(data, overlays)
        unresolved = unresolved_attachments(data)
        for u in unresolved:
            print(f"warning: managed policy not in export, not evaluated: {u}", file=sys.stderr)
    elif overlays:
        data["deny_overlays"] = overlays
    acct = load_account(data)
    if a.dot:
        print(to_dot(acct))
        return 0
    res = find_paths(acct, include_conditional=not a.no_conditional)
    if a.report:
        with open(a.report, 'w', encoding='utf-8') as f:
            f.write(render(res, unresolved))
    if a.json:
        print(json.dumps({k: (None if v is None else [{"from": e.src, "to": e.dst, "technique": e.technique, "conditional": e.conditional} for e in v]) for k, v in res.items()}, indent=2))
    else:
        for node, path in sorted(res.items()):
            if path is None:
                print(f"{node}: no escalation path found (within modelled techniques)")
                continue
            hops = " -> ".join([path[0].src] + [e.dst for e in path])
            print(f"{node}: CANDIDATE PATH in {sum(1 for e in path if e.technique != 'already admin')} step(s)  {hops}")
            for e in path:
                if e.technique != "already admin":
                    print(f"    {e.src} -> {e.dst}: {e.technique}{' [conditional]' if e.conditional else ''}")
    return 3 if any(v for v in res.values()) else 0


def main(argv=None):
    try:
        return _main(argv)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"error: invalid/incomplete input or file operation: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
