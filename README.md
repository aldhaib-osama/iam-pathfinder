# iampathfinder: offline IAM privilege-escalation path finder

Takes a JSON snapshot of IAM users, groups, roles and policies and finds the shortest chain of known techniques by which each non-admin principal might reach an admin target within the simplified model. Python 3.9+, standard library only. No AWS access needed.

## What it does
- Policy evaluator: Allow/Deny, explicit Deny precedence, `Action`/`NotAction`, `Resource`/`NotResource`, wildcards, case-insensitive actions. Conditional Allow and potentially applicable conditional Deny are treated as unresolved. Role trust Conditions are also unresolved.
- Graph: edge P -> Q means P might act as Q within the simplified model. Techniques covered: self policy change (Attach/Put policy on self or own group, CreatePolicyVersion / SetDefaultPolicyVersion on an attached managed policy), CreateAccessKey / CreateLoginProfile / UpdateLoginProfile on another user, sts:AssumeRole (trust-policy aware, including account-wide trust needing an identity allow), UpdateAssumeRolePolicy, iam:PassRole with Lambda or EC2.
- BFS shortest path, text / JSON / Graphviz DOT output, exit 3 when a candidate path exists (usable in CI).

## Run
```
cd iam-pathfinder
export PYTHONPATH=src
python3 -m iampathfinder.cli examples/snapshot.json
python3 -m iampathfinder.cli examples/snapshot.json --dot | dot -Tpng -o graph.png   # needs graphviz
python3 -m unittest discover -s tests -v
```
Real account (offline analysis of an export you create yourself with read-only IAM permissions):
```
aws iam get-account-authorization-details --output json > auth.json
python3 -m iampathfinder.cli auth.json --aws-export --report report.md
python3 -m iampathfinder.cli auth.json --aws-export --overlay my_org_denies.json   # org-level Deny statements as a JSON list
```
The tool itself never calls AWS. Try it on `examples/auth_details.json` (fictional account). The simplified hand-written format is in `examples/snapshot.json`.

## Added in the depth pass
- Raw `get-account-authorization-details` ingestion: URL-encoded documents, inline and managed policies, group membership, policy versions. Managed policies that are not in the export (typically AWS-managed ones) are reported on stderr and in the report as NOT evaluated; their permissions are never guessed. A permissions boundary whose policy is missing makes loading fail.
- Permissions boundaries: an action needs an identity allow AND a boundary allow.
- Org-level Deny overlays (`--overlay`): SCP-style deny statements only. Allow-list SCPs are rejected, not approximated.
- `SetDefaultPolicyVersion` is a path only if the export shows a non-default version that is admin-level; without version data it stays marked unresolved.
- Markdown report with a remediation idea per technique (starting points for a reviewer, not verified fixes).
- Property tests (150 seeded random accounts each): adding an overlay or a boundary never adds an edge for a principal that was not already admin. Principals that were full admins have no outgoing edges; if a Deny stops one being a full admin its narrower edges appear. That is a model artefact, documented in the test.

## Limits
- Not modelled: allow-list SCPs, session policies, resource policies other than role trust, most Condition operators, cross-account paths, and many other known escalation techniques. "No path found" means none within the modelled techniques, not that the account is safe.
- Wildcard matching is simplified (fnmatch), not a full IAM evaluation engine.
- Prefer AWS IAM Access Analyzer and established tools (for example PMapper, Cloudsplaining) for real audits. This project is a readable implementation of the core idea.

## Status and attribution
Educational prototype, not production-ready. Initial code and review were AI-assisted. Dahab has not yet reviewed or run this project. Runtime has no third-party dependencies; setuptools is needed only for package installation.

## Candidate paths, not exploitation proof
An edge is a hypothesis based on this snapshot model, not a verified capability. Console-only credentials may not enable API calls. Existing login profiles, key quotas, MFA, instance profiles, execution prerequisites are not fully represented. Non-default policy-version contents are used when the raw export includes them; without version data, SetDefaultPolicyVersion stays unresolved. CreatePolicyVersion may encounter quotas. Existing explicit Deny can survive a self-policy change; these self-change paths are marked conditional when Deny is present.

Role trust handles only a small subset: exact AWS/service principals, account root, wildcard Principal and sts:AssumeRole actions. Unconditional matching Deny blocks; conditional Deny makes a candidate unresolved. NotPrincipal and other unsupported constructs are incomplete. An explicit identity Deny blocks direct AssumeRole paths too. Service trust requires AssumeRole, but service workflows remain simplified.

The IAM-admin terminal is conservative: an unconditional blanket identity Action/Resource grant with no identity Deny, an equally broad boundary if present, and no potentially IAM/STS-restricting org overlay Deny. This is not a definition of unrestricted account administrator. This misses some practical admin-equivalent combinations. Resource-scoped service creation permissions are not fully modelled. `--no-conditional` removes unresolved edges; it does not certify the remaining paths. CLI exit 3 means a candidate exists, including conditional ones, not that exploitation was validated.

AWS policy evaluation reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html

## Expanded-feature review and important restrictions
- Independent expanded-feature review: 43 tests pass on Python 3.10.12, including ten new trust/boundary/import/validation cases beyond the submitted 33 tests. CI 3.9/3.12 is configured, not verified by a hosted run. See REVIEW_NOTES.md.
- Raw import preserves entity ARNs, including IAM paths and partitions. Simplified hand-written snapshots without explicit ARNs still construct commercial-partition ARNs. Cross-account and full partition-aware trust evaluation remain out of scope.
- Truncated and mixed-account exports are rejected. Export all pages without restrictive filters. Absence of some users/groups/policies is not always detectable. Unknown attachments may contain Deny as well as Allow, so results on incomplete data can be wrong in either direction, not merely miss paths.
- Boundaries and overlays restrict self-edit and direct-trust edges too. Self-editing identity policies cannot by itself remove a boundary or an organisation Deny. Boundary-removal/overlay-modification escalation techniques are not modelled.
- For directly named principals, this model conservatively requires a boundary Allow, even for IAM users for whom AWS resource-policy rules can bypass a boundary's implicit Deny. This can miss valid paths. Explicit Deny remains enforced. Role sessions are not modelled.
- Deny overlays are manually supplied account-wide restrictions, not a complete SCP implementation: OU hierarchy, account/service exceptions and organisation applicability are not evaluated. Any potentially IAM/STS-restricting Deny prevents the conservative admin terminal, including resource-scoped or conditional restrictions, so some admin-equivalent targets are missed.
- JSON output is the path map only; missing-managed-policy warnings go to stderr and the Markdown report. Always retain diagnostics. Invalid/incomplete input exits 2; no candidate exits 0; candidate found exits 3. Exit 0 never certifies safety.
- Seeded property tests check the implementation on selected finite generated inputs. They are not a mathematical proof that every restriction behaves correctly.

## Optional installation
```sh
python3 -m venv .venv
# Linux/macOS. On Windows use .venv\Scripts\activate instead.
. .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install .
iampathfinder examples/auth_details.json --aws-export --report report.md
```
The source commands above avoid installation and third-party runtime dependencies. Keep real exports and generated reports private; do not commit real account data.
