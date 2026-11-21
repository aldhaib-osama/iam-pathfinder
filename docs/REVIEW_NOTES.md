# Historical review archive

This earlier AI-assisted review record describes previous snapshots, not an independent human review or current verification. Its original test counts and CI statements are retained for traceability. See `TEST_RESULTS.txt` and the current README for dated output and execution provenance.

---

# Expanded-feature independent review, 21 November 2026

Status: AI-assisted educational portfolio project. Dahab has not reviewed or run it. Not production-ready and not an AWS authorization engine. No account access or publication occurred.

## Executed checks
- Original expanded candidate: 33 tests passed but missed material new-feature defects.
- Repaired candidate: 43 tests pass on Python 3.10.12, including 10 new independent tests. Full output is in TEST_RESULTS.txt.
- Installed package using updated local pip/setuptools/wheel and exercised installed CLI against the fictional raw export, report generation, overlay JSON output, DOT generation/Graphviz parsing and error exit 2. Candidate findings exit 3 deliberately.
- Python 3.9/3.12 hosted CI is configured but NOT executed. No real AWS data or account was used. Markdown report content was inspected as text, not rendered as a web page.

## Expanded defects repaired
- Raw importer discarded original ARN paths and partitions. It now preserves user, group and role ARNs. Mixed-account and explicitly truncated exports are rejected.
- Direct role-trust paths bypassed organisation Deny and boundary restrictions. Explicit Deny is now enforced there; unresolved Deny stays conditional.
- Self-policy modifications could jump directly to ADMIN despite a restrictive boundary or organisation IAM/STS Deny. These edits cannot remove external restrictions, so unsupported terminal jumps are now excluded.
- The admin-terminal action probes used Resource="*" and missed resource-specific Deny. Terminal recognition is now deliberately conservative and includes potentially IAM/STS-restricting overlays.
- Existing policy-version handling could omit identity-Deny uncertainty. It now retains that uncertainty.
- Empty/malformed boundaries or policy/overlay shapes could be ignored or crash downstream. Added basic structural policy validation and clear CLI error handling. This is not complete IAM schema validation.
- README statements inherited from the baseline contradicted policy-version support and the new terminal logic. Those statements are reconciled, and limits are stated plainly.

## Material limits
- Boundaries with direct same-account resource trust have principal-type-specific AWS behavior. This implementation conservatively requires boundary Allow even for directly named IAM users, so it can miss valid AWS paths. It does not model role sessions.
- The ADMIN label is a conservative IAM-administration terminal, not unrestricted account administrator. An IAM/STS-specific conditional or resource-restricted overlay may suppress an admin-equivalent target entirely. Conversely, technique prerequisites remain incomplete, so reported paths can still be false positives.
- Unknown attached policies may contain Deny as well as Allow. Results on incomplete exports may be wrong in either direction. Warnings go to stderr and Markdown report; JSON is the path map only.
- Organisation overlays are user-provided account-wide Deny restrictions, not full SCP evaluation or discovery. Hierarchy, applicability, service exceptions, allow-list SCPs, most Conditions, cross-account access and many techniques are not implemented.
- Credential usability, quotas, login-profile existence, instance profiles and service-specific resource authorization are incomplete. No path never means safe. Removing a boundary or modifying an organisation policy is not modelled as an escalation technique.
- Seeded generated property tests are finite regression checks, not a formal proof or AWS differential validation.
- Real exports and reports are sensitive; do not commit them. Keep the AI-assistance attribution and update maintainer-review status only after Dahab has actually reviewed/run the project.

AWS semantic reference checked:
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html
