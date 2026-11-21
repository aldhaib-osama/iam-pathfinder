# Reproducible IAM experiments

Five controlled changes to fresh copies of `examples/snapshot.json` illustrate the model's handling of Deny, required permissions, boundaries, overlays and Conditions. All inputs are fictional. Dated outputs and execution provenance are recorded in `TEST_RESULTS.txt`; these records are not personal learning or interview-readiness claims.

| Change to the fictional snapshot | Observed result for `user:dev-dana` | README-grounded explanation |
| --- | --- | --- |
| Add an unconditional explicit Deny for `iam:PassRole` | No escalation path found within modelled techniques | Explicit Deny takes precedence over Allow. |
| Remove the Allow for `iam:PassRole` | No escalation path found within modelled techniques | The modelled Lambda technique requires PassRole as well as the listed Lambda permissions. |
| Add a permissions boundary allowing only `s3:Get*` and `s3:List*` | No escalation path found within modelled techniques | Identity-policy paths need both identity Allow and boundary Allow when a boundary exists. |
| Add an account-wide Deny overlay for `lambda:InvokeFunction` | No escalation path found within modelled techniques | The overlay restricts the Lambda technique; it is not a full implementation of SCPs. |
| Add a nonempty Condition to the existing PassRole Allow | Candidate Lambda path remains, marked `[conditional]` | Conditional Allow remains unresolved rather than being evaluated as definitely satisfied. |

All five complete account runs exited with code 3 because other candidate paths remained. The disappearance of one user's path does not imply a zero exit code for the whole account, and no path is not a safety certificate. Raw inputs and stdout/stderr are supplied in the review evidence bundle.

## Reproducing a case

Run from the repository root with Python 3.9+ and `PYTHONPATH=src`:

```sh
python3 -m iampathfinder.cli /path/to/explicit-deny.json
```

Use the corresponding copied fictional JSON for each case. Findings are modelled candidates, not proof of exploitation or complete AWS authorization evaluation.
