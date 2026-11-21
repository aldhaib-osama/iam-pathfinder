"""Raw-export ingestion, permissions boundaries, org Deny overlays, policy-version prerequisites,
remediation report, and a seeded monotonicity property test (Deny/boundary can never ADD a candidate edge)."""
import copy, json, os, random, subprocess, sys, tempfile, unittest
HERE = os.path.dirname(__file__)
SRC = os.path.join(HERE, "..", "src")
sys.path.insert(0, SRC)
from iampathfinder.awsexport import from_authorization_details, unresolved_attachments
from iampathfinder.graph import build_edges, find_paths
from iampathfinder.model import load_account
from iampathfinder.report import render, hint_for

RAW = json.load(open(os.path.join(HERE, "..", "examples", "auth_details.json")))
OVERLAY = json.load(open(os.path.join(HERE, "..", "examples", "overlay_deny_lambda.json")))
A = "111122223333"


def paths(raw=RAW, overlays=None):
    return find_paths(load_account(from_authorization_details(copy.deepcopy(raw), overlays)))


def ADMIN_DOC(): return {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


class Export(unittest.TestCase):
    def test_decodes_urlencoded_docs_and_finds_paths(self):
        p = paths()
        self.assertEqual(p["user:dev"][0].technique, "iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction")
        self.assertIn("CreatePolicyVersion", p["user:team-lead"][0].technique)
    def test_group_policy_is_merged(self):
        snap = from_authorization_details(copy.deepcopy(RAW))
        acct = load_account(snap)
        self.assertEqual(len(acct.principals["user:dev"].documents), 2)   # inline + group
    def test_boundary_blocks_path(self):
        self.assertIsNone(paths()["user:bounded-dev"])
        raw = copy.deepcopy(RAW)
        for u in raw["UserDetailList"]:
            u.pop("PermissionsBoundary", None)
        self.assertIsNotNone(paths(raw)["user:bounded-dev"])        # same permissions without the boundary escalate
    def test_missing_boundary_policy_fails_loudly(self):
        raw = copy.deepcopy(RAW)
        raw["Policies"] = [p for p in raw["Policies"] if p["PolicyName"] != "dev-boundary"]
        with self.assertRaises(ValueError):
            from_authorization_details(raw)
    def test_unresolved_aws_managed_policy_is_reported_not_guessed(self):
        un = unresolved_attachments(from_authorization_details(copy.deepcopy(RAW)))
        self.assertEqual(un, [f"user:intern -> arn:aws:iam::aws:policy/ReadOnlyAccess"])
    def test_garbage_input_rejected(self):
        for bad in ({}, {"UserDetailList": [{"Arn": "nope", "UserName": "x"}]}):
            with self.assertRaises((ValueError, KeyError)):
                from_authorization_details(bad)

class Overlay(unittest.TestCase):
    def test_overlay_denies_lambda_path_but_not_unrelated(self):
        p = paths(overlays=OVERLAY)
        self.assertIsNone(p["user:dev"])
        self.assertIsNotNone(p["user:team-lead"])
    def test_overlay_must_be_deny_only(self):
        with self.assertRaises(ValueError):
            load_account(from_authorization_details(copy.deepcopy(RAW), [ADMIN_DOC()]))
    def test_unrelated_overlay_does_not_unmake_admin(self):
        p = paths(overlays=OVERLAY)
        self.assertNotIn("role:lambda-exec", p)       # still recognised as admin, not reported as an escalation

class PolicyVersions(unittest.TestCase):
    def test_set_default_needs_an_admin_version_when_versions_known(self):
        raw = copy.deepcopy(RAW)
        raw["Policies"][0]["PolicyVersionList"][1]["Document"] = json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]})
        techs = [e.technique for e in build_edges(load_account(from_authorization_details(raw))) if e.src == "user:team-lead"]
        self.assertFalse(any("SetDefaultPolicyVersion" in t for t in techs))
        self.assertTrue(any("CreatePolicyVersion" in t for t in techs))
    def test_set_default_found_with_admin_version(self):
        techs = [e.technique for e in build_edges(load_account(from_authorization_details(copy.deepcopy(RAW)))) if e.src == "user:team-lead"]
        self.assertTrue(any("existing admin-level version" in t for t in techs))

class Report(unittest.TestCase):
    def test_report_has_hints_and_caveats(self):
        md = render(paths(), ["user:intern -> arn:aws:iam::aws:policy/ReadOnlyAccess"])
        self.assertIn("hypotheses", md)
        self.assertIn("iam:PassedToService", md)
        self.assertIn("Not evaluated", md)
    def test_every_technique_has_a_hint(self):
        for e in build_edges(load_account(from_authorization_details(copy.deepcopy(RAW)))):
            self.assertNotIn("Review whether", hint_for(e.technique), e.technique)

class CLI(unittest.TestCase):
    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "r.md")
            r = subprocess.run([sys.executable, "-m", "iampathfinder.cli", os.path.join(HERE, "..", "examples", "auth_details.json"),
                                "--aws-export", "--report", out], env=dict(os.environ, PYTHONPATH=SRC), capture_output=True, text=True)
            self.assertEqual(r.returncode, 3, r.stderr)
            self.assertIn("not evaluated", r.stderr)
            self.assertTrue(os.path.getsize(out) > 100)

# ---- property tests -----------------------------------------------------
ACTIONS = ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction", "ec2:RunInstances", "iam:CreateAccessKey",
           "iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:UpdateAssumeRolePolicy", "iam:CreatePolicyVersion", "sts:AssumeRole", "s3:GetObject", "iam:*", "lambda:*", "*"]

def rand_doc(rnd, effect="Allow"):
    return {"Statement": [{"Effect": effect, "Action": rnd.sample(ACTIONS, rnd.randint(1, 4)), "Resource": rnd.choice(["*", f"arn:aws:iam::{A}:role/*", f"arn:aws:iam::{A}:user/*"])}
                          for _ in range(rnd.randint(1, 3))]}

def rand_snapshot(rnd):
    users = [{"name": f"u{i}", "policies": [{"name": "p", "arn": f"arn:aws:iam::{A}:policy/p{i}", "document": rand_doc(rnd)}]} for i in range(rnd.randint(2, 4))]
    roles = [{"name": f"r{i}", "policies": [{"name": "p", "document": rand_doc(rnd)}],
              "trust": {"Statement": [{"Effect": "Allow", "Principal": rnd.choice([{"Service": "lambda.amazonaws.com"}, {"AWS": f"arn:aws:iam::{A}:root"}, {"AWS": f"arn:aws:iam::{A}:user/u0"}]), "Action": "sts:AssumeRole"}]}}
             for i in range(rnd.randint(1, 3))]
    return {"account": A, "users": users, "roles": roles}

def keys(snap, skip_srcs=frozenset()):
    return {(e.src, e.dst, e.technique) for e in build_edges(load_account(snap)) if e.src not in skip_srcs}

def admins(snap):
    return {e.src for e in build_edges(load_account(snap)) if e.technique == "already admin"}

# Monotonicity is checked for principals that were NOT already admin in the base snapshot. A base admin has no outgoing
# edges at all (it is a terminal), so when a Deny stops it being a *full* admin it legitimately starts showing the
# narrower edges it still has. That is a model artefact worth knowing about, not an added capability.

class Property(unittest.TestCase):
    def test_deny_overlay_never_adds_edges(self):
        for seed in range(150):
            rnd = random.Random(seed)
            snap = rand_snapshot(rnd)
            base = keys(snap)
            snap2 = dict(snap, deny_overlays=[rand_doc(rnd, "Deny")])
            self.assertLessEqual(keys(snap2, admins(snap)), base, seed)
    def test_boundary_never_adds_edges(self):
        for seed in range(150):
            rnd = random.Random(1000 + seed)
            snap = rand_snapshot(rnd)
            base = keys(snap)
            base_admins = admins(snap)
            for u in snap["users"][:1]:
                u["permissions_boundary"] = rand_doc(rnd)
            self.assertLessEqual(keys(snap, base_admins), base, seed)
    def test_random_snapshots_never_crash_and_paths_are_valid(self):
        for seed in range(150):
            snap = rand_snapshot(random.Random(2000 + seed))
            for node, path in find_paths(load_account(snap)).items():
                if path:
                    self.assertEqual(path[0].src, node)
                    for a, b in zip(path, path[1:]):
                        self.assertEqual(a.dst, b.src)
                    self.assertTrue(path[-1].dst == "ADMIN")

if __name__ == "__main__":
    unittest.main()
