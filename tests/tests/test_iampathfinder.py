import os, sys, unittest
HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "src"))
from iampathfinder.graph import find_paths
from iampathfinder.model import load_account, load_file
from iampathfinder.policy import evaluate, is_admin
from iampathfinder.cli import main

def S(**kw): return {"Statement": [dict(Effect="Allow", **kw)]}

class Policy(unittest.TestCase):
    def test_wildcards_case_insensitive_actions(self):
        self.assertEqual(evaluate([S(Action="S3:Get*", Resource="*")], "s3:GetObject", "arn:x"), "allow")
    def test_deny_wins(self):
        d = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}, {"Effect": "Deny", "Action": "iam:*", "Resource": "*"}]}
        self.assertEqual(evaluate([d], "iam:CreateUser", "*"), "deny")
        self.assertFalse(is_admin([d]))
    def test_notaction_and_conditional(self):
        self.assertEqual(evaluate([S(NotAction="iam:*", Resource="*")], "iam:ListUsers", "*"), "none")
        self.assertEqual(evaluate([S(NotAction="iam:*", Resource="*")], "s3:Get", "*"), "allow")
        self.assertEqual(evaluate([S(Action="*", Resource="*", Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}})], "s3:Get", "*"), "conditional")
    def test_resource_scoping(self):
        self.assertEqual(evaluate([S(Action="s3:*", Resource="arn:aws:s3:::a/*")], "s3:GetObject", "arn:aws:s3:::b/k"), "none")

class Graph(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = find_paths(load_file(os.path.join(HERE, "..", "examples", "snapshot.json")))
    def techniques(self, node):
        return [e.technique for e in self.res[node]]
    def test_passrole_lambda(self):
        self.assertIn("iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction", self.techniques("user:dev-dana")[0])
    def test_policy_version(self):
        self.assertEqual(len(self.res["user:ci-bot"]), 1)  # direct self-escalation to admin
        self.assertIn("CreatePolicyVersion", self.techniques("user:ci-bot")[0])
    def test_createkey_lateral_then_admin(self):
        p = self.res["user:helpdesk-hana"]
        self.assertIsNotNone(p)
        self.assertEqual(p[0].technique, "iam:CreateAccessKey")
    def test_explicit_deny_blocks(self):
        self.assertIsNone(self.res["user:auditor-aya"])
    def test_admins_excluded(self):
        self.assertNotIn("user:admin-amir", self.res)
    def test_cli_exit_code(self):
        self.assertEqual(main([os.path.join(HERE, "..", "examples", "snapshot.json")]), 3)

class Trust(unittest.TestCase):
    def test_account_trust_needs_identity_allow(self):
        data = {"account": "1", "users": [{"name": "u", "policies": []}],
                "roles": [{"name": "r", "trust": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:root"}, "Action": "sts:AssumeRole"}]},
                           "policies": [{"name": "a", "document": S(Action="*", Resource="*")}]}]}
        self.assertIsNone(find_paths(load_account(data))["user:u"])
        data["users"][0]["policies"] = [{"name": "x", "document": S(Action="sts:AssumeRole", Resource="*")}]
        self.assertIsNotNone(find_paths(load_account(data))["user:u"])

if __name__ == "__main__":
    unittest.main()
