"""Independent regressions for the expanded import/boundary/overlay features."""
import copy
import os
import sys
import unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from iampathfinder.awsexport import from_authorization_details
from iampathfinder.model import load_account
from iampathfinder.graph import build_edges, find_paths, _admin

ALL = {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}
def allow(action, resource='*'):
    return {'Statement': [{'Effect': 'Allow', 'Action': action, 'Resource': resource}]}
def base():
    return {'account': '1', 'users': [{'name': 'u', 'policies': []}], 'roles': [
        {'name': 'r', 'policies': [{'document': ALL}], 'trust': {'Statement': [
            {'Effect': 'Allow', 'Action': 'sts:AssumeRole', 'Principal': {'AWS': 'arn:aws:iam::1:user/u'}}]}}]}

class ExpandedReview(unittest.TestCase):
    def test_direct_trust_org_deny_not_bypassed(self):
        data = base()
        data['deny_overlays'] = [{'Statement': [{'Effect': 'Deny', 'Action': 'sts:AssumeRole', 'Resource': 'arn:aws:iam::1:role/r'}]}]
        edges = build_edges(load_account(data))
        self.assertFalse(any(e.src == 'user:u' and 'AssumeRole' in e.technique for e in edges))

    def test_direct_trust_boundary_explicit_deny_not_bypassed(self):
        data = base()
        data['users'][0]['permissions_boundary'] = {'Statement': ALL['Statement'] + [
            {'Effect': 'Deny', 'Action': 'sts:AssumeRole', 'Resource': '*'}]}
        self.assertIsNone(find_paths(load_account(data))['user:u'])

    def test_self_attach_cannot_escape_readonly_boundary(self):
        data = base()
        data['users'][0]['policies'] = [{'document': allow('iam:AttachUserPolicy')}]
        data['users'][0]['permissions_boundary'] = allow(['iam:AttachUserPolicy', 's3:GetObject'])
        self.assertIsNone(find_paths(load_account(data))['user:u'])

    def test_existing_version_cannot_escape_boundary(self):
        data = base()
        data['users'][0]['policies'] = [{'arn': 'arn:p', 'document': allow('iam:SetDefaultPolicyVersion')}]
        data['users'][0]['permissions_boundary'] = allow('iam:SetDefaultPolicyVersion')
        data['policy_versions'] = {'arn:p': [ALL]}
        self.assertIsNone(find_paths(load_account(data))['user:u'])

    def test_admin_resource_specific_org_deny_is_not_missed(self):
        data = base()
        data['deny_overlays'] = [{'Statement': [{'Effect': 'Deny', 'Action': 'iam:CreateAccessKey', 'Resource': 'arn:aws:iam::1:user/protected'}]}]
        self.assertFalse(_admin(load_account(data).principals['role:r']))

    def test_conditional_overlay_marks_direct_trust_uncertain(self):
        data = base()
        data['deny_overlays'] = [{'Statement': [{'Effect': 'Deny', 'Action': 'sts:AssumeRole', 'Resource': '*', 'Condition': {'Bool': {'x': 'true'}}}]}]
        edge = next(e for e in build_edges(load_account(data)) if e.src == 'user:u' and 'named in trust' in e.technique)
        self.assertTrue(edge.conditional)

    def test_import_preserves_paths_and_partition(self):
        raw = {'UserDetailList': [{'Arn': 'arn:aws-us-gov:iam::1:user/team/u', 'UserName': 'u'}],
               'GroupDetailList': [{'Arn': 'arn:aws-us-gov:iam::1:group/team/g', 'GroupName': 'g'}],
               'RoleDetailList': [{'Arn': 'arn:aws-us-gov:iam::1:role/team/r', 'RoleName': 'r', 'AssumeRolePolicyDocument': {'Statement': []}}]}
        snap = from_authorization_details(raw)
        acct = load_account(snap)
        self.assertEqual(acct.principals['user:u'].arn, raw['UserDetailList'][0]['Arn'])
        self.assertEqual(acct.principals['role:r'].arn, raw['RoleDetailList'][0]['Arn'])
        self.assertEqual(acct.groups['g']['arn'], raw['GroupDetailList'][0]['Arn'])

    def test_truncated_and_mixed_account_exports_rejected(self):
        raw = {'UserDetailList': [{'Arn': 'arn:aws:iam::1:user/u', 'UserName': 'u'}], 'IsTruncated': True}
        with self.assertRaises(ValueError):
            from_authorization_details(raw)
        raw.pop('IsTruncated')
        raw['UserDetailList'].append({'Arn': 'arn:aws:iam::2:user/v', 'UserName': 'v'})
        with self.assertRaises(ValueError):
            from_authorization_details(raw)

class ValidationReview(unittest.TestCase):
    def test_empty_boundary_cannot_silently_disappear(self):
        data = base()
        data['users'][0]['permissions_boundary'] = {}
        with self.assertRaises(ValueError):
            load_account(data)

    def test_malformed_policy_and_overlay_rejected(self):
        data = base()
        data['deny_overlays'] = {'Statement': []}
        with self.assertRaises(ValueError):
            load_account(data)
        data = base()
        data['users'][0]['policies'] = [{'document': {'Statement': [None]}}]
        with self.assertRaises(ValueError):
            load_account(data)

if __name__ == '__main__':
    unittest.main()
