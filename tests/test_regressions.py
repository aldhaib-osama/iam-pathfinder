"""Policy and graph cases independent of the bundled account snapshot."""
import os
import sys
import unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from iampathfinder.model import load_account
from iampathfinder.policy import evaluate, is_admin
from iampathfinder.graph import find_paths, to_dot

ADMIN = {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}

def account(trust_condition=False, trust_deny=False, identity_deny=False):
    trust = {'Effect': 'Allow', 'Action': 'sts:AssumeRole', 'Principal': {'AWS': 'arn:aws:iam::1:user/u'}}
    if trust_condition:
        trust['Condition'] = {'Bool': {'aws:MultiFactorAuthPresent': 'true'}}
    statements = [trust]
    if trust_deny:
        statements.append(dict(trust, Effect='Deny'))
    docs = []
    if identity_deny:
        docs = [{'document': {'Statement': [{'Effect': 'Deny', 'Action': 'sts:AssumeRole', 'Resource': '*'}]}}]
    return load_account({'account': '1', 'users': [{'name': 'u', 'policies': docs}],
                         'roles': [{'name': 'r', 'trust': {'Statement': statements}, 'policies': [{'document': ADMIN}]}]})

class Regression(unittest.TestCase):
    def test_direct_trust_needs_no_identity_allow_but_deny_wins(self):
        self.assertIsNotNone(find_paths(account())['user:u'])
        self.assertIsNone(find_paths(account(identity_deny=True))['user:u'])
        self.assertIsNone(find_paths(account(trust_deny=True))['user:u'])

    def test_conditional_trust_cannot_be_unconditional(self):
        acct = account(trust_condition=True)
        self.assertTrue(find_paths(acct)['user:u'][0].conditional)
        self.assertIsNone(find_paths(acct, include_conditional=False)['user:u'])

    def test_conditional_deny_and_resource_specific_admin_deny(self):
        doc = {'Statement': ADMIN['Statement'] + [{'Effect': 'Deny', 'Action': 's3:GetObject', 'Resource': 'arn:bucket/private', 'Condition': {'Bool': {'x': 'true'}}}]}
        self.assertEqual(evaluate([doc], 's3:GetObject', 'arn:bucket/private'), 'conditional')
        self.assertFalse(is_admin([doc]))
        self.assertFalse(is_admin([{'Statement': ADMIN['Statement'] + [{'Effect': 'Deny', 'Action': 's3:GetObject', 'Resource': 'arn:bucket/private'}]}]))

    def test_service_trust_requires_assumerole_action(self):
        acct = account()
        acct.principals['user:u'].documents = [{'Statement': [{'Effect': 'Allow', 'Action': ['iam:PassRole', 'lambda:*'], 'Resource': '*'}]}]
        acct.principals['role:r'].trust = {'Statement': [{'Effect': 'Allow', 'Action': 'sts:TagSession', 'Principal': {'Service': 'lambda.amazonaws.com'}}]}
        self.assertIsNone(find_paths(acct)['user:u'])

    def test_setdefaultversion_requires_unverified_existing_version(self):
        acct = load_account({'account': '1', 'users': [{'name': 'u', 'policies': [{'arn': 'arn:policy/p', 'document': {'Statement': [{'Effect': 'Allow', 'Action': 'iam:SetDefaultPolicyVersion', 'Resource': 'arn:policy/p'}]}}]}]})
        self.assertTrue(find_paths(acct)['user:u'][0].conditional)
        self.assertIsNone(find_paths(acct, include_conditional=False)['user:u'])

if __name__ == '__main__':
    unittest.main()
