"""Selected additional-input regressions. Assistant-run, not a maintainer-run claim."""
import copy
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from iampathfinder.awsexport import _doc, from_authorization_details
from iampathfinder.model import load_account, validate_policy
from iampathfinder.cli import main

DOC = {'Statement': [{'Effect': 'Allow', 'Action': 'iam:AttachUserPolicy', 'Resource': '*'}]}
def snapshot():
    return {'account': '1', 'users': [{'name': 'u', 'policies': [{'document': DOC}]}]}
def export():
    return {'UserDetailList': [{'Arn': 'arn:aws:iam::1:user/u', 'UserName': 'u'}]}

class AdditionalInputs(unittest.TestCase):
    def test_duplicate_entities_never_silently_overwrite(self):
        for key in ('users', 'roles', 'groups'):
            with self.assertRaises(ValueError):
                load_account({'account': '1', key: [{'name': 'u'}, {'name': 'u'}]})
        raw = export()
        raw['UserDetailList'] *= 2
        with self.assertRaises(ValueError):
            from_authorization_details(raw)
        raw = export()
        raw['Policies'] = [{'Arn': 'arn:aws:iam::1:policy/p'}] * 2
        with self.assertRaises(ValueError):
            from_authorization_details(raw)

    def test_supplied_malformed_boundary_is_not_ignored(self):
        for boundary in ({}, None, [], {'PermissionsBoundaryType': 'Policy'}, {'PermissionsBoundaryArn': ''}):
            raw = export()
            raw['UserDetailList'][0]['PermissionsBoundary'] = boundary
            with self.assertRaises(ValueError):
                from_authorization_details(raw)

    def test_every_known_pagination_marker_rejects_incomplete_input(self):
        for key, value in (('NextToken', 'more'), ('Marker', 'more'), ('IsTruncated', True)):
            raw = export()
            raw[key] = value
            with self.assertRaises(ValueError):
                from_authorization_details(raw)

    def test_plain_json_percent_literals_preserved_encoded_json_decoded(self):
        import urllib.parse
        doc = {'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::b/key%2Fname'}]}
        text = json.dumps(doc)
        self.assertEqual(_doc(text), doc)
        self.assertEqual(_doc(urllib.parse.quote(text)), doc)

    def test_mutually_exclusive_policy_fields_rejected(self):
        for pair in (('Resource', 'NotResource'), ('Principal', 'NotPrincipal')):
            doc = copy.deepcopy(DOC)
            for key in pair:
                doc['Statement'][0][key] = '*'
            with self.assertRaises(ValueError):
                validate_policy(doc)

    def test_explicit_empty_snapshot_is_distinct_from_missing_data(self):
        with self.assertRaises(ValueError):
            load_account({'account': '1'})
        self.assertFalse(load_account({'account': '1', 'users': [], 'roles': [], 'groups': []}).principals)
        with self.assertRaisesRegex(ValueError, 'no account identifier'):
            from_authorization_details({'UserDetailList': [], 'RoleDetailList': [], 'GroupDetailList': []})
        raw = {'UserDetailList': [], 'Policies': [{'Arn': 'arn:aws:iam::1:policy/p', 'PolicyVersionList': []}]}
        self.assertEqual(from_authorization_details(raw)['account'], '1')

    def test_dot_and_normal_exit_status_consistent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'snapshot.json')
            for data, expected in ((snapshot(), 3), ({'account': '1', 'users': []}, 0)):
                with open(path, 'w') as f:
                    json.dump(data, f)
                for mode in ([], ['--dot']):
                    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                        self.assertEqual(main([path] + mode), expected)

if __name__ == '__main__':
    unittest.main()
