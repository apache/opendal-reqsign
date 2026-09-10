# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Exercise fixture ownership and partial VM deployment cleanup without Azure."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent
FAKE_AZ = r"""#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
root = pathlib.Path(os.environ['FAKE_AZ_STATE'])
def option(name, default=''):
    return args[args.index(name)+1] if name in args else default
with (root / 'calls.jsonl').open('a') as f:
    f.write(json.dumps(args) + '\n')
if args[:2] == ['account', 'get-access-token']:
    print('fake-devops-token')
elif args[:3] == ['storage', 'blob', 'upload']:
    if os.getenv('FAIL_UPLOAD'): sys.exit(1)
    body = pathlib.Path(option('--file')).read_bytes()
    assert body == b'reqsign-live-azure-ok\n'
    (root / option('--name')).write_bytes(body)
elif args[:3] == ['storage', 'blob', 'generate-sas']:
    if os.getenv('FAIL_SAS'): sys.exit(1)
    assert option('--permissions') == 'r'
    print('fake-read-only-token')
elif args[:3] == ['storage', 'blob', 'delete']:
    if os.getenv('FAIL_DELETE'): sys.exit(1)
    (root / option('--name')).unlink()
elif args[:2] == ['vm', 'create']:
    name = option('--name')
    location = option('--location')
    nic = root / (name + 'VMNic')
    # Model NIC creation preceding a capacity failure, and Azure's region rule.
    if nic.exists() and nic.read_text() != location:
        print('InvalidResourceLocation', file=sys.stderr)
        sys.exit(1)
    nic.write_text(location)
    (root / option('--os-disk-name')).write_text(location)
    if location == 'eastus' or os.getenv('FAIL_ALL_VMS'):
        print('SkuNotAvailable', file=sys.stderr)
        sys.exit(1)
    (root / name).write_text(location)
elif args[:2] in (['vm', 'list'], ['resource', 'list']):
    import re
    for name in re.findall("name=='([^']+)'", option('--query')):
        if (root / name).exists(): print('/fake/' + name)
elif args[:2] in (['vm', 'delete'], ['resource', 'delete']):
    (root / option('--ids').split('/')[-1]).unlink()
else:
    raise AssertionError(args)
"""


FAKE_CURL = r"""#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
root = pathlib.Path(os.environ['FAKE_AZ_STATE'])
def option(name, default=''):
    return args[args.index(name)+1] if name in args else default
method = option('--request', 'GET')
# Both waiting and cancellation must finish before fixture cleanup.
assert list(root.glob('ci-probe-*'))
if method == 'POST':
    request = json.loads(option('--data'))
    params = request['templateParameters']
    assert params['githubSha'] == 'a' * 40
    assert params['githubRef'] == 'refs/heads/test'
    assert (root / request['variables']['REQSIGN_AZURE_STORAGE_PROBE_URL']['value'].rsplit('/', 1)[1]).exists()
    assert set(params) == {'githubSha', 'githubRef'}
    (root / 'queued.json').write_text(json.dumps(params))
    pathlib.Path(option('--output')).write_text(json.dumps({
        'id': 23, '_links': {'web': {'href': 'https://example.test/run/23'}}}))
    print('200')
elif method == 'PATCH':
    assert json.loads(option('--data')) == {'status': 'cancelling'}
    (root / 'cancelled').touch()
elif os.getenv('FAIL_PIPELINE_POLL'):
    if not (root / 'poll-failed').exists():
        (root / 'poll-failed').touch()
        sys.exit(22)
    print(json.dumps({'state': 'inProgress'}))
else:
    print(json.dumps({'state': 'completed',
                      'result': os.getenv('PIPELINE_RESULT', 'succeeded')}))
"""


class LiveScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'state'
        self.state.mkdir()
        binary = self.root / 'az'
        binary.write_text(FAKE_AZ)
        binary.chmod(0o755)
        curl = self.root / 'curl'
        curl.write_text(FAKE_CURL)
        curl.chmod(0o755)
        self.env = {
            **os.environ,
            'PATH': str(self.root) + os.pathsep + os.environ['PATH'],
            'FAKE_AZ_STATE': str(self.state),
            'AZURE_STORAGE_ACCOUNT': 'fixture',
            'AZURE_STORAGE_CONTAINER': 'tests',
            'AZURE_STORAGE_AUTH_MODE': 'login',
            'GITHUB_ACTIONS': 'false',
            'GITHUB_SHA': 'a' * 40,
            'GITHUB_REF': 'refs/heads/test',
            'AZURE_DEVOPS_ORGANIZATION': 'fixture',
            'AZURE_DEVOPS_PROJECT': 'tests',
            'AZURE_DEVOPS_PIPELINE_ID': '1',
            'AZURE_RUNTIME_RESOURCE_GROUP': 'fixture-rg',
            'AZURE_IMDS_IDENTITY_ID': '/fake/identity',
            'RUNNER_TEMP': str(self.root),
            'GITHUB_RUN_ID': '123',
            'GITHUB_RUN_ATTEMPT': '1',
            'GITHUB_OUTPUT': str(self.root / 'outputs'),
        }

    def run_script(self, script, *args):
        return subprocess.run(['bash', str(SCRIPTS / script), *args],
                              env=self.env, capture_output=True, text=True)

    def calls(self):
        return [json.loads(line) for line in
                (self.state / 'calls.jsonl').read_text().splitlines()]

    def resources(self):
        return [p.name for p in self.state.iterdir() if p.name != 'calls.jsonl']

    def test_probe_body_sas_and_cleanup(self):
        self.env.update(AZURE_STORAGE_AUTH_MODE='key',
                        REQSIGN_AZURE_STORAGE_ACCOUNT_KEY='fake-key')
        child = """import os, pathlib
name = os.environ['REQSIGN_AZURE_STORAGE_PROBE_URL'].rsplit('/', 1)[1]
assert (pathlib.Path(os.environ['FAKE_AZ_STATE']) / name).read_bytes() == b'reqsign-live-azure-ok\\n'
assert os.environ['REQSIGN_AZURE_STORAGE_SAS_TOKEN'] == 'fake-read-only-token'
"""
        result = self.run_script('with-probe.sh', 'python3', '-c', child)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.resources(), [])
        self.assertNotIn('fake-read-only-token', result.stdout + result.stderr)

    def test_failed_test_is_cleaned_and_preserves_status(self):
        result = self.run_script('with-probe.sh', 'bash', '-c', 'exit 42')
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(self.resources(), [])

    def test_failed_setup_does_not_run_test(self):
        self.env['FAIL_UPLOAD'] = '1'
        result = self.run_script('with-probe.sh', 'touch', str(self.root / 'ran'))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'ran').exists())

    def test_failed_sas_setup_cleans_blob(self):
        self.env.update(AZURE_STORAGE_AUTH_MODE='key', FAIL_SAS='1',
                        REQSIGN_AZURE_STORAGE_ACCOUNT_KEY='fake-key')
        result = self.run_script('with-probe.sh', 'touch', str(self.root / 'ran'))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'ran').exists())
        self.assertEqual(self.resources(), [])

    def test_cleanup_failure_fails_successful_test(self):
        self.env['FAIL_DELETE'] = '1'
        result = self.run_script('with-probe.sh', 'true')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Failed to delete', result.stderr)

    def test_repeated_jobs_get_different_objects(self):
        for _ in range(2):
            result = self.run_script('with-probe.sh', 'true')
            self.assertEqual(result.returncode, 0, result.stderr)
        uploads = [c[c.index('--name') + 1] for c in self.calls()
                   if c[:3] == ['storage', 'blob', 'upload']]
        self.assertEqual(len(set(uploads)), 2)
        self.assertEqual(self.resources(), [])

    def test_region_fallback_and_partial_resources_cleanup(self):
        result = self.run_script('imds-vm.sh', 'create')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('InvalidResourceLocation', result.stderr)
        self.assertIn('eastus2', (self.root / 'outputs').read_text())
        creates = [c for c in self.calls() if c[:2] == ['vm', 'create']]
        self.assertEqual(len(creates), 4)
        names = [c[c.index('--name') + 1] for c in creates]
        self.assertEqual(len(set(names)), 4)
        result = self.run_script('imds-vm.sh', 'cleanup')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.resources(), [])

    def test_all_vm_attempts_fail_and_are_cleaned(self):
        self.env['FAIL_ALL_VMS'] = '1'
        result = self.run_script('imds-vm.sh', 'create')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'outputs').exists())
        result = self.run_script('imds-vm.sh', 'cleanup')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.resources(), [])

    def test_pipeline_reads_temporary_probe_until_completed(self):
        result = self.run_script('with-probe.sh', 'bash', str(SCRIPTS / 'azure-pipelines.sh'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.state / 'queued.json').exists())
        self.assertFalse((self.state / 'cancelled').exists())
        self.assertEqual(list(self.state.glob('ci-probe-*')), [])

    def test_failed_pipeline_fails_job_and_cleans_probe(self):
        self.env['PIPELINE_RESULT'] = 'failed'
        result = self.run_script('with-probe.sh', 'bash', str(SCRIPTS / 'azure-pipelines.sh'))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.state / 'cancelled').exists())
        self.assertEqual(list(self.state.glob('ci-probe-*')), [])

    def test_poll_failure_cancels_pipeline_before_probe_cleanup(self):
        self.env['FAIL_PIPELINE_POLL'] = '1'
        result = self.run_script('with-probe.sh', 'bash', str(SCRIPTS / 'azure-pipelines.sh'))
        self.assertEqual(result.returncode, 22, result.stderr)
        self.assertTrue((self.state / 'cancelled').exists())
        self.assertEqual(list(self.state.glob('ci-probe-*')), [])


if __name__ == '__main__':
    unittest.main()
