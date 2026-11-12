#!/usr/bin/env python3
"""One owned exact-image TLS/static-seal/Raft component; no installed authority.

Uses actual Go material/config generation. A separate, explicitly synthetic
self-init inspector has no root policy and cannot administer the product.
All private bytes live below a temporary external cache directory and are
removed; logs/receipts/source inventories remain in the selected archive.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
CACHE = Path.home() / '.cache/asservat-build'
IMAGE = 'ghcr.io/openbao/openbao@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f'
AMD64 = 'sha256:a78eb12a9fc7a3ebb4bec1724e2bdd6a28e33394820641d061166919a3f1866b'
VERSION = 'OpenBao v2.7.2 (9e0a0d3c3504a0a00b45e61355afac5e35c78379)'
AUTH_MOUNTS = ['asservat-setup', 'asservat-configuration', 'asservat-owner']
TRANSIT_MOUNTS = ['asservat-audit', 'public-transit']
PKI_MOUNTS = ['owner-pki', 'connector-pki', 'worker-pki']
INITIAL_ROLES = {'asservat-install-wrap': 'asservat-install-encrypt',
                 'asservat-install-unwrap': 'asservat-install-decrypt',
                 'asservat-install-issuer-issue': 'asservat-install-issuer'}
PREREQUISITE_PATHS = (
    ['sys/mounts/auth/' + name for name in AUTH_MOUNTS]
    + ['auth/' + name + '/config' for name in AUTH_MOUNTS]
    + ['sys/mounts/' + name for name in TRANSIT_MOUNTS + PKI_MOUNTS + ['fleet-bootstrap']]
    + ['asservat-audit/keys/audit']
    + ['auth/token/roles/' + name for name in INITIAL_ROLES]
    + ['sys/policies/acl/' + policy for policy in INITIAL_ROLES.values()]
    + [name + '/cert/ca' for name in PKI_MOUNTS])

MOUNT = '/run/asservat/openbao'
RELEVANT = [
    'go.mod', 'go.sum', 'scripts/test-small-openbao.py',
    'specs/contracts/small-openbao.schema.json',
    'internal/contracts/small_openbao.go', 'internal/contracts/owner_deployment.go',
    'internal/contracts/key_service_codec.go',
    'internal/adapters/kubernetes/small_openbao_material.go',
    'internal/adapters/kubernetes/small_openbao_material_test.go',
    'internal/adapters/kubernetes/installer_serving_tls_test.go',
    'internal/adapters/kubernetes/initial_preparer.go',
    'internal/adapters/providerconfig/installer_apply.go',
    'internal/contracts/initial_bootstrap_input.go',
    'internal/adapters/providerconfig/initial_provider_policies.go',
    'internal/adapters/providerconfig/initial_provider.go',
    'internal/adapters/providerconfig/owner_provider_recipe.go',
    'internal/adapters/providerconfig/setup_reader.go',
    'internal/adapters/kubernetes/small_openbao_prerequisites_test.go',
]


def hashes():
    return {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in RELEVANT}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    args = parser.parse_args()
    archive = args.archive.resolve()
    if archive.exists() or not archive.is_relative_to(CACHE.resolve()):
        raise SystemExit('use a NEW external archive below ~/.cache/asservat-build')
    archive.mkdir(parents=True, mode=0o700)
    CACHE.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='small-openbao-private-', dir=CACHE))
    owner = 'asv-small-bao-' + uuid.uuid4().hex[:12]
    label = 'asservat.test=' + owner
    network = owner
    containers = [owner + '-preflight', owner + '-backend', owner + '-partial', owner + '-cleanup']
    report = {'scope': 'exact OpenBao 2.7.2 nonroot TLS/static-auto-seal/self-init/Raft persistence; synthetic scoped component inspector only; read-only application prerequisite compatibility; NO Kubernetes auth qualification, real setup-child EntityID, SQL authority or installed activation',
              'image': IMAGE, 'platform': 'linux/amd64', 'platformManifest': AMD64,
              'owner': owner, 'network': network, 'containers': containers,
              'sourceHashesBefore': hashes(), 'commands': [], 'stages': [],
              'cleanupErrors': [], 'goExits': [], 'checks': {}, 'exit': 1}
    private_tokens = []
    started = time.monotonic()
    network_created = False

    def safe(text):
        for token in private_tokens:
            text = text.replace(token, '[private-component-token]')
        return re.sub(r'\b(?:hvs|hvb|s)\.[A-Za-z0-9_-]+', '[private-provider-token]', text)

    def run(command, *, timeout=60, required=True, env=None):
        try:
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            result = subprocess.CompletedProcess(command, 124, '', 'bounded command timeout')
        report['commands'].append({'args': command, 'exit': result.returncode,
                                   'stdout': safe(result.stdout), 'stderr': safe(result.stderr)})
        if required and result.returncode:
            raise RuntimeError('command failed: ' + command[0] + ' exit ' + str(result.returncode))
        return result

    def stage(name):
        report['stages'].append({'name': name, 'elapsedSeconds': round(time.monotonic() - started, 3)})
        print(name, flush=True)

    def request(address, host, ca, method, path, data=None, token=None, expected=None, timeout=3):
        context = ssl.create_default_context(cafile=str(ca))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        conn = http.client.HTTPSConnection(host, 8200, context=context, timeout=timeout)
        conn._create_connection = lambda *args, **kwargs: socket.create_connection((address, 8200), timeout=timeout)
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['X-Vault-Token'] = token
        try:
            conn.request(method, '/v1/' + path, body=None if data is None else json.dumps(data).encode(), headers=headers)
            response = conn.getresponse()
            raw = response.read(128 * 1024 + 1)
            if len(raw) > 128 * 1024:
                raise RuntimeError('component response exceeds bound')
            body = json.loads(raw) if raw else None
            if expected is not None and response.status not in expected:
                raise RuntimeError(path + ': HTTP ' + str(response.status) + ' ' + safe(str((body or {}).get('errors', [])))[:300])
            return response.status, body
        finally:
            conn.close()

    def material(name):
        target = work / name
        target.mkdir(mode=0o755)
        env = os.environ.copy()
        (CACHE / 'tmp').mkdir(exist_ok=True)
        env.update({'TMPDIR': str(CACHE / 'tmp'), 'ASSERVAT_SMALL_OPENBAO_COMPONENT_MATERIAL': str(target)})
        r = run(['go', 'test', '-count=1', '-timeout=60s', './internal/adapters/kubernetes', '-run', '^TestSmallOpenBaoComponentMaterial$', '-v'], timeout=180, env=env)
        report['goExits'].append(r.returncode)
        if not re.search(r'^--- PASS: TestSmallOpenBaoComponentMaterial\b', r.stdout, re.M):
            raise RuntimeError('actual material generator test was not executed')
        for path in target.iterdir():
            path.chmod(0o444)
        return target

    def fixture_config(target, partial=False, token=None):
        config = (target / 'config.hcl').read_text()
        if token is None:
            token = secrets.token_hex(24)
            private_tokens.append(token)
        token_path = target / 'component-token'
        if token_path.exists():
            if token_path.read_text() != token:
                raise RuntimeError('original component credential changed')
        else:
            token_path.write_text(token)
            token_path.chmod(0o444)
        def op(name, path, data):
            return {name: {'operation': 'update', 'path': path, 'data': data}}
        def hcl_value(v):
            if isinstance(v, dict):
                return '{ ' + ', '.join(json.dumps(k) + ' = ' + hcl_value(x) for k, x in v.items()) + ' }'
            if isinstance(v, list):
                return '[ ' + ', '.join(hcl_value(x) for x in v) + ' ]'
            return json.dumps(v)
        def hcl_block(label, requests):
            result = 'initialize ' + json.dumps(label) + ' {\n'
            for item in requests:
                for name, fields in item.items():
                    result += 'request ' + json.dumps(name) + ' {\n'
                    result += '\n'.join(k + ' = ' + hcl_value(v) for k, v in fields.items()) + '\n}\n'
            return result + '}\n'
        fixture_policy = {'path': {p: {'capabilities': caps} for p, caps in {
            'auth/token/lookup-self': ['read'],
            'sys/policies/acl/asservat-backend': ['read'],
            'component-transit/keys/test': ['read'],
            'component-transit/encrypt/test': ['update'],
            'component-transit/decrypt/test': ['update'],
            'component-pki/cert/ca': ['read'],
        }.items()}}
        # Exact read-only product prerequisite observations. This fixture token
        # cannot configure those objects, issue a child token or authenticate a
        # Kubernetes workload; no product setup grant is substituted.
        fixture_policy['path'].update({path: {'capabilities': ['read']} for path in PREREQUISITE_PATHS})
        before = [op('fixture-policy', 'sys/policies/acl/component-inspector', {'policy': json.dumps(fixture_policy)}),
                  op('fixture-token', 'auth/token/create-orphan', {'id': {'eval_type': 'string', 'eval_source': 'file', 'path': MOUNT + '/component-token'}, 'policies': ['component-inspector'], 'no_default_policy': True, 'renewable': False, 'ttl': '15m', 'explicit_max_ttl': '15m', 'type': 'service'})]
        after = [op('fixture-transit', 'sys/mounts/component-transit', {'type': 'transit'}),
                 op('fixture-key', 'component-transit/keys/test', {'type': 'aes256-gcm96', 'exportable': False}),
                 op('fixture-pki', 'sys/mounts/component-pki', {'type': 'pki', 'config': {'max_lease_ttl': '24h'}}),
                 op('fixture-ca', 'component-pki/root/generate/internal', {'common_name': 'component-only.invalid', 'ttl': '24h'})]
        if partial:
            failure = 'request "fixture-forced-failure" {\n operation = "update"\n path = "sys/mounts/invalid-component"\n data = { type = "deliberately-unavailable-component-plugin" }\n}\n'
            marker = 'request "backend-identity"'
            if config.count(marker) != 1:
                raise RuntimeError('fixed product final marker not found')
            config = config.replace(marker, failure + marker, 1)
        config = hcl_block('component-before', before) + config + hcl_block('component-after', after)
        config_path = target / 'component.hcl'
        if config_path.exists():
            config_path.chmod(0o600)
        config_path.write_text(config)
        config_path.chmod(0o444)
        return token

    def start_backend(name, target, data):
        data.mkdir(mode=0o777)
        data.chmod(0o777)
        command = ['docker', 'run', '-d', '--name', name, '--label', label,
                   '--network', network, '--network-alias', 'trial-openbao.bootstrap.svc',
                   '--read-only', '--user', '65532:65532', '--cap-drop', 'ALL',
                   '--security-opt', 'no-new-privileges', '--memory', '384m', '--pids-limit', '96',
                   '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',
                   '--mount', 'type=bind,src=' + str(target) + ',dst=' + MOUNT + ',readonly',
                   '--mount', 'type=bind,src=' + str(data) + ',dst=/data',
                   '--entrypoint', '/usr/bin/bao', IMAGE, 'server', '-config=' + MOUNT + '/component.hcl']
        run(command)
        return backend_address(name)

    def backend_address(name):
        networks = json.loads(run(['docker', 'inspect', name, '--format', '{{json .NetworkSettings.Networks}}']).stdout)
        if list(networks) != [network] or not networks[network].get('IPAddress'):
            raise RuntimeError('original owned backend network identity mismatch')
        return networks[network]['IPAddress']

    def await_health(name, port, target, *, allow_partial=False):
        until = time.monotonic() + 45
        last = {}
        while time.monotonic() < until:
            try:
                status, body = request(port, 'trial-openbao.bootstrap.svc', target / 'ca.crt', 'GET', 'sys/health')
                last = {'status': status, **{k: body.get(k) for k in ['initialized', 'sealed', 'standby', 'version']}}
                report.setdefault('lastHealth', {})[name] = last
                if status == 200 and body.get('initialized') and not body.get('sealed'):
                    return body
            except (OSError, ValueError, http.client.HTTPException) as error:
                last = {'errorClass': type(error).__name__}
                report.setdefault('lastHealth', {})[name] = last
            state = json.loads(run(['docker', 'inspect', name, '--format', '{{json .State}}']).stdout)
            if not state['Running']:
                if allow_partial:
                    return None
                raise RuntimeError('server exited before healthy: exit ' + str(state['ExitCode']))
            time.sleep(0.2)
        raise RuntimeError('original 45s health deadline expired: ' + json.dumps(last))

    try:
        stage('exact-image')
        manifest = json.loads(run(['docker', 'buildx', 'imagetools', 'inspect', IMAGE, '--raw']).stdout)
        observed = [m for m in manifest['manifests'] if m.get('platform', {}).get('os') == 'linux' and m.get('platform', {}).get('architecture') == 'amd64']
        if len(observed) != 1 or observed[0]['digest'] != AMD64:
            raise RuntimeError('official index platform mismatch')
        if run(['docker', 'image', 'inspect', IMAGE], required=False).returncode:
            run(['docker', 'pull', '--platform', 'linux/amd64', IMAGE], timeout=180)
        info = json.loads(run(['docker', 'image', 'inspect', IMAGE]).stdout)[0]
        if info['Architecture'] != 'amd64' or info['Os'] != 'linux':
            raise RuntimeError('local image platform mismatch')
        report['imageID'], report['repoDigests'] = info['Id'], info.get('RepoDigests', [])
        preflight = run(['docker', 'run', '--rm', '--name', containers[0], '--label', label,
                         '--network', 'none', '--read-only', '--user', '65532:65532',
                         '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                         '--memory', '96m', '--pids-limit', '32', '--entrypoint', '/bin/sh', IMAGE,
                         '-ec', 'test "$(id -u)" = 65532; test -x /usr/bin/bao; command -v sh; command -v sleep; command -v kill; /usr/bin/bao version'])
        if VERSION not in preflight.stdout:
            raise RuntimeError('exact binary version mismatch')
        report['checks']['restrictedExecutable'] = True
        stage('generate-real-material')
        target = material('healthy-material')
        token = fixture_config(target)
        # Exercise exact private-credential/config replay before any server.
        if fixture_config(target, token=token) != token:
            raise RuntimeError('original component credential replay changed')
        stage('strict-certificate-preflight')
        run(['openssl', 'version'])
        run(['openssl', 'verify', '-x509_strict', '-CAfile', str(target / 'ca.crt'),
             '-verify_hostname', 'trial-openbao.bootstrap.svc', str(target / 'tls.crt')])
        wrong_host = run(['openssl', 'verify', '-x509_strict', '-CAfile', str(target / 'ca.crt'),
                          '-verify_hostname', 'foreign.invalid', str(target / 'tls.crt')], required=False)
        if wrong_host.returncode == 0:
            raise RuntimeError('strict certificate hostname refusal missing')
        report['checks']['strictCertificatePreflight'] = True
        stage('pinned-config-validation')
        for filename in ['config.hcl', 'component.hcl']:
            run(['docker', 'run', '--rm', '--name', containers[0], '--label', label,
                 '--network', 'none', '--read-only', '--user', '65532:65532',
                 '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                 '--mount', 'type=bind,src=' + str(target) + ',dst=' + MOUNT + ',readonly',
                 '--entrypoint', '/usr/bin/bao', IMAGE, 'operator', 'validate-config', '-config=' + MOUNT + '/' + filename])
        report['checks']['pinnedBinaryConfigValidation'] = True
        run(['docker', 'network', 'create', '--internal', '--label', label, network])
        network_created = True
        stage('self-init-and-static-auto-unseal')
        data = work / 'healthy-data'
        port = start_backend(containers[1], target, data)
        health = await_health(containers[1], port, target)
        if health['version'] != '2.7.2':
            raise RuntimeError('health version mismatch')
        host, ca = 'trial-openbao.bootstrap.svc', target / 'ca.crt'
        def api(method, path, body=None, expected=(200,), credential=token):
            return request(port, host, ca, method, path, body, credential, expected=expected)[1]
        marker_path = 'sys/policies/acl/asservat-backend'
        backend = json.loads(api('GET', marker_path)['data']['policy'])
        if backend != {'path': {'asservat-backend/' + (target / 'backend-id').read_text(): {'capabilities': ['deny']}}}:
            raise RuntimeError('final original initialization marker mismatch')
        report['checks']['exactFinalInitializationMarker'] = True
        stage('application-prerequisite-readback')
        def application_prerequisites():
            raw = {path: api('GET', path)['data'] for path in PREREQUISITE_PATHS}
            plan = json.loads((target / 'plan.json').read_text())
            snapshot = {}
            for mount in AUTH_MOUNTS:
                mount_path, config_path = 'sys/mounts/auth/' + mount, 'auth/' + mount + '/config'
                if raw[mount_path]['type'] != 'kubernetes':
                    raise RuntimeError('missing exact application auth mount')
                config = raw[config_path]
                ca_blocks = re.findall(r'-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----', config['kubernetes_ca_cert'], re.S)
                ca_der = sorted(base64.b64decode(x) for x in ca_blocks)
                expected_roots = sorted(base64.b64decode(x) for x in plan['kubernetes']['roots'])
                if (config['kubernetes_host'] != plan['kubernetes']['endpoint']
                        or config['disable_local_ca_jwt'] is not False
                        or config['token_reviewer_jwt_set'] is not False
                        or config.get('pem_keys') not in (None, []) or ca_der != expected_roots):
                    raise RuntimeError('application auth config differs from original API/local reviewer')
                snapshot[config_path] = {key: config.get(key) for key in ['kubernetes_host', 'kubernetes_ca_cert', 'disable_local_ca_jwt', 'token_reviewer_jwt_set', 'pem_keys']}
            for mount in TRANSIT_MOUNTS + PKI_MOUNTS + ['fleet-bootstrap']:
                path = 'sys/mounts/' + mount
                expected_type = 'transit' if mount in TRANSIT_MOUNTS else 'pki' if mount in PKI_MOUNTS else 'kv'
                if raw[path]['type'] != expected_type or mount == 'fleet-bootstrap' and raw[path]['options'].get('version') != '2':
                    raise RuntimeError('application mount type/version changed')
                snapshot[path] = {'type': raw[path]['type'], 'options': raw[path].get('options')}
            key_path = 'asservat-audit/keys/audit'
            key_data = raw[key_path]
            if key_data['type'] != 'aes256-gcm96' or key_data['exportable'] or key_data['allow_plaintext_backup'] or key_data['latest_version'] != 1:
                raise RuntimeError('initial audit key is missing, replaced or exportable')
            snapshot[key_path] = {key: key_data[key] for key in ['type', 'exportable', 'allow_plaintext_backup', 'latest_version']}
            for role, policy in INITIAL_ROLES.items():
                path = 'auth/token/roles/' + role
                data = raw[path]
                if (data['allowed_policies'] != [policy] or data['orphan'] or data['renewable']
                        or not data['token_no_default_policy'] or data['token_type'] != 'service'
                        or data['token_explicit_max_ttl'] != 900 or data.get('token_period', 0) != 0):
                    raise RuntimeError('initial role lost bounded child token constraints')
                snapshot[path] = {key: data.get(key) for key in ['allowed_policies', 'orphan', 'renewable', 'token_no_default_policy', 'token_type', 'token_explicit_max_ttl', 'token_period']}
                acl = json.loads(raw['sys/policies/acl/' + policy]['policy'])
                if policy == 'asservat-install-issuer':
                    expected = {'auth/token/lookup-self': {'capabilities': ['read']},
                                'auth/token/lookup-accessor': {'capabilities': ['update']},
                                'auth/token/revoke-accessor': {'capabilities': ['update']}}
                    for child in ['asservat-install-wrap', 'asservat-install-unwrap']:
                        expected['auth/token/roles/' + child] = {'capabilities': ['read']}
                        expected['auth/token/create/' + child] = {'capabilities': ['update']}
                    for child_policy in INITIAL_ROLES.values():
                        expected['sys/policies/acl/' + child_policy] = {'capabilities': ['read']}
                else:
                    operation = 'encrypt' if policy == 'asservat-install-encrypt' else 'decrypt'
                    expected = {'auth/token/lookup-self': {'capabilities': ['read']},
                                'asservat-audit/' + operation + '/audit': {'capabilities': ['update']}}
                if acl != {'path': expected}:
                    raise RuntimeError('initial runtime policy differs from exact shared contract')
                snapshot['sys/policies/acl/' + policy] = acl
            issuers = [raw[mount + '/cert/ca']['certificate'] for mount in PKI_MOUNTS]
            if any(not issuer.startswith('-----BEGIN CERTIFICATE-----') for issuer in issuers) or len(set(issuers)) != 3:
                raise RuntimeError('application issuer roots missing or shared')
            for mount, issuer in zip(PKI_MOUNTS, issuers):
                snapshot[mount + '/cert/ca'] = issuer
            return snapshot
        prerequisites = application_prerequisites()
        report['checks']['applicationPrerequisitesReadback'] = True

        plaintext = base64.b64encode(b'synthetic bounded component key material').decode()
        ciphertext = api('POST', 'component-transit/encrypt/test', {'plaintext': plaintext})['data']['ciphertext']
        if api('POST', 'component-transit/decrypt/test', {'ciphertext': ciphertext})['data']['plaintext'] != plaintext:
            raise RuntimeError('actual Transit bytes mismatch')
        issuer = api('GET', 'component-pki/cert/ca')['data']['certificate']
        key = api('GET', 'component-transit/keys/test')['data']
        if key['type'] != 'aes256-gcm96' or key['exportable'] or key['latest_version'] != 1:
            raise RuntimeError('fixture key properties mismatch')
        report['checks']['syntheticTransitAndIssuer'] = True
        stage('tls-and-root-refusal')
        observed_token = api('GET', 'auth/token/lookup-self')['data']
        if observed_token['policies'] != ['component-inspector'] or observed_token.get('identity_policies') or not observed_token['orphan'] or observed_token['renewable']:
            raise RuntimeError('synthetic inspector privileges differ')
        request(port, host, ca, 'GET', 'sys/mounts', token=token, expected=(403,))
        request(port, host, ca, 'GET', 'sys/mounts', expected=(403,))
        request(port, host, ca, 'GET', 'sys/mounts', token='root', expected=(403,))
        # Narrow fixture token may not create any token or read raw storage.
        request(port, host, ca, 'POST', 'auth/token/create', {}, token, expected=(403,))
        request(port, host, ca, 'GET', 'sys/raw/core/seal-config', token=token, expected=(403,))
        conn = http.client.HTTPConnection(port, 8200, timeout=3)
        conn.request('GET', '/v1/sys/health')
        if conn.getresponse().status != 400:
            raise RuntimeError('plaintext HTTP was not refused')
        conn.close()
        wrong = http.client.HTTPSConnection(host, 8200, context=ssl.create_default_context(), timeout=3)
        wrong._create_connection = lambda *a, **k: socket.create_connection((port, 8200), timeout=3)
        try:
            wrong.request('GET', '/v1/sys/health')
        except ssl.SSLCertVerificationError:
            report['checks']['wrongTLSRootRefused'] = True
        else:
            raise RuntimeError('untrusted TLS root accepted')
        finally:
            wrong.close()
        report['checks']['noRootCredentialOrAdminAccess'] = True
        report['checks']['plaintextHTTPRefused'] = True
        stage('same-data-restart')
        run(['docker', 'stop', '-t', '10', containers[1]], timeout=20)
        run(['docker', 'start', containers[1]])
        port = backend_address(containers[1])
        await_health(containers[1], port, target)
        if json.loads(api('GET', marker_path)['data']['policy']) != backend or api('GET', 'component-pki/cert/ca')['data']['certificate'] != issuer or api('POST', 'component-transit/decrypt/test', {'ciphertext': ciphertext})['data']['plaintext'] != plaintext or api('GET', 'component-transit/keys/test')['data'] != key:
            raise RuntimeError('retained backend/key/issuer/ciphertext changed')
        if application_prerequisites() != prerequisites:
            raise RuntimeError('retained application prerequisites changed after restart')
        report['checks']['restartRetainedApplicationPrerequisites'] = True
        report['checks']['restartRetainedOriginalKeyIssuerAndBytes'] = True
        run(['docker', 'stop', '-t', '10', containers[1]], timeout=20)
        stage('partial-initialization')
        partial = material('partial-material')
        partial_token = fixture_config(partial, partial=True)
        partial_port = start_backend(containers[2], partial, work / 'partial-data')
        partial_health = await_health(containers[2], partial_port, partial, allow_partial=True)
        report['partialHealthReady'] = partial_health is not None
        if partial_health is not None:
            # Health alone is not a valid setup acknowledgement. The actual
            # final original marker must be present and exact.
            status, _ = request(partial_port, host, partial / 'ca.crt', 'GET', marker_path, token=partial_token, expected=(404,))
            report['checks']['partialFinalMarkerRefused'] = status == 404
        else:
            failed_logs = run(['docker', 'logs', containers[2]], required=False)
            if 'request.[fixture-forced-failure' not in failed_logs.stdout + failed_logs.stderr:
                raise RuntimeError('partial startup failed at an unexpected stage')
            report['checks']['partialStartupRefused'] = True
        # Correcting config cannot re-run self-init over existing storage.
        fixture_config(partial, partial=False, token=partial_token)
        # Keep the ORIGINAL fixture credential; a new candidate is not used.
        run(['docker', 'restart', '-t', '10', containers[2]], timeout=20)
        partial_port = backend_address(containers[2])
        after_partial = await_health(containers[2], partial_port, partial, allow_partial=True)
        if after_partial is not None:
            request(partial_port, host, partial / 'ca.crt', 'GET', marker_path, token=partial_token, expected=(404,))
            report['checks']['partialRestartMarkerStillMissing'] = True
        else:
            failed_logs = run(['docker', 'logs', containers[2]], required=False)
            if 'self-initialization failed: refusing to unseal' not in failed_logs.stdout + failed_logs.stderr:
                raise RuntimeError('partial restart failed without persisted initialization refusal')
            report['checks']['partialRestartPersistedRefusal'] = True
        report['checks']['partialRestartDidNotReinitialize'] = True
        report['exit'] = 0
        stage('component-passed')
    except Exception as error:
        report['failure'] = safe(str(error))
        print('FAILED: ' + report['failure'], flush=True)
    finally:
        for name in containers:
            result = run(['docker', 'container', 'inspect', name], required=False)
            if result.returncode == 0:
                state = json.loads(result.stdout)[0]
                report.setdefault('terminalContainers', {})[name] = {'image': state['Image'], 'state': state['State']}
                logs = run(['docker', 'logs', '--tail', '200', name], required=False)
                (archive / (name + '.log')).write_text(safe(logs.stdout + logs.stderr))
                if run(['docker', 'rm', '-f', '-v', name], required=False).returncode:
                    report['cleanupErrors'].append('container:' + name)
        for path in [work / 'healthy-data', work / 'partial-data']:
            if path.exists():
                command = ['docker', 'run', '--rm', '--name', containers[3], '--label', label,
                           '--network', 'none', '--read-only', '--user', '65532:65532', '--cap-drop', 'ALL',
                           '--security-opt', 'no-new-privileges', '--memory', '64m', '--pids-limit', '16',
                           '--mount', 'type=bind,src=' + str(path) + ',dst=/data', '--entrypoint', '/bin/sh', IMAGE,
                           '-ec', 'rm -rf /data/* /data/.[!.]* /data/..?*']
                if run(command, required=False).returncode:
                    report['cleanupErrors'].append('private-data:' + path.name)
        if network_created and run(['docker', 'network', 'rm', network], required=False).returncode:
            report['cleanupErrors'].append('network')
        absent = {}
        for kind, name in [('container', c) for c in containers] + [('network', network)]:
            r = run(['docker', kind, 'inspect', name], required=False)
            absent[kind + ':' + name] = r.returncode != 0 and ('no such' in r.stderr.lower() or 'not found' in r.stderr.lower())
        report['ownedResourcesAbsent'] = absent
        owner_readback = {}
        for kind in ['container', 'network', 'volume']:
            r = run(['docker', kind, 'ls', '-q', '--filter', 'label=' + label], required=False)
            owner_readback[kind] = r.returncode == 0 and not r.stdout.strip()
        report['ownerFiltersEmpty'] = owner_readback
        try:
            shutil.rmtree(work)
        except OSError:
            report['cleanupErrors'].append('private-directory')
        report['sourceHashesAfter'] = hashes()
        report['sourceUnchanged'] = report['sourceHashesBefore'] == report['sourceHashesAfter']
        report['elapsedSeconds'] = round(time.monotonic() - started, 3)
        if report['cleanupErrors'] or not all(absent.values()) or not all(owner_readback.values()) or not report['sourceUnchanged']:
            report['exit'] = 1
        (archive / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({k: report.get(k) for k in ['exit', 'failure', 'goExits', 'sourceUnchanged', 'checks', 'cleanupErrors', 'ownedResourcesAbsent', 'ownerFiltersEmpty']}), flush=True)
    return report['exit']


if __name__ == '__main__':
    raise SystemExit(main())
