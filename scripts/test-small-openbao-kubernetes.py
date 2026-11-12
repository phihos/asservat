#!/usr/bin/env python3
"""One fresh owned Kind + Restricted in-cluster OpenBao compatibility probe.

No SQL/evidence/production authority. No external service credentials. The probe
uses actual .svc DNS/TLS, local rotating reviewer and kubelet-projected JWTs.
Exit 3 records a fully measured unchanged initial-issuer incompatibility.
"""
import argparse
import base64
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
CACHE = Path.home() / '.cache/asservat-build'
NODE = 'kindest/node@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5'
BAO = 'ghcr.io/openbao/openbao@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f'
RELEVANT = [
    'go.mod', 'go.sum', 'scripts/test-small-openbao-kubernetes.py', 'scripts/test-small-openbao-kubernetes_test.py',
    'specs/contracts/small-openbao.schema.json',
    'internal/adapters/kubernetes/small_openbao_material_test.go',
    'internal/bootstrap/initial_openbao_mint.go',
    'test/fixtures/openbao-setup/main.go', 'test/fixtures/openbao-setup/main_test.go', 'test/fixtures/openbao-setup/Dockerfile',
    'internal/contracts/small_openbao.go', 'internal/contracts/owner_deployment.go',
    'internal/contracts/key_service_codec.go', 'internal/contracts/hub_worker.go',
    'internal/contracts/initial_provider.go', 'internal/contracts/initial_provider_bundled.go', 'internal/contracts/initial_provider_bundled_test.go',
    'specs/contracts/initial-provider-material.schema.json', 'specs/contracts/bundled-initial-provider-identity.schema.json',
    'internal/adapters/kms/initial_provider_bundled.go',
    'internal/adapters/kms/initial_provider_bundled_test.go', 'internal/adapters/kms/initial_provider_bundled_observer_test.go',
    'internal/adapters/kms/initial_provider_test.go',
    'internal/adapters/kubernetes/small_openbao_material.go',
    'internal/adapters/kubernetes/small_openbao_policy_test.go',
    'internal/adapters/kubernetes/initial_preparer.go',
    'internal/adapters/kms/initial_provider.go', 'internal/adapters/kms/initial_provider_retirement.go',
]


def hashes():
    paths = [ROOT / p for p in RELEVANT]
    paths += list((ROOT / 'internal/adapters/providerconfig').glob('*.go'))
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(paths))}


def validate_kept(manifest, data):
    """Closed exact-owner inventory; shared Kind networking is never removed."""
    expected = {'format', 'owner', 'nodeID', 'volumes', 'image', 'imageID', 'workDirectory'}
    if set(data) != expected or data['format'] != 'asservat-openbao-kept/v1':
        raise ValueError('unsupported kept inventory')
    owner = data['owner']
    work = Path(data['workDirectory'])
    if not re.fullmatch(r'asv-bao-k8s-[a-f0-9]{10}', owner) or data['image'] != owner + ':probe':
        raise ValueError('invalid exact owner')
    if not re.fullmatch(r'[a-f0-9]{64}', data['nodeID']) or not re.fullmatch(r'sha256:[a-f0-9]{64}', data['imageID']):
        raise ValueError('invalid pinned resource identity')
    if not manifest.resolve().is_relative_to(CACHE.resolve()) or not work.is_absolute() or work.parent != CACHE or work.is_symlink() or not re.fullmatch(r'openbao-kubernetes-private-[a-z0-9_]+', work.name):
        raise ValueError('invalid private fixture path')
    if not isinstance(data['volumes'], list) or len(data['volumes']) > 4:
        raise ValueError('invalid volume inventory')
    for volume in data['volumes']:
        if set(volume) != {'Name', 'CreatedAt', 'Driver', 'Labels'} or not re.fullmatch(r'[a-f0-9]{64}', volume['Name']) or volume['Driver'] != 'local' or not volume['CreatedAt']:
            raise ValueError('invalid exact volume identity')
    return owner, work


def cleanup_kept(manifest):
    manifest = manifest.resolve()
    data = json.loads(manifest.read_text())
    owner, work = validate_kept(manifest, data)
    commands, failures = [], []

    def call(args, required=True):
        result = subprocess.run(args, capture_output=True, text=True, timeout=120)
        commands.append({'args': args, 'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
        if required and result.returncode:
            raise RuntimeError('owned cleanup command failed')
        return result

    # Preflight ALL identities before any deletion. A changed object is never
    # removed merely because a previous run used the same name.
    node = call(['docker', 'inspect', owner + '-control-plane'], required=False)
    if node.returncode == 0:
        current = json.loads(node.stdout)[0]
        if current['Id'] != data['nodeID'] or current['Config']['Labels'].get('io.x-k8s.kind.cluster') != owner:
            raise ValueError('changed owned Kind identity')
        mounted = [m['Name'] for m in current['Mounts'] if m['Type'] == 'volume']
        if sorted(mounted) != sorted(v['Name'] for v in data['volumes']):
            raise ValueError('changed owned volume mounts')
    for volume in data['volumes']:
        result = call(['docker', 'volume', 'inspect', volume['Name']], required=False)
        if result.returncode == 0 and {k: json.loads(result.stdout)[0].get(k) for k in volume} != volume:
            raise ValueError('changed exact volume identity')
    image = call(['docker', 'image', 'inspect', data['image']], required=False)
    if image.returncode == 0 and json.loads(image.stdout)[0]['Id'] != data['imageID']:
        raise ValueError('changed probe image identity')
    if node.returncode == 0:
        call(['kind', 'delete', 'cluster', '--name', owner])
    for volume in data['volumes']:
        if call(['docker', 'volume', 'inspect', volume['Name']], required=False).returncode == 0:
            call(['docker', 'volume', 'rm', volume['Name']])
    if image.returncode == 0:
        call(['docker', 'image', 'rm', data['image']])
    if work.exists():
        shutil.rmtree(work)
    absent = call(['docker', 'ps', '-aq', '--filter', 'label=io.x-k8s.kind.cluster=' + owner])
    if absent.stdout.strip():
        failures.append('owned-kind')
    for volume in data['volumes']:
        if call(['docker', 'volume', 'inspect', volume['Name']], required=False).returncode == 0:
            failures.append('owned-volume')
    receipt = {'format': 'asservat-openbao-kept-cleanup/v1', 'owner': owner, 'cleanupErrors': failures, 'privateDirectoryAbsent': not work.exists(), 'commands': commands}
    manifest.with_name('kept-cleanup.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({k: receipt[k] for k in ['owner', 'cleanupErrors', 'privateDirectoryAbsent']}), flush=True)
    return int(bool(failures) or work.exists())


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--archive', type=Path)
    mode.add_argument('--cleanup-kept', type=Path)
    parser.add_argument('--keep-on-failure', action='store_true', help='Retain only this owned Kind and private fixture paths for local diagnosis; never a final qualification.')
    args = parser.parse_args()
    if args.cleanup_kept:
        return cleanup_kept(args.cleanup_kept)
    archive = args.archive.resolve()
    if archive.exists() or not archive.is_relative_to(CACHE.resolve()):
        raise SystemExit('use a NEW archive below ~/.cache/asservat-build')
    archive.mkdir(parents=True, mode=0o700)
    work = Path(tempfile.mkdtemp(prefix='openbao-kubernetes-private-', dir=CACHE))
    owner = 'asv-bao-k8s-' + uuid.uuid4().hex[:10]
    image = owner + ':probe'
    kubeconfig = work / 'kubeconfig'
    namespace = 'openbao-probe'
    report = {'scope': 'owned same-API Kubernetes setup/auth/inspection/initial-issuer compatibility; synthetic expected installation facts; no SQL/evidence/installed authority',
              'cluster': owner, 'image': BAO, 'nodeImage': NODE, 'probeImage': image,
              'commands': [], 'cleanupErrors': [], 'exit': 1, 'sourceHashesBefore': hashes()}
    started = time.monotonic()
    owned_cluster = False
    image_built = False
    volume_names = []
    volume_identities = []
    node_id = None
    env = os.environ.copy()
    (CACHE / 'tmp').mkdir(exist_ok=True)
    env.update({'TMPDIR': str(CACHE / 'tmp'), 'CGO_ENABLED': '0'})

    def run(command, *, timeout=60, required=True, private=False, data=None):
        try:
            r = subprocess.run(command, cwd=ROOT, env=env, input=data, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            r = subprocess.CompletedProcess(command, 124, '', 'bounded command timeout')
        item = {'args': command, 'exit': r.returncode}
        # Material output, kubeconfig and private CREATE input never enter the
        # retained command receipt (including error bodies).
        if not private:
            item.update({'stdout': r.stdout, 'stderr': r.stderr})
        report['commands'].append(item)
        if required and r.returncode:
            raise RuntimeError('command failed: ' + command[0] + ' exit ' + str(r.returncode))
        return r

    def stage(name):
        report.setdefault('stages', []).append({'name': name, 'elapsedSeconds': round(time.monotonic() - started, 3)})
        print(name, flush=True)

    def kubectl(*args, **kwargs):
        return run(['kubectl', '--kubeconfig', str(kubeconfig), *args], **kwargs)

    def create(objects, private=False):
        kubectl('create', '-f', '-', data=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': objects}), private=private)

    def meta(name):
        return {'name': name, 'namespace': namespace, 'labels': {'asservat.test': owner}}

    def get(kind, name):
        return json.loads(kubectl('-n', namespace, 'get', kind, name, '-o', 'json').stdout)

    try:
        stage('compile-exact-probe')
        build = work / 'image'
        build.mkdir()
        run(['go', 'build', '-tags=asservat_testfixture', '-o', str(build / 'probe'), './test/fixtures/openbao-setup'], timeout=180)
        shutil.copyfile(ROOT / 'test/fixtures/openbao-setup/Dockerfile', build / 'Dockerfile')
        run(['docker', 'build', '-t', image, str(build)], timeout=120)
        image_built = True
        report['probeImageID'] = json.loads(run(['docker', 'image', 'inspect', image]).stdout)[0]['Id']
        stage('fresh-owned-kind')
        owned_cluster = True
        run(['kind', 'create', 'cluster', '--name', owner, '--image', NODE, '--kubeconfig', str(kubeconfig), '--wait', '90s'], timeout=150)
        node = json.loads(run(['docker', 'inspect', owner + '-control-plane']).stdout)[0]
        node_id = node['Id']
        volume_names = [m['Name'] for m in node['Mounts'] if m['Type'] == 'volume']
        for name in volume_names:
            info = json.loads(run(['docker', 'volume', 'inspect', name]).stdout)[0]
            volume_identities.append({k: info.get(k) for k in ['Name', 'CreatedAt', 'Driver', 'Labels']})
        run(['kind', 'load', 'docker-image', image, '--name', owner], timeout=90)
        # Pulling this original pinned image inside the owned node is allowed;
        # do not retag an unrelated manifest under its digest name.
        run(['docker', 'exec', owner + '-control-plane', 'crictl', 'pull', BAO], timeout=180)
        ca_b64 = kubectl('config', 'view', '--raw', '-o', 'jsonpath={.clusters[0].cluster.certificate-authority-data}').stdout
        api_pem = base64.b64decode(ca_b64).decode()
        api_der = ssl.PEM_cert_to_DER_cert(api_pem)
        plan = {'format': 'asservat-small-openbao/v1', 'namespace': namespace, 'name': 'trial', 'image': BAO,
                'kubernetes': {'endpoint': 'https://kubernetes.default.svc', 'roots': [base64.b64encode(api_der).decode()]},
                'setupAccount': 'trial-bootstrap-runner'}
        stage('actual-generated-material')
        material_result = run([str(build / 'probe'), 'material'], private=True, data=json.dumps(plan))
        material = json.loads(material_result.stdout)
        server_command = json.loads(run([str(build / 'probe'), 'command']).stdout)
        provider_ca = base64.b64decode(material['ca.crt'])
        prefix = 'asservat-10000000000040008000000000000001'
        create([{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': namespace, 'labels': {'asservat.test': owner, 'pod-security.kubernetes.io/enforce': 'restricted'}}},
                *[{'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': meta(name), 'automountServiceAccountToken': False} for name in ['trial-openbao', 'trial-bootstrap-runner', prefix + '-worker']],
                {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRole', 'metadata': {'name': owner + '-reviewer', 'labels': {'asservat.test': owner}}, 'rules': [{'apiGroups': ['authentication.k8s.io'], 'resources': ['tokenreviews'], 'verbs': ['create']}]},
                {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRoleBinding', 'metadata': {'name': owner + '-reviewer', 'labels': {'asservat.test': owner}}, 'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': owner + '-reviewer'}, 'subjects': [{'kind': 'ServiceAccount', 'name': 'trial-openbao', 'namespace': namespace}]}])
        create([{'apiVersion': 'v1', 'kind': 'Secret', 'metadata': meta('trial-openbao-state'), 'type': 'Opaque', 'immutable': True, 'data': material},
                {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': meta(prefix + '-worker-providers'), 'type': 'Opaque', 'immutable': True}], private=True)
        native = {'namespaceUID': get('namespace', namespace)['metadata']['uid'],
                  'workerUID': get('serviceaccount', prefix + '-worker')['metadata']['uid'],
                  'credentialUID': get('secret', prefix + '-worker-providers')['metadata']['uid'],
                  'setupUID': get('serviceaccount', 'trial-bootstrap-runner')['metadata']['uid']}
        probe_input = {'plan': plan, 'providerCA': base64.b64encode(provider_ca).decode(), **native}
        create([{'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': meta('probe-input'), 'immutable': True, 'data': {'input.json': json.dumps(probe_input)}}])
        stage('tokenreview-only-account')
        for verb, resource, expected in [('create', 'tokenreviews.authentication.k8s.io', 'yes'), ('create', 'subjectaccessreviews.authorization.k8s.io', 'no'), ('get', 'secrets', 'no')]:
            r = kubectl('auth', 'can-i', verb, resource, '--as=system:serviceaccount:' + namespace + ':trial-openbao', required=False)
            if r.stdout.strip() != expected:
                raise RuntimeError('reviewer privilege boundary mismatch: ' + resource)
        report['reviewerOnlyTokenReview'] = True
        pod_security = {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532, 'fsGroup': 65532, 'seccompProfile': {'type': 'RuntimeDefault'}}
        container_security = {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}}
        stage('generated-bao-pod')
        create([{'apiVersion': 'v1', 'kind': 'Service', 'metadata': meta('trial-openbao'), 'spec': {'selector': {'app': 'trial-openbao'}, 'ports': [{'name': 'https', 'port': 8200, 'targetPort': 8200}]}},
                {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {**meta('trial-openbao'), 'labels': {'app': 'trial-openbao', 'asservat.test': owner}},
                 'spec': {'serviceAccountName': 'trial-openbao', 'automountServiceAccountToken': False, 'restartPolicy': 'Never', 'activeDeadlineSeconds': 300, 'securityContext': pod_security,
                          'containers': [{'name': 'bao', 'image': BAO, 'imagePullPolicy': 'IfNotPresent', 'command': server_command, 'securityContext': container_security,
                                          'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'}, 'limits': {'cpu': '2', 'memory': '512Mi'}},
                                          'ports': [{'containerPort': 8200}],
                                          'readinessProbe': {'exec': {'command': ['/usr/bin/bao', 'status', '-address=https://127.0.0.1:8200', '-ca-cert=/run/asservat/openbao/ca.crt', '-tls-server-name=trial-openbao.' + namespace + '.svc']}, 'periodSeconds': 1, 'timeoutSeconds': 3, 'failureThreshold': 60},
                                          'volumeMounts': [{'name': 'material', 'mountPath': '/run/asservat/openbao', 'readOnly': True}, {'name': 'data', 'mountPath': '/data'}, {'name': 'reviewer', 'mountPath': '/var/run/secrets/kubernetes.io/serviceaccount', 'readOnly': True}, {'name': 'tmp', 'mountPath': '/tmp'}]}],
                          'volumes': [{'name': 'material', 'secret': {'secretName': 'trial-openbao-state', 'defaultMode': 288, 'items': [{'key': k, 'path': k} for k in ['config.hcl', 'seal.key', 'ca.crt', 'tls.crt', 'tls.key']]}},
                                      {'name': 'data', 'emptyDir': {}}, {'name': 'tmp', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '32Mi'}},
                                      {'name': 'reviewer', 'projected': {'defaultMode': 288, 'sources': [{'serviceAccountToken': {'path': 'token', 'expirationSeconds': 600}}, {'configMap': {'name': 'kube-root-ca.crt', 'items': [{'key': 'ca.crt', 'path': 'ca.crt'}]}}]}}]}}])
        kubectl('-n', namespace, 'wait', '--for=condition=Ready', '--timeout=75s', 'pod/trial-openbao', timeout=90)
        stage('real-in-cluster-probe')
        create([{'apiVersion': 'v1', 'kind': 'Pod', 'metadata': meta('probe'), 'spec': {'serviceAccountName': 'trial-bootstrap-runner', 'automountServiceAccountToken': False, 'restartPolicy': 'Never', 'activeDeadlineSeconds': 140, 'securityContext': pod_security,
                 'containers': [{'name': 'probe', 'image': image, 'imagePullPolicy': 'Never', 'securityContext': container_security, 'resources': {'requests': {'cpu': '100m', 'memory': '96Mi'}, 'limits': {'cpu': '2', 'memory': '256Mi'}}, 'volumeMounts': [{'name': 'input', 'mountPath': '/run/probe', 'readOnly': True}]}],
                 'volumes': [{'name': 'input', 'projected': {'defaultMode': 288, 'sources': [{'configMap': {'name': 'probe-input', 'items': [{'key': 'input.json', 'path': 'input.json'}]}}, {'serviceAccountToken': {'path': 'setup.token', 'audience': 'https://asservat.io/openbao/setup', 'expirationSeconds': 600}}, {'serviceAccountToken': {'path': 'wrong.token', 'audience': 'https://wrong-audience.invalid', 'expirationSeconds': 600}}]}}]}}])
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            pod = get('pod', 'probe')
            if pod['status'].get('phase') in ['Succeeded', 'Failed']:
                terminated = pod['status']['containerStatuses'][0]['state']['terminated']
                report['probeExit'] = terminated['exitCode']
                break
            time.sleep(0.25)
        else:
            raise RuntimeError('original probe deadline expired')
        logs = kubectl('-n', namespace, 'logs', 'probe').stdout
        (archive / 'probe.log').write_text(logs)
        decoded = [json.loads(line) for line in logs.splitlines() if line.startswith('{')]
        if not decoded:
            raise RuntimeError('probe produced no bounded report')
        report['probeResult'] = decoded[-1]
        report['exit'] = report['probeExit']
        if report['probeExit'] == 3 and not report['probeResult'].get('measurementComplete'):
            report['exit'] = 1
        stage('probe-terminal')
    except Exception as error:
        report['failure'] = str(error)
        print('FAILED: ' + str(error), flush=True)
    finally:
        if owned_cluster:
            for pod_name in ['trial-openbao', 'probe']:
                r = kubectl('-n', namespace, 'logs', pod_name, '--tail=180', required=False)
                (archive / (pod_name + '.log')).write_text(r.stdout + r.stderr)
            r = kubectl('-n', namespace, 'get', 'pods', '-o', 'json', required=False)
            if r.returncode == 0:
                (archive / 'pod-statuses.json').write_text(r.stdout)
        keep = args.keep_on_failure and report['exit'] not in [0, 3] and owned_cluster and node_id and image_built
        if keep:
            kept = {'format': 'asservat-openbao-kept/v1', 'owner': owner, 'nodeID': node_id,
                    'volumes': volume_identities, 'image': image, 'imageID': report['probeImageID'], 'workDirectory': str(work)}
            manifest = archive / 'kept-resources.json'
            validate_kept(manifest, kept)
            manifest.write_text(json.dumps(kept, indent=2) + '\n')
            manifest.chmod(0o600)
            report['keptResources'] = str(manifest)
            report['cleanupDeferred'] = True
            report['qualification'] = False
            print('Owned failed fixture retained; credentials retain ORIGINAL expiry, Pod original deadline is unchanged.', flush=True)
            print('Cleanup: python3 scripts/test-small-openbao-kubernetes.py --cleanup-kept ' + str(manifest), flush=True)
        else:
            if owned_cluster:
                if run(['kind', 'delete', 'cluster', '--name', owner], timeout=90, required=False).returncode:
                    report['cleanupErrors'].append('owned-kind')
                absent = run(['docker', 'ps', '-aq', '--filter', 'label=io.x-k8s.kind.cluster=' + owner], required=False)
                report['ownedKindNodesAbsent'] = absent.returncode == 0 and not absent.stdout.strip()
                remaining_volumes = []
                for name in volume_names:
                    r = run(['docker', 'volume', 'inspect', name], required=False)
                    if r.returncode == 0:
                        if run(['docker', 'volume', 'rm', name], required=False).returncode:
                            remaining_volumes.append(name)
                report['ownedVolumesAbsent'] = not remaining_volumes
                if remaining_volumes:
                    report['cleanupErrors'].append('owned-volumes')
            if image_built and run(['docker', 'image', 'rm', image], required=False).returncode:
                report['cleanupErrors'].append('probe-image')
            try:
                shutil.rmtree(work)
            except OSError:
                report['cleanupErrors'].append('private-directory')
        report['sourceHashesAfter'] = hashes()
        report['sourceUnchanged'] = report['sourceHashesBefore'] == report['sourceHashesAfter']
        report['elapsedSeconds'] = round(time.monotonic() - started, 3)
        if report['cleanupErrors'] or not report['sourceUnchanged'] or (owned_cluster and not keep and not report.get('ownedKindNodesAbsent')):
            report['exit'] = 1
        (archive / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({k: report.get(k) for k in ['exit', 'probeExit', 'failure', 'sourceUnchanged', 'cleanupErrors', 'ownedKindNodesAbsent', 'ownedVolumesAbsent', 'elapsedSeconds']}), flush=True)
    return report['exit']


if __name__ == '__main__':
    raise SystemExit(main())
