#!/usr/bin/env python3
"""Owned, loopback-only Keycloak qualification with synthetic identities."""
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'quay.io/keycloak/keycloak@sha256:b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc'

def run(args, **kwargs):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE, timeout=180, **kwargs).strip()

def source_hashes():
    files = [Path(__file__), ROOT/'go.mod', ROOT/'go.sum']
    files += list((ROOT/'internal').rglob('*.go'))
    files += list((ROOT/'test/integration').glob('*.go'))
    files += list((ROOT/'migrations').rglob('*.sql')) + list((ROOT/'migrations').rglob('*.go'))
    files += list((ROOT/'test/fixtures/sql').glob('*.sql'))
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}

def main():
    cache = Path.home()/'.cache/asservat-build'
    cache.mkdir(parents=True, exist_ok=True)
    results = ROOT/'test/results'
    results.mkdir(exist_ok=True)
    report = {'scope': 'Synthetic Keycloak plus Asservat browser/SQL/encrypted-credential composition; no public deployment or collection', 'image': IMAGE, 'sourceBefore': source_hashes(), 'testExit': None, 'cleanupFailures': []}
    status = 1
    with tempfile.TemporaryDirectory(prefix='identity-', dir=cache) as tmp:
        work = Path(tmp)
        work.chmod(0o755)  # Container reads only explicitly mounted synthetic files.
        name = 'asservat-'+work.name
        created = False
        support = []
        try:
            fixture_spec = importlib.util.spec_from_file_location('custody_fixture', ROOT/'scripts/test-custody.py')
            fixture_module = importlib.util.module_from_spec(fixture_spec)
            fixture_spec.loader.exec_module(fixture_module)
            def service(suffix, image, extra, command, container_port):
                owned = name+'-'+suffix
                run(['docker','run','-d','--name',owned,'--label','asservat.test='+work.name,'--cpus','2','--memory','768m','--pids-limit','256','-p',f'127.0.0.1::{container_port}',*extra,image,*command])
                support.append(owned)
                info=json.loads(run(['docker','inspect',owned]))[0]
                report.setdefault('supportImages',{})[owned]={'requested':image,'imageID':info['Image']}
                return int(info['NetworkSettings']['Ports'][str(container_port)+'/tcp'][0]['HostPort']),owned
            pgport,pgname=service('postgres',fixture_module.POSTGRES,['-e','POSTGRES_PASSWORD=synthetic-only','-e','POSTGRES_DB=custody_test'],['-c','max_connections=48','-c','synchronous_commit=on'],5432)
            baoport,_=service('kms',fixture_module.BAO,['-e','SKIP_SETCAP=true','-e','BAO_DISABLE_MLOCK=true','--entrypoint','/usr/bin/bao'],['server','-dev','-dev-no-store-token','-dev-root-token-id=synthetic-root','-dev-listen-address=0.0.0.0:8200'],8200)
            # ADR-193 step 4: encrypted issuance audit needs an owned S3 store.
            s3port,_=service('s3',fixture_module.SEAWEED,['--user','1000:1000','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,size=64m','-v','/data','-e','AWS_ACCESS_KEY_ID=synthetic-only','-e','AWS_SECRET_ACCESS_KEY=synthetic-only-secret','--entrypoint','/usr/bin/weed'],['mini','-dir=/data','-ip.bind=0.0.0.0','-admin.ui=false','-s3.port=8333'],8333)
            for _ in range(100):
                if subprocess.run(['docker','exec',pgname,'pg_isready','-h','127.0.0.1','-U','postgres','-d','custody_test'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0: break
                time.sleep(.1)
            else: raise RuntimeError('owned PostgreSQL readiness failed')
            for _ in range(80):
                try:
                    urllib.request.urlopen(f'http://127.0.0.1:{s3port}', timeout=1).close()
                    break
                except urllib.error.HTTPError as exc:
                    if exc.code in (403, 404): break
                except OSError: pass
                time.sleep(.25)
            else: raise RuntimeError('owned S3 readiness failed')
            dsn=f'postgres://postgres:synthetic-only@127.0.0.1:{pgport}/custody_test?sslmode=disable'
            migration_env=os.environ.copy();migration_env.update({'GOOSE_DRIVER':'postgres','GOOSE_DBSTRING':dsn})
            report['migration']=run([str(cache/'bin/goose'),'-dir',str(ROOT/'migrations'),'up'],env=migration_env)
            run(['docker','exec',pgname,'psql','-U','postgres','-d','custody_test','-v','ON_ERROR_STOP=1','-c',(ROOT/'test/fixtures/sql/runtime-roles.sql').read_text()])
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            issuer = f'https://localhost:{port}/realms/asservat-test'
            callback_host='127.0.0.1'
            run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', f'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:{callback_host}', '-keyout', str(work/'key.pem'), '-out', str(work/'cert.pem')])
            for filename in ['key.pem', 'cert.pem']:
                (work/filename).chmod(0o444)
            admin_password, user_password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            env = work/'container.env'
            env.write_text(f'KC_BOOTSTRAP_ADMIN_USERNAME=fixture-admin\nKC_BOOTSTRAP_ADMIN_PASSWORD={admin_password}\n')
            env.chmod(0o600)
            config = work/'fixture.json'
            config.write_text(json.dumps({'issuer': issuer, 'rootCA': str(work/'cert.pem'), 'adminUser': 'fixture-admin', 'adminPassword': admin_password, 'userPassword': user_password,'postgres':dsn,'kms':f'http://127.0.0.1:{baoport}','s3':f'http://127.0.0.1:{s3port}','callbackHost':callback_host,'callbackKey':str(work/'key.pem')}))
            config.chmod(0o600)
            run(['docker', 'run', '-d', '--name', name, '--label', 'asservat.test='+work.name, '--cpus', '2', '--memory', '1536m', '--pids-limit', '512', '--network', 'host', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--env-file', str(env), '--mount', f'type=bind,src={work}/cert.pem,dst=/fixture/cert.pem,readonly', '--mount', f'type=bind,src={work}/key.pem,dst=/fixture/key.pem,readonly', IMAGE, 'start', '--db=dev-file', '--http-enabled=false', '--http-host=127.0.0.1', f'--https-port={port}', '--https-certificate-file=/fixture/cert.pem', '--https-certificate-key-file=/fixture/key.pem', '--truststore-paths=/fixture/cert.pem', '--hostname', f'https://localhost:{port}', '--cache=local', '--health-enabled=false', '--metrics-enabled=false'])
            created = True
            report['imageID'] = run(['docker', 'inspect', name, '--format', '{{.Image}}'])
            tls = ssl.create_default_context(cafile=str(work/'cert.pem'))
            endpoint = f'https://localhost:{port}/realms/master/.well-known/openid-configuration'
            ready = False
            for _ in range(120):
                try:
                    with urllib.request.urlopen(endpoint, context=tls, timeout=2) as response:
                        ready = response.status == 200
                except (OSError, ValueError):
                    pass
                if ready:
                    break
                time.sleep(1)
            if not ready:
                raise RuntimeError('owned Keycloak failed readiness')
            listeners=run(['ss','-H','-ltn',f'sport = :{port}'])
            report['listenerEvidence']=listeners
            def loopback_listener(line):
                host,_,selected_port=line.split()[3].rpartition(':')
                parsed=ipaddress.ip_address(host.strip('[]'))
                normalized=getattr(parsed,'ipv4_mapped',None) or parsed
                return str(normalized)=='127.0.0.1' and selected_port==str(port)
            if not listeners or not all(loopback_listener(line) for line in listeners.splitlines()):
                raise RuntimeError('owned Keycloak did not bind exclusively to loopback')
            report['verifiedListenAddress']=f'127.0.0.1:{port}'
            print('Owned TLS Keycloak ready; running provider qualification', flush=True)
            test_env = os.environ.copy()
            test_env.update({'ASSERVAT_IDENTITY_FIXTURE': str(config), 'TMPDIR': str(cache/'tmp')})
            (cache/'tmp').mkdir(exist_ok=True)
            with (results/'identity-provider.log').open('w') as log:
                status = subprocess.run(['go', 'test', '-race', '-count=1', '-v', './test/integration', '-run', '^TestKeycloakProvider$'], cwd=ROOT, env=test_env, stdout=log, stderr=subprocess.STDOUT, timeout=180).returncode
            report['testExit'] = status
            if status:
                diagnostic=subprocess.run(['docker','logs',name],text=True,capture_output=True,timeout=10)
                (results/'identity-provider-keycloak.log').write_text(diagnostic.stdout+diagnostic.stderr)
        finally:
            if created:
                try:
                    run(['docker', 'rm', '-f', name])
                except Exception:
                    report['cleanupFailures'].append(name)
            for owned in reversed(support):
                try:
                    run(['docker','rm','-f','-v',owned])
                except Exception:
                    report['cleanupFailures'].append(owned)
            report['sourceAfter'] = source_hashes()
            report['sourceUnchangedDuringTest'] = report['sourceBefore'] == report['sourceAfter']
            (results/'identity-provider-environment.json').write_text(json.dumps(report, indent=2)+'\n')
    if report['cleanupFailures'] or not report['sourceUnchangedDuringTest']:
        status = 1
    print(f'Provider test exit: {status}', flush=True)
    return status

if __name__ == '__main__':
    raise SystemExit(main())
