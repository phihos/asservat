#!/usr/bin/env python3
"""Owned actual bundled PG/Keycloak component; no installed Asservat authority.

Extends the original externally archived component runner. False is the default
profile. The opt-in profile deliberately assigns one synthetic human only after
proving the dedicated imported processing group is empty.
"""
import argparse,hashlib,json,os,pathlib,subprocess,time,uuid
parser=argparse.ArgumentParser()
parser.add_argument("--processing-operators",action="store_true",help="explicitly qualify the imported empty dedicated group")
parser.add_argument("--archive",type=pathlib.Path,required=True,help="new archive below ~/.cache/asservat-build")
parser.add_argument("--postgres-image",required=True,help="exact already-built bundled PostgreSQL component image")
args=parser.parse_args()
os.umask(0o077)
repo=pathlib.Path(__file__).resolve().parent.parent
cache=pathlib.Path.home()/'.cache/asservat-build'
base=args.archive.resolve().parent
owner='asv-small-kc-'+uuid.uuid4().hex[:10]
out=args.archive.resolve()
if out.exists() or not out.is_relative_to(cache.resolve()):raise SystemExit('use a NEW external archive below ~/.cache/asservat-build')
out.mkdir(parents=True,mode=0o700)
material=out/'material';material.mkdir()
network=owner+'-network'
pgimage=args.postgres_image
kcimage='quay.io/keycloak/keycloak@sha256:723b1d6e254c0fc96d5cffec860c7e0744d6a3277822b865bb538cf891575e41'
binary=out/'keycloak-component.test'
volumes={name:owner+'-'+name for name in ['pg-data','pg-repo','pg-secret','kc-secret']}
containers=[];created_volumes=[];network_created=False
sourcepaths=['scripts/test-small-keycloak.py','go.mod','go.sum','internal/contracts/small_keycloak.go','internal/contracts/small_services.go','internal/contracts/small_postgres.go','internal/bootstrap/small_keycloak_prepare.go','internal/bootstrap/small_keycloak_state.go','internal/adapters/kubernetes/small_keycloak_state.go','internal/adapters/kubernetes/small_postgres_material.go','internal/adapters/postgres/small_keycloak_database.go','test/integration/small_keycloak_test.go','test/integration/identity_provider_test.go','charts/asservat/templates/keycloak-deployment.yaml','charts/asservat/templates/keycloak-service.yaml','packaging/postgres/Dockerfile','packaging/postgres/entrypoint.sh','packaging/postgres/postgresql.conf','packaging/postgres/pg_hba.conf']
sourcepaths += [str(p.relative_to(repo)) for folder in ['internal/adapters/oidc','internal/domain/identity'] for p in sorted((repo/folder).glob('*.go')) if not p.name.endswith('_test.go')]
sourcepaths += ['internal/adapters/mtls/owner_roots.go']
sourcepaths += [str(p.relative_to(repo)) for folder in ['internal/domain/privacy','internal/domain/artifact','internal/domain/authorization'] for p in sorted((repo/folder).glob('*.go')) if not p.name.endswith('_test.go')]
report={'scope':'owned PG/Keycloak component with actual generated material; synthetic realm administration is not Asservat installation/evidence authority','owner':owner,'steps':[],'sources':{p:hashlib.sha256((repo/p).read_bytes()).hexdigest() for p in sourcepaths},'driverSHA256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'processingOperators':args.processing_operators}
log=out/'commands.log'
def command(args,check=True,timeout=60):
 r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 with log.open('ab') as f:f.write((' '.join(args)+'\nexit='+str(r.returncode)+'\n').encode());f.write(r.stdout);f.write(r.stderr)
 if check and r.returncode:raise RuntimeError('command failed at '+args[0]+' '+(args[1] if len(args)>1 else ''))
 return r
def docker(args,**kwargs):return command(['docker',*args],**kwargs)
def wait(check,seconds,stage):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if check():report['steps'].append(stage);return
  time.sleep(1)
 raise RuntimeError(stage+' deadline')
def client(stage,label=None):
 label=label or stage
 name=owner+'-client-'+label;containers.append(name)
 envbase=json.loads(docker(['image','inspect',pgimage]).stdout)[0]['Config'].get('Env',[])
 unset=[]
 for entry in envbase:
  key=entry.split('=',1)[0]
  if key.startswith('PG'):unset+=['-u',key]
 result=docker(['run','--rm','--name',name,'--label','asservat.test.owner='+owner,'--network',network,'--read-only','--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','512m','--cpus','2','--mount','type=bind,src='+str(binary)+',dst=/probe,readonly','--mount','type=bind,src='+str(material)+',dst=/fixture,readonly','--mount','type=bind,src='+str(out)+',dst=/result','-e','ASSERVAT_SMALL_KEYCLOAK_FIXTURE=/fixture','-e','ASSERVAT_SMALL_KEYCLOAK_STAGE='+stage,'-e','ASSERVAT_SMALL_KEYCLOAK_RECEIPT=/result/identity-receipt.json','--entrypoint','/usr/bin/env',pgimage,*unset,'/probe','-test.v','-test.run','^TestSmallKeycloakBundleWithRealPostgres$','-test.timeout','90s'],check=False,timeout=110)
 (out/(label+'.log')).write_bytes(result.stdout+result.stderr)
 if result.returncode:raise RuntimeError('component stage '+stage+' exit '+str(result.returncode))
 report['steps'].append(label)
status=1
started_monotonic=time.monotonic()
try:
 build_env=os.environ.copy();build_env['TMPDIR']=str(cache/'tmp');(cache/'tmp').mkdir(exist_ok=True)
 build=subprocess.run(['go','test','-c','-o',str(binary),'./test/integration'],cwd=repo,env=build_env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=180)
 (out/'compile.log').write_bytes(build.stdout);report['compileExit']=build.returncode
 if build.returncode:raise RuntimeError('actual component compile failed')
 report['binarySHA256']=hashlib.sha256(binary.read_bytes()).hexdigest()
 env=os.environ.copy();env['ASSERVAT_SMALL_KEYCLOAK_EXPORT']=str(material)
 env['ASSERVAT_SMALL_KEYCLOAK_PROCESSING_OPERATORS']='true' if args.processing_operators else 'false' 
 r=subprocess.run([str(binary),'-test.v','-test.run','^TestSmallKeycloakBundleWithRealPostgres$'],cwd=repo,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
 (out/'export.log').write_bytes(r.stdout)
 if r.returncode:raise RuntimeError('actual material exporter failed')
 report['steps'].append('actual-material-export')
 (material/'operator-keycloak-password').write_text('operator-${ASSERVAT_UNUSED_LITERAL}-$$-value')
 report['operatorLiteralPassword']=True
 # Explicit synthetic operator-supplied serving TLS, independent of product roots.
 command(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','1','-subj','/CN=owned-component-root','-keyout',str(material/'kc-ca.key'),'-out',str(material/'kc-ca.crt'),'-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'])
 command(['openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN=identity.smoke','-keyout',str(material/'kc-tls.key'),'-out',str(material/'kc-tls.csr')])
 (material/'kc-tls.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:identity.smoke\n')
 command(['openssl','x509','-req','-in',str(material/'kc-tls.csr'),'-CA',str(material/'kc-ca.crt'),'-CAkey',str(material/'kc-ca.key'),'-CAcreateserial','-days','1','-extfile',str(material/'kc-tls.ext'),'-out',str(material/'kc-leaf.crt')])
 (material/'kc-tls.crt').write_bytes((material/'kc-leaf.crt').read_bytes()+(material/'kc-ca.crt').read_bytes())
 if docker(['image','inspect',kcimage],check=False).returncode:docker(['pull',kcimage],timeout=180)
 report['keycloakImage']={'requested':kcimage,'id':docker(['image','inspect',kcimage,'--format','{{.Id}}']).stdout.decode().strip()}
 report['postgresImage']={'requested':pgimage,'id':docker(['image','inspect',pgimage,'--format','{{.Id}}']).stdout.decode().strip()}
 docker(['network','create','--label','asservat.test.owner='+owner,network]);network_created=True
 for name in volumes.values():docker(['volume','create','--label','asservat.test.owner='+owner,name]);created_volumes.append(name)
 seed='''set -eu
for f in ca.crt server.crt server.key administrator-password ddl-verifier backup-verifier backup.pgpass backup-cipher keycloak-verifier; do cp /input/pg/$f /pg/$f; done
cp /input/kc/asservat-realm.json /kc/asservat-realm.json
cp /input/kc-tls.crt /kc/tls.crt
cp /input/kc-tls.key /kc/tls.key
cp /input/pg/ca.crt /kc/ca.crt
chown -R 999:999 /pg /data /repo
chown -R 1000:1000 /kc
chmod 0700 /pg /data /repo /kc
chmod 0600 /pg/*
chmod 0440 /kc/*
'''
 mounts=[]
 for key,dst in [('pg-secret','/pg'),('kc-secret','/kc'),('pg-data','/data'),('pg-repo','/repo')]:mounts+=['--mount','type=volume,src='+volumes[key]+',dst='+dst]
 docker(['run','--rm','--label','asservat.test.owner='+owner,'--network','none','--user','0:0','--entrypoint','bash','--mount','type=bind,src='+str(material)+',dst=/input,readonly',*mounts,pgimage,'-ec',seed])
 pgname=owner+'-postgres';containers.append(pgname)
 docker(['run','-d','--name',pgname,'--label','asservat.test.owner='+owner,'--network',network,'--network-alias','trial-postgres.smoke.svc','--network-alias','wrong-host','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','1g','--cpus','2','--tmpfs','/tmp:rw,uid=999,gid=999,mode=1777','--tmpfs','/run/asservat/postgres:rw,uid=999,gid=999,mode=0700','--mount','type=volume,src='+volumes['pg-data']+',dst=/var/lib/postgresql','--mount','type=volume,src='+volumes['pg-repo']+',dst=/var/lib/pgbackrest','--mount','type=volume,src='+volumes['pg-secret']+',dst=/run/asservat/postgres-private,readonly','-e','PGHOST=trial-postgres.smoke.svc','-e','PGMAXCONNECTIONS=122','-e','KEYCLOAK_DATABASE=true',pgimage,'server'])
 wait(lambda:docker(['exec',pgname,'pg_isready','-h','127.0.0.1'],check=False).returncode==0,45,'postgres-ready')
 client('database')
 envfile=out/'keycloak.env'
 envfile.write_text('\n'.join(['KC_HOSTNAME=https://identity.smoke:8443','KC_HOSTNAME_STRICT=true','KC_HTTPS_CERTIFICATE_FILE=/private/tls.crt','KC_HTTPS_CERTIFICATE_KEY_FILE=/private/tls.key','KC_DB_URL=jdbc:postgresql://trial-postgres.smoke.svc:5432/keycloak?sslmode=verify-full&sslrootcert=/private/ca.crt','KC_DB_USERNAME=keycloak','KCRAW_DB_PASSWORD='+(material/'operator-keycloak-password').read_text(),'ASSERVAT_UNUSED_LITERAL=interpolation-must-not-happen','KC_DB_POOL_INITIAL_SIZE=1','KC_DB_POOL_MIN_SIZE=1','KC_DB_POOL_MAX_SIZE=5','KC_BOOTSTRAP_ADMIN_USERNAME='+(material/'kc/bootstrap-admin-username').read_text(),'KC_BOOTSTRAP_ADMIN_PASSWORD='+(material/'kc/bootstrap-admin-password').read_text(),'KC_ASSERVAT_CONSOLE_SECRET='+(material/'kc/console-client-secret').read_text()])+'\n')
 kcname=owner+'-keycloak';containers.append(kcname)
 start_mark=str(int(time.time()))
 docker(['run','-d','--name',kcname,'--label','asservat.test.owner='+owner,'--network',network,'--network-alias','identity.smoke','--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','1g','--cpus','2','--pids-limit','512','--tmpfs','/tmp:rw,uid=1000,gid=1000,mode=1777,size=64m','--mount','type=volume,src='+volumes['kc-secret']+',dst=/private,readonly','--mount','type=volume,src='+volumes['kc-secret']+',dst=/opt/keycloak/data/import,readonly','--env-file',str(envfile),kcimage,'start','--import-realm','--db=postgres','--cache=local','--http-enabled=false','--https-port=8443','--health-enabled=true'])
 def started():
  if docker(['inspect',kcname,'--format','{{.State.Running}}']).stdout.strip()!=b'true':raise RuntimeError('Keycloak process exited during cold start')
  logs=docker(['logs','--since',start_mark,kcname]).stdout
  return b'Keycloak 26.8.2' in logs and b'started in' in logs
 wait(started,150,'keycloak-listener-start')
 client('readiness','readiness-cold')
 for owned in [pgname,kcname]:
  if docker(['inspect',owned,'--format','{{json .HostConfig.PortBindings}}']).stdout.strip() not in [b'{}',b'null']:raise RuntimeError('unexpected published port')
 report['steps'].append('no-published-ports')
 client('identity')
 docker(['stop','-t','20',kcname])
 client('retained')
 start_mark=str(int(time.time()))
 docker(['start',kcname])
 wait(started,90,'keycloak-restart-listener')
 client('readiness','readiness-restart')
 client('restart')
 status=0
except Exception as e:
 report['failure']=str(e)
finally:
 for name in containers:
  r=docker(['logs',name],check=False)
  (out/(name+'.log')).write_bytes(r.stdout+r.stderr)
 cleanup=[]
 for name in reversed(containers):
  if docker(['inspect',name],check=False).returncode==0 and docker(['rm','-f',name],check=False).returncode:cleanup.append(name)
 for name in reversed(created_volumes):
  if docker(['volume','rm',name],check=False).returncode:cleanup.append(name)
 if network_created and docker(['network','rm',network],check=False).returncode:cleanup.append(network)
 report['cleanupErrors']=cleanup
 report['sourceUnchanged']=all(hashlib.sha256((repo/p).read_bytes()).hexdigest()==digest for p,digest in report['sources'].items())
 report['remainingOwned']={kind:docker(([kind,'ls','-q','--filter','label=asservat.test.owner='+owner] if kind!='container' else ['ps','-aq','--filter','label=asservat.test.owner='+owner]),check=False).stdout.decode().splitlines() for kind in ['container','volume','network']}
 report['durationSeconds']=round(time.monotonic()-started_monotonic,3)
 report['exit']=status if not cleanup and report['sourceUnchanged'] and not any(report['remainingOwned'].values()) else 1
 (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
 (base/'latest-result.txt').write_text(str(out/'result.json')+'\n')
 print(json.dumps({'result':str(out/'result.json'),'exit':report['exit'],'failure':report.get('failure'),'steps':report['steps'],'cleanupErrors':cleanup,'remainingOwned':report['remainingOwned'],'sourceUnchanged':report['sourceUnchanged']}))
raise SystemExit(report['exit'])
