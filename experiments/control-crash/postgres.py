"""Own only this labelled experiment container, anonymous volume and internal network."""
import json,subprocess,sys,time
NAME='asservat-postgres-control-crash-20261009';NETWORK='asservat-control-crash-20261009'
LABEL='asservat.experiment=control-crash-20261009'
IMAGE='postgres@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c'
def run(a):return subprocess.check_output(a,text=True).strip()
def info():
 x=json.loads(run(['docker','inspect',NAME]))[0]
 assert x['Config']['Labels']['asservat.experiment']=='control-crash-20261009'
 return x
mode=sys.argv[1]
if mode=='up':
 run(['docker','network','create','--internal','--label',LABEL,NETWORK])
 run(['docker','run','-d','--name',NAME,'--label',LABEL,'--network',NETWORK,'--user','postgres','--memory','768m','--cpus','2','--pids-limit','160','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,size=32m','--tmpfs','/var/run/postgresql:rw,nosuid,nodev,size=16m,mode=1777','-v','/var/lib/postgresql','-e','POSTGRES_PASSWORD=synthetic-only','-e','POSTGRES_DB=asservat_lab',IMAGE,'-c','max_connections=80','-c','shared_buffers=128MB','-c','fsync=on','-c','synchronous_commit=on'])
 for _ in range(60):
  if subprocess.run(['docker','exec',NAME,'pg_isready','-U','postgres','-d','asservat_lab'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('Fixture did not become ready')
 print('Ready:',info()['Id'])
elif mode=='info':
 x=info();print(json.dumps({'id':x['Id'],'image':x['Config']['Image'],'state':x['State']['Status'],'endpoint':x['NetworkSettings']['Networks'][NETWORK]['IPAddress']}))
elif mode=='down':
 info();run(['docker','rm','-f','-v',NAME])
 n=json.loads(run(['docker','network','inspect',NETWORK]))[0];assert n['Labels']['asservat.experiment']=='control-crash-20261009'
 run(['docker','network','rm',NETWORK]);print('Removed only owned PostgreSQL container, anonymous volume and network')
else:raise SystemExit('up|info|down')
