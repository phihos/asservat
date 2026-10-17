"""Create/remove only the labelled disposable S3 fixture. No production backend change."""
import json,subprocess,sys,time,urllib.error,urllib.request
NAME='asservat-s3-feasibility-20261009';NETWORK='asservat-feasibility-20261009'
IMAGE='chrislusf/seaweedfs@sha256:4e61d15fd35994cb1e43e1e553dff106794841fd9a99ade2fc8c8bfce4d7872d'
LABEL='asservat.experiment=feasibility-20261009'
def run(args):return subprocess.check_output(args,text=True).strip()
def info():
 x=json.loads(run(['docker','inspect',NAME]))[0]
 assert x['Config']['Labels']['asservat.experiment']=='feasibility-20261009'
 ip=x['NetworkSettings']['Networks'][NETWORK]['IPAddress']
 return {'containerID':x['Id'],'imageID':x['Image'],'endpoint':'http://'+ip+':8333','state':x['State']['Status'],'network':NETWORK}
if sys.argv[1]=='up':
 # Creation fails on a name collision; never attach to an unrelated service.
 run(['docker','network','create','--internal','--label',LABEL,NETWORK])
 args=['docker','run','-d','--name',NAME,'--label',LABEL,'--network',NETWORK,'--memory','768m','--cpus','1','--pids-limit','256','--cap-drop','ALL','--security-opt','no-new-privileges','--user','1000:1000','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,size=64m','-v','/data','-e','AWS_ACCESS_KEY_ID=synthetic-only','-e','AWS_SECRET_ACCESS_KEY=synthetic-only-secret','--entrypoint','/usr/bin/weed',IMAGE,'mini','-dir=/data','-ip.bind=0.0.0.0','-admin.ui=false','-s3.port=8333']
 run(args)
 for attempt in range(30):
  x=info()
  if x['state']!='running':raise RuntimeError('Fixture stopped; inspect its log')
  try:urllib.request.urlopen(x['endpoint'],timeout=1);break
  except urllib.error.HTTPError as e:
   if e.code==403:break
  except OSError:pass
  time.sleep(.5)
 else:raise RuntimeError('S3 readiness timeout')
 print(json.dumps(x))
elif sys.argv[1]=='info':print(json.dumps(info()))
elif sys.argv[1]=='down':
 info();run(['docker','rm','-f','-v',NAME])
 n=json.loads(run(['docker','network','inspect',NETWORK]))[0]
 assert n['Labels']['asservat.experiment']=='feasibility-20261009'
 run(['docker','network','rm',NETWORK]);print('Removed own S3 container, anonymous volume and network')
else:raise SystemExit('up|info|down')
