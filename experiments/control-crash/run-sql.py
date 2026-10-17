"""Run only against the labelled disposable PostgreSQL fixture."""
import hashlib,json,os,pathlib,subprocess,sys,time
ROOT=pathlib.Path(__file__).resolve().parents[2];EXP=ROOT/'experiments/control-crash'
NAME='asservat-postgres-control-crash-20261009';NETWORK='asservat-control-crash-20261009'
x=json.loads(subprocess.check_output(['docker','inspect',NAME]))[0]
assert x['Config']['Labels']['asservat.experiment']=='control-crash-20261009'
assert x['State']['Running']
ip=x['NetworkSettings']['Networks'][NETWORK]['IPAddress']
env=os.environ.copy();cache=pathlib.Path.home()/'.cache/asservat-control-crash-20261009/go-tmp';cache.mkdir(parents=True,exist_ok=True)
env.update(ASSERVAT_TEST_PG=f'postgres://postgres:synthetic-only@{ip}:5432/asservat_lab?sslmode=disable',TMPDIR=str(cache),GOTELEMETRY='off',GOTOOLCHAIN='local')
mode=sys.argv[1] if len(sys.argv)>1 else 'test'
args=['go','test','-race','-count=1','-v','-timeout','2m','./...']
if mode=='restart':
 subprocess.run(['docker','kill','--signal=KILL',NAME],check=True,stdout=subprocess.DEVNULL)
 subprocess.run(['docker','start',NAME],check=True,stdout=subprocess.DEVNULL)
 for _ in range(50):
  if subprocess.run(['docker','exec',NAME,'pg_isready','-U','postgres','-d','asservat_lab'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
  time.sleep(.2)
 else:raise RuntimeError('PostgreSQL restart readiness timeout')
 env['ASSERVAT_AFTER_RESTART']='1';args=['go','test','-count=1','-v','-run','^TestAfterRestartDurability$','-timeout','30s']
elif mode!='test':raise SystemExit('test|restart')
record={'scope':'Isolated single-primary SQL experiment. Synthetic units/identities; no production authorization or HA qualification.','command':args,'fixtureID':x['Id'],'image':x['Config']['Image'],'startedUnix':time.time(),'inputSHA256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((EXP/'go').rglob('*')) if p.is_file()}}
with (EXP/'results'/f'sql-{mode}.log').open('w') as out:p=subprocess.run(args,cwd=EXP/'go',env=env,stdout=out,stderr=subprocess.STDOUT)
record.update(exit=p.returncode,seconds=time.time()-record['startedUnix'])
(EXP/'results'/f'sql-{mode}.json').write_text(json.dumps(record,indent=2)+'\n');print(mode,'exit',p.returncode,'seconds',round(record['seconds'],3));sys.exit(p.returncode)
