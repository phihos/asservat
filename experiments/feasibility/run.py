"""Run host-side tests against the explicitly labelled private Docker S3 fixture."""
import hashlib,json,os,pathlib,subprocess,sys,time
ROOT=pathlib.Path(__file__).resolve().parents[2];EXP=ROOT/'experiments/feasibility'
fixture=json.loads(subprocess.check_output([sys.executable,str(EXP/'services.py'),'info'],text=True))
assert fixture['state']=='running'
cache=pathlib.Path(os.environ.get('ASSERVAT_LAB_STATE',str(pathlib.Path.home()/'.cache/asservat-feasibility-20261009')))
(cache/'go-tmp').mkdir(parents=True,exist_ok=True)
env=os.environ.copy();env.update(ASSERVAT_TEST_S3=fixture['endpoint'],TMPDIR=str(cache/'go-tmp'),GOTELEMETRY='off',GOTOOLCHAIN='local',ASSERVAT_PACKET_REPORT=str(EXP/'results/filter-parity.json'),ASSERVAT_FILTER_PROGRAMS=str(EXP/'results/filter-programs.json'),ASSERVAT_GADGET_PCAP=str(EXP/'results/gadget-pods.pcapng'),ASSERVAT_DOWNLOADED_PCAP=str(EXP/'results/downloaded-gadget.pcapng'))
mode=sys.argv[1] if len(sys.argv)>1 else 'test'
if mode=='test':args=['go','test','-race','-count=1','-v','./...']
elif mode=='measure':env.update(ASSERVAT_MEASURE='1',ASSERVAT_MEASUREMENT_PATH=str(EXP/'results/storage-measurements.json'));args=['go','test','-count=1','-run','^TestStorageMeasurements$','-v']
elif mode=='large':env.update(ASSERVAT_LARGE='1',ASSERVAT_LARGE_REPORT=str(EXP/'results/large-stream.json'));args=['go','test','-count=1','-run','^TestLargeStreamingArtifact$','-v','-timeout','8m']
elif mode=='baseline':env.update(ASSERVAT_BASELINE='1',ASSERVAT_BASELINE_REPORT=str(EXP/'results/sequential-baseline.json'));args=['go','test','-count=1','-run','^TestSequentialBaseline$','-v']
else:raise SystemExit('test|measure|large|baseline')
inputs=[*sorted((EXP/'go').rglob('*.go')),EXP/'go/go.mod',EXP/'go/go.sum']
record={'command':args,'scope':'Synthetic experiment only','fixture':fixture,'startedUnix':time.time(),'inputSHA256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}}
with (EXP/'results'/f'final-{mode}.log').open('w') as out:r=subprocess.run(args,cwd=EXP/'go',env=env,stdout=out,stderr=subprocess.STDOUT)
record.update(exit=r.returncode,elapsedSeconds=time.time()-record['startedUnix'])
(EXP/'results'/f'final-{mode}.json').write_text(json.dumps(record,indent=2)+'\n');print(mode,'exit',r.returncode,'seconds',round(record['elapsedSeconds'],2));raise SystemExit(r.returncode)
