from pathlib import Path
import hashlib,json,os,re,signal,subprocess,time,tempfile,shutil
stage=Path(__file__).resolve().parent
repo=Path('/home/phil/Projekte/asservat')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
maps={n:json.loads((stage/(n+'.json')).read_text()) for n in ['payload','bases','dependencies','freeze']}
def live_paths():
    paths=set(subprocess.check_output(['rg','--files','-g','*.go','-g','go.mod','-g','go.sum'],cwd=repo,text=True).splitlines())
    for directory in ['internal','api','cmd','migrations']:
        paths.update(subprocess.check_output(['rg','--files',directory],cwd=repo,text=True).splitlines())
    paths.update(['Makefile','scripts/check-go-architecture.py','docs/architecture/catalog.yaml'])
    return paths
mirror=None
mirror_map={**maps['dependencies'],**maps['payload']}
def check():
    state={'dependencies':[k for k,v in maps['dependencies'].items() if sha(repo/k)!=v], 'bases':[k for k,v in maps['bases'].items() if sha(repo/k)!=v], 'payload':[k for k,v in maps['payload'].items() if sha(stage/'files'/k)!=v], 'liveFileSet':sorted(live_paths()^set(maps['dependencies'])), 'payloadFileSet':sorted({str(p.relative_to(stage/'files')) for p in (stage/'files').rglob('*') if p.is_file()}^set(maps['payload'])), 'freeze':[k for k,v in maps['freeze'].items() if sha(stage/k)!=v]}
    if mirror is not None:
        state['mirror']=[k for k,v in mirror_map.items() if sha(mirror/k)!=v]
        state['mirrorFileSet']=sorted({str(p.relative_to(mirror)) for p in mirror.rglob('*') if p.is_file()}^set(mirror_map))
    return state
# Refuse reuse before touching logs. No overwritten evidence is reconstructed.
evidence=stage/'evidence'
evidence.mkdir(exist_ok=False)
initial=check()
(evidence/'preflight.json').write_text(json.dumps(initial,indent=2)+'\n')
if any(initial.values()):raise SystemExit('source preflight mismatch')
free=shutil.disk_usage('/tmp').free
if free<4*1024**3 or subprocess.check_output(['stat','-f','-c','%T','/tmp'],text=True).strip()!='tmpfs':raise SystemExit('owned tmpfs scratch requires 4 GiB free')
scratch=Path(tempfile.mkdtemp(prefix='asservat-direct-holder-',dir='/tmp'))
if scratch.stat().st_uid!=os.getuid() or scratch.stat().st_mode & 0o777 !=0o700:raise SystemExit('invalid owned scratch')
(evidence/'scratch.json').write_text(json.dumps({'path':str(scratch),'uid':os.getuid(),'mode':'0700','freeBefore':free},indent=2)+'\n')
env=os.environ.copy();env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(scratch))
for key in list(env):
    if key.startswith('ASSERVAT_') and ('FIXTURE' in key or 'NATIVE' in key):del env[key]
reports=[];terminal=1

def phase(name,command,expected=0,marker=None):
    before=check()
    if any(before.values()):
        (evidence/(name+'-preflight.json')).write_text(json.dumps(before,indent=2)+'\n')
        raise RuntimeError('immutable preflight mismatch')
    start=time.monotonic()
    with (evidence/(name+'.log')).open('x') as log:
        child=subprocess.Popen(command,cwd=repo,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        print(json.dumps({'phase':name,'pid':child.pid,'command':command}),flush=True)
        try:code=child.wait(timeout=600)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGTERM)
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
            code=124
    after=check();log=(evidence/(name+'.log')).read_text()
    report={'phase':name,'command':command,'exit':code,'expectedExit':expected,'seconds':round(time.monotonic()-start,3),'before':before,'after':after,'topLevelPass':len(re.findall(r'^--- PASS:',log,re.M)),'namedPass':len(re.findall(r'^\s*--- PASS:',log,re.M)),'skips':len(re.findall(r'^\s*--- SKIP:',log,re.M)),'failureMarker':marker,'markerOccurrences':log.count(marker) if marker else None}
    (evidence/(name+'.json')).write_text(json.dumps(report,indent=2)+'\n');reports.append(report)
    print(json.dumps(report),flush=True)
    if code!=expected or any(after.values()) or marker and marker not in log:raise RuntimeError('phase did not produce required verdict: '+name)
    if name=='race' and (report['topLevelPass']<23 or report['skips']):raise RuntimeError('missing or skipped selected tests')
try:
    mirror=scratch/'mirror';mirror.mkdir()
    for path,digest in mirror_map.items():
        source=stage/'files'/path if path in maps['payload'] else repo/path
        if sha(source)!=digest:raise RuntimeError('changed mirror input: '+path)
        target=mirror/path;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
        if sha(target)!=digest:raise RuntimeError('mirror copy mismatch: '+path)
    (evidence/'mirror-manifest.json').write_text(json.dumps(mirror_map,indent=2,sort_keys=True)+'\n')
    overlay=['-overlay',str(stage/'overlay.json')]
    packages=['./internal/contracts','./internal/adapters/kubernetes','./internal/adapters/mtls','./internal/transport/clusterobservation','./internal/bootstrap']
    phase('compile',['go','test',*overlay,'-vet=off','-run','^$',*packages])
    phase('before',['go','test','-overlay',str(stage/'before-overlay.json'),'-vet=off','-count=1','-timeout=30s','-run','^TestDirectHolderUnavailableFirstCandidateKeepsIndependentPositive$','-v','./internal/bootstrap'],expected=1,marker='unavailable first candidate cancelled independent pending positive')
    pattern='^Test(OwnerLocalObservation|OwnerObservation(DialCandidate|Candidate|Operation)|ClusterObservationCaller|DirectHolder|Local(Pending|Registry|Receiver|ObservationRouting)|OperationHolder|OwnerPending|OwnerOperation(Routing|Receiver)|HubObservationOperation|ObservationOperationRouting|OperationChannel|OperationCoordinator|OperationOwner|ConnectorOperation|ConnectorObservationChannel|HubConnectorObservation|OwnerBootstrap|RegionalOperationActual|RegionalObservationOperation)'
    phase('race',['go','test',*overlay,'-race','-vet=off','-count=1','-timeout=180s','-run',pattern,'-v',*packages])
    phase('vet',['go','vet',*overlay,*packages])
    phase('go-architecture',['python3',str(mirror/'scripts/check-go-architecture.py')])
    terminal=0
finally:
    final=check()
    shutil.rmtree(scratch)
    cleanup={'removed':not scratch.exists(),'freeAfter':shutil.disk_usage('/tmp').free}
    (evidence/'scratch-cleanup.json').write_text(json.dumps(cleanup)+'\n')
    summary={'terminal':terminal,'phases':reports,'finalHashes':final,'cleanup':cleanup,'nativeQualification':False,'installedSelection':False}
    (evidence/'RESULT.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({'terminal':terminal,'phases':len(reports),'finalHashes':final,'cleanup':cleanup}),flush=True)
