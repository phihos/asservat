import hashlib,json,os,pathlib,subprocess,sys,time
root=pathlib.Path('/home/phil/Projekte/asservat-capture-phase-c62e02ac')
out=pathlib.Path(__file__).parent
label=sys.argv[1];cmd=sys.argv[2:]
env=os.environ.copy();extra={'TMPDIR':'/home/phil/.cache/asservat-build/tmp','GOTMPDIR':'/home/phil/.cache/asservat-build/tmp','GOMAXPROCS':'2','GOFLAGS':'-buildvcs=false -p=1'};env.update(extra)
paths=sorted(set(subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','*.go','go.mod','go.sum'],cwd=root,text=True).splitlines()))
def hashes():return {p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in paths}
before=hashes();(out/(label+'-source-before.json')).write_text(json.dumps(before,indent=2)+'\n')
start=time.monotonic()
with (out/(label+'.log')).open('w') as log:p=subprocess.run(cmd,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT)
after=hashes();(out/(label+'-source-after.json')).write_text(json.dumps(after,indent=2)+'\n')
result={'command':cmd,'cwd':str(root),'environment':extra,'exit':p.returncode,'wallSeconds':time.monotonic()-start,'sourceCount':len(paths),'sourceUnchanged':before==after,'log':label+'.log'}
(out/(label+'-result.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result));print((out/(label+'.log')).read_text())
sys.exit(p.returncode)
