import hashlib,json,os,pathlib,subprocess,sys,time
root=pathlib.Path('/home/phil/Projekte/asservat-capacity-candidates-c62e02ac')
cache=pathlib.Path(__file__).parent
name=sys.argv[1]
args=sys.argv[2:]
files=subprocess.check_output(['git','ls-files','-z','*.go','go.mod','go.sum'],cwd=root).decode().split(chr(0))
def hashes(): return {f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in files if f}
before=hashes()
(cache/(name+'-source-before.json')).write_text(json.dumps(before,indent=2)+'\n')
env=dict(os.environ)
overrides={'TMPDIR':'/home/phil/.cache/asservat-build/tmp','GOTMPDIR':'/home/phil/.cache/asservat-build/tmp','GOMAXPROCS':'2','GOFLAGS':'-buildvcs=false -p=1'}
env.update(overrides)
start=time.time()
with (cache/(name+'.log')).open('wb') as log:
 result=subprocess.run(args,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT)
after=hashes()
(cache/(name+'-source-after.json')).write_text(json.dumps(after,indent=2)+'\n')
receipt={'command':args,'cwd':str(root),'environmentOverrides':overrides,'inheritedGOCACHE':env.get('GOCACHE'),'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'exitCode':result.returncode,'elapsedSeconds':time.time()-start,'sourceCount':len(before),'sourceUnchanged':before==after,'log':str(cache/(name+'.log'))}
(cache/(name+'-result.json')).write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt))
print((cache/(name+'.log')).read_text())
sys.exit(result.returncode)
