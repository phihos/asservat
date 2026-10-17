"""Run only in the owned disposable VM; changes only its core hook and synthetic fixture."""
import concurrent.futures,hashlib,json,os,pathlib,resource,signal,socket,subprocess,time
P=pathlib.Path
assert P('/root/ASSERVAT_DISPOSABLE_VM').exists()
RUN_ID=os.environ.get('ASSERVAT_RUN_ID','run-1');assert RUN_ID.replace('-','').isalnum() and len(RUN_ID)<32
BASE=P('/run/asservat-crash');DISK=P('/var/lib/asservat-crash')/RUN_ID;BIN=P('/opt/asservat-lab')
BASE.mkdir(mode=0o700,exist_ok=True);DISK.mkdir(mode=0o700,parents=True,exist_ok=True);(BASE/RUN_ID).mkdir(mode=0o700,exist_ok=True)
PAT=P('/proc/sys/kernel/core_pattern');LIM=P('/proc/sys/kernel/core_pipe_limit')
original={'pattern':PAT.read_text(),'pipeLimit':LIM.read_text()};pattern='|/opt/asservat-lab/helper %P %s %u'
out={'environment':{'kernel':os.uname().release,'original':original,'helperSHA256':hashlib.sha256((BIN/'helper').read_bytes()).hexdigest(),'receiverSHA256':hashlib.sha256((BIN/'receiver').read_bytes()).hexdigest()},'cases':[]}
def put(p,s):p.write_text(str(s))
def ticks(pid):return int(P(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19])
def waitfile(p,timeout=5):
 end=time.monotonic()+timeout
 while not p.exists():
  if time.monotonic()>end:raise TimeoutError(str(p))
  time.sleep(.01)
def crasher(size=4194304,nested=False):
 def prep():
  resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 cmd=['setpriv','--reuid','65534','--regid','65534','--clear-groups',str(BIN/'fixture'),str(size)]
 if nested:cmd=['unshare','--pid','--fork','--mount-proc',*cmd]
 p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=prep)
 inner=int(p.stdout.readline());pid=p.pid
 if nested:
  children=P(f'/proc/{pid}/task/{pid}/children').read_text().split();assert len(children)==1;pid=int(children[0]);assert inner==1
 return p,pid,inner
def launch_receiver(cfg,path):
 put(path,json.dumps(cfg));(path.parent/'ready').unlink(missing_ok=True)
 def prep():
  put(P('/sys/fs/cgroup/asservat-receiver/cgroup.procs'),os.getpid())
 return subprocess.Popen(['unshare','--net',str(BIN/'receiver'),str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,preexec_fn=prep,env={'PATH':'/usr/bin:/bin','GOMEMLIMIT':'64MiB','GOMAXPROCS':'2'})
def finish_receiver(p):
 if p is None:return
 if p.poll() is None:p.terminate()
 try:p.wait(timeout=2)
 except subprocess.TimeoutExpired:p.kill();p.wait()
 return p.stderr.read().decode(errors='replace')[:2048]
def one_case(name,mode='normal',size=4194304,count=1,nested=False,expires=True,permits=True,receiver=True,kill_receiver=False,restart_spent=False,backlog=False,wrong_identity=False,kill_signal=False):
 directory=DISK/name;native=BASE/RUN_ID/name;directory.mkdir(mode=0o700);native.mkdir(mode=0o700)
 procs=[crasher(size,nested) for _ in range(count)];cfg={'Mode':mode,'Dir':str(directory),'NativeDir':str(native),'Expires':int(time.time()*1000)+(30000 if expires else -1),'Permits':[{'PID':pid,'Start':ticks(pid)} for _,pid,_ in procs] if permits else []}
 if wrong_identity:cfg['Permits'][0]['Start']+=1
 sock=BASE/'socket';sock.unlink(missing_ok=True);rx=None;blocker=None;clients=[]
 try:
  if receiver:
   rx=launch_receiver(cfg,directory/'config.json');waitfile(directory/'ready')
  if backlog:
   blocker=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);blocker.bind(str(sock));blocker.listen(1)
   for _ in range(4):
    c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.setblocking(False)
    try:c.connect(str(sock))
    except OSError:pass
    clients.append(c)
  if restart_spent:
   # Fault phase consumes a prepared entry while the target is alive, without a real core.
   attempt=subprocess.run([str(BIN/'helper'),str(procs[0][1]),'11','65534'],input=b'',timeout=4)
   assert attempt.returncode!=0
   finish_receiver(rx);cfg['Mode']='normal';rx=launch_receiver(cfg,directory/'config.json');waitfile(directory/'ready')
  started=time.monotonic()
  for p,pid,_ in procs:
   if kill_signal:os.kill(pid,signal.SIGKILL)
   else:p.stdin.write(b'x');p.stdin.flush()
   p.stdin.close()
  if kill_receiver:
   waitfile(directory/(str(procs[0][1])+'.ack'));rx.kill();rx.wait()
  timings=[]
  def reap(entry):
   p,pid,inner=entry;rc=p.wait(timeout=5);return {'pid':pid,'namespacePID':inner,'returnCode':rc,'reapMilliseconds':round((time.monotonic()-started)*1000,3)}
  with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:timings=list(pool.map(reap,procs))
  assert max(x['reapMilliseconds'] for x in timings)<4000,timings
  reports=[]
  deadline=time.monotonic()+1.5
  expected=min(count,2) if name=='storm' else (0 if kill_signal or not receiver else count)
  while True:
   reports=[json.loads(f.read_text()) for _,pid,_ in procs if (f:=directory/(str(pid)+'.json')).exists()]
   if kill_receiver or (len(reports)>=expected and all(r.get('Finalized',False) for r in reports)):break
   if time.monotonic()>deadline:raise TimeoutError('final receiver outcomes: '+name)
   time.sleep(.01)
  result={'name':name,'mode':mode,'timings':timings,'reports':reports,'spentEntries':len(list(directory.glob('*.spent'))),'encryptedBytes':sum(p.stat().st_size for p in directory.glob('*.enc')),'networkNamespace':'receiver has no external network interfaces' if receiver else 'no receiver'}
  if name in ['complete','nested-pid']:
   assert len(reports)==1 and reports[0]['Complete'] and reports[0]['NativeVerified'],result
   r=reports[0];assert r['UID']==65534 and r['Signal']==11 and 'asservat-helper' in r['HelperCgroup'],r
   core=native/(str(r['PID'])+'.core');assert core.read_bytes()[:4]==b'\x7fELF'
   command=['unshare','--net','gdb','-nx','-nh','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off','-ex','bt',str(BIN/'fixture'),str(core)]
   gdb=subprocess.run(command,env={'PATH':'/usr/bin:/bin','DEBUGINFOD_URLS':''},capture_output=True,text=True,timeout=10)
   result['gdbExit']=gdb.returncode;result['gdbBacktrace']=gdb.stdout;result['gdbStderr']=gdb.stderr
   assert gdb.returncode==0 and 'crash_here' in gdb.stdout and 'main' in gdb.stdout,result
   # Deliberately generated marker is not present in encrypted persistent evidence.
   assert b'ASSERVAT_SYNTHETIC_CORE_MARKER' not in (directory/(str(r['PID'])+'.enc')).read_bytes()
  if name in ['no-permit','expired','restart-spent','wrong-identity']:assert not any(r['Accepted'] for r in reports),result
  if name=='sigkill-no-core':assert not reports and result['encryptedBytes']==0,result
  if name=='oversized':assert reports and reports[0]['Finalized'] and 0<reports[0]['Bytes']<=16*1024*1024 and not reports[0]['Complete'] and result['encryptedBytes']<17*1024*1024,result
  if name=='storm':assert len(reports)<=2 and not any(r['Complete'] for r in reports),result
  out['cases'].append(result);put(BASE/'results.json',json.dumps(out,indent=2));print(name,'PASS','max reap ms',max(x['reapMilliseconds'] for x in timings),flush=True)
 finally:
  finish_receiver(rx)
  for c in clients:c.close()
  if blocker:blocker.close()
  for p,_,_ in procs:
   if p.poll() is None:p.kill();p.wait()
  for f in native.glob('*.core'):f.unlink()
try:
 # Dedicated helper/receiver cgroups. The observed process is not moved into these.
 for name,memory,pids,cpu in [('asservat-helper',64<<20,8,'20000 100000'),('asservat-receiver',96<<20,32,'100000 100000')]:
  cg=P('/sys/fs/cgroup')/name;cg.mkdir(exist_ok=True);put(cg/'memory.max',memory);put(cg/'pids.max',pids);put(cg/'cpu.max',cpu)
 put(PAT,pattern);put(LIM,2)
 one_case('complete');one_case('nested-pid',nested=True)
 one_case('missing-receiver',receiver=False)
 one_case('full-listen-queue',receiver=False,backlog=True)
 one_case('no-permit',permits=False);one_case('expired',expires=False)
 one_case('wrong-identity',wrong_identity=True);one_case('sigkill-no-core',kill_signal=True)
 one_case('stalled-handshake',mode='stallHandshake')
 one_case('stalled-reader',mode='stallRead')
 one_case('oversized',size=40<<20)
 one_case('receiver-killed',mode='stallRead',kill_receiver=True)
 one_case('restart-spent',mode='stallRead',restart_spent=True)
 one_case('storm',mode='stallHandshake',count=16)
 # Simulate a competing writer in this disposable VM and check uninstall ownership.
 put(PAT,'|/bin/false');restore_allowed=PAT.read_text().strip()==pattern
 assert not restore_allowed and PAT.read_text().strip()=='|/bin/false'
 out['foreignWriterPreserved']=True
 out['cgroups']={name:{f:(P('/sys/fs/cgroup')/name/f).read_text() for f in ['memory.peak','memory.events','pids.peak','cpu.stat']} for name in ['asservat-helper','asservat-receiver']}
 out['result']='pass'
finally:
 # We own the simulated foreign pattern too; restore the VM's pre-experiment settings.
 put(PAT,original['pattern']);put(LIM,original['pipeLimit'])
 out['restored']=PAT.read_text()==original['pattern'] and LIM.read_text()==original['pipeLimit']
 put(BASE/'results.json',json.dumps(out,indent=2));assert out['restored']
