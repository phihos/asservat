"""Disposable single-user QEMU lab. No libvirt changes or host privileges."""
import argparse,hashlib,json,os,pathlib,socket,subprocess,sys,time,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[3]
STATE=pathlib.Path(os.environ.get('ASSERVAT_LAB_STATE',str(pathlib.Path.home()/'.cache/asservat-control-crash-20261009'))).expanduser()
STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
BASE='https://cloud-images.ubuntu.com/noble/20260926/'
IMAGE='noble-server-cloudimg-amd64.img'

def run(args,**kw):return subprocess.run(args,check=True,**kw)
def sshargs():
 meta=json.loads((STATE/'run.json').read_text())
 return ['ssh','-i',str(STATE/'key'),'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(STATE/'known_hosts'),'-o','ConnectTimeout=5','-p',str(meta['port']),'root@127.0.0.1']
def download():
 sums=urllib.request.urlopen(BASE+'SHA256SUMS',timeout=30).read().decode()
 expected=next(line.split()[0] for line in sums.splitlines() if line.split()[-1].lstrip('*')==IMAGE)
 dest=STATE/IMAGE
 if not dest.exists():
  with urllib.request.urlopen(BASE+IMAGE,timeout=60) as r,open(dest.with_suffix('.partial'),'wb') as w:
   while block:=r.read(1<<20):w.write(block)
  dest.with_suffix('.partial').rename(dest)
 h=hashlib.sha256()
 with open(dest,'rb') as f:
  while block:=f.read(1<<20):h.update(block)
 if h.hexdigest()!=expected:raise RuntimeError('Image SHA256 mismatch')
 (STATE/'image.json').write_text(json.dumps({'source':BASE+IMAGE,'sha256':expected,'verification':'SHA256 list retrieved over upstream HTTPS; detached GPG signature not independently verified'},indent=2))
 print('Image checksum verified',flush=True)
def up():
 if (STATE/'run.json').exists() or (STATE/'key').exists() or (STATE/'disk.qcow2').exists():raise RuntimeError('Existing lab state: inspect/shut down, or choose a fresh ASSERVAT_LAB_STATE directory')
 download()
 run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(STATE/'key')])
 pub=(STATE/'key.pub').read_text().strip()
 (STATE/'user-data').write_text('#cloud-config\ndisable_root: false\nssh_pwauth: false\nusers:\n  - name: root\n    lock_passwd: true\n    ssh_authorized_keys:\n      - '+pub+'\npackage_update: false\n')
 (STATE/'meta-data').write_text('instance-id: asservat-control-crash-20261009\nlocal-hostname: asservat-lab\n')
 run(['xorriso','-as','mkisofs','-quiet','-output',str(STATE/'seed.iso'),'-volid','cidata','-joliet','-rock',str(STATE/'user-data'),str(STATE/'meta-data')])
 run(['qemu-img','create','-q','-f','qcow2','-F','qcow2','-b',str(STATE/IMAGE),str(STATE/'disk.qcow2'),'10G'])
 with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
 args=['qemu-system-x86_64','-name','asservat-control-crash-20261009','-enable-kvm','-cpu','host','-smp','2','-m','2048','-display','none','-serial','file:'+str(STATE/'serial.log'),'-monitor','unix:'+str(STATE/'monitor.sock')+',server=on,wait=off','-drive','file='+str(STATE/'disk.qcow2')+',if=virtio,format=qcow2','-drive','file='+str(STATE/'seed.iso')+',media=cdrom,readonly=on','-netdev',f'user,id=n,hostfwd=tcp:127.0.0.1:{port}-:22','-device','virtio-net-pci,netdev=n','-daemonize','-pidfile',str(STATE/'qemu.pid')]
 run(args)
 (STATE/'run.json').write_text(json.dumps({'port':port,'pid':int((STATE/'qemu.pid').read_text()),'qemu':args,'started':time.time()},indent=2))
 # Pin the host key from the local serial console's cloud-init output, not TOFU over SSH.
 print('VM launched; host key readiness can be checked using the serial log',flush=True)
def pin():
 meta=json.loads((STATE/'run.json').read_text());serial=(STATE/'serial.log').read_text(errors='replace')
 keys=[line.strip().replace('\r','').split() for line in serial.splitlines() if line.startswith('ssh-ed25519 ')]
 if not keys:raise RuntimeError('cloud-init host public key not yet in local serial log')
 (STATE/'known_hosts').write_text(f'[127.0.0.1]:{meta["port"]} '+keys[-1][0]+' '+keys[-1][1]+'\n')
 print('Pinned VM SSH host key from serial console')
def down():
 meta=json.loads((STATE/'run.json').read_text());pid=meta['pid']
 cmd=pathlib.Path(f'/proc/{pid}/cmdline').read_bytes()
 if b'asservat-control-crash-20261009' not in cmd:raise RuntimeError('PID ownership mismatch')
 with socket.socket(socket.AF_UNIX) as s:s.connect(str(STATE/'monitor.sock'));s.sendall(b'quit\n')
 (STATE/'run.json').rename(STATE/'stopped-run.json')
 print('Stopped only this lab VM')
if __name__=='__main__':
 action=sys.argv[1]
 if action=='up':up()
 elif action=='pin':pin()
 elif action=='ssh':sys.exit(subprocess.call(sshargs()+sys.argv[2:]))
 elif action=='down':down()
 else:raise SystemExit('up|pin|ssh|down')
