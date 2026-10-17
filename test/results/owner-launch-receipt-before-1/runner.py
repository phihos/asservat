#!/usr/bin/env python3
# Staged source-only. Parent owns integration, source freeze and the sole build slot.
# Exact old-transport regression; real failing Go exit is preserved. No native claim.
from pathlib import Path
from collections import Counter
import importlib.util,hashlib,json,os,re,signal,subprocess,time,sys
ROOT=Path('/home/phil/Projekte/asservat');CACHE=Path('/home/phil/.cache/asservat-build')
assert len(sys.argv)==3 and sys.argv[2]=='--parent-exclusive-slot-allocated', 'parent must allocate the exclusive slot'
name=sys.argv[1];assert re.fullmatch(r'[a-z0-9][a-z0-9-]*',name)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
helper=CACHE/'planning/owner-qualification-20261013/run.py'
helperHash='70b900ee945711b7829c9054bf89a72bba1085904b1f94fade0006747c015d07'
assert sha(helper)==helperHash, 'reviewed freeze helper changed'
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('gate',helper);gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
out=ROOT/'test/results'/name;out.mkdir();tmp=CACHE/(name+'-tmp');tmp.mkdir()
def freeze():
 state=gate.freeze()
 for folder in ('docs','examples','design','web'):
  state.update({str(p.relative_to(ROOT)):sha(p) for p in (ROOT/folder).rglob('*') if p.is_file() and 'node_modules' not in p.parts and '__pycache__' not in p.parts})
 for name in ('README.md','AGENTS.md','.gitignore'):state[name]=sha(ROOT/name)
 return state
before=freeze();(out/'sources.json').write_text(json.dumps(before,indent=2)+'\n')
runnerHash=sha(Path(__file__))
(out/'runner.py').write_bytes(Path(__file__).read_bytes());(out/'freeze-helper.py').write_bytes(helper.read_bytes())
env=dict(os.environ,GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(tmp),ASSERVAT_BUILD_TMP=str(tmp),PYTHONDONTWRITEBYTECODE='1')
for k in list(env):
 if k.startswith('ASSERVAT_') and k!='ASSERVAT_BUILD_TMP':del env[k]
sourcePatterns={'regression':'^TestOwnerIdentityProviderJournalAcrossOriginalLaunchReceipt$'}
packagePaths={'regression':'./internal/adapters/kubernetes'}
expectedNames={'regression':['TestOwnerIdentityProviderJournalAcrossOriginalLaunchReceipt']}
reviewedPayloads={'internal/adapters/kubernetes/owner_endpoint.go': 'a897f45b6468f1c49e1b41c41cf8a3b5b1deb0af251a270c64c267b1e3d5dc5b', 'internal/adapters/kubernetes/owner_endpoint_test.go': '42845fad1710c57e756dbd98d8fa9c70589eeed77738d2f9e751e700e3224d79', 'internal/adapters/kubernetes/owner_configuration.go': 'b852ce649cc1f64fb3d80ef69aa0a1c6e9de6ceba8434ee38897973016017db9', 'internal/adapters/kubernetes/owner_configuration_test.go': 'a3e141db13e5808285917a8aaaac42f1850d992603351d41fa685326326480c7', 'internal/adapters/kubernetes/owner_workload_guard.go': '6c2f1a0d89c199d9b52adb5d2be6860f57c12ceb86d516ee1e77f5b652eed3ba', 'internal/adapters/kubernetes/owner_workload_guard_test.go': '2f3db270ab319abad041a916096e080744fe57bb46312d23c990e6f124105698', 'internal/adapters/kubernetes/owner_enrollment.go': '37ece74cb1e49540166cecbaa7753c8565c7dabc16ae63b751da4d267fd4a5fb', 'internal/adapters/kubernetes/owner_enrollment_test.go': 'e1b7f3ad488e9a241f2eaf449e258e8ecc429d4eb9680a4840764192a1847003', 'internal/adapters/kubernetes/owner_protection.go': '678ab2dc0e9c6f29fbe92fbc92ece89a67907435174307f21906e3837768ff9b', 'internal/adapters/kubernetes/owner_workload.go': '61502ee00703cd5bce976f97d443f241ef24579ad2b05d2c927213ef10d45fa5', 'internal/adapters/kubernetes/owner_bootstrap_configuration_test.go': 'a87894f203ac956707008d72e84dfded8e96bbd77fdb953f41707c7d8ffa4bdc', 'internal/adapters/kubernetes/owner_endpoint_ports.go': 'bf552f1f0791e1b57ff8c08fbfd0fd705ac4456800a7d57c242fba416eac89e5', 'internal/adapters/kubernetes/owner_identity_activation.go': '51dcf3c61701a15244137a661b036ec6969a47055b4dc6b0362d3dc7d81b4c08', 'internal/adapters/kubernetes/owner_identity_activation_test.go': '577488b0691d9ed27cce9fa307e710f9e5df6be42b875908ace898e58296e268', 'internal/adapters/kubernetes/owner_installed.go': '1513cf73b6bf852d25c0a4cd9493ac9fc301af4aa3e0bf0c64088ed32684d5f9', 'internal/adapters/kubernetes/owner_installed_test.go': 'aafc37b3718919a01e1044112bd8e848fb3f5b00daf22ee2771be795d9601f1e', 'internal/adapters/kubernetes/owner_observation_workload.go': 'b1bcb2c7ea4e0ae84752409028747f6778dfbabaf8000239e216eca2c22cbc6a', 'internal/adapters/kubernetes/owner_identity_projection_material.go': 'b8b59f9856080a4375ac572f24b8c7bf6c10dad0741e287f232e34ae3d600086', 'internal/adapters/kubernetes/owner_identity_projection_objects_test.go': '8d0f257169f91ff2e8b0b399a26f96d410c953080c559606cfc548253a98be26', 'internal/adapters/kubernetes/owner_identity_projection_transition.go': 'f6d3c1fb6b7b8d58b9f06693febb693651cfb776350d8aaa5a0c2f55e4101a66', 'internal/adapters/kubernetes/owner_identity_projection_transition_test.go': 'dd4b1bbfbe2cfdf98935629a745ee353a1938f74a51169b8b836d14ba5dbae5a', 'internal/adapters/kubernetes/owner_identity_role_source.go': 'e3390fa3ae855bd8010a5925d9119c7240f8aefe16142bde1e8c568e10deeab3', 'internal/adapters/kubernetes/owner_identity_roles_test.go': '16d866ab685bd6f90c9a70a0bb0d415ddf73f39713590eb7cc238635b2add1bd', 'internal/adapters/kubernetes/owner_installed_template_test.go': 'edc49b18310fcf147b643c6c79c304f5bd94d40d925768d98daff60d22ac91e3', 'internal/adapters/kubernetes/owner_identity_producer_fixture_test.go': '0b1c412ffecf8bd1cc09430f36e7d92b41751732c9d87e5a4efc3a757d0c5730', 'internal/adapters/kubernetes/owner_identity_producer_test.go': '9669e4cc27f0c7e8470ad39dd69225025852fdc72536e20ec94de661109dbd37', 'internal/adapters/kubernetes/owner_identity_projection_input.go': '4a9c6f7a5d845d29321dd6ecf2fae412c784badc354029789024ee06c60bf901', 'internal/adapters/kubernetes/owner_identity_projection_input_objects_test.go': '26ac33d00603e618afad9ff1568edf7d900e3a3d9f6fff8fb1368eb3b0d12330', 'internal/adapters/kubernetes/owner_identity_projection_input_test.go': '1a22865537c4a83da56a8091882f6b55e8bced0b2ab7cfa6623c49a67d5b6016', 'internal/adapters/kubernetes/owner_identity_composed_fixture_test.go': '6985d0e3ede8a8a4112f9f1035d0e9dda851130b77d61c757712f7d6ade8eea0', 'internal/adapters/kubernetes/owner_identity_composed_test.go': '46d8df287e0d927c4619636368b8883e7960305627e842514cd1602a19fd7df6', 'internal/adapters/kubernetes/owner_observation_candidates.go': '1ef94784f1f00c70baa52cebc7ffea73f4bf1b59a4eb78afd166eb48bd09fe45', 'internal/adapters/kubernetes/owner_observation_candidates_test.go': '1ba2536372d33fc96a3f2da6e3e2145c200f3b1be8b56b94d5b7204c57a731bc', 'internal/adapters/kubernetes/owner_observation_operation.go': '230d64599cb5522d77924da9594af0e098ec70027e9e1554408580bb4b377f75', 'internal/adapters/kubernetes/owner_observation_operation_routes.go': '8134349bea66b65a6ce3d9502d0f23fbf87815c0363e970021ee292df7613e54', 'internal/adapters/kubernetes/owner_observation_operation_test.go': 'f0a51a71eb531a52aee4614e9fe6596052b8f4aa4f751532ba7125ed8d702b16', 'internal/adapters/kubernetes/owner_provider_binding.go': '08258592510ea1e1e62643a0e95c8bb6de5cb73f76c5859bf32e010ecc85eef9', 'internal/adapters/kubernetes/owner_provider_installed.go': 'c78381a7d69324f66fea7a58c61487f2632cb8d3b122974b01d816c6c777b0bf', 'internal/adapters/kubernetes/owner_provider_installed_test.go': '0fe586365618a1b432f5490607246b7f6227ba35c223586a9212b390dd3a628e', 'internal/adapters/kubernetes/owner_provider_material_reader.go': 'ec971c18c1e0c04ec32c6cb22aae9298c3d284dbc3d076ae75fb173dfd691d1a', 'internal/adapters/kubernetes/owner_provider_material_reader_test.go': '01bdf8fb4d044feb054142dc95b330f99d6cb0f8a64b8270339c314711b4291f', 'internal/adapters/kubernetes/owner_provider_objects_test.go': '51d77ae63b6203f66c11c66002fbe15d9ae3e9154eb181c508c611435d85b550', 'internal/adapters/kubernetes/owner_provider_projection.go': '19cc614d5b7e1a9ae0efddbb0a874763293a9b174153a8b26149916b9175cc6a', 'internal/adapters/kubernetes/owner_provider_projection_test.go': '75f2652249c6b5531d5ef23e5ecf9f17c5a1ed7edef66f616ea6ee7055e8f091', 'internal/adapters/kubernetes/owner_identity_operation.go': '17a0ef9873f3e58dde59981cd8f9f912067009ce87655c399e6f4493495cc080', 'internal/adapters/kubernetes/owner_identity_operation_composed_test.go': '0c8f6ce9b99d0212fddb67206320f27a2011a32d11ac0350dd74805f5794a07e', 'internal/adapters/kubernetes/owner_identity_operation_current.go': 'c4750547693de1ff42008d48d09443c199e44393a449212e79ce20edb4e89341', 'internal/adapters/kubernetes/owner_identity_operation_fixture_test.go': '7aba46b25f16a9573da41074911163f67dc4efd1ae9e7e916276f0cf260ef12f', 'internal/adapters/kubernetes/owner_identity_operation_material.go': 'd9f82bdf30bb577f02cf12c92c3224863fb09c66eecd34e0d41398a922352bfe', 'internal/adapters/kubernetes/owner_identity_operation_native.go': '03190a907bf36adcbc6d8d310a3e55d1da22c8b3d12f11195df723b38f02a5bf', 'internal/adapters/kubernetes/owner_identity_operation_open.go': '3cb84d74b301509b0ecc5f3d6b173e781be5bce1b246d4764eb53d5a7afdb360', 'internal/adapters/kubernetes/owner_identity_operation_retry_test.go': '331c6a01b502bb105ac723d09d912b868691f327c2a46302bb4630e2fb90a13a', 'internal/adapters/kubernetes/owner_identity_operation_roles.go': '7e1e52850c07131be6116fb35dbd3ec517a876b6d2db2824b667af760aec2a65', 'internal/adapters/kubernetes/owner_identity_operation_root.go': '4d17246d59b126f78e4f7bb089454797783286218c20659b3f37fb8169849c88', 'internal/adapters/kubernetes/owner_identity_operation_test.go': '4b742bb772c269bd722c37847db7cd7e09b4dc90e622aab0afb7384a5ffed66a', 'internal/adapters/kubernetes/owner_installation_outcome.go': 'd549aaf6d6e0c418352fce9af676f5cb678965f54f2bd0a391a7432781ea71fe', 'internal/adapters/kubernetes/owner_projection_operation_inspect.go': 'b2a19e116f27c2b54f079521bd47b548a3b22bff111a0d39ee6ef493cd61650c', 'internal/adapters/kubernetes/owner_projection_operation_provider_test.go': 'b11d3fa4f7b42da427310a1417b7180344254d395247abeed9697a352ec9b7ca', 'internal/adapters/kubernetes/owner_projection_operation_test.go': '661cea3a3185d7819ce43da547c5833861ba89e55aaad85c40389bd4dfb3005b', 'internal/adapters/kubernetes/owner_bootstrap_current.go': '763111848056ac4234cb21dccfb46254263284953a5c229f14bd080b76cf8930', 'internal/adapters/kubernetes/owner_bootstrap_deployment.go': '5986f252156a10cb65408918d57f9922bea990c3cc811a3019f07278a4789b04', 'internal/adapters/kubernetes/owner_bootstrap_fixture_test.go': '0209a48503f1e4263964523d0136591722d600cf2aa3f96f0d1fd24dce72d42e', 'internal/adapters/kubernetes/owner_bootstrap_objects.go': '4aaf81253d62b87467e3cd183acdef8dfabb0a925e26d819d2118e77ef478b7c', 'internal/adapters/kubernetes/owner_bootstrap_selection.go': '5dcd762bd369c69d487cc4f7086d87295c3f917741c54a10b3f8b1192529077f', 'internal/adapters/kubernetes/owner_bootstrap_selection_test.go': '9570fe30b1d41e7ab2dd1dbaa560516f48dfbce7dc6913db03a0cbf9005cc6bd', 'internal/adapters/kubernetes/owner_bootstrap_state.go': 'efc2aba9b8b6716ed5ccaa964b5dc7aac9bc0365b2a34694b427c70cf801a785', 'internal/adapters/kubernetes/owner_bootstrap_state_test.go': '0258ca353b1bdd878b62a4e178e07611b6935d03c52d73255dacfc98925fcf26', 'internal/adapters/kubernetes/owner_bootstrap_values.go': '3781d8740cdc05a8f1ea0e45b27e215227011a19301f41d4db438e522acc18a8', 'internal/adapters/kubernetes/owner_bootstrap_worker_caller.go': '7ff49a453dc595efbcdd91f3dbb174a8defaf22c9f748203da7a07b8bc5d2c12', 'internal/adapters/kubernetes/owner_bootstrap_worker_caller_fixture_test.go': 'b661a959351cd4df6afbbc9153d0a1e5671c4ded8f6f2ef54da0135ff4278334', 'internal/adapters/kubernetes/owner_bootstrap_worker_caller_originals.go': 'c3b2552c9921b442c3f6f7d710818b4c09dc67c858b933960f3174cc156e3f93', 'internal/adapters/kubernetes/owner_bootstrap_worker_caller_test.go': 'e37501bbfc4d7853b2f7202d8853c310f8dd9d57feee0b360c1f4f168ca15677', 'internal/adapters/kubernetes/owner_local_observation_operation.go': 'bd5cb5574d0ca299ab75eebdc875938171f501ae573f88394faff51058264055', 'internal/adapters/kubernetes/owner_local_observation_operation_test.go': '81ba8fb4cabc6f2ec30d5c5dd44fa9edb82ba89e4a0a8524ac8633f25e87636d', 'internal/adapters/kubernetes/owner_observation_dial_candidates.go': '1cdbf64954042d9608669f05b89a3218c56f8b8e9c84047fba626d06f6002edf', 'internal/adapters/kubernetes/owner_observation_dial_candidates_test.go': '31478dcfa154711fb2734e42012e4c5952ca37e392e330e14a25e171c0ae4839', 'internal/adapters/kubernetes/owner_bootstrap_selection_diagnostics_test.go': '55ab95a5fa3a02f5df51b4990f7e9424312e99f37fd8ec1e0af9a40df81c0c1b', 'internal/adapters/kubernetes/owner_identity_operation_diagnostics_test.go': '2f50d8460703d38814b2305c633a415e2056e39275c4fa9017be3a48abe550f5', 'internal/adapters/kubernetes/owner_identity_operation_preflight.go': 'd311d6ef104712516cf0f1ae0b2d18f491c074783ebf1bbd6627049c98250c68', 'internal/adapters/kubernetes/owner_identity_operation_preflight_test.go': 'd6dd4021594c3264fc484935e695cf9fbafa880a80c1d9b37e565f6a3207d36d', 'internal/adapters/kubernetes/owner_projection_diagnostic.go': '3018bc41f6d8063cb34d6fca9a482ce88b9743ead539b9aa41fac22bdc49a4ce', 'internal/adapters/kubernetes/owner_projection_preflight_source.go': 'b914f0521feac4a069b6b860556f9dceec9a5c94199d2ffab9d205122c3d4e2e', 'internal/adapters/kubernetes/owner_identity_launch.go': 'a4c2efdee260cf2a931f932b64197c63fccf84f2fc8317d905c919dc6b7a2c5d', 'internal/adapters/kubernetes/owner_identity_projection.go': 'b5fa1356fceb2cb69a8fce9885d38bb00ef867f87eb7a79c492ea3b1c4f03ee2', 'internal/adapters/kubernetes/owner_identity_projection_objects.go': 'f5881f71a77fbec90eece0adc3ef12d1dbdedc77e8b5eaae5a422018d0de91d9', 'internal/adapters/kubernetes/owner_identity_roles.go': '2a6b8a6be3a605554c8d52af494bbd3cc92bb7f3e68ea634f2bc29c9f8806fc0', 'internal/adapters/kubernetes/owner_installation_driver.go': '2038d2b72dfdb666d075b0d7e294b7a2cbe1c5accf4f1c9a5c23fefdbf1cb2ea', 'internal/adapters/kubernetes/owner_projection_diagnostic_test.go': '12d1ce86bff806ed29cc8ff7cf9592655c576bd00ae1367e8f43d6874a3e6f0f', 'internal/adapters/kubernetes/owner_projection_finalization.go': 'e6453270b029a84e15e0cc3533bbdfe55f77555aa9ab41bd86d52c9891f795b7', 'internal/adapters/kubernetes/owner_projection_finalization_handle_test.go': '25ce3c8865fde18706689b06347598a0829cf9983c042b97d3e4e18da99ff5ba', 'internal/adapters/kubernetes/owner_projection_finalization_test.go': '6c58d99e423cad6083d5d392a619f45b9c901eeda5a6aca7187675e6d9b0f11f', 'internal/adapters/kubernetes/owner_projection_operation.go': '0d0ce22340609f8e9f7c6ac01550844a2cbc5d606eed4867e25c03968b851ac6', 'internal/adapters/kubernetes/owner_projection_operation_composed_test.go': '03c320ee99e79f8c2fe8d3adf0dd4b6eca0fd0dc1a7290cd9b8def1d92726437', 'internal/adapters/kubernetes/owner_projection_operation_effects.go': '919d93e2ddc5fa43c908d2c60f5a5d80372d4b00ca060e296e2a44b486e46448', 'internal/adapters/kubernetes/owner_projection_operation_fixture_test.go': '88cfe0e9b9f24c72a20db54b93a26cc24e7c094343de144893e7beb6747e8a0e', 'internal/adapters/kubernetes/owner_projection_operation_native.go': '25961943a534dff8ece10aeb1212b98622bf867ba8c181ff0e67c9bf6fc2a962', 'internal/adapters/kubernetes/owner_projection_operation_plan.go': 'cb90f19a1e9963df5ab3960f1b9090fee9162c8d45e21346211eb294a2196dc2', 'internal/adapters/kubernetes/owner_projection_pending.go': '26bb2ad94978797c2340544e2e1dbdd0254c96d171d6a502085399ad9db53efa', 'internal/adapters/kubernetes/owner_projection_preflight.go': 'e631a6f696945ac5042ec24bc11d503ddac3b969c9b098ae49e51f695d1c01d2', 'internal/adapters/kubernetes/owner_installation_driver_test.go': 'd39337a4f7bb9c547bb85131ac095fb3c64a25834c5258aa8d37c1cdbefce285', 'internal/adapters/kubernetes/owner_projection_preflight_test.go': '3f7b1a546d41405c0926a59559688c481076ffc30c74e1abf905d686e03f196a', 'internal/adapters/kubernetes/owner_identity_objects.go': '7c1371e5ce3a84941b22aa3841d35f13f121462494443d1a02aa5a02b5ed07a0', 'internal/adapters/kubernetes/owner_identity_objects_test.go': '91645bd6cf375e83ac4973f296cac34b9d11e96dee0e2bb35c4d52eb08b9493e', 'internal/adapters/kubernetes/owner_identity_read_diagnostic.go': 'c164db93b17f6e9cf3e620cb22229f66c7988b1a15489a8ed09e6db53c884ca5', 'internal/adapters/kubernetes/owner_identity_read_diagnostic_test.go': '880f506ec2656785b3e7ec4a8f4d4815dff4b5c9a62f42b137b8d359df16fadf', 'internal/adapters/kubernetes/owner_identity_reader.go': '2c96b96f6b05979d04b945eb25d6ebda54db6b03d887bff472eefb5c8086cebd', 'internal/adapters/kubernetes/owner_identity_reader_test.go': '7613f1ef199d543323a1a815e63bd5c6f0deb7e78124e9e69ad14ebae3115094', 'internal/adapters/kubernetes/owner_identity_provider_journal_test.go': '2aa73309be6ae028eae0c4e9b5968bc6c9230604183a9e045f9d90d192447232'}
selections={label:(packagePaths[label],'^('+'|'.join(names)+')$') for label,names in expectedNames.items()}
steps=[]
for label,(pkg,pattern) in selections.items():
 steps.append((label,['go','test','-race','-count=1','-timeout=15m','-json','-run',pattern,pkg]))

# Reuse the reviewed codec gate's process-group joining and nonraising signal
# handler. Never lose a spawned handle or let repeated signals interrupt cleanup.
def joined(p):
 if p is None:return True
 def exists():
  try:os.killpg(p.pid,0);return True
  except ProcessLookupError:return False
 def send(s):
  try:os.killpg(p.pid,s)
  except ProcessLookupError:pass
 if p.poll() is None:
  send(signal.SIGTERM)
  try:p.wait(timeout=10)
  except subprocess.TimeoutExpired:send(signal.SIGKILL);p.wait(timeout=10)
 else:p.wait(timeout=1)
 if exists():
  send(signal.SIGKILL);until=time.monotonic()+10
  while exists() and time.monotonic()<until:time.sleep(.05)
 return p.poll() is not None and not exists()
interrupt_signal=None
def interrupt(signum,frame):
 global interrupt_signal
 if interrupt_signal is None:interrupt_signal=signum
signal.signal(signal.SIGINT,interrupt);signal.signal(signal.SIGTERM,interrupt)
report={'runnerSHA256':runnerHash,'steps':[],'sourceCount':len(before),'bootID':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'status':'failed','reviewedPayloads':reviewedPayloads,'selections':selections,'helperSHA256':helperHash}
code=1;child=None
try:
 for path,digest in reviewedPayloads.items():
  assert sha(ROOT/path)==digest,'reviewed payload differs: '+path
  target=out/'payloads'/(path+'.txt');target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/path).read_bytes())
 for label,cmd in steps:
  if interrupt_signal is not None:raise InterruptedError('qualification signal '+str(interrupt_signal))
  assert freeze()==before,'source changed before '+label
  assert sha(Path(__file__))==runnerHash and sha(helper)==helperHash,'runner/helper changed'
  required=set()
  if label in selections:
   pkg,pattern=selections[label]
   declarations=[]
   for file in (ROOT/pkg).glob('*_test.go'):
    declarations += [test for test in re.findall(r'^func (Test\w+)\(\w+ \*testing.T\)',file.read_text(),re.M) if re.search(sourcePatterns[label],test)]
   assert Counter(declarations)==Counter(expectedNames[label]),'selected source declarations changed: '+label
   required={('asservat.local/asservat/'+pkg[2:],test) for test in declarations}
   assert required
  assert joined(child),'previous owned group not joined before '+label
  start=time.monotonic();stopReason=None
  with (out/(label+'.log')).open('x') as log:
   child=subprocess.Popen(cmd,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
   print(json.dumps({'step':label,'pid':child.pid,'processGroup':child.pid}),flush=True)
   while child.poll() is None:
    if interrupt_signal is not None:stopReason='qualification signal '+str(interrupt_signal)
    elif time.monotonic()-start>1020:stopReason='component outer ceiling exceeded'
    if stopReason is not None:break
    time.sleep(.1)
   clean=joined(child)
  item={'name':label,'command':cmd,'pid':child.pid,'processGroup':child.pid,'exit':child.returncode,'seconds':round(time.monotonic()-start,3),'processJoined':clean,'processGroupAbsent':clean,'stopReason':stopReason}
  if required:
   passed=set();named=[];failed=[];packagePassed=set();runs=Counter();topPasses=Counter()
   for line in (out/(label+'.log')).read_text().splitlines():
    try:e=json.loads(line)
    except json.JSONDecodeError:continue
    if not e.get('Test') and e.get('Action')=='pass':packagePassed.add(e.get('Package'))
    if e.get('Test') and '/' not in e['Test']:
     key=(e.get('Package'),e['Test'])
     if e.get('Action')=='run':runs[key]+=1
     if e.get('Action')=='pass':topPasses[key]+=1
    if e.get('Test') and e.get('Action')=='pass':
     passed.add((e.get('Package'),e['Test']));named.append(e['Package']+'/'+e['Test'])
    if e.get('Action') in ('fail','skip'):failed.append(e)
   expectedCounter=Counter({key:1 for key in required})
   item.update(requiredTests=sorted(required),requiredTopLevelTests=len(required),missingPackagePasses=sorted({pkg for pkg,_ in required}-packagePassed),missingRequiredTests=sorted(required-passed),exactTopLevelRuns=runs==expectedCounter,exactTopLevelPasses=topPasses==expectedCounter,observedTopLevelRuns=sorted((pkg,test,count) for (pkg,test),count in runs.items()),observedTopLevelPasses=sorted((pkg,test,count) for (pkg,test),count in topPasses.items()),passedNamedTests=named,failuresOrSkips=failed)
  report['steps'].append(item)
  print(json.dumps({'step':label,'exit':child.returncode,'seconds':item['seconds'],'missing':item.get('missingRequiredTests',[]),'processGroupAbsent':clean}),flush=True)
  if child.returncode or not clean or stopReason or item.get('missingRequiredTests') or item.get('missingPackagePasses') or item.get('failuresOrSkips') or not item.get('exactTopLevelRuns',True) or not item.get('exactTopLevelPasses',True):break
 else:code=0
except BaseException as e:report['error']=str(e)
finally:
 signal.signal(signal.SIGINT,signal.SIG_IGN);signal.signal(signal.SIGTERM,signal.SIG_IGN)
 report['signalReceived']=interrupt_signal
 if interrupt_signal is not None:code=1
 try:report['finalProcessGroupAbsent']=joined(child)
 except Exception as e:report['finalProcessGroupAbsent']=False;report['joinError']=str(e)
 if not report['finalProcessGroupAbsent']:code=1
 try:
  report['sourceUnchanged']=freeze()==before
  report['runnerUnchanged']=sha(Path(__file__))==runnerHash and sha(helper)==helperHash
 except Exception as e:report['sourceUnchanged']=False;report['runnerUnchanged']=False;report['freezeError']=str(e)
 if not report['sourceUnchanged'] or not report['runnerUnchanged']:code=1
 report['scratchRemoved']=False
 if report['finalProcessGroupAbsent']:
  try:
   assert joined(child),'owned group not joined before scratch removal'
   tmp.rmdir();report['scratchRemoved']=True
  except Exception as e:report['scratchCleanupError']=str(e);code=1
 else:code=1
 report['status']='passed' if code==0 else 'failed';report['exit']=code
 report['archiveHashes']={str(p.relative_to(out)):sha(p) for p in out.rglob('*') if p.is_file()}
 (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'sourceUnchanged':report['sourceUnchanged'],'scratchRemoved':report['scratchRemoved']}),flush=True)
sys.exit(code)
