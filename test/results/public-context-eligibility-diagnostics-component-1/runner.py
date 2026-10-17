#!/usr/bin/env python3
# Staged source-only. Parent owns integration, source freeze and the sole build slot.
# Compile, seven exact fixture-diagnostic race parents, and vet. No native claim.
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
sourcePatterns={'journey-diagnostics': '^(TestPublicJourneyDiagnosticsOriginalAuditDispatch|TestPublicJourneyDiagnosticsOriginalPreviewDelegate|TestPublicJourneyDiagnosticsFirstRequestPublication|TestPublicJourneyDiagnosticsOriginalRegionalVerifier|TestPublicJourneyDiagnosticsOriginalRegionalRunner|TestPublicJourneyDiagnosticsRegionalFacetPreservation|TestPublicJourneyDiagnosticsOriginalEligibility)$'}
packagePaths={'journey-diagnostics': './test/integration'}
expectedNames={'journey-diagnostics': ['TestPublicJourneyDiagnosticsOriginalAuditDispatch', 'TestPublicJourneyDiagnosticsOriginalPreviewDelegate', 'TestPublicJourneyDiagnosticsFirstRequestPublication', 'TestPublicJourneyDiagnosticsOriginalRegionalVerifier', 'TestPublicJourneyDiagnosticsOriginalRegionalRunner', 'TestPublicJourneyDiagnosticsRegionalFacetPreservation', 'TestPublicJourneyDiagnosticsOriginalEligibility']}
reviewedPayloads={'internal/adapters/kubernetes/configuration_worker_provider_contention_test.go': '1de10803e75708ec33e196718857b70abeebe15921f61da84b3f58f74c187830', 'internal/adapters/postgres/configuration_runtime_role_plan.go': '4fc21d41b11611c7189d59d7d6bda1016099597bd70171a50cd9ebcd889c20e4', 'internal/adapters/postgres/configuration_runtime_role_plan_test.go': '9772d52114fe4432378ad236bf30fbb420667aef5588da942f596da353522386', 'internal/adapters/postgres/custody.go': '627f38ada7a5cccbff6864e5abe1d624b0e87a3d1ca47d4f56ebd2028de6ca52', 'internal/adapters/postgres/custodydb/fleet.sql.go': '03c4e38dae5c1fa7efb4fb63288a09c934a580a6cb2d1d55c64bd12a09a08c26', 'internal/adapters/postgres/custodydb/models.go': 'b9725700a0cb5c0acc79ce326685b6c53547a925258e86474b0ac91d43549df7', 'internal/adapters/postgres/fleet_observation.go': '8fdd2dcc5dd0dff5cdefd7707e23ef37c4aa5fab3607b8b0d4759a22b7ff1558', 'internal/adapters/postgres/fleet_observation_basis.go': 'a55cfa40b08e0f9edc49fa8f70717f467a81bcbfd63cb3c5909cd4d997797ba1', 'internal/adapters/postgres/fleet_observation_contention.go': '4c3a548d67334bcba6f6cd0da5ef812465c2c02bd3287169f7a0cfdc3d212704', 'internal/adapters/postgres/initial_installation.go': '86be16c02e7c8d82bfa855339098c0c1b237092df40cd5e0013c8a909bfbf547', 'internal/adapters/postgres/initial_installation_tables.go': 'dc0dc2d6aa64662db21f5f37feecfe49cd8fb8419b7c47235fc456881a167a61', 'internal/adapters/postgres/initial_roles.go': 'd4e765250e84634a0784e4b637f416aa9d42f632e7880ffc4ccf518a082f9683', 'internal/adapters/postgres/initial_schema_test.go': 'f0cc1943c79a7afce4656a4aee151d56ec2ed852995abb3ccd5d36481dbc0ddf', 'internal/application/fleet/trust_observer.go': '4a236c486015456b42cabbd56f0aa8e3e60072080a7f45814934473a5a7ea4a7', 'internal/application/fleet/trust_observer_contention_test.go': '81362ce78dad0da52a7f7a065536d4061fa18a494f4a01ff56db35cbbdc7b39d', 'internal/application/fleet/trust_observer_test.go': '2ec7e3955933026c2b28e6305ebd6933fbadbaac9358f661bc79721a20c8d39e', 'internal/application/fleet/trust_observer_unknown_commit_test.go': '30da98bcde725af3abd6d0886a867823d1205fad400a9b4eddae9d9da84b0b84', 'internal/application/planning/context_assessment.go': '6feedf172f61bc27792f2d9c336a97f3b4dc5e1434df65a28a68047b23e9e186', 'internal/bootstrap/configuration_runtime_source_notice.go': '80eba48f60d628cc62018f231b7689151cf308428ecf0ca1a8e13c7b32609ba5', 'internal/domain/fleet/observation_basis.go': '87dfa47f8c162ff0085c8fb9dd38b77816fb9aea141d329eb6ef3ebc5f7c45f8', 'internal/domain/fleet/observation_basis_test.go': 'f7492708a516215a57a3e24eac69fab66a75d818f414e1eeb71ee465da717e77', 'internal/transport/presentation/context_compiled_assessment_test.go': 'bc8abf9f84472196b17a18e665593903e18a20637bfe690bb4e593cb22fda716', 'migrations/00059_fleet_observation_separation.sql': '7c8deaa4bd9ab8f8a4f3100167cc6de6a66c652e593343f7e11124e20a38aa8e', 'migrations/queries/fleet.sql': 'ca8c0dbad3923c7531d5ea944533e9873f4a49350b6a5fd43debe28bf69b4de0', 'scripts/test-context-storage.py': '4b4ac1cfe44ca1b1df658f6cf7cde5e359ba2265dd12d46aaaab5d0c0e4ad548', 'scripts/test-regional-context-selection.py': '69f508d97c8626fb9763665ab5c0bf6669bb2dbdab444bf75f5d0b68d5a204ea', 'test/fixtures/sql/runtime-roles.sql': '99aca95f63794421ab69913fdf92527dbdf8c77b027cdd4d2da23a879f5f8214', 'test/integration/api_execution_native_test.go': 'b739d7cdabd74ded0ab358725928ef74e855b9474e939a8296cce703bce26a75', 'test/integration/bootstrap_issuance_test.go': 'e2d04f4aacd262f097f01b55835c658cb59f36ddc379d9ac24d2c84f5a2da7f4', 'test/integration/bootstrap_reservation_test.go': 'a03a33769d964dd652a2c03cf99119b2136c4a83d685d30346958826f39bb0a9', 'test/integration/capacity_context_test.go': '43354b4f901e023562977ab43e0ae729ba5257bca3261ea9b01fdd60349b8f07', 'test/integration/capacity_owner_registry_test.go': '8717212f3fb24a21ad9a0d43a6f4820cd20fb74c357a092a6d7cd46b0684cf5a', 'test/integration/capacity_producer_test.go': '4e1862f12f7b534b58156a03bcbe47643059c0406324f5c65b77071b9ebba47b', 'test/integration/capacity_sql_fixture_test.go': 'f56199deae1c69ffdc486e015bdcb3710845d8b9d5dcd9733a3b7480c4ca7179', 'test/integration/capture_admission_test.go': 'c16f5c1a0addbf5230d8e8b5e5a71e5b23ab865eda46f417e30c2a72181de2d5', 'test/integration/capture_intent_lifecycle_test.go': '7e2a3eed3b8615c9c08c3e5d07afd210451da60beffc5b11c515cf37d17a2b71', 'test/integration/configuration_role_reconciliation_test.go': 'cd7356d651aa5d0df485bfad013935701b36f641f12062fdedb7024b33ae567f', 'test/integration/connector_identity_test.go': 'a40473af362ba6ed0a906111d18ffe98793848e61b3ede82d84431029317c3e8', 'test/integration/connector_observation_operation_sql_test.go': '857833c1dbc4d872eca0b042424d17ab2195f31148efa39d266314471737b3a6', 'test/integration/context_continuation_native_test.go': '93cee050d9f8954f7ec0fa35ca94c127ee66a31d38d80d307584ec3f96213383', 'test/integration/context_deletion_test.go': 'ad70ccd3a658e09092c8e36987d88a5cd39dac471d08a7c617877b33bf0b2669', 'test/integration/context_native_content_test.go': '5830095e3fa0f568f0b456fb9054f50c229b98af7ec10c9cabcc1bb78c209bec', 'test/integration/context_start_exchange_test.go': 'a530733056c17613ba1ad9b7b97d8df5916ef6e695478fa10c77b5bdfcbec33c', 'test/integration/context_start_owners_test.go': '73454cda47eb3a3f21b257aa4f85238b07f84a6bb585a4bf2f5985a64a8c4eff', 'test/integration/database_recovery_test.go': '3a391096be192e9534faf446b03f2af09cde4a9781512174cafe3b9d9c0042ec', 'test/integration/direct_observation_native_sql_test.go': 'fe521a11d4ff3408e9c0591edf82387956c40ab450817df5d8df7c9b4cccfc20', 'test/integration/download_sessions_test.go': 'dcae0e568794e1b00589be60e79eea98fb69aa32d05e3fd379fbffa9e94a4138', 'test/integration/download_stop_lifecycle_test.go': '7f2d839ad70f02c4b3778124f78592658bd2897150e0c7041db2b42b9c685635', 'test/integration/enrollment_provider_test.go': '65dc357ba448d09727c42748a431bf07a79b1ed7296769b529e3b8e2514689ee', 'test/integration/enrollment_signing_test.go': 'e99aea91a69215c3a3998f2710e96e3cfaad9f47cc46c627288b30bab32dfadd', 'test/integration/enrollment_test.go': '93aef2455201b4221b60735af2dfbde7c61dbd66828ec77b154d6a0b9c374dfa', 'test/integration/fleet_freshness_native_test.go': '82af1ba6416fce87a0f9390f39885c4ed533d07dd5080ba35354ead4936b8630', 'test/integration/fleet_observation_basis_fixture_test.go': '55f18a963a8225cb2299facaef105ad51258caea8a091c3089df5ba66a24d10a', 'test/integration/fleet_observation_commit_reply_test.go': 'e74510462e684fb617b258712c7d780e8eb97eadf9dbfac412c45962c754f3a8', 'test/integration/fleet_observation_contention_test.go': 'a5a1f60c03f8dd5095a88b2d7ce1828c02f78078bbe5096e8694b9d6ecb70c5e', 'test/integration/fleet_observation_fixture_sql_test.go': 'a49dbdf1bb3ee1e9e99cd8d8113bc234d8c987c61a8d653d94404af5c91e719b', 'test/integration/fleet_observation_fixture_test.go': 'c8a9df7d4fdc0958e29500dc3e4c674266c98220f2648891cbbd1e11148a0c33', 'test/integration/fleet_observation_test.go': '9e92349b7a142ba7586dca758e6cc308b4754c8fcd5b681e021f6686ff7897cc', 'test/integration/hub_worker_test.go': 'ad959c6102cc8f3a712de7f09c17777c01c8b3eb40a2d34971e13c4cda2b48b0', 'test/integration/initial_installation_test.go': '573b0169dc3297b61c35c8b79a83e96ffd6b97d2ec94446e309542c1c8d42afd', 'test/integration/initial_installer_pod_test.go': '943e8e7d334777805ec5557dddce47e722643dbf379e30f68a00c4f29dadf008', 'test/integration/initial_runtime_bridge_sql_test.go': 'a6cb0c21e8761e5503ab34f250cffb08e38d16ce8a9d99ce5502bb25840c6844', 'test/integration/initial_sql_roles_test.go': '42ebdade563adb8b2407b8ea06d328630797653b26d8daf3b0c3fba89de00a35', 'test/integration/local_key_lifecycle_test.go': '941fd104574a40aad17b482967cb649370b6d11c5cead450cc46804ccb0b94c2', 'test/integration/native_retention_observer_test.go': '2be83b7ac399c6c7a9b91f11d4fb42a3dde9c4ca5700f06dc02f3368f6cb9e27', 'test/integration/operation_audit_lifecycle_test.go': '79cb6df34bfadbb5dab3f751b349038b36cd630d5079222f8c43e386684ea86d', 'test/integration/operation_audit_overdue_test.go': '0916bb6c2bfb238033f83478e431c106bac5125b2ae423bdcf0f2a750ab4da5e', 'test/integration/operation_verification_budget_test.go': 'e4ae65e8fcf550b0cf5a49aff9dab2abf986f516105addae1623a4353fb72667', 'test/integration/owner_configuration_sql_test.go': '74663a7605dda1f28e5df1548e9f0f522cf3fc5dbc84e0922863f37f5e1346ae', 'test/integration/owner_identity_constructor_current_test.go': '90589ea86acc7000da68a96cb163b953610ad01a04f7b6882c6969c5d8ffd65a', 'test/integration/owner_identity_roles_test.go': '09a3818830f2fb9c3ef06e264cfce6e5420cc2742b6f70d634f68c64be0eac58', 'test/integration/owner_native_activation_test.go': '953e6b874dd9251a3eddfdda2efdf36fbeb671972efb4a62f1c46bf58cad828d', 'test/integration/owner_registration_test.go': '744b1d1231d39be27f4beaed709717cb173a9c3d7b511ff6821108bcf7f15ac1', 'test/integration/peer_registry_test.go': '7c317a85716c8579b431d644f21afec4734cc02f655afd4d769f689dc18c03e4', 'test/integration/policy_authority_test.go': 'cc02976fa28619d7f76b884d2c8846a72016a7331e8518bc01aafb181ee0aaaf', 'test/integration/public_context_journey_diagnostics_test.go': '58316bf16d9fb7232019905df5beec34ecb5ceca0e791390800b32c81b608133', 'test/integration/public_context_journey_native_test.go': '3415d9209e216fc1feb96660476f912b257d527b81d582af976ccfa1d3e6e276', 'test/integration/public_context_journey_pools_test.go': '46b73f6b90b2f1032b54674a6ed65f7ae426237bf58e58b610b7101ed8729826', 'test/integration/public_context_journey_test.go': '71da180febd8b82e122d4e219f8ff0f452587214ee7eb453973608c032aca9aa', 'test/integration/public_runtime_roles_test.go': 'b5ec20019c6c00f615c2bf3d2d59fd5d03337a831eab20767849dc8d7fa1baa8', 'test/integration/recovery_effect_fixture_test.go': 'a86d0c5d41462712baf5ce9309285c51c0668cd23b38f6c81cee6846f2826788', 'test/integration/retention_effect_fixture_test.go': 'bba253cdfa3a5c55750eb83ff8a756be4f5912dcba223d420b70be7bab1ff021', 'test/integration/worker_configuration_kube_test.go': 'd09572b0f88eca6ec172e633fa635e89dc74dea9eb18c08ae2ccf080b2da1817', 'test/integration/worker_enrollment_helpers_test.go': 'f1a092c6ebce895578224e0549475d7b7ec0900721b494a725b3e9f715007f68', 'test/integration/public_context_request_diagnostics_test.go': '4d1a21cf7b86e0fcb01c7a25150528ccbc477572b72ac9dd8b8ba00fcc6a99f0', 'test/integration/public_context_regional_diagnostics_test.go': '72839ba05946879f40a41fe5b7056151d0bab9145ee4fea339ee27e5dd6c60cf', 'internal/adapters/kubernetes/initial_runtime_resources.go': '7e2ab93567fafc8222c01d516716a7a5d953fdca9ac7c06c1f6fdaf16d47b103', 'internal/adapters/kubernetes/owner_identity_launch.go': 'a4c2efdee260cf2a931f932b64197c63fccf84f2fc8317d905c919dc6b7a2c5d', 'internal/adapters/kubernetes/owner_identity_projection.go': 'b5fa1356fceb2cb69a8fce9885d38bb00ef867f87eb7a79c492ea3b1c4f03ee2', 'internal/adapters/kubernetes/owner_identity_projection_objects.go': 'f5881f71a77fbec90eece0adc3ef12d1dbdedc77e8b5eaae5a422018d0de91d9', 'internal/adapters/kubernetes/owner_identity_roles.go': '2a6b8a6be3a605554c8d52af494bbd3cc92bb7f3e68ea634f2bc29c9f8806fc0', 'internal/adapters/kubernetes/owner_installation_driver.go': '2038d2b72dfdb666d075b0d7e294b7a2cbe1c5accf4f1c9a5c23fefdbf1cb2ea', 'internal/adapters/kubernetes/owner_installation_driver_test.go': 'd39337a4f7bb9c547bb85131ac095fb3c64a25834c5258aa8d37c1cdbefce285', 'internal/adapters/kubernetes/owner_projection_diagnostic_test.go': '12d1ce86bff806ed29cc8ff7cf9592655c576bd00ae1367e8f43d6874a3e6f0f', 'internal/adapters/kubernetes/owner_projection_finalization.go': 'e6453270b029a84e15e0cc3533bbdfe55f77555aa9ab41bd86d52c9891f795b7', 'internal/adapters/kubernetes/owner_projection_finalization_handle_test.go': '25ce3c8865fde18706689b06347598a0829cf9983c042b97d3e4e18da99ff5ba', 'internal/adapters/kubernetes/owner_projection_finalization_test.go': '6c58d99e423cad6083d5d392a619f45b9c901eeda5a6aca7187675e6d9b0f11f', 'internal/adapters/kubernetes/owner_projection_operation.go': '0d0ce22340609f8e9f7c6ac01550844a2cbc5d606eed4867e25c03968b851ac6', 'internal/adapters/kubernetes/owner_projection_operation_composed_test.go': '03c320ee99e79f8c2fe8d3adf0dd4b6eca0fd0dc1a7290cd9b8def1d92726437', 'internal/adapters/kubernetes/owner_projection_operation_effects.go': '919d93e2ddc5fa43c908d2c60f5a5d80372d4b00ca060e296e2a44b486e46448', 'internal/adapters/kubernetes/owner_projection_operation_fixture_test.go': '88cfe0e9b9f24c72a20db54b93a26cc24e7c094343de144893e7beb6747e8a0e', 'internal/adapters/kubernetes/owner_projection_operation_native.go': '25961943a534dff8ece10aeb1212b98622bf867ba8c181ff0e67c9bf6fc2a962', 'internal/adapters/kubernetes/owner_projection_operation_plan.go': 'cb90f19a1e9963df5ab3960f1b9090fee9162c8d45e21346211eb294a2196dc2', 'internal/adapters/kubernetes/owner_projection_pending.go': '26bb2ad94978797c2340544e2e1dbdd0254c96d171d6a502085399ad9db53efa', 'internal/adapters/kubernetes/owner_projection_preflight.go': 'e631a6f696945ac5042ec24bc11d503ddac3b969c9b098ae49e51f695d1c01d2', 'internal/adapters/kubernetes/owner_projection_preflight_test.go': '3f7b1a546d41405c0926a59559688c481076ffc30c74e1abf905d686e03f196a', 'internal/adapters/postgres/owner_identity_operation_test.go': 'dcf0a61c658a0d65a2189c9b0a58988c1dfe09064e6d7be08af2ab5e9bc3821c', 'internal/adapters/postgres/owner_projection_finalization.go': 'dd61ce8af4662b973596ef4efb006e15c67adc0ff0761a6807653d628740f208', 'internal/adapters/postgres/owner_projection_operation.go': '46600cd95f2a6e1f290848bd0e8badaba15ca39195e73a9113c1646bd3adc18b', 'test/integration/initial_runtime_owner_pair_native_test.go': 'aec921a90073d5520d59a2c2f4e96748d6991f00908244e217b6f9ab2444e236'}
selections={label:(packagePaths[label],'^('+'|'.join(names)+')$') for label,names in expectedNames.items()}
steps=[('compile',['go','test','-count=1','-run','^$','./test/integration'])]
for label,(pkg,pattern) in selections.items():
 steps.append((label,['go','test','-race','-count=1','-timeout=15m','-json','-run',pattern,pkg]))
steps += [('vet',['go','vet','./...'])]
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
