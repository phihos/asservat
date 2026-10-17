#!/usr/bin/env python3
# Staged source-only. Parent owns integration, source freeze and the sole build slot.
# Adapted from source-limiter-diagnostics.py; four bounded race groups retain 15m.
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
sourcePatterns={'race-kubernetes-split': '^TestOwnerProjectionSplit', 'race-kubernetes-projection': '^Test(OwnerProjection(Diagnostic|Operation)|ProviderOwner(Installation|Projection))', 'race-kubernetes-owner': '^Test(OwnerPreflight|OwnerBootstrapDiagnostic|OwnerNativeDiagnostic|OwnerIdentityOperation|OwnerOperationDiagnostics|OwnerOriginalDiagnostic|ProviderOwner(Operation|Accepted))', 'race-kubernetes-source': '^Test(ConfigurationWorker(Diagnostic|Native|PostLock|FinalBracket|ReadsSource|BlockedPostLock|AliasedDepleted|SourceReaders|OwnerDecoder|FleetDecoder)|ConfigurationRole|GuardProof|OwnerWorkload(Protection|Probe)|OwnerSchedulingLease|CapacityGuards|RetentionGuard|FleetAdministrationProtectedConfig|OwnerConfigurationClosedSnapshot|WorkerConfigurationClosedSnapshot|BrowserSettingsProtectedConfig)'}
expectedNames={'race-kubernetes-split': ['TestOwnerProjectionSplitBridgeWaitChangesDenyBeforeFirstClaim', 'TestOwnerProjectionSplitCloseCancelsAndJoinsOriginalBranches', 'TestOwnerProjectionSplitCompletedNativeAndAcceptedPrecedePrivate', 'TestOwnerProjectionSplitExactGraphsAndPrivateAdmission', 'TestOwnerProjectionSplitInvalidOriginalOwnerDeploymentPrecedesBridge', 'TestOwnerProjectionSplitOpaquePrefixRejectsCopiesAndReplay', 'TestOwnerProjectionSplitOriginalDeadlineCannotBeRenewedAfterBridgeWait', 'TestOwnerProjectionSplitPinsRootAndDefinesFirstPrivateSelection', 'TestOwnerProjectionSplitPostClaimMutationStillSpendsWithoutEffect', 'TestOwnerProjectionSplitSourceChangeDuringFinalGuardIsCompared'], 'race-kubernetes-projection': ['TestOwnerProjectionDiagnosticClosedCodesKeepOriginalErrorsIs', 'TestOwnerProjectionDiagnosticPreservesFirstAdvanceAndInspection', 'TestOwnerProjectionDiagnosticSlotRejectsCopiedAndLaterFailures', 'TestOwnerProjectionDiagnosticUnknownEnumsRemainFixed', 'TestOwnerProjectionOperationChildEndSurvivesLaterOriginalContext', 'TestOwnerProjectionOperationRejectsCopiedOuterHandle', 'TestOwnerProjectionOperationRejectsSkippedPhasesBeforeNativeOrEffect', 'TestOwnerProjectionOperationResultCopiesStateAndCanBeReturnedOnlyOnce', 'TestProviderOwnerInstallationCloseJoinsAdmittedNativeWork', 'TestProviderOwnerInstallationRunsFiniteOriginalSequence', 'TestProviderOwnerInstallationStopsKnownSpentAttemptWithoutPolling', 'TestProviderOwnerInstallationUsesOnlyOneUnknownResultInspection', 'TestProviderOwnerProjectionContainsOnlyOriginalSQLAndPublicRecipe', 'TestProviderOwnerProjectionOperationCompleteAndLaunch', 'TestProviderOwnerProjectionOperationLostCreateIsInspectOnly', 'TestProviderOwnerProjectionOperationProviderDenialPrecedesIntent', 'TestProviderOwnerProjectionOperationRequiresPostLockAndFinalCurrentProof', 'TestProviderOwnerProjectionOperationUnknownReceiptCannotRepeatCAS', 'TestProviderOwnerProjectionRejectsLegacyAndUnverifiedSelectionBeforeEffects'], 'race-kubernetes-owner': ['TestOwnerBootstrapDiagnosticFinalNativeRetainsNormalization', 'TestOwnerBootstrapDiagnosticOuterBoundaryDoesNotClaimSQLCause', 'TestOwnerBootstrapDiagnosticRetainsOriginalFailureThroughInspect', 'TestOwnerIdentityOperationCancellationWhileWaitingForPhaseMutex', 'TestOwnerIdentityOperationCloseJoinsAdmittedRead', 'TestOwnerIdentityOperationFinalCannotSkipActualCurrentPhase', 'TestOwnerIdentityOperationRejectsDetachedAndRepeatedCalls', 'TestOwnerIdentityOperationRetainsShorterAdmittedPhaseDeadline', 'TestOwnerIdentityOperationRoleAttemptIsSingleUse', 'TestOwnerNativeDiagnosticPreservesAcceptedShortCircuitClockReads', 'TestOwnerOperationDiagnosticsNeverRenderDriverValues', 'TestOwnerOriginalDiagnosticDoesNotCompareObservationDates', 'TestOwnerOriginalDiagnosticKeepsExactFieldsAndFirstDifference', 'TestOwnerPreflightAcceptedFailurePrecedesPrivateJournal', 'TestOwnerPreflightActualGraphsAndLockOrder', 'TestOwnerPreflightActualSelectionWriteRemainsLocked', 'TestOwnerPreflightCallerCancellationBeforeLockDeniesEffects', 'TestOwnerPreflightCloseJoinsInitialRead', 'TestOwnerPreflightNoLegacyFallback', 'TestOwnerPreflightOriginalAgeNotReplacedAfterLockWait', 'TestOwnerPreflightPostLockChangesDenyBeforeSelectionClaims', 'TestOwnerPreflightRoleAbsenceCannotAdoptAppearingOrLostRoot', 'TestOwnerPreflightShortParentDeadlineSurvivesBothAdmissions', 'TestProviderOwnerAcceptedObservationDoesNotRefreshOnRead', 'TestProviderOwnerOperationClaimBeforePostLockDenialStaysSpent', 'TestProviderOwnerOperationFinalRepeatsRBACAndAdmissionChecks', 'TestProviderOwnerOperationOpenAndFourOriginalRolePhases', 'TestProviderOwnerOperationUnknownEffectOnlyReconcilesOriginalResult', 'TestProviderOwnerOperationUnknownRootCreatePinsExactAttemptAcrossCalls'], 'race-kubernetes-source': ['TestBrowserSettingsProtectedConfig', 'TestCapacityGuardsRequireExactIndependentCurrentDenial', 'TestConfigurationRoleDeploymentUsesItsOwnTwoProcessBound', 'TestConfigurationRoleInertClaimCanCompleteWithoutLaunchingPod', 'TestConfigurationRoleInertDeploymentPreservesFutureRolloutBound', 'TestConfigurationRoleOperationChecksGuardAroundNegativeProbes', 'TestConfigurationRoleOperationCloseCancelsAndJoins', 'TestConfigurationRoleOperationDoesNotEscapeOrRenew', 'TestConfigurationRoleOperationRechecksChangedEnforcementAndSources', 'TestConfigurationRoleRootCompleteOriginalOperation', 'TestConfigurationRoleRootOpenKeepsOriginalFiveSecondPath', 'TestConfigurationRoleSourceKeepsOriginalIdentityAndBounds', 'TestConfigurationRoleSourceOriginalFiveSecondPath', 'TestConfigurationRoleSourceUnchangedObjectsStillRequireEnforcement', 'TestConfigurationRoleZeroToOneAfterClaimInvalidatesOriginalOperation', 'TestConfigurationWorkerAliasedDepletedLimiterCannotInventAvailability', 'TestConfigurationWorkerBlockedPostLockReadRetainsOriginalEnd', 'TestConfigurationWorkerDiagnosticBlockedReadKeepsOriginalDeadline', 'TestConfigurationWorkerDiagnosticCodesSurviveNormalizedProjection', 'TestConfigurationWorkerDiagnosticFinalPredicatesKeepClockOrder', 'TestConfigurationWorkerDiagnosticGuardSubcode', 'TestConfigurationWorkerDiagnosticMutationKeepsActualGraph', 'TestConfigurationWorkerDiagnosticProbeDetailsAndJoinedPriority', 'TestConfigurationWorkerFinalBracketNeedsNewNativeEnforcement', 'TestConfigurationWorkerFleetDecoderCannotRenewOriginalInterval', 'TestConfigurationWorkerNativeAndPostLockReadsAreExplicit', 'TestConfigurationWorkerNativeConstructorKeepsExactClientsAndPins', 'TestConfigurationWorkerNativeResponsesRequireEveryOriginalProbe', 'TestConfigurationWorkerOwnerDecoderKeepsCompleteBodyWithoutIO', 'TestConfigurationWorkerPostLockRejectsChangedCompleteValues', 'TestConfigurationWorkerReadsSourceAfterFinalGuard', 'TestConfigurationWorkerSourceReadersRetainCurrentValuesAndSuspension', 'TestConfigurationWorkerSourceReadersUseActualEightReadBrackets', 'TestFleetAdministrationProtectedConfig', 'TestGuardProofPreservesStructuredAdmissionCause', 'TestOwnerConfigurationClosedSnapshot', 'TestOwnerSchedulingLeasePlanRejectsAmbiguousScope', 'TestOwnerWorkloadProbePlanRejectsAmbiguousScope', 'TestOwnerWorkloadProtectionRequiresActualCurrentDenial', 'TestRetentionGuardCurrentEnforcementAndNegativeControls', 'TestWorkerConfigurationClosedSnapshot']}
reviewedPayloads={'internal/adapters/kubernetes/owner_projection_operation.go': '902932ff1398a1abf35b472bd91689954b67c8e8dc5e6634c1e48ee8668ed0b0', 'internal/adapters/kubernetes/owner_projection_preflight.go': '0f0c21dd0e0b9178213cae42fd461d7393867a8b1aa4cb4c77bc368090c210d4', 'internal/adapters/kubernetes/owner_projection_preflight_source.go': 'b914f0521feac4a069b6b860556f9dceec9a5c94199d2ffab9d205122c3d4e2e', 'internal/adapters/kubernetes/owner_projection_preflight_test.go': 'a31ea928d3110fd53840177ace2851af80b23a961021475fb3150d2f9e1785f4'}
selections={label:('./internal/adapters/kubernetes','^('+'|'.join(names)+')$') for label,names in expectedNames.items()}
steps=[('compile',['go','test','-count=1','-run','^$','./test/integration'])]
for label,(pkg,pattern) in selections.items():
 steps.append((label,['go','test','-race','-count=1','-timeout=15m','-json','-run',pattern,pkg]))
steps += [('vet',['go','vet','./...']),('canonical',['make','go-architecture-check','spec-check','architecture-check','design-check','PYTHON='+str(CACHE/'spec-venv/bin/python')])]
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
    declarations += [test for test in re.findall(r'^func (Test\w+)\(t \*testing.T\)',file.read_text(),re.M) if re.search(sourcePatterns[label],test)]
   assert Counter(declarations)==Counter(expectedNames[label]),'selected source declarations changed: '+label
   required={('asservat.local/asservat/'+pkg[2:],test) for test in declarations}
   assert required
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
except Exception as e:report['error']=str(e)
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
 try:tmp.rmdir();report['scratchRemoved']=True
 except OSError:report['scratchRemoved']=False;code=1
 report['status']='passed' if code==0 else 'failed';report['exit']=code
 report['archiveHashes']={str(p.relative_to(out)):sha(p) for p in out.rglob('*') if p.is_file()}
 (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'sourceUnchanged':report['sourceUnchanged'],'scratchRemoved':report['scratchRemoved']}),flush=True)
sys.exit(code)
