#!/usr/bin/env python3
# Staged source-only. Parent owns integration, source freeze and the sole build slot.
# Adapted from reviewed projection-final-current.py. Both race packages retain 15m.
# All reviewed source must already be integrated by root before allocation.
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
sourcePatterns={'race-kubernetes': '^Test(?:OwnerProjection|ProviderOwnerProjection|ProviderOwnerInstallation|OwnerIdentity|ProviderOwnerOperation|OwnerPreflight|OwnerBootstrap|ProviderOwnerBootstrap)', 'race-postgres': '^'}
expectedNames={'race-kubernetes': ['TestOwnerBootstrapChildIntentExpiryDoesNotBecomeNewCreateAuthority', 'TestOwnerBootstrapCopiedAndClosedProducerHasNoEffect', 'TestOwnerBootstrapDiagnosticFinalNativeRetainsNormalization', 'TestOwnerBootstrapDiagnosticOuterBoundaryDoesNotClaimSQLCause', 'TestOwnerBootstrapDiagnosticRetainsOriginalFailureThroughInspect', 'TestOwnerBootstrapFinalGuardAndChildReplacementDeny', 'TestOwnerBootstrapGeneratedBindingRejectsCallerAuthoritySubstitution', 'TestOwnerBootstrapLostCreateAndReceiptRemainExact', 'TestOwnerBootstrapOriginalAllocationAndGeneratedInput', 'TestOwnerBootstrapPositiveCreatePinsIdentityBeforeReceipt', 'TestOwnerBootstrapProjectionRejectsCallerPermissionRootBeforeClaim', 'TestOwnerBootstrapProtectedSourceCapabilityAndDigest', 'TestOwnerBootstrapSameClusterAllocatesDistinctLogicalPeers', 'TestOwnerBootstrapStateRejectsAliasesAndUnboundedClaims', 'TestOwnerBootstrapStateRetainsOmissionAndHistoricalBytes', 'TestOwnerBootstrapTransitionsPreserveSiblingsAndSingleAdmission', 'TestOwnerBootstrapUnknownClaimCannotIssueCreate', 'TestOwnerBootstrapUnknownParentPinsExactLocalAllocation', 'TestOwnerBootstrapWorkerCallerCancellationDuringFinalRead', 'TestOwnerBootstrapWorkerCallerCloseAndCopyDeny', 'TestOwnerBootstrapWorkerCallerExpiredFinalReturnStaysUnavailable', 'TestOwnerBootstrapWorkerCallerFinalJournalAndGuardAreCurrent', 'TestOwnerBootstrapWorkerCallerOriginalReceipts', 'TestOwnerBootstrapWorkerCallerRejectsUnacknowledgedOrReplacement', 'TestOwnerBootstrapWorkerCallerUnavailableFinalJournalStaysUnavailable', 'TestOwnerIdentityAcceptedRevisionCannotReplaceOriginalServiceOrTrust', 'TestOwnerIdentityActivationKeepsOriginalRolesAndResources', 'TestOwnerIdentityChildObjectUnknownCreateIsIndependentLookupOnly', 'TestOwnerIdentityChildrenKeepIndependentAttemptsAndSiblingIsolation', 'TestOwnerIdentityComposedUnknownObjectsAndLaunchAreLookupOnly', 'TestOwnerIdentityJournalRequiresSeparatePositiveLaunch', 'TestOwnerIdentityNativeReadersRequireOriginalMountedBundle', 'TestOwnerIdentityOperationCancellationWhileWaitingForPhaseMutex', 'TestOwnerIdentityOperationCloseJoinsAdmittedRead', 'TestOwnerIdentityOperationFinalCannotSkipActualCurrentPhase', 'TestOwnerIdentityOperationRejectsDetachedAndRepeatedCalls', 'TestOwnerIdentityOperationRetainsShorterAdmittedPhaseDeadline', 'TestOwnerIdentityOperationRoleAttemptIsSingleUse', 'TestOwnerIdentityPendingLaunchDoesNotConvertInertOrReplacementIntoCompletion', 'TestOwnerIdentityPrivateRoleStateRetainsOriginalAttemptAndEnd', 'TestOwnerIdentityProducerOriginalRoleCASAndFreshNegativeProofs', 'TestOwnerIdentityProducerUnknownRoleCASNeverGrantsReplacement', 'TestOwnerIdentityProjectionAndLaunchKeepAllSiblingState', 'TestOwnerIdentityProjectionCanAdvanceOnlyUntouchedSecondChild', 'TestOwnerIdentityProjectionClonesNestedCallerInputForBothLayouts', 'TestOwnerIdentityProjectionReadsExactOriginalTemplateBeforeClaims', 'TestOwnerIdentityProjectionRejectsChangedOriginalInputsBeforeEffects', 'TestOwnerIdentityReaderRequiresCurrentPodAndOriginalGuard', 'TestOwnerPreflightAcceptedFailurePrecedesPrivateJournal', 'TestOwnerPreflightActualGraphsAndLockOrder', 'TestOwnerPreflightActualSelectionWriteRemainsLocked', 'TestOwnerPreflightCallerCancellationBeforeLockDeniesEffects', 'TestOwnerPreflightCloseJoinsInitialRead', 'TestOwnerPreflightNoLegacyFallback', 'TestOwnerPreflightOriginalAgeNotReplacedAfterLockWait', 'TestOwnerPreflightPostLockChangesDenyBeforeSelectionClaims', 'TestOwnerPreflightRoleAbsenceCannotAdoptAppearingOrLostRoot', 'TestOwnerPreflightShortParentDeadlineSurvivesBothAdmissions', 'TestOwnerProjectionDiagnosticClosedCodesKeepOriginalErrorsIs', 'TestOwnerProjectionDiagnosticPreservesFirstExecuteAndOnlyFinalization', 'TestOwnerProjectionDiagnosticSlotRejectsCopiedAndLaterFailures', 'TestOwnerProjectionDiagnosticUnknownEnumsRemainFixed', 'TestOwnerProjectionFinalizationCompatibilityEntryClaimsBeforeProviderIO', 'TestOwnerProjectionFinalizationExactGraphsAndReadOnlyResults', 'TestOwnerProjectionFinalizationFencesEveryOtherRootController', 'TestOwnerProjectionFinalizationOriginalCallerAndCleanupCutoff', 'TestOwnerProjectionFinalizationReconstructedRootCannotAdoptProgress', 'TestOwnerProjectionFinalizationRejectsCurrentChanges', 'TestOwnerProjectionFinalizationRejectsReplacementBeforeReceiptOrNextEffect', 'TestOwnerProjectionFinalizationRejectsSQLSemanticABA', 'TestOwnerProjectionFinalizationRetainsOnlyPublicPendingPins', 'TestOwnerProjectionFinalizationUnknownCreateNeverSelectsSameName', 'TestOwnerProjectionFinalizationUnknownLaunchReadbackCannotReplay', 'TestOwnerProjectionFinalizationUnknownPreSQLClaimHasNoVersion', 'TestOwnerProjectionFinalizationUnknownReceiptUsesOnlyExactCommittedCAS', 'TestOwnerProjectionFinalizerCloseJoinsAdmittedWork', 'TestOwnerProjectionFinalizerRejectsCopiesDetachedSkippedAndRepeatedPhases', 'TestOwnerProjectionFinalizerRequiresExactSemanticVersionOnce', 'TestOwnerProjectionFinalizerResultIsOneUseAndCopiesState', 'TestOwnerProjectionFinalizerRetainsShorterOriginalDeadline', 'TestOwnerProjectionOperationChildEndSurvivesLaterOriginalContext', 'TestOwnerProjectionOperationRejectsCopiedOuterHandle', 'TestOwnerProjectionOperationRejectsSkippedPhasesBeforeNativeOrEffect', 'TestOwnerProjectionOperationResultCopiesStateAndCanBeReturnedOnlyOnce', 'TestOwnerProjectionSplitBridgeWaitChangesDenyBeforeFirstClaim', 'TestOwnerProjectionSplitCloseCancelsAndJoinsOriginalBranches', 'TestOwnerProjectionSplitCompletedNativeAndAcceptedPrecedePrivate', 'TestOwnerProjectionSplitExactGraphsAndPrivateAdmission', 'TestOwnerProjectionSplitInvalidOriginalOwnerDeploymentPrecedesBridge', 'TestOwnerProjectionSplitOpaquePrefixRejectsCopiesAndReplay', 'TestOwnerProjectionSplitOriginalDeadlineCannotBeRenewedAfterBridgeWait', 'TestOwnerProjectionSplitPinsRootAndDefinesFirstPrivateSelection', 'TestOwnerProjectionSplitPostClaimMutationStillSpendsWithoutEffect', 'TestOwnerProjectionSplitSourceChangeDuringFinalGuardIsCompared', 'TestProviderOwnerInstallationCancellationDuringOuterJoinCannotReturnComplete', 'TestProviderOwnerInstallationCloseJoinsAdmittedNativeWork', 'TestProviderOwnerInstallationFailedFinalizerDoesNotInspectAgain', 'TestProviderOwnerInstallationRunsFiniteOriginalSequence', 'TestProviderOwnerInstallationStopsKnownSpentAttemptWithoutPolling', 'TestProviderOwnerInstallationUnknownReceiptConsumesSingleFinalizer', 'TestProviderOwnerInstallationUsesOnlyOneUnknownResultInspection', 'TestProviderOwnerOperationClaimBeforePostLockDenialStaysSpent', 'TestProviderOwnerOperationFinalRepeatsRBACAndAdmissionChecks', 'TestProviderOwnerOperationOpenAndFourOriginalRolePhases', 'TestProviderOwnerOperationUnknownEffectOnlyReconcilesOriginalResult', 'TestProviderOwnerOperationUnknownRootCreatePinsExactAttemptAcrossCalls', 'TestProviderOwnerProjectionContainsOnlyOriginalSQLAndPublicRecipe', 'TestProviderOwnerProjectionOperationCompleteAndLaunch', 'TestProviderOwnerProjectionOperationLostCreateRemainsUnverified', 'TestProviderOwnerProjectionOperationProviderDenialPrecedesIntent', 'TestProviderOwnerProjectionOperationRequiresPostLockAndFinalCurrentProof', 'TestProviderOwnerProjectionOperationUnknownReceiptCannotRepeatCAS', 'TestProviderOwnerProjectionRejectsLegacyAndUnverifiedSelectionBeforeEffects'], 'race-postgres': ['TestAPIExecutionProgressUsesItsDurableOutcome', 'TestAPIExecutionStoredResultDecodingRejectsSubstitution', 'TestAPIVerificationAuditRequiresExactCompletedResult', 'TestAcceptedPublicationRequiresRetainedIntentReceipt', 'TestCapacityAuditProfilesDecodeClosedAndNoLegacyFallback', 'TestCapacityCredentialManifestRetainsOriginalCompartmentAndIncarnation', 'TestCapacityEnrollmentDecoderDistinguishesAbsentPartialAndReady', 'TestCapacityEnrollmentDecoderRejectsOpenOrInconsistentReceipt', 'TestCapacityManagedStorageFenceRetainsEarliestOriginalDeadline', 'TestCapacityManifestClosedDecoderRejectsUnknownAndDuplicateFields', 'TestCapacityOrdinarySessionDecodeKeepsOriginalBacking', 'TestCapacityRecoveryDecoderRetainsExactIndependentProof', 'TestCapacityRoleCanAuthenticateOwnerWithoutPeerEffects', 'TestCapacityRolePlansKeepClosedRPCsAndPurposeFixedPeerReads', 'TestCapacitySQLPrecisionOnlyNarrowsOriginalInterval', 'TestCapacitySessionSnapshotClosedAndNeverFallsBack', 'TestCapacitySetupInputChecksCompleteBackingBeforeClaim', 'TestCapacitySourceAcknowledgementRejectsAmbiguousFields', 'TestCaptureCleanupFullPolicyConstructorRetainsValidation', 'TestCaptureCleanupManifestDecoderRejectsAmbiguousInput', 'TestCaptureCleanupManifestKeepsOriginalThreeRoleCompartment', 'TestCaptureCleanupPlansKeepPrivateSQLAndPurposeSeparation', 'TestCaptureCleanupScopePreservesOriginalCohorts', 'TestCaptureOperationRetainedReceiptRequiresExactNewProtocol', 'TestConfigurationRuntimeRolePlanCannotCreatePublicAuthority', 'TestConfigurationWorkerLaunchClaimsKeepOriginalRoleAuthority', 'TestConfigurationWorkerLaunchFinalSQLStateOnlyAddsOriginalReceipt', 'TestConnectorCredentialDecoderAcceptsOriginalOverlappingObservations', 'TestConnectorObservationOperationRegistryActualOrderedSourceCalls', 'TestConnectorObservationOperationRegistryDeadlineAfterWait', 'TestConnectorObservationOperationRegistryFailuresRetainPhase', 'TestConnectorObservationOperationRegistryOriginalBindingBeforeIO', 'TestConnectorObservationRegistryRejectsMismatchedOriginalBeforeAnyIO', 'TestContextDeletionRecordRejectsRelationalOrCanonicalSubstitution', 'TestContextMetadataDeadlineIsOriginalAndNotSerialized', 'TestContextPlanRequiresExactFiniteNativeControlAndStopBacking', 'TestContextPreviewQuotaAndRequestKeysHaveDifferentClientScopes', 'TestContextPreviewRecordPreservesImmutableReviewAndRejectsCorruption', 'TestContextResolutionShapePreservesSequentialObservationIntervals', 'TestContextStorageObservationRejectsChangedOrInvalidSources', 'TestContextStorageObservationRetainsOriginalBounds', 'TestControlCapacitySeparatesFullAndRetainedReplayBacking', 'TestControlConfigurationObservationCannotRenewAfterBlockingWork', 'TestCurrentAuthorityAuditRequiresExactImmutableReceipt', 'TestCurrentBatchReceiptRequiresVersionButHistoryKeepsBytes', 'TestCurrentBootstrapIntentAudit', 'TestCurrentCatalogRequiresBothOriginalAuditReceipts', 'TestCurrentIssuedBootstrapAudit', 'TestCurrentWindowReceiptsRequireVersionsButHistoryKeepsBytes', 'TestCurrentWorkerChecksExactRetainedReceiptWithoutBlockingHistoricalDecode', 'TestExactCaptureIntentReceiptRejectsSubstitution', 'TestFirstContextClosedLocalOwnersDoNotClearUncertainResponse', 'TestFirstContextObservePreservesContentAndRetirementHeadroom', 'TestFirstContextPreparationDoesNotGrantASecondAttempt', 'TestFirstContextRetryRequiresExactIndependentSuccessfulOutcome', 'TestFixedRuntimeRoleFunctionAliasUsesExactOverload', 'TestFleetObservationContentionFinalRowCannotRefreshOrReplace', 'TestFleetObservationContentionOnlyExactServerLockAbort', 'TestFleetObservationContentionRejectsIndependentlyReactivatedIncarnation', 'TestFleetObservationContentionRequiresCurrentExactPositiveSource', 'TestInitialBootstrapHistoryTransferPreservesMeasuredOwnerOrigins', 'TestInitialHistoryLoginIsInstallationAndPurposeBound', 'TestInitialHistoryManagerIsAnIndependentFinitePin', 'TestInitialInstallationHistoricalObservation', 'TestInitialInstallationInventoryMatchesCatalogOrdering', 'TestInitialRuntimeOwnerBridgeExactFleetAndOriginalIntervals', 'TestInitialRuntimeOwnerBridgeMinimumBoundCannotRenew', 'TestInitialRuntimeOwnerBridgeRejectsUnavailablePreflightBeforeSQL', 'TestInitialSQLCredentialEntropyScopeAndRedaction', 'TestInitialSQLCredentialStateScopeAndClosedDecoding', 'TestInitialSQLHistoryDiagnosticHidesValues', 'TestInitialSQLMaterialReconstructsOriginalPrivateState', 'TestInitialSchemaBindingAlsoRejectsHistoricalRecordFromOtherIncarnation', 'TestInitialSchemaClaimAndCompletionBoundsCannotRenewLease', 'TestInitialSchemaEmbeddedBundleAndClosedAnnotations', 'TestInitialSchemaExpectationRejectsIncompatibleCompiledProvenance', 'TestInitialSchemaGrantUnionRemainsPurposeLimited', 'TestInitialSchemaHistoryRequiresOriginalOrderedUpPrefix', 'TestInitialSchemaRetainsExpiredCurrentRootBeforeSQL', 'TestInitialSchemaShorterObservationCancelsAlreadyPassedSQLContext', 'TestInitialSchemaStoreCannotCreateOrDeleteViaGoose', 'TestNativeCompletionRequiresCurrentExactOpenGeneration', 'TestOperationLifecycleCannotTreatCurrentRestartActivationAsHistoricalReconciliation', 'TestOwnerConfigurationReadDiagnosticPredicatesAndSingleClock', 'TestOwnerConfigurationReadDiagnosticQueryClassesAndRetryReset', 'TestOwnerConfigurationReadDiagnosticRecoveryParityAndErrorIdentity', 'TestOwnerIdentityOperationSQLRejectsZeroHandleBeforePoolUse', 'TestOwnerIdentityRolesKeepSeparateAuthority', 'TestOwnerIdentitySQLPrerequisiteErrorsStaySanitized', 'TestOwnerIdentitySQLPrerequisiteParityAndSingleQuery', 'TestOwnerProjectionFinalCurrentReasonPreservesShortCircuit', 'TestOwnerProjectionFinalCurrentReasonRejectsUnknownAndPrivateText', 'TestOwnerProjectionFinalCurrentReasonUsesActualSingleSQLResult', 'TestOwnerProjectionSQLDiagnosticActualEntryPreservesNormalization', 'TestOwnerProjectionSQLDiagnosticKeepsClosedStagesAndOriginalCause', 'TestPermissionContinuityRequiresExactVersionsOrVerifiedTransitions', 'TestProcessingCaptureCoverageOriginalRootBounds', 'TestProcessingCaptureCoveragePurposePrivileges', 'TestProcessingCaptureCoverageRetainsEachOriginalRule', 'TestProgressProjectsOnlyDurableFacts', 'TestProgressRejectsIncompletePublicationOrCorruptIdentity', 'TestPublicContextDraftRolesHaveExactPurposeGrants', 'TestPublicDownloadSourceRoleReadsReceiptsWithoutEffectPrivileges', 'TestPublicRuntimeRolePlanKeepsPurposeIdentityAndProjection', 'TestRefreshOwnerObservationPreservesOriginalInterval', 'TestScopeDigestNormalizationAndBasisIdentity', 'TestSessionCapacityReadsKeepUnmanagedRowsUnchanged', 'TestSessionCapacityReadsRejectUnboundOrDamagedSnapshots', 'TestSessionCapacityReadsRetainOriginalLimitsAndCurrentSpend', 'TestUnversionedHistoryRemainsHistoricalProgress']}
reviewedPayloads={'internal/adapters/kubernetes/initial_runtime_resources.go': '7e2ab93567fafc8222c01d516716a7a5d953fdca9ac7c06c1f6fdaf16d47b103', 'internal/adapters/kubernetes/owner_identity_launch.go': 'a4c2efdee260cf2a931f932b64197c63fccf84f2fc8317d905c919dc6b7a2c5d', 'internal/adapters/kubernetes/owner_identity_projection.go': 'b5fa1356fceb2cb69a8fce9885d38bb00ef867f87eb7a79c492ea3b1c4f03ee2', 'internal/adapters/kubernetes/owner_identity_projection_objects.go': 'f5881f71a77fbec90eece0adc3ef12d1dbdedc77e8b5eaae5a422018d0de91d9', 'internal/adapters/kubernetes/owner_identity_roles.go': '2a6b8a6be3a605554c8d52af494bbd3cc92bb7f3e68ea634f2bc29c9f8806fc0', 'internal/adapters/kubernetes/owner_installation_driver.go': '2038d2b72dfdb666d075b0d7e294b7a2cbe1c5accf4f1c9a5c23fefdbf1cb2ea', 'internal/adapters/kubernetes/owner_installation_driver_test.go': 'da7c43fa05bc126332e9754eeba1ac289335976f009aeb4df4e2ef46c04ee06f', 'internal/adapters/kubernetes/owner_projection_diagnostic_test.go': '12d1ce86bff806ed29cc8ff7cf9592655c576bd00ae1367e8f43d6874a3e6f0f', 'internal/adapters/kubernetes/owner_projection_finalization.go': 'e6453270b029a84e15e0cc3533bbdfe55f77555aa9ab41bd86d52c9891f795b7', 'internal/adapters/kubernetes/owner_projection_finalization_handle_test.go': '25ce3c8865fde18706689b06347598a0829cf9983c042b97d3e4e18da99ff5ba', 'internal/adapters/kubernetes/owner_projection_finalization_test.go': '6c58d99e423cad6083d5d392a619f45b9c901eeda5a6aca7187675e6d9b0f11f', 'internal/adapters/kubernetes/owner_projection_operation.go': '0d0ce22340609f8e9f7c6ac01550844a2cbc5d606eed4867e25c03968b851ac6', 'internal/adapters/kubernetes/owner_projection_operation_composed_test.go': '03c320ee99e79f8c2fe8d3adf0dd4b6eca0fd0dc1a7290cd9b8def1d92726437', 'internal/adapters/kubernetes/owner_projection_operation_effects.go': '919d93e2ddc5fa43c908d2c60f5a5d80372d4b00ca060e296e2a44b486e46448', 'internal/adapters/kubernetes/owner_projection_operation_fixture_test.go': '88cfe0e9b9f24c72a20db54b93a26cc24e7c094343de144893e7beb6747e8a0e', 'internal/adapters/kubernetes/owner_projection_operation_native.go': '25961943a534dff8ece10aeb1212b98622bf867ba8c181ff0e67c9bf6fc2a962', 'internal/adapters/kubernetes/owner_projection_operation_plan.go': 'cb90f19a1e9963df5ab3960f1b9090fee9162c8d45e21346211eb294a2196dc2', 'internal/adapters/kubernetes/owner_projection_pending.go': '26bb2ad94978797c2340544e2e1dbdd0254c96d171d6a502085399ad9db53efa', 'internal/adapters/kubernetes/owner_projection_preflight.go': 'e631a6f696945ac5042ec24bc11d503ddac3b969c9b098ae49e51f695d1c01d2', 'internal/adapters/kubernetes/owner_projection_preflight_test.go': '5dd91497bd32a8526a22de5655c2b16b77de2123dc77090091cc9c8f9d78591e', 'internal/adapters/postgres/owner_identity_operation_test.go': 'dcf0a61c658a0d65a2189c9b0a58988c1dfe09064e6d7be08af2ab5e9bc3821c', 'internal/adapters/postgres/owner_projection_finalization.go': 'dd61ce8af4662b973596ef4efb006e15c67adc0ff0761a6807653d628740f208', 'internal/adapters/postgres/owner_projection_operation.go': '46600cd95f2a6e1f290848bd0e8badaba15ca39195e73a9113c1646bd3adc18b', 'test/integration/initial_runtime_owner_pair_native_test.go': 'aec921a90073d5520d59a2c2f4e96748d6991f00908244e217b6f9ab2444e236'}
selections={'race-kubernetes': ('./internal/adapters/kubernetes', '^Test(?:OwnerProjection|ProviderOwnerProjection|ProviderOwnerInstallation|OwnerIdentity|ProviderOwnerOperation|OwnerPreflight|OwnerBootstrap|ProviderOwnerBootstrap)'), 'race-postgres': ('./internal/adapters/postgres', '^')}
steps=[('compile',['go','test','-count=1','-run','^$','./test/integration']),
       ('race-kubernetes',['go','test','-race','-count=1','-timeout=15m','-json','-run',sourcePatterns['race-kubernetes'],'./internal/adapters/kubernetes']),
       ('race-postgres',['go','test','-race','-count=1','-timeout=15m','-json','./internal/adapters/postgres']),
       ('vet',['go','vet','./...']),('go-architecture',['make','go-architecture-check'])]
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
    declarations += [test for test in re.findall(r'^func ((?:Test|Fuzz|Example)\w+)\(',file.read_text(),re.M) if re.search(sourcePatterns[label],test)]
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
