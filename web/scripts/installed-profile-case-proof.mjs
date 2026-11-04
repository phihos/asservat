// Qualification only: observe the product's existing session-driven case reads.
// This helper issues no HTTP requests and never treats metadata as authority.
import assert from 'node:assert/strict';
import { validSession } from '../src/generated/validate-auth.js';
import { validOutput_get_case } from '../src/generated/validate-evidence.js';

export function checkInstalledProfileCaseRefreshes({ heap, caseID, artifactID, observations }) {
  let originalSession, originalArtifact;
  let pendingSession = false;
  let sessions = 0, cases = 0;
  for (const observation of observations) {
    if (observation.kind === 'session') {
      const session = observation.reply;
      assert(validSession(session) && session.principal.kind === 'user', 'canonical current browser session');
      assert(!pendingSession && ++sessions <= 5, 'one existing refresh per case within original five-minute driver');
      if (originalSession) {
        assert(heap, 'comparison retains one original case read');
        assert.deepEqual(session.principal, originalSession.principal, 'same original browser human');
        assert(Date.parse(session.expires_at) <= Date.parse(originalSession.expires_at), 'original session expiry never extended');
      } else originalSession = session;
      pendingSession = true;
    } else {
      assert.equal(observation.kind, 'case', 'closed metadata observation');
      const reply = observation.reply;
      assert(pendingSession && validOutput_get_case(reply) && reply.status === 'ok', 'one canonical case after successful session refresh');
      assert.equal(reply.data.case.case_id, caseID, 'original case');
      assert.equal(reply.data.case.access, 'ordinary', 'ordinary case remains current');
      const artifact = reply.data.artifacts.find(value => value.artifact_id === artifactID);
      assert(artifact && reply.data.artifacts.filter(value => value.artifact_id === artifactID).length === 1, 'exact original selected artifact');
      // Pin immutable source/target/acquisition facts. Current handling notices
      // and retention affordances may change on the product's fresh case read.
      const stable = {
        artifact_id: artifact.artifact_id, digest: artifact.digest,
        kind: artifact.kind, native_format: artifact.native_format,
        data_class: artifact.data_class, verified_native_bytes: artifact.verified_native_bytes,
        target: artifact.target && {
          cluster_id: artifact.target.cluster_id, namespace_uid: artifact.target.namespace_uid,
          workload_uid: artifact.target.workload_uid, pod_uid: artifact.target.pod_uid,
        },
        profile_acquisition: artifact.profile_acquisition,
      };
      if (originalArtifact) assert.deepEqual(stable, originalArtifact, 'original profile facts on every current case read');
      else originalArtifact = stable;
      pendingSession = false;
      cases++;
    }
  }
  assert(cases >= 1 && sessions === cases && !pendingSession, 'every observed successful refresh has exactly one current case');
  assert(heap || cases === 1, 'comparison retains strict single metadata read');
  return cases;
}
