# Ordinary context cases

C-16 serves approved pod-status case metadata under REQ-EVD-004, REQ-MCP-005
and S-02. Raw and shared access use their own facets; there is no ordinary
fallback for them.

## Read

`catalog.ContextCaseService.GetContextCase(ctx, CurrentIdentity, caseID)`
accepts the request-owned identity from the browser or bearer ingress. The
caller supplies no namespace, target, audience or storage reference. Unknown,
unreadable and unavailable cases return the same `case unavailable`
error.

One authorization per operation ([ADR-311](../decisions/311-operation-authority-recheck.md)):
the service reads one cursor page of published-artifact locators for the case,
then evaluates `ReadApproved` eligibility in one batched query over the case's
distinct whole-pod targets, together with complete denies, the original
retained audience (stable group IDs and subjects) and the stored retention
deadlines. Being the requester, publication or later workload ownership is not
sufficient. Download scope is not required to read ordinary metadata.

The read is a plain MVCC select; it takes no recovery or permission-root lock.
No live Pod, Node or collector is needed to read published evidence.

Each artifact contains its opaque artifact and capture IDs, internal target,
immutable artifact version and effective access/delete dates. There are no
native hashes, filenames, byte counts, storage URLs, evidence or free-text
titles. The result maps to `Ready`, `ordinary`, `pod-status`, `metadata`,
`complete` and an empty timeline. The handling notice is
`potentialPersonalData`; managed deletion cannot recall external copies.

The descriptor `digest` is the immutable artifact **version**: for this profile
the SHA-256 of the versioned ciphertext-copy receipt (`ContextCopiesDigest`).
Native SHA-256 and filenames come only from native download preparation, which
`get_case` never performs.

Every case read writes its audit row (D6), including denials.

## Locator projection

`context_case_locator` has one immutable row per published artifact with
root/case/cluster UUIDs and namespace, workload and Pod UIDs. An index on
`(root_id,case_id,artifact_id)` serves exact lookup and is the pagination
cursor; a case with many artifacts is read page by page. Deleted or expired
artifacts are excluded.

A catalog `AFTER INSERT` trigger derives the locator in the publication
transaction from the accepted expectation, so runtime code cannot insert
arbitrary locators. Unpublished uploads never become cases. The table rejects
UPDATE; rows go away with their artifact's metadata when retention deletes it.

Case grouping, aliases, editable titles, search and sharing are separate
work. An artifact never stays readable merely to keep a case visible.

## Capture navigation

C-09 `ContextCaseNavigator` implements `ContextCaseNavigation` through a
consumer-owned case reader. It adds a link only to Succeeded progress whose
case read contains that exact artifact, capture and target. Failure omits the
link without hiding readable progress. C-09 does not import C-16 or duplicate
the policy evaluator.
