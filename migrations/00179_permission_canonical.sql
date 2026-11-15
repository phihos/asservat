-- +goose Up
-- ADR-335 D14 / REQ-PER-001: ClusterAccessBinding bases cover every
-- namespace of their cluster (namespace_uid '*'); access reviews may map to
-- any role (REQ-PER-004); a binding names any number of workloads (the
-- Kubernetes object size limit bounds the list).
ALTER TABLE permission_basis DROP CONSTRAINT permission_basis_kind_check;
ALTER TABLE permission_basis ADD CONSTRAINT permission_basis_kind_check CHECK(kind IN ('AccessBinding','PermissionSource','ClusterAccessBinding'));
ALTER TABLE permission_basis DROP CONSTRAINT permission_basis_workload_uids_check;
ALTER TABLE permission_review_source DROP CONSTRAINT permission_review_source_role_check;
ALTER TABLE permission_review_source ADD CONSTRAINT permission_review_source_role_check CHECK(role IN ('workload-maintainer','evidence-reader','evidence-owner','action-approver'));
ALTER TABLE permission_review_assignment DROP CONSTRAINT permission_review_assignment_role_check;
ALTER TABLE permission_review_assignment ADD CONSTRAINT permission_review_assignment_role_check CHECK(role IN ('workload-maintainer','evidence-reader','evidence-owner','action-approver'));

-- +goose Down
ALTER TABLE permission_review_assignment DROP CONSTRAINT permission_review_assignment_role_check;
ALTER TABLE permission_review_assignment ADD CONSTRAINT permission_review_assignment_role_check CHECK(role IN ('workload-maintainer','evidence-reader'));
ALTER TABLE permission_review_source DROP CONSTRAINT permission_review_source_role_check;
ALTER TABLE permission_review_source ADD CONSTRAINT permission_review_source_role_check CHECK(role IN ('workload-maintainer','evidence-reader'));
ALTER TABLE permission_basis ADD CONSTRAINT permission_basis_workload_uids_check CHECK(cardinality(workload_uids)<=64);
ALTER TABLE permission_basis DROP CONSTRAINT permission_basis_kind_check;
ALTER TABLE permission_basis ADD CONSTRAINT permission_basis_kind_check CHECK(kind IN ('AccessBinding','PermissionSource'));
