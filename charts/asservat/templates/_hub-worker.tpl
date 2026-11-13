{{/*
hub-worker helpers (Helm-native installation,
docs/reviews/helm-native-field-map.md). Fold the generic ones
(name, labels, image, security contexts, secretName, waitSchema, provider
endpoints) into the shared _helpers.tpl once it exists in this branch.
*/}}

{{/* "true" when this release renders the hub-worker (mode hub or combined). */}}
{{- define "asservat.hubWorker.enabled" -}}
{{- $w := default dict (index (default dict .Values.hub) "hub-worker") -}}
{{- if and (ne .Values.mode "cluster") $w.enabled }}true{{ end -}}
{{- end -}}

{{/* "true" when this hub release renders hub-namespace CRs. */}}
{{- define "asservat.hubWorker.hub" -}}
{{- if ne .Values.mode "cluster" }}true{{ end -}}
{{- end -}}

{{/* Capacity is configured when the top-level capacity object is set (the
     former bootstrap.continuation.public.capacity, same field names). */}}
{{- define "asservat.hubWorker.capacityEnabled" -}}
{{- if .Values.capacity }}true{{ end -}}
{{- end -}}

{{- define "asservat.hubWorker.prefix" -}}
{{- .Values.installation.name -}}
{{- end -}}

{{- define "asservat.hubWorker.fullname" -}}
{{- printf "%s-hub-worker" (include "asservat.hubWorker.prefix" .) -}}
{{- end -}}

{{/* Chart constants that `asservat setup` must apply with the same values. */}}
{{- define "asservat.hubWorker.authMount" -}}asservat-configuration{{- end -}}
{{- define "asservat.hubWorker.audience" -}}asservat-hub-worker{{- end -}}
{{- define "asservat.hubWorker.auditMount" -}}asservat-audit{{- end -}}
{{- define "asservat.hubWorker.auditKey" -}}audit{{- end -}}

{{/* OpenBao Kubernetes auth role (and policy) name of one purpose; call with
     (list $ "audit-wrap"). Purposes: audit-wrap, audit-unwrap, cleanup-wrap,
     cleanup-open, cleanup-verify, cleanup-sign. */}}
{{- define "asservat.hubWorker.providerRole" -}}
{{- printf "%s-%s" (include "asservat.hubWorker.fullname" (index . 0)) (index . 1) -}}
{{- end -}}

{{/* All six role names as JSON {purpose: name}, for `setup`. */}}
{{- define "asservat.hubWorker.providerRoleNames" -}}
{{- $out := dict -}}
{{- range $p := list "audit-wrap" "audit-unwrap" "cleanup-wrap" "cleanup-open" "cleanup-verify" "cleanup-sign" -}}
{{- $_ := set $out $p (include "asservat.hubWorker.providerRole" (list $ $p)) -}}
{{- end -}}
{{- toJson $out -}}
{{- end -}}

{{/* Generated Secret name or its secrets.<key>.existingSecret override;
     call with (list $ "ids"). */}}
{{- define "asservat.hubWorker.secretName" -}}
{{- $root := index . 0 -}}
{{- $key := index . 1 -}}
{{- $o := default dict (index (default dict $root.Values.secrets) $key) -}}
{{- default (printf "%s-%s" (include "asservat.hubWorker.prefix" $root) $key) $o.existingSecret -}}
{{- end -}}

{{- define "asservat.hubWorker.labels" -}}
app.kubernetes.io/name: asservat
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/component: hub-worker
app.kubernetes.io/part-of: asservat
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
{{- end -}}

{{- define "asservat.hubWorker.selectorLabels" -}}
app.kubernetes.io/name: asservat
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/component: hub-worker
{{- end -}}

{{- define "asservat.hubWorker.image" -}}
{{- $i := default dict .Values.image -}}
{{- if or (not $i.repository) (not (regexMatch "^sha256:[a-f0-9]{64}$" (default "" $i.digest))) -}}
{{- fail "image.repository and image.digest (sha256:<64 hex>) are required" -}}
{{- end -}}
{{- printf "%s@%s" $i.repository $i.digest -}}
{{- end -}}

{{/* Endpoints of the selected PostgreSQL, audit object store and OpenBao:
     bundled service addresses or services.<provider>.external values. */}}
{{- define "asservat.hubWorker.postgres" -}}
{{- $s := .Values.services.postgres -}}
{{- if eq $s.provider "bundled" -}}
{{- toJson (dict "host" (printf "%s-postgres.%s.svc" (include "asservat.hubWorker.prefix" .) .Release.Namespace) "port" 5432 "database" "asservat") -}}
{{- else -}}
{{- $e := default dict $s.external -}}
{{- toJson (dict "host" (required "services.postgres.external.host is required" $e.host) "port" (int (default 5432 $e.port)) "database" (default "asservat" $e.database)) -}}
{{- end -}}
{{- end -}}

{{- define "asservat.hubWorker.auditStore" -}}
{{- $s := .Values.services.objectStore -}}
{{- if eq $s.provider "seaweedfs" -}}
{{- toJson (dict "endpoint" (printf "https://%s-objectstore.%s.svc:8333" (include "asservat.hubWorker.prefix" .) .Release.Namespace) "region" "us-east-1" "bucket" (printf "%s-audit" (include "asservat.hubWorker.prefix" .))) -}}
{{- else -}}
{{- $e := default dict $s.external -}}
{{- toJson (dict "endpoint" (required "services.objectStore.external.endpoint is required" $e.endpoint) "region" (required "services.objectStore.external.region is required" $e.region) "bucket" (required "services.objectStore.external.bucket is required" $e.bucket)) -}}
{{- end -}}
{{- end -}}

{{- define "asservat.hubWorker.keyService" -}}
{{- $s := .Values.services.keyService -}}
{{- $endpoint := "" -}}
{{- if eq $s.provider "openbao" -}}
{{- $endpoint = printf "https://%s-openbao.%s.svc:8200" (include "asservat.hubWorker.prefix" .) .Release.Namespace -}}
{{- else -}}
{{- $endpoint = required "services.keyService.external.endpoint is required" (dig "external" "endpoint" "" $s) -}}
{{- end -}}
{{- toJson (dict "endpoint" $endpoint "auditMount" (include "asservat.hubWorker.auditMount" .) "auditKey" (include "asservat.hubWorker.auditKey" .)) -}}
{{- end -}}

{{/* "true" when the cleanup child runs: cleanup.enabled, default true with
     capacity; it requires capacity. */}}
{{- define "asservat.hubWorker.cleanupEnabled" -}}
{{- $on := dig "enabled" (not (empty .Values.capacity)) (default dict .Values.cleanup) -}}
{{- if and $on (not .Values.capacity) }}{{ fail "cleanup.enabled requires capacity" }}{{ end -}}
{{- if $on }}true{{ end -}}
{{- end -}}

{{- define "asservat.hubWorker.permissionEnabled" -}}
{{- if dig "enabled" false (default dict .Values.permission) }}true{{ end -}}
{{- end -}}

{{/* "true" when the permission child deletes expired context evidence. */}}
{{- define "asservat.hubWorker.contextDeletionEnabled" -}}
{{- if and (include "asservat.hubWorker.permissionEnabled" .) (hasKey .Values.permission "contextDeletion") }}true{{ end -}}
{{- end -}}

{{/* Transit key names on the audit mount; chart constants shared with setup. */}}
{{- define "asservat.hubWorker.contextDeletionKey" -}}
{{- printf "%s-context-deletion" (include "asservat.hubWorker.prefix" .) -}}
{{- end -}}
{{- define "asservat.hubWorker.workerConfigurationAuditKey" -}}
{{- printf "%s-worker-configuration-audit" (include "asservat.hubWorker.prefix" .) -}}
{{- end -}}

{{/* Capacity, cleanup and permission sections (contracts.HubWorkerCapacity,
     HubWorkerCleanup, HubWorkerPermission), each omitted when disabled, and
     a "provider" entry merged into the provider section. */}}
{{- define "asservat.hubWorker.sections" -}}
{{- $out := dict -}}
{{- $provider := dict -}}
{{- $mount := include "asservat.hubWorker.auditMount" . -}}
{{- $signing := dict "mount" $mount "key" (include "asservat.hubWorker.contextDeletionKey" .) -}}
{{- if include "asservat.hubWorker.capacityEnabled" . -}}
{{- $c := deepCopy .Values.capacity -}}
{{/* TODO: no chart template renders the processing source ConfigMap yet. */}}
{{- $_ := set $c "processingSource" (printf "%s-processing-source" (include "asservat.hubWorker.prefix" .)) -}}
{{- $_ := set $c "paths" list -}}
{{- $_ := set $c "sharedQueries" (dig "publisher" "enabled" false (default dict .Values.hub)) -}}
{{- $_ := set $out "capacity" $c -}}
{{- end -}}
{{- if include "asservat.hubWorker.cleanupEnabled" . -}}
{{- $_ := set $out "cleanup" dict -}}
{{- $_ := set $provider "contextDeletionSigning" $signing -}}
{{- end -}}
{{- if include "asservat.hubWorker.permissionEnabled" . -}}
{{- $p := .Values.permission -}}
{{- $v := dict "statusUsers" (default list $p.statusUsers) "delegations" (default list $p.delegations) -}}
{{- if $p.review }}{{ $_ := set $v "review" $p.review }}{{ end -}}
{{- if dig "retention" (not (empty .Values.retention)) $p }}{{ $_ := set $v "retention" true }}{{ end -}}
{{- with $p.workerConfiguration -}}
{{- $_ := set $v "workerConfiguration" (dict "namespace" (required "permission.workerConfiguration.namespace is required" .namespace) "source" (required "permission.workerConfiguration.source is required" .source)) -}}
{{- $_ := set $provider "workerConfigurationAudit" (dict "mount" $mount "key" (include "asservat.hubWorker.workerConfigurationAuditKey" $)) -}}
{{- end -}}
{{- if include "asservat.hubWorker.contextDeletionEnabled" . -}}
{{/* Defaults to the audit store: bundled object storage holds one bucket. */}}
{{- $store := merge (deepCopy (default dict (dig "contextDeletion" "evidenceStore" dict $p))) (fromJson (include "asservat.hubWorker.auditStore" .)) -}}
{{- $_ := set $v "contextDeletion" (dict "evidenceStore" $store) -}}
{{- $_ := set $provider "contextDeletionSigning" $signing -}}
{{- end -}}
{{- with $p.browser }}{{ $_ := set $v "browser" (dict "settings" (required "permission.browser.settings is required" .settings)) }}{{ end -}}
{{- with $p.identity }}{{ $_ := set $v "identity" (dict "settings" (required "permission.identity.settings is required" .settings) "issuer" (required "permission.identity.issuer is required" .issuer)) }}{{ end -}}
{{- $_ := set $out "permission" $v -}}
{{- end -}}
{{- if $provider }}{{ $_ := set $out "provider" $provider }}{{ end -}}
{{- toJson $out -}}
{{- end -}}

{{/* The rendered config.json (contracts.HubWorkerConfig). */}}
{{- define "asservat.hubWorker.config" -}}
{{- $sections := fromJson (include "asservat.hubWorker.sections" .) -}}
{{- $roles := dict "auditWrap" (include "asservat.hubWorker.providerRole" (list . "audit-wrap")) "auditUnwrap" (include "asservat.hubWorker.providerRole" (list . "audit-unwrap")) -}}
{{- if hasKey $sections "cleanup" -}}
{{- $_ := set $roles "cleanupWrap" (include "asservat.hubWorker.providerRole" (list . "cleanup-wrap")) -}}
{{- $_ := set $roles "cleanupOpen" (include "asservat.hubWorker.providerRole" (list . "cleanup-open")) -}}
{{- $_ := set $roles "cleanupVerify" (include "asservat.hubWorker.providerRole" (list . "cleanup-verify")) -}}
{{- $_ := set $roles "cleanupSign" (include "asservat.hubWorker.providerRole" (list . "cleanup-sign")) -}}
{{- end -}}
{{- $provider := dict "authMount" (include "asservat.hubWorker.authMount" .) "audience" (include "asservat.hubWorker.audience" .) "roles" $roles -}}
{{- if hasKey $sections "provider" -}}
{{- $provider = merge $provider (get $sections "provider") -}}
{{- $_ := unset $sections "provider" -}}
{{- end -}}
{{- $prefix := include "asservat.hubWorker.prefix" . -}}
{{- $v := dict "format" "asservat-hub-worker-config/v1" "namespace" .Release.Namespace "serviceAccount" (include "asservat.hubWorker.fullname" .) "fleetSource" (printf "%s-fleet" $prefix) "ownerSource" (printf "%s-owner-source" $prefix) "leaderLease" (printf "%s-hub-worker-leader" $prefix) "postgres" (fromJson (include "asservat.hubWorker.postgres" .)) "auditStore" (fromJson (include "asservat.hubWorker.auditStore" .)) "keyService" (fromJson (include "asservat.hubWorker.keyService" .)) "provider" $provider -}}
{{- toJson (merge $v $sections) -}}
{{- end -}}

{{/* Projected trust roots: roots/postgres.crt, roots/audit-store.crt and
     roots/key-service.crt from the bundled services' state Secrets (ca.crt)
     or, for external providers, from the hub-worker ConfigMap keys rendered
     from services.<provider>.external.rootsPEM. */}}
{{- define "asservat.hubWorker.externalRoots" -}}
{{- $out := dict -}}
{{- if ne .Values.services.postgres.provider "bundled" }}{{ $_ := set $out "postgres" (required "services.postgres.external.rootsPEM is required" (dig "external" "rootsPEM" "" .Values.services.postgres)) }}{{ end -}}
{{- if ne .Values.services.objectStore.provider "seaweedfs" }}{{ $_ := set $out "audit-store" (required "services.objectStore.external.rootsPEM is required" (dig "external" "rootsPEM" "" .Values.services.objectStore)) }}{{ end -}}
{{- if ne .Values.services.keyService.provider "openbao" }}{{ $_ := set $out "key-service" (required "services.keyService.external.rootsPEM is required" (dig "external" "rootsPEM" "" .Values.services.keyService)) }}{{ end -}}
{{- toJson $out -}}
{{- end -}}

{{- define "asservat.hubWorker.rootsProjection" -}}
{{- $prefix := include "asservat.hubWorker.prefix" . -}}
{{- range $root := list (list "postgres" "bundled" .Values.services.postgres.provider) (list "objectstore" "seaweedfs" .Values.services.objectStore.provider) (list "openbao" "openbao" .Values.services.keyService.provider) }}
{{- if eq (index $root 1) (index $root 2) }}
- secret:
    name: {{ printf "%s-%s-state" $prefix (index $root 0) | quote }}
    optional: false
    items:
      - key: ca.crt
        path: {{ get (dict "postgres" "roots/postgres.crt" "objectstore" "roots/audit-store.crt" "openbao" "roots/key-service.crt") (index $root 0) }}
{{- end }}
{{- end }}
{{- end -}}

{{/* Init container waiting for the current schema.
     TODO: replace with the shared asservat.waitSchema helper; the wait
     subcommand belongs to the setup stream. */}}
{{- define "asservat.hubWorker.waitSchema" -}}
- name: wait-schema
  image: {{ include "asservat.hubWorker.image" . | quote }}
  imagePullPolicy: {{ default "IfNotPresent" .Values.image.pullPolicy }}
  command: [/asservat, setup, --wait-schema]
  securityContext:
    {{- include "asservat.hubWorker.securityContext" . | nindent 4 }}
  resources:
    requests: {cpu: 20m, memory: 32Mi}
    limits: {cpu: "1", memory: 256Mi}
  volumeMounts:
    - {name: inputs, mountPath: /run/asservat/hub-worker, readOnly: true}
    - {name: ids, mountPath: /run/asservat/ids, readOnly: true}
{{- end -}}

{{- define "asservat.hubWorker.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "asservat.hubWorker.securityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
{{- end -}}
