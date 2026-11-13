{{/*
hub-worker helpers (contracts.HubWorkerConfig). Generic helpers live in
_helpers.tpl. The config holds only chart values: generated IDs come from
`<name>-ids`, OpenBao mounts/audience/key names are fixed or derive from the
installation ID in Go, object UIDs are read by name.
*/}}

{{/* The browser/MCP issuer: identity.issuer, or the bundled Keycloak realm. */}}
{{- define "asservat.hubWorker.identityIssuer" -}}
{{- if .Values.identity.issuer -}}
{{- .Values.identity.issuer -}}
{{- else if eq .Values.services.identity.provider "keycloak" -}}
{{- $kc := .Values.services.identity.keycloak -}}
{{- printf "%s/realms/%s" (trimSuffix "/" (required "services.identity.keycloak.hostname is required" $kc.hostname)) $kc.realm -}}
{{- else -}}
{{- fail "identity.issuer is required" -}}
{{- end -}}
{{- end -}}

{{/* The rendered config.json (contracts.HubWorkerConfig). Children: the
     configuration child always; permission always (AccessBindings, browser
     and identity settings projections, needed by a usable console);
     capacity, cleanup and context deletion with `capacity`; the hub
     retention source with `retention`; worker configuration acceptance with
     hub.download-worker.enabled. */}}
{{- define "asservat.hubWorker.config" -}}
{{- $n := include "asservat.name" . -}}
{{- $w := index .Values.hub "hub-worker" -}}
{{- $perm := default dict $w.permission -}}
{{- $p := fromJson (include "asservat.providers" .) -}}
{{- $role := dict -}}
{{- range $purpose := list "audit-wrap" "audit-unwrap" "cleanup-wrap" "cleanup-open" "cleanup-verify" "cleanup-sign" -}}
{{- $_ := set $role $purpose (include "asservat.openBaoRole" (list $ "hub-worker" $purpose)) -}}
{{- end -}}
{{- $roles := dict "auditWrap" (get $role "audit-wrap") "auditUnwrap" (get $role "audit-unwrap") -}}
{{- $account := include "asservat.fullname" (list . "hub-worker") -}}
{{- $permission := dict
  "statusUsers" (default (list (printf "system:serviceaccount:%s:%s" .Release.Namespace $account)) $perm.statusUsers)
  "delegations" (default list .Values.identity.permissionDelegations)
  "browser" (dict "settings" (printf "%s-browser-settings" $n))
  "identity" (dict "settings" (printf "%s-identity-settings" $n) "issuer" (include "asservat.hubWorker.identityIssuer" .)) -}}
{{- with $perm.review }}{{ $_ := set $permission "review" . }}{{ end -}}
{{- if .Values.retention }}{{ $_ := set $permission "retention" true }}{{ end -}}
{{- if (index .Values.hub "download-worker").enabled -}}
{{- $_ := set $permission "workerConfiguration" (dict "namespace" (printf "%s-downloads" $n) "source" (printf "%s-worker-profile" $n)) -}}
{{- end -}}
{{- $v := dict "format" "asservat-hub-worker-config/v1" "namespace" .Release.Namespace "serviceAccount" $account
  "fleetSource" (printf "%s-fleet" $n) "ownerSource" (printf "%s-owner-source" $n) "leaderLease" (printf "%s-hub-worker-leader" $n)
  "postgres" $p.postgres
  "auditStore" (dict "endpoint" $p.objectStore.endpoint "region" $p.objectStore.region "bucket" $p.objectStore.auditBucket)
  "keyService" (dict "endpoint" $p.openBao.endpoint) -}}
{{- if .Values.capacity -}}
{{- $c := deepCopy .Values.capacity -}}
{{- $_ := set $c "processingSource" (printf "%s-processing-source" $n) -}}
{{- $_ := set $c "paths" list -}}
{{- $_ := set $c "sharedQueries" (gt (int (default 0 .Values.hub.publisher.replicas)) 0) -}}
{{- $_ := set $v "capacity" $c -}}
{{- $_ := set $v "cleanup" dict -}}
{{- $_ := set $roles "cleanupWrap" (get $role "cleanup-wrap") -}}
{{- $_ := set $roles "cleanupOpen" (get $role "cleanup-open") -}}
{{- $_ := set $roles "cleanupVerify" (get $role "cleanup-verify") -}}
{{- $_ := set $roles "cleanupSign" (get $role "cleanup-sign") -}}
{{- $_ := set $permission "contextDeletion" (dict "evidenceStore" (dict "endpoint" $p.objectStore.endpoint "region" $p.objectStore.region "bucket" $p.objectStore.evidenceBucket)) -}}
{{- end -}}
{{- $_ := set $v "permission" $permission -}}
{{- $_ := set $v "provider" (dict "roles" $roles) -}}
{{- toJson $v -}}
{{- end -}}

{{/* fleet.json (contracts.FleetSettings): chart values only; the readers
     add the installation ID and issuer epoch from `<name>-ids`. */}}
{{- define "asservat.hubWorker.fleet" -}}
{{- $f := .Values.fleet -}}
{{- $clients := $f.clients -}}
{{- if not $clients }}{{ $clients = list (default "asservat-console" .Values.identity.clientID) }}{{ end -}}
{{- toJson (dict "schemaVersion" "fleet-settings/v1" "revision" (int .Release.Revision) "suspended" false
  "issuer" (default (include "asservat.hubWorker.identityIssuer" .) $f.issuer)
  "clients" $clients "subjects" (default list $f.subjects) "groups" (default list $f.groups) "deliveryProfiles" (include "asservat.hubApi.deliveryProfiles" . | fromJsonArray)
  "maxActiveBootstraps" (int $f.maxActiveBootstraps) "maxBootstrapHistory" (int $f.maxBootstrapHistory) "maxClusters" (int $f.maxClusters)) -}}
{{- end -}}

{{/* owner-pool.json (contracts.OwnerSource): the hub-api owner pool by name.
     The hub-worker adds the generated IDs, the objects' UIDs and the owner
     PKI CA. Ports are the hub-api listeners (owner 9443, native 9444,
     operation 9448). */}}
{{- define "asservat.hubWorker.ownerSource" -}}
{{- $api := include "asservat.fullname" (list . "hub-api") -}}
{{- toJson (dict "format" "asservat-hub-owner-source/v1" "revision" (int .Release.Revision) "suspended" false
  "service" (printf "%s-owner" $api) "deployment" $api "serviceAccount" $api
  "port" 9443 "nativePort" 9444 "nativeBootstrap" "owner-bootstrap/v1" "nativeCandidateLimit" 1024 "operationPort" 9448) -}}
{{- end -}}
