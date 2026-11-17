{{/* hub-api-specific helpers; shared names, labels and providers are in
     _helpers.tpl. */}}

{{/* Download-worker namespaces in the hub cluster (JSON list). */}}
{{- define "asservat.hubApi.workerNamespaces" -}}
{{- $h := index .Values.hub "hub-api" -}}
{{- $d := default dict (index .Values.hub "download-worker") -}}
{{- $default := list -}}
{{- if dig "enabled" true $d }}{{ $default = list (printf "%s-downloads" (include "asservat.name" .)) }}{{ end -}}
{{- toJson (default $default $h.workerNamespaces) -}}
{{- end -}}

{{/* Browser identity: issuer and console client (JSON). Bundled Keycloak
     derives both from services.identity.keycloak. */}}
{{- define "asservat.hubApi.identity" -}}
{{- $i := .Values.identity -}}
{{- $out := dict "issuer" $i.issuer "clientID" $i.clientID -}}
{{- if eq .Values.services.identity.provider "keycloak" -}}
{{- $k := .Values.services.identity.keycloak -}}
{{- $_ := set $out "issuer" (default (printf "%s/realms/%s" $k.hostname $k.realm) $i.issuer) -}}
{{- $_ := set $out "clientID" (default "asservat-console" $i.clientID) -}}
{{- end -}}
{{- $_ := set $out "browserAudience" (default $out.clientID $i.browserAudience) -}}
{{- toJson $out -}}
{{- end -}}

{{/* The OIDC client secret: identity.clientSecret.existingSecret, or the
     bundled Keycloak's `<name>-keycloak-state` (console-client-secret). */}}
{{- define "asservat.hubApi.clientSecret" -}}
{{- $c := .Values.identity.clientSecret -}}
{{- if $c.existingSecret -}}
{{- toJson (dict "name" $c.existingSecret "key" (default "client-secret" $c.key)) -}}
{{- else if eq .Values.services.identity.provider "keycloak" -}}
{{- toJson (dict "name" (printf "%s-keycloak-state" (include "asservat.name" .)) "key" "console-client-secret") -}}
{{- else -}}
{{- fail "identity.clientSecret.existingSecret is required with an external identity provider" -}}
{{- end -}}
{{- end -}}

{{/* True when the regional connector shares this release (mode=combined). */}}
{{- define "asservat.hubApi.combined" -}}
{{- if eq .Values.mode "combined" }}true{{ end -}}
{{- end -}}

{{/* True when the hub publishes its regional offer: mode=combined or
     registered mode=cluster clusters (values clusters). */}}
{{- define "asservat.hubApi.offer" -}}
{{- if or (include "asservat.hubApi.combined" .) (and (include "asservat.hub" .) .Values.clusters) }}true{{ end -}}
{{- end -}}

{{/* The registered mode=cluster clusters (contracts.RemoteCluster, JSON
     list); the hub derives their IDs from the names. */}}
{{- define "asservat.hubApi.clusters" -}}
{{- $root := . -}}
{{- $out := list -}}
{{- range .Values.clusters -}}
{{- $out = append $out (dict "name" (required "clusters[].name is required" .name) "namespace" (default $root.Release.Namespace .namespace) "standby" (int (default 2 .standby)) "captures" (int (dig "capturesPerCluster" 8 (fromJson (include "asservat.capacity" $root))))) -}}
{{- end -}}
{{- toJson $out -}}
{{- end -}}

{{/* The hub-api config.json (contracts.HubAPIConfig): render-time values
     only. Object, key and role names derive from name in Go. */}}
{{- define "asservat.hubApi.config" -}}
{{- $h := index .Values.hub "hub-api" -}}
{{- $c := fromJson (include "asservat.providers" .) -}}
{{- $_ := set $c "format" "asservat-hub-api-config/v1" -}}
{{- $_ := set $c "name" (include "asservat.name" .) -}}
{{- $_ := set $c "namespace" .Release.Namespace -}}
{{- $_ := set $c "connections" (int $h.connections) -}}
{{- $_ := set $c "concurrency" (int $h.concurrency) -}}
{{- $obs := dict -}}
{{- with $h.peers }}{{ $_ := set $obs "peers" . }}{{ end -}}
{{- if include "asservat.capacity" . -}}
{{- $lc := dict "keys" (list "asservat.io/evidence") -}}
{{- with .Values.workloadKeys -}}
{{- with .labels }}{{ $_ := set $lc "labelKeys" . }}{{ end -}}
{{- with .annotations }}{{ $_ := set $lc "annotationKeys" . }}{{ end -}}
{{- end -}}
{{- $_ := set $obs "localCapacity" $lc -}}
{{- end -}}
{{- $_ := set $c "observation" $obs -}}
{{- $_ := set $c "connectorTokens" (include "asservat.connectorTokens" . | fromJson) -}}
{{- $_ := set $c "native" (dict "workerNamespaces" (include "asservat.hubApi.workerNamespaces" . | fromJsonArray)) -}}
{{- if .Values.origin -}}
{{- $u := $h.public -}}
{{- $id := fromJson (include "asservat.hubApi.identity" .) -}}
{{- $pub := dict "origin" .Values.origin "browserAudience" $id.browserAudience "version" (.Chart.AppVersion | default .Chart.Version) -}}
{{- $_ := set $pub "captures" (int (dig "capturesPerCluster" 8 (fromJson (include "asservat.capacity" .)))) -}}
{{- with dig "workload" "dump" nil (default dict .Values.capacity) }}{{ $_ := set $pub "workloadRate" . }}{{ end -}}
{{- range $key := list "standby" "previewSeconds" "operationConcurrency" "mcpPerIdentity" "downloadConcurrency" "operationAudit" "downloadPlan" -}}
{{- $_ := set $pub $key (index $u $key) -}}
{{- end -}}
{{- if or $u.processing (include "asservat.capacity" .) }}{{ $_ := set $pub "processing" true }}{{ end -}}
{{- with .Values.captureHistory }}{{ $_ := set $pub "captureHistory" . }}{{ end -}}
{{- if eq .Values.exposure.tls.mode "proxy" }}{{ $_ := set $pub "proxyTLS" true }}{{ end -}}
{{- if include "asservat.hubApi.offer" . -}}
{{- $offer := dict "image" (include "asservat.image" .) -}}
{{- if not (include "asservat.hubApi.combined" .) }}{{ $_ := set $offer "hubOnly" true }}{{ end -}}
{{- if .Values.clusters }}{{ $_ := required "clusters need hub.url, the URL workload clusters dial" .Values.hub.url }}{{ end -}}
{{- $_ := set $pub "regionalOffer" $offer -}}
{{- end -}}
{{- $_ := set $c "public" $pub -}}
{{- end -}}
{{- with include "asservat.hubApi.clusters" . | fromJsonArray -}}
{{- if not $.Values.origin }}{{ fail "clusters require origin" }}{{ end -}}
{{- $_ := set $c "clusters" . -}}
{{- end -}}
{{- toJson $c -}}
{{- end -}}

{{/* The empty download-worker control catalog (contracts.OwnerWorkerTrust). */}}
{{- define "asservat.hubApi.workerControls" -}}
{{- toJson (dict "format" "asservat-owner-worker-trust/v1" "controls" list) -}}
{{- end -}}

{{/* browser.json (contracts.BrowserSettings). */}}
{{- define "asservat.hubApi.browserSettings" -}}
{{- $i := .Values.identity -}}
{{- $id := fromJson (include "asservat.hubApi.identity" .) -}}
{{- toJson (dict "schemaVersion" "browser-settings/v1" "issuer" (required "identity.issuer is required" $id.issuer) "clientID" (required "identity.clientID is required" $id.clientID) "origin" .Values.origin
  "maxLifetimeSeconds" (int $i.maxLifetimeSeconds) "inactivityTimeoutSeconds" (int $i.inactivityTimeoutSeconds)) -}}
{{- end -}}

{{/* identity.json (contracts.IdentitySettings). Without identity.clients the
     console client is the one human client. Bundled Keycloak defaults the
     administrators to its /asservat-admins group. */}}
{{- define "asservat.hubApi.identitySettings" -}}
{{- $i := .Values.identity -}}
{{- $id := fromJson (include "asservat.hubApi.identity" .) -}}
{{- $clients := default (list (dict "id" $id.clientID "kind" "human" "classQualified" true)) $i.clients -}}
{{- $admins := dict -}}
{{- with $i.administrators.groups }}{{ $_ := set $admins "groups" . }}{{ end -}}
{{- with $i.administrators.subjects }}{{ $_ := set $admins "subjects" . }}{{ end -}}
{{- if and (empty $admins) (eq .Values.services.identity.provider "keycloak") }}{{ $_ := set $admins "groups" (list "/asservat-admins") }}{{ end -}}
{{- if empty $admins }}{{ fail "identity.administrators.groups or identity.administrators.subjects is required" }}{{ end -}}
{{- $out := dict "schemaVersion" "identity-settings/v1" "issuer" $id.issuer "clients" $clients "groupsClaim" (default "groups" $i.groupsClaim) "usernameClaim" (default "preferred_username" $i.usernameClaim) "administrators" $admins -}}
{{- with $i.requiredGroups }}{{ $_ := set $out "requiredGroups" . }}{{ end -}}
{{- with $i.approvals }}{{ $_ := set $out "approvals" . }}{{ end -}}
{{- $admins := dict -}}
{{- with $i.administrators }}{{ with .groups }}{{ $_ := set $admins "groups" . }}{{ end }}{{ with .subjects }}{{ $_ := set $admins "subjects" . }}{{ end }}{{ end -}}
{{- if $admins }}{{ $_ := set $out "administrators" $admins }}{{ end -}}
{{- toJson $out -}}
{{- end -}}

{{/* download-environment.json (contracts.DownloadEnvironmentSettings), also
     the capacity processing source (ADR-192). rootID, installationID and
     recoveryEpoch come from the <name>-ids Secret in the reader. With
     download workers the hub-local region is permitted and every human
     client may download context captures of the baseline's purpose over
     every installed path (installedPaths). */}}
{{- define "asservat.hubApi.downloadEnvironment" -}}
{{- $i := .Values.identity -}}
{{- $id := fromJson (include "asservat.hubApi.identity" .) -}}
{{- $p := fromJson (include "asservat.providers" .) -}}
{{- $regions := list -}}
{{- $clients := list -}}
{{- if include "asservat.hubApi.workerNamespaces" . | fromJsonArray -}}
{{- $regions = list $p.objectStore.region -}}
{{- with .Values.retention.purposeRef -}}
{{- $purpose := . -}}
{{- range (default (list (dict "id" $id.clientID "kind" "human")) $i.clients) -}}
{{- if eq .kind "human" -}}
{{- $clients = append $clients (dict "issuer" $id.issuer "id" .id "kind" .kind "dataClasses" (list "metadata" "extract" "raw") "privacyClasses" (list "potentialPersonalData") "evidenceTypes" (list "context" "packetCapture" "syscallTrace" "profile" "logs") "purposes" (list $purpose) "pathIDs" list "installedPaths" true) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $out := dict "format" "asservat-download-environment/v1" "revision" (int .Release.Revision) "suspended" false "permittedRegions" $regions "paths" list "clients" $clients "operators" (default list $i.processingOperators) -}}
{{- /* With download workers the paths are the readers' installed (derived)
     paths: Helm does not know their generated fields. */ -}}
{{- if $regions }}{{ $_ := set $out "installedPaths" true }}{{ end -}}
{{- if hasKey .Values "processors" }}{{ $_ := set $out "processors" (default list .Values.processors) }}{{ end -}}
{{- toJson $out -}}
{{- end -}}
